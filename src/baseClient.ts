import { writeFile, readFile } from "fs";
import { resolve as resolvePath } from "path";

import sharp from "sharp";
import fetch from "node-fetch";
import WebSocket from "ws";
import crypto from "crypto";
import qrcode from "qrcode";
import { generateKeyPair, sharedKey } from "curve25519-js";
import { TypedEmitter } from "tiny-typed-emitter";

import {
  WAWebMessage,
  WAStubMessage,
  WhatsAppLoginPayload,
  WhatsAppConnPayload,
  WhatsAppStreamPayload,
  WhatsAppPropsPayload,
  WhatsAppUploadMediaURL,
  WAReceiveMedia,
  WhatsAppAdminTestPayload,
  WAMessage,
  WhatsAppGroupMetadataPayload,
  WAContextInfo,
  WhatsAppMediaUploadPayload,
  WhatsAppMediaConnPayload,
  WAMedia,
  WADecryptedMedia,
} from "./types";
import { doesFileExist } from "./utils/path";
import {
  HmacSha256,
  AESDecrypt,
  randHex,
  AESEncrypt,
  HKDF,
  Sha256,
  dataUrlToBuffer,
} from "./utils/encryption";
import { arraysEqual, concatIntArray } from "./utils/arrays";
import { whatsappReadBinary, WANode } from "./utils/whatsappBinaryReader";
import {
  WAMessageNode,
  whatsappWriteBinary,
} from "./utils/whatsappBinaryWriter";
import {
  WAMetrics,
  WAFlags,
  WAWebMessageInfo,
  WAMediaAppInfo,
} from "./utils/whatsappTokens";

interface WAListeners {
  node: (node: WANode) => void;
  message: (msg: WAWebMessage, description: string) => void;
  messageStub: (msg: WAStubMessage) => void;
  noNetwork: () => void;
  loggedOut: () => void;
  ready: () => void;
  myWid: (wid: string) => void;
  qrCode: () => void;
}

export default class WABaseClient extends TypedEmitter<WAListeners> {
  protected apiSocket: WebSocket;

  protected keysPath?: string;
  protected qrPath: string;
  protected clientId?: string;

  public myWid?: string;

  public messageSentCount = 0;

  protected keyPair: {
    public: Uint8Array;
    private: Uint8Array;
  } | null;

  protected clientToken: string | null = null;
  protected serverToken: string | null = null;
  protected encKey: Uint8Array = new Uint8Array();
  protected macKey: Uint8Array = new Uint8Array();

  public isLoggedIn: boolean = false;

  protected eventListeners: {
    [key: string]: (e: WebSocket.MessageEvent) => void;
  } = {};

  constructor(
    opts: { qrPath: string; restoreSession: boolean; keysPath: string } = {
      qrPath: "./qrcode.png",
      restoreSession: false,
      keysPath: "./keys.json",
    }
  ) {
    super();

    const loginMsgId = "" + Date.now();

    this.apiSocket = new WebSocket("wss://web.whatsapp.com/ws", {
      headers: { Origin: "https://web.whatsapp.com" },
    });

    this.keyPair = null;

    this.qrPath = resolvePath(".", opts.qrPath);

    if (opts.restoreSession) {
      this.keysPath = resolvePath(".", opts.keysPath);
    }

    this.apiSocket.onopen = this.init(loginMsgId, opts.restoreSession);

    if (opts.restoreSession) {
      doesFileExist(this.keysPath!).then((doesExist) => {
        if (!doesExist) {
          this.apiSocket.onmessage = this.onSocketMessage(loginMsgId);
        }
      });
    } else {
      this.apiSocket.onmessage = this.onSocketMessage(loginMsgId);
    }
  }

  protected addEventListener(
    cb: (e: WebSocket.MessageEvent) => void,
    id: string
  ) {
    this.eventListeners[id] = cb;
  }

  protected saveKeys() {
    writeFile(
      this.keysPath!,
      JSON.stringify({
        clientId: this.clientId,
        clientToken: this.clientToken,
        serverToken: this.serverToken,
        macKey: Array.from(this.macKey),
        encKey: Array.from(this.encKey),
      }),
      (err) => console.error(err)
    );
  }

  protected async getKeys() {
    return new Promise((resolve, reject) => {
      readFile(this.keysPath!, "utf-8", (err, data) => {
        if (err) reject(err);

        const {
          clientId,
          clientToken,
          serverToken,
          macKey,
          encKey,
        } = JSON.parse(data);

        this.encKey = Uint8Array.from(encKey);
        this.macKey = Uint8Array.from(macKey);
        this.clientId = clientId;
        this.clientToken = clientToken;
        this.serverToken = serverToken;

        resolve();
      });
    });
  }

  protected async restoreSession(loginMsgId: string) {
    this.apiSocket.send(
      `${loginMsgId},["admin","login","${this.clientToken}","${this.serverToken}","${this.clientId}","takeover"]`
    );

    this.apiSocket.onmessage = (e) => {
      if (typeof e.data === "string") {
        const receivedMessageId = e.data.substring(0, e.data.indexOf(","));

        if (receivedMessageId === loginMsgId && e.data !== `${loginMsgId},`) {
          const data = JSON.parse(
            e.data.substring(e.data.indexOf(",") + 1)
          ) as { status: number };

          if (data.status === 200) {
            this.apiSocket.onmessage = this.onSocketMessage(loginMsgId);
          } else {
            this.emit("loggedOut");
          }
        }
      }
    };
  }

  protected keepAlive() {
    if (this.apiSocket) {
      this.apiSocket.send("?,,");
      setTimeout(this.keepAlive.bind(this), 20 * 1000);
    }
  }

  public disconnect() {
    this.apiSocket.send(`goodbye,,["admin","Conn","disconnect"]`);
  }

  async sendSocketAsync(messageTag: string, data: any): Promise<any> {
    return new Promise((resolve) => {
      this.apiSocket.send(data);

      this.addEventListener(async (e) => {
        if (typeof e.data === "string") {
          const receivedMessageId = e.data.substring(0, e.data.indexOf(","));

          if (receivedMessageId === messageTag && e.data !== `${messageTag},`) {
            const data = JSON.parse(e.data.substring(e.data.indexOf(",") + 1));
            delete this.eventListeners[messageTag];

            resolve(data);
          }
        }
      }, messageTag);
    });
  }

  onSocketMessage(loginMsgId: string) {
    return async (e: WebSocket.MessageEvent) => {
      Object.values(this.eventListeners).forEach((func) => func(e));

      if (typeof e.data === "string") {
        try {
          const messageTag = e.data.substring(0, e.data.indexOf(","));
          const data = JSON.parse(e.data.substring(e.data.indexOf(",") + 1)) as
            | WhatsAppLoginPayload
            | WhatsAppConnPayload
            | WhatsAppStreamPayload
            | WhatsAppPropsPayload
            | WhatsAppUploadMediaURL;

          // Initial response and setting up the QR code
          if (messageTag === loginMsgId && !this.clientToken) {
            await this.setupQrCode(data as WhatsAppLoginPayload);
            // Encryption and device data
          } else if (
            Array.isArray(data) &&
            data.length >= 2 &&
            data[0] === "Conn" &&
            data[1].secret
          ) {
            this.isLoggedIn = true;
            this.myWid = (data as WhatsAppConnPayload)[1].wid;
            this.emit("myWid", this.myWid);
            this.setupEncryptionKeys(data as WhatsAppConnPayload);
            setTimeout(this.keepAlive.bind(this), 20 * 1000);

            if (this.keysPath) {
              this.saveKeys();
            }
          } else if (
            Array.isArray(data) &&
            data.length >= 2 &&
            data[0] === "Conn" &&
            data[1].clientToken
          ) {
            const {
              clientToken,
              serverToken,
            } = (data as WhatsAppConnPayload)[1];
            this.isLoggedIn = true;
            this.clientToken = clientToken;
            this.serverToken = serverToken;
            this.myWid = (data as WhatsAppConnPayload)[1].wid;
            this.emit("myWid", this.myWid);

            setTimeout(this.keepAlive.bind(this), 20 * 1000);

            if (this.keysPath) {
              this.saveKeys();
            }
          } else if (
            Array.isArray(data) &&
            data.length >= 2 &&
            data[0] === "Cmd" &&
            data[1].type === "challenge"
          ) {
            const str = data[1].challenge;
            const decoded = Buffer.from(str, "base64");
            const signed = HmacSha256(this.macKey, Uint8Array.from(decoded));
            const encoded = Buffer.from(signed).toString("base64");

            this.apiSocket.send(
              `${messageTag}, ["admin", "challenge", "${encoded}", "${this.serverToken}", "${this.clientId}"]`
            );
          } else if (
            (data as WhatsAppLoginPayload).status &&
            !(data as WhatsAppLoginPayload).ref &&
            messageTag === loginMsgId
          ) {
          }
        } catch {}
      } else if (Buffer.isBuffer(e.data)) {
        const result = new Uint8Array(e.data);
        const node = await this.decryptMessage(result);

        this.emit("node", node);
      }
    };
  }

  async decryptMessage(result: Uint8Array) {
    const delimPos = result.indexOf(44); //look for index of comma because there is a message tag before it
    const messageContent = result.slice(delimPos + 1);
    const hmacValidation = HmacSha256(this.macKey, messageContent.slice(32));

    if (!arraysEqual(hmacValidation, messageContent.slice(0, 32))) {
      throw new Error(`hmac mismatch
        ${Buffer.from(hmacValidation).toString("hex")},
        ${Buffer.from(messageContent.slice(0, 32)).toString("hex")}`);
    }

    const data = AESDecrypt(this.encKey, messageContent.slice(32));

    return await whatsappReadBinary(data, true);
  }

  async sendAdminTest() {
    const id = randHex(10).toUpperCase();
    const timeout = setTimeout(() => {
      this.emit("noNetwork");
    }, 10 * 1000);

    return await this.sendSocketAsync(id, ["admin", "test"]).then(
      (data: WhatsAppAdminTestPayload) => {
        if (data[0] === "Pong" && data[1]) {
          clearTimeout(timeout);
          return true;
        }
        return false;
      }
    );
  }

  async sendProto(
    msgData: WAMessageNode,
    id: string,
    metric: keyof typeof WAMetrics = "MESSAGE"
  ) {
    const encoder = new TextEncoder();
    const cipher = AESEncrypt(this.encKey, await whatsappWriteBinary(msgData));
    const encryptedMsg = concatIntArray(
      HmacSha256(this.macKey, cipher),
      cipher
    );
    const payload = concatIntArray(
      encoder.encode(id),
      encoder.encode(","),
      Uint8Array.from([WAMetrics[metric]]),
      Uint8Array.from([WAFlags.IGNORE]),
      encryptedMsg
    );

    this.messageSentCount++;

    const timeout = setTimeout(async () => {
      await this.sendAdminTest().then(async (isLoggedIn) => {
        this.isLoggedIn = isLoggedIn;
      });
    }, 2 * 1000);

    return await this.sendSocketAsync(id, payload).then((data) => {
      clearTimeout(timeout);
      return data;
    });
  }

  async sendMessage(content: WAMessage, remoteJid: string, msgId?: string) {
    const id = msgId ? msgId : "3EB0" + randHex(8).toUpperCase();
    const msgParams = {
      key: {
        id,
        remoteJid,
        fromMe: true,
      },
      messageTimestamp: Math.round(Date.now() / 1000),
      status: 1,
      message: content,
    };
    const msgData: WAMessageNode = {
      description: "action",
      attributes: {
        type: "relay",
        epoch: "" + this.messageSentCount,
      },
      content: [
        {
          description: "message",
          content: await WAWebMessageInfo.encode(msgParams),
        },
      ],
    };

    await this.sendProto(msgData, id);

    return { id, content };
  }

  async getGroupMetadata(
    remoteJid: string
  ): Promise<WhatsAppGroupMetadataPayload> {
    const id = randHex(10).toUpperCase();

    return await this.sendSocketAsync(
      id,
      `${id},,["query","GroupMetadata","${remoteJid}"]`
    );
  }

  async sendQuotedMessage(
    content: WAMessage,
    remoteJid: string,
    quotedInfo: {
      quotedAuthorJid: string;
      quotedMsg: WAMessage;
      quotedMsgId: string;
    },
    mentionedJids?: WAContextInfo["mentionedJid"]
  ) {
    const contextInfo = {
      mentionedJid: mentionedJids
        ? quotedInfo.quotedMsg.extendedTextMessage
          ? quotedInfo.quotedMsg.extendedTextMessage?.contextInfo?.mentionedJid?.concat(
              mentionedJids
            )
          : mentionedJids
        : [],
      stanzaId: quotedInfo.quotedMsgId,
      participant: quotedInfo.quotedAuthorJid,
      quotedMessage: quotedInfo.quotedMsg.extendedTextMessage
        ? {
            conversation: quotedInfo.quotedMsg.extendedTextMessage.text,
          }
        : quotedInfo.quotedMsg,
    };

    if (content.conversation) {
      return await this.sendMessage(
        {
          extendedTextMessage: {
            contextInfo,
            text: content.conversation,
          },
        },
        remoteJid
      );
    } else {
      const quotingContent = Object.assign({}, content);
      const innerContent = Object.keys(quotingContent)
        .map((_key) => {
          const key: keyof typeof quotingContent = _key as any;
          return key !== "decryptedMediaMessage" && key !== "conversation"
            ? { key, content: quotingContent[key] }
            : undefined;
        })
        .filter((obj) => obj !== undefined)[0]!;

      return await this.sendMessage(
        {
          [innerContent.key]: {
            contextInfo,
            ...innerContent.content,
          },
        },
        remoteJid
      );
    }
  }

  async uploadMedia(
    hostnames: string[],
    uploadPath: string,
    body: Uint8Array
  ): Promise<WhatsAppMediaUploadPayload> {
    return await fetch(`https://${hostnames[0]}${uploadPath}`, {
      body,
      method: "POST",
      headers: {
        Origin: "https://web.whatsapp.com",
        Referer: "https://web.whatsapp.com/",
      },
    })
      .then((res) => res.json())
      .then(async (res: WhatsAppMediaUploadPayload) => {
        if (res.url) return res;
        return await this.uploadMedia(hostnames.slice(1), uploadPath, body);
      });
  }

  async queryMediaConn(): Promise<WhatsAppMediaConnPayload["media_conn"]> {
    return new Promise(async (resolve) => {
      const messageTag = randHex(12).toUpperCase();
      await this.sendSocketAsync(
        messageTag,
        `${messageTag},["query", "mediaConn"]`
      ).then(async (data: WhatsAppMediaConnPayload) => {
        resolve({
          hosts: data.media_conn.hosts,
          auth: data.media_conn.auth,
          ttl: data.media_conn.ttl,
        });
      });
    });
  }

  async encryptMedia(
    _mediaObj:
      | {
          msgType: "image";
          mimetype: string;
          file: Buffer;
          caption: {
            text: string;
            mentionedJids?: WAContextInfo["mentionedJid"];
          };
        }
      | {
          msgType: "sticker";
          mimetype: string;
          file: Buffer;
        }
      | {
          msgType: "video";
          mimetype: string;
          file: Buffer;
          caption: {
            text: string;
            mentionedJids?: WAContextInfo["mentionedJid"];
          };
          duration: number;
          isGif: boolean;
        }
      | {
          msgType: "audio";
          mimetype: string;
          file: Buffer;
          duration: number;
        }
      | {
          msgType: "document";
          mimetype: string;
          file: Buffer;
        }
  ): Promise<WAMessage> {
    return new Promise(async (resolve) => {
      const mediaKey = Uint8Array.from(crypto.randomBytes(32));
      const mediaKeyExpanded = HKDF(
        mediaKey,
        112,
        WAMediaAppInfo[_mediaObj.msgType]
      );
      const iv = mediaKeyExpanded.slice(0, 16);
      const cipherKey = mediaKeyExpanded.slice(16, 48);
      const macKey = mediaKeyExpanded.slice(48, 80);
      const enc = AESEncrypt(
        cipherKey,
        Uint8Array.from(_mediaObj.file),
        iv,
        false
      );
      const mac = HmacSha256(macKey, concatIntArray(iv, enc)).slice(0, 10);
      const fileSha256 = Sha256(_mediaObj.file);
      const fileEncSha256 = Sha256(concatIntArray(enc, mac));
      const type =
        _mediaObj.msgType === "sticker" ? "image" : _mediaObj.msgType;
      const { hosts, auth } = await this.queryMediaConn();
      const token = Buffer.from(fileEncSha256).toString("base64");
      const path = `mms/${type}`;

      const mediaObj: WAMedia = {
        mimetype: _mediaObj.mimetype,
        mediaKey,
        caption: "caption" in _mediaObj ? _mediaObj.caption.text : undefined,
        url: "",
        fileSha256,
        fileEncSha256,
        fileLength: _mediaObj.file.byteLength,
      };

      if (_mediaObj.msgType === "sticker") {
        mediaObj.pngThumbnail = await sharp(_mediaObj.file)
          .resize(100)
          .png()
          .toBuffer();
      } else if (_mediaObj.msgType === "image") {
        mediaObj.jpegThumbnail = await sharp(_mediaObj.file)
          .resize(100)
          .jpeg()
          .toBuffer();
      } else if (_mediaObj.msgType === "audio") {
        if (_mediaObj.duration) {
          mediaObj.seconds = _mediaObj.duration;
        } else {
          throw new Error("Audio messages require duration");
        }
      } else if (_mediaObj.msgType === "video") {
        mediaObj.gifPlayback = _mediaObj.isGif;
      }

      const media = await this.uploadMedia(
        hosts.map((host) => host.hostname),
        `/${path}/${token}?auth=${auth}&token=${token}`,
        concatIntArray(enc, mac)
      );

      mediaObj.url = media.url;

      resolve({
        [_mediaObj.msgType + "Message"]: mediaObj,
      });
    });
  }

  async sendMediaProto(mediaProto: {
    mediaFile: WAMedia;
    msgType: string;
    remoteJid: string;
    msgId: string;
    mentionedJids?: WAContextInfo["mentionedJid"];
  }) {
    if (!mediaProto.mentionedJids) {
      return await this.sendMessage(
        {
          [mediaProto.msgType + "Message"]: mediaProto.mediaFile,
        },
        mediaProto.remoteJid,
        mediaProto.msgId
      );
    } else {
      return await this.sendMessage(
        {
          [mediaProto.msgType + "Message"]: {
            ...mediaProto.mediaFile,
            contextInfo: {
              mentionedJid: mediaProto.mentionedJids,
            },
          },
        },
        mediaProto.remoteJid,
        mediaProto.msgId
      );
    }
  }

  async decryptMedia(
    mediaObj: WAReceiveMedia,
    type: "image" | "sticker" | "video" | "audio" | "document"
  ): Promise<WADecryptedMedia> {
    const mediaKey = Uint8Array.from(Buffer.from(mediaObj.mediaKey, "base64"));
    const mediaKeyExpanded = HKDF(mediaKey, 112, WAMediaAppInfo[type]);
    const iv = mediaKeyExpanded.slice(0, 16);
    const cipherKey = mediaKeyExpanded.slice(16, 48);
    const macKey = mediaKeyExpanded.slice(48, 80);

    const rawFile = await fetch(mediaObj.url)
      .then((res) => res.arrayBuffer())
      .then((arrayBuffer) => Buffer.from(arrayBuffer))
      .then((buffer) => Uint8Array.from(buffer));
    const file = rawFile.slice(0, rawFile.length - 10);
    const mac = rawFile.slice(rawFile.length - 10);

    const hmacValidation = HmacSha256(macKey, concatIntArray(iv, file));

    if (!arraysEqual(hmacValidation.slice(0, 10), mac)) {
      throw new Error("Invalid media data");
    }

    return {
      type,
      caption: mediaObj.caption,
      contextInfo: mediaObj.contextInfo,
      gifPlayback: mediaObj.gifPlayback,
      buffer: Buffer.from(AESDecrypt(cipherKey, concatIntArray(iv, file))),
    };
  }

  protected setupEncryptionKeys(data: WhatsAppConnPayload) {
    const decodedSecret = Uint8Array.from(
      Buffer.from(data[1].secret, "base64")
    );
    const publicKey = decodedSecret.slice(0, 32);
    const sharedSecret = sharedKey(this.keyPair!.private, publicKey);
    const sharedSecretExpanded = HKDF(sharedSecret, 80);
    const hmacValidation = HmacSha256(
      sharedSecretExpanded.slice(32, 64),
      concatIntArray(decodedSecret.slice(0, 32), decodedSecret.slice(64))
    );

    if (!arraysEqual(hmacValidation, decodedSecret.slice(32, 64)))
      throw "hmac mismatch";

    const keysEncrypted = concatIntArray(
      sharedSecretExpanded.slice(64),
      decodedSecret.slice(64)
    );
    const keysDecrypted = AESDecrypt(
      sharedSecretExpanded.slice(0, 32),
      keysEncrypted
    );

    this.encKey = keysDecrypted.slice(0, 32);
    this.macKey = keysDecrypted.slice(32, 64);

    this.clientToken = data[1].clientToken;
    this.serverToken = data[1].serverToken;
  }

  protected async setupQrCode(data: WhatsAppLoginPayload) {
    this.keyPair = generateKeyPair(Uint8Array.from(crypto.randomBytes(32)));
    const publicKeyBase64 = Buffer.from(this.keyPair.public).toString("base64");
    const qrCode = dataUrlToBuffer(
      await qrcode.toDataURL(`${data.ref},${publicKeyBase64},${this.clientId}`)
    );

    writeFile(this.qrPath, qrCode.data, (err) => {
      if (err) console.error(err);
      this.emit("qrCode");
    });
  }

  protected init(loginMsgId: string, restoreSession: boolean) {
    return async (e: WebSocket.OpenEvent) => {
      if (
        !restoreSession ||
        (restoreSession && !(await doesFileExist(this.keysPath!)))
      ) {
        this.clientId = crypto.randomBytes(16).toString("base64");
      } else {
        await this.getKeys();
      }

      e.target.send(
        `${loginMsgId},["admin","init",[0,4,2080],["WhatsApp forwarder","WhatsAppForwarder","0.1.0"],"${this.clientId}",true]`
      );

      if (restoreSession && (await doesFileExist(this.keysPath!))) {
        this.restoreSession(loginMsgId);
      }
    };
  }
}
