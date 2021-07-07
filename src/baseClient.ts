import { writeFile, readFile } from "fs";
import { resolve as resolvePath } from "path";

import sharp from "sharp";
import fetch from "node-fetch";
import WebSocket from "ws";
import crypto from "crypto";
import { generateKeyPair, sharedKey } from "curve25519-js";
import { TypedEmitter } from "tiny-typed-emitter";

import {
  WAWebMessage,
  WAStubMessage,
  WhatsAppLoginPayload,
  WhatsAppConnPayload,
  WhatsAppStreamPayload,
  WhatsAppPropsPayload,
  WAReceiveMedia,
  WhatsAppAdminTestPayload,
  WAMessage,
  WhatsAppGroupMetadataPayload,
  WAContextInfo,
  WhatsAppMediaUploadPayload,
  WhatsAppMediaConnPayload,
  WAMedia,
  WADecryptedMedia,
  WAMediaTypes,
  WhatsAppChallengePayload,
} from "./types";
import { doesFileExist } from "./utils/path";
import {
  HmacSha256,
  AESDecrypt,
  randHex,
  AESEncrypt,
  HKDF,
  Sha256,
  uintArrayToStream,
} from "./utils/encryption";
import { arraysEqual, concatIntArray } from "./utils/arrays";
import { whatsappReadBinary, WANode } from "./binary/reader";
import { WAMessageNode, whatsappWriteBinary } from "./binary/writer";
import {
  WAMetrics,
  WAFlags,
  WAWebMessageInfo,
  WAMediaAppInfo,
} from "./binary/tokens";

interface WAClientInfo {
  os: string;
  browser: string;
  osVersion: string;
}

export interface WAKeys {
  clientId: string;
  clientToken: string;
  serverToken: string;
  macKey: Uint8Array;
  encKey: Uint8Array;
}

interface WAListeners {
  node: (node: WANode) => void;
  message: (msg: WAWebMessage, description: string) => void;
  messageStub: (msg: WAStubMessage) => void;
  noNetwork: () => void;
  loggedOut: () => void;
  ready: () => void;
  myWid: (wid: string) => void;
  keys: (keys: WAKeys) => void;
  qrCode: (qrCodeData: string) => void;
}

export default class WABaseClient extends TypedEmitter<WAListeners> {
  protected apiSocket: WebSocket;

  protected clientId?: string;

  public myWid?: string;

  public messageSentCount = 0;

  protected keyPair: {
    public: Uint8Array;
    private: Uint8Array;
  } | null = null;

  protected clientToken: string | null = null;
  protected serverToken: string | null = null;
  protected encKey: Uint8Array = new Uint8Array();
  protected macKey: Uint8Array = new Uint8Array();

  public isLoggedIn: boolean = false;

  protected messageListeners: {
    [key: string]: (e: WebSocket.MessageEvent) => void;
  } = {};

  constructor(
    opts: {
      restoreSession: boolean;
      keys: WAKeys | null;
      clientInfo: WAClientInfo;
    } = {
      restoreSession: false,
      keys: null,
      clientInfo: {
        os: "Node.js",
        browser: "WhatsApp Bot",
        osVersion: "1.0.0",
      },
    }
  ) {
    super();

    this.apiSocket = new WebSocket("wss://web.whatsapp.com/ws", {
      headers: { Origin: "https://web.whatsapp.com" },
    });

    if (opts.keys && opts.restoreSession) {
      Object.entries(opts.keys).forEach(([key, val]) => {
        if (!val) {
          throw new Error(`Missing value for '${key}'`);
        }
      });

      const { clientId, clientToken, serverToken, macKey, encKey } = opts.keys;

      this.clientId = clientId;
      this.clientToken = clientToken;
      this.serverToken = serverToken;
      this.macKey = macKey;
      this.encKey = encKey;
    } else if (opts.restoreSession) {
      throw new Error("Keys are needed for restoring a session");
    }

    this.apiSocket.onmessage = this.onSocketMessage.bind(this);

    this.init({
      restoreSession: opts.restoreSession,
      clientInfo: opts.clientInfo,
    });
  }

  protected async init({
    restoreSession,
    clientInfo,
  }: {
    restoreSession: boolean;
    clientInfo: WAClientInfo;
  }) {
    const loginMsgId = "" + Date.now();

    if (!restoreSession || (restoreSession && !this.clientId)) {
      this.clientId = crypto.randomBytes(16).toString("base64");
    }

    this.apiSocket.on("open", async () => {
      const data: WhatsAppLoginPayload = await this.sendSocketAsync(
        loginMsgId,
        JSON.stringify([
          "admin",
          "init",
          [2, 2123, 7],
          [clientInfo.browser, clientInfo.os, clientInfo.osVersion],
          this.clientId,
          true,
        ])
      );

      if (restoreSession && this.clientId) {
        this.restoreSession(loginMsgId);
      } else {
        if (!this.clientToken) {
          await this.setupQrCode(data.ref);
        } else if (data.status && !data.ref) {
        }
      }
    });
  }

  protected async restoreSession(loginMsgId: string) {
    const data: { status: number } = await this.sendSocketAsync(
      loginMsgId,
      JSON.stringify([
        "admin",
        "login",
        this.clientToken,
        this.serverToken,
        this.clientId,
        "takeover",
      ])
    );

    if (data.status !== 200) {
      this.emit("loggedOut");
    }
  }

  protected async setupQrCode(ref: string) {
    this.keyPair = generateKeyPair(Uint8Array.from(crypto.randomBytes(32)));
    const publicKeyBase64 = Buffer.from(this.keyPair.public).toString("base64");
    const qrCodeData = `${ref},${publicKeyBase64},${this.clientId}`;

    this.emit("qrCode", qrCodeData);
  }

  private handleLoginPayload(data: WhatsAppConnPayload) {
    this.isLoggedIn = true;
    this.myWid = (data as WhatsAppConnPayload)[1].wid;
    this.emit("myWid", this.myWid);

    setTimeout(this.keepAlive.bind(this), 20 * 1000);

    // Login
    if (data[1].secret) {
      this.setupEncryptionKeys(data as WhatsAppConnPayload);
      // Restore session
    } else if (data[1].clientToken) {
      const { clientToken, serverToken } = (data as WhatsAppConnPayload)[1];

      this.clientToken = clientToken;
      this.serverToken = serverToken;
    }

    this.emit("keys", {
      clientId: this.clientId!,
      clientToken: this.clientToken!,
      serverToken: this.serverToken!,
      macKey: this.macKey,
      encKey: this.encKey,
    });
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

  async sendSocketAsync(messageTag: string, data: any): Promise<any> {
    return new Promise((resolve) => {
      const encoder = new TextEncoder();
      this.apiSocket.send(
        concatIntArray(
          encoder.encode(messageTag),
          encoder.encode(","),
          data instanceof Uint8Array ? data : encoder.encode(data)
        )
      );

      this.addMessageListener(async (e) => {
        if (typeof e.data === "string") {
          const receivedMessageId = e.data.substring(0, e.data.indexOf(","));

          if (receivedMessageId === messageTag && e.data !== `${messageTag},`) {
            const data = JSON.parse(e.data.substring(e.data.indexOf(",") + 1));
            delete this.messageListeners[messageTag];

            resolve(data);
          }
        }
      }, messageTag);
    });
  }

  protected addMessageListener(
    cb: (e: WebSocket.MessageEvent) => void,
    id: string
  ) {
    this.messageListeners[id] = cb;
  }

  private async onSocketMessage(e: WebSocket.MessageEvent) {
    Object.values(this.messageListeners).forEach((func) => func(e));

    if (typeof e.data === "string") {
      try {
        const messageTag = e.data.substring(0, e.data.indexOf(","));
        const data = JSON.parse(e.data.substring(e.data.indexOf(",") + 1)) as
          | WhatsAppConnPayload
          | WhatsAppStreamPayload
          | WhatsAppPropsPayload
          | WhatsAppChallengePayload;

        if (Array.isArray(data) && data.length >= 2 && data[0] === "Conn") {
          this.handleLoginPayload(data);
        } else if (
          Array.isArray(data) &&
          data.length >= 2 &&
          data[0] === "Cmd" &&
          data[1].type === "challenge"
        ) {
          this.solveChallenge(data, messageTag);
        }
      } catch {}
    } else if (Buffer.isBuffer(e.data)) {
      const result = new Uint8Array(e.data);
      const node = await this.decryptMessage(result);

      this.emit("node", node);
    }
  }

  protected keepAlive() {
    if (this.apiSocket) {
      this.apiSocket.send("?,,");
      setTimeout(this.keepAlive.bind(this), 20 * 1000);
    }
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

  async encryptAndSendNode(
    msgData: WAMessageNode,
    id: string,
    metric: keyof typeof WAMetrics = "MESSAGE"
  ) {
    const cipher = AESEncrypt(this.encKey, await whatsappWriteBinary(msgData));
    const encryptedMsg = concatIntArray(
      HmacSha256(this.macKey, cipher),
      cipher
    );
    const payload = concatIntArray(
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

    await this.encryptAndSendNode(msgData, id);

    return { id, content };
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
    const { quotedMsg, quotedAuthorJid, quotedMsgId } = quotedInfo;
    const mentionedJid =
      mentionedJids?.concat(
        quotedInfo.quotedMsg.extendedTextMessage?.contextInfo?.mentionedJid ??
          []
      ) ?? [];

    const contextInfo = {
      mentionedJid,
      stanzaId: quotedMsgId,
      participant: quotedAuthorJid,
      quotedMessage: quotedMsg.extendedTextMessage
        ? {
            conversation: quotedMsg.extendedTextMessage.text,
          }
        : quotedMsg,
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
      const quotingContent = { ...content };
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

  async getMediaConnectionData(): Promise<
    WhatsAppMediaConnPayload["media_conn"]
  > {
    const messageTag = randHex(12).toUpperCase();
    return await this.sendSocketAsync(
      messageTag,
      JSON.stringify(["query", "mediaConn"])
    ).then(async (data: WhatsAppMediaConnPayload) => ({
      hosts: data.media_conn.hosts,
      auth: data.media_conn.auth,
      ttl: data.media_conn.ttl,
    }));
  }

  async uploadMedia(
    type: Exclude<WAMediaTypes, "sticker">,
    token: string,
    body: Uint8Array
  ): Promise<WhatsAppMediaUploadPayload | null> {
    const { hosts, auth } = await this.getMediaConnectionData();

    const hostnames = hosts.map((host) => host.hostname);
    const uploadPath = `/mms/${type}/${token}?auth=${auth}&token=${token}`;

    for (const hostname of hostnames) {
      const res: WhatsAppMediaUploadPayload = await fetch(
        `https://${hostname}${uploadPath}`,
        {
          body: uintArrayToStream(body),
          method: "POST",
          headers: {
            Origin: "https://web.whatsapp.com",
            Referer: "https://web.whatsapp.com/",
          },
        }
      ).then((res) => res.json());

      if (res.url) return res;
    }

    return null;
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
  ): Promise<WAMessage | null> {
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
    const type = _mediaObj.msgType === "sticker" ? "image" : _mediaObj.msgType;

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
      type,
      Buffer.from(fileEncSha256)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/\=+$/, ""),
      concatIntArray(enc, mac)
    );

    if (media) {
      mediaObj.url = media.url;

      return {
        [_mediaObj.msgType + "Message"]: mediaObj,
      };
    }

    return null;
  }

  async sendMediaProto(mediaProto: {
    mediaFile: WAMedia;
    msgType: WAMediaTypes;
    remoteJid: string;
    msgId: string;
    mentionedJids?: WAContextInfo["mentionedJid"];
  }) {
    let node: WAMessage = {
      [mediaProto.msgType + "Message"]: mediaProto.mediaFile,
    };

    if (mediaProto.mentionedJids) {
      type msg = `${WAMediaTypes}Message`;

      node[`${mediaProto.msgType}Message` as msg]!.contextInfo = {
        mentionedJid: mediaProto.mentionedJids,
      };
    }

    return await this.sendMessage(node, mediaProto.remoteJid, mediaProto.msgId);
  }

  /**
   * Decrypts a given media object
   * @param {WAReceiveMedia} mediaObj The media object received from the server
   * @param {WAMediaTypes} type The media type
   * @returns The decrypted media message
   */
  async decryptMedia(
    mediaObj: WAReceiveMedia,
    type: WAMediaTypes
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

  async getGroupMetadata(
    remoteJid: string
  ): Promise<WhatsAppGroupMetadataPayload> {
    const id = randHex(10).toUpperCase();

    return await this.sendSocketAsync(
      id,
      `,` + JSON.stringify(["query", "GroupMetadata", remoteJid])
    );
  }

  private solveChallenge(
    data: WhatsAppChallengePayload & any[],
    messageTag: string
  ) {
    const str = data[1].challenge;
    const decoded = Buffer.from(str, "base64");
    const signed = HmacSha256(this.macKey, Uint8Array.from(decoded));
    const encoded = Buffer.from(signed).toString("base64");

    this.apiSocket.send(
      `${messageTag}, ["admin", "challenge", "${encoded}", "${this.serverToken}", "${this.clientId}"]`
    );
  }

  public disconnect() {
    this.apiSocket.send(`goodbye,,["admin","Conn","disconnect"]`);
  }
}
