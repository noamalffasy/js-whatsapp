import { writeFile, readFile, exists as pathExists } from "fs";
import { resolve as resolvePath } from "path";

import sharp from "sharp";
import fetch from "node-fetch";
import FormData from "form-data";
import WebSocket from "ws";
import crypto from "crypto";
import qrcode from "qrcode";
import { generateKeyPair, sharedKey } from "curve25519-js";

import { doesFileExist } from "./utils/path";
import {
  dataUrlToBuffer,
  HmacSha256,
  AESDecrypt,
  HKDF,
  randHex,
  AESEncrypt,
  Sha256
} from "./utils/encryption";
import { whatsappReadBinary, WANode } from "./utils/whatsappBinaryReader";
import {
  whatsappWriteBinary,
  WAMessageNode
} from "./utils/whatsappBinaryWriter";
import { concatIntArray, arraysEqual } from "./utils/arrays";
import {
  WAMediaAppInfo,
  WAWebMessageInfo,
  WAMetrics,
  WAFlags
} from "./utils/whatsappTokens";

export interface WhatsAppLoginPayload {
  status: number;
  ref: string;
  ttl: 200000;
  update: boolean;
  curr: string;
  time: number;
}

export interface WhatsAppConnPayload {
  0: "Conn";
  1: {
    battery: number;
    browserToken: string;
    clientToken: string;
    phone: {
      wa_version: string;
      mcc: string;
      mnc: string;
      os_version: string;
      device_manufacturer: string;
      device_model: string;
      os_build_number: string;
    };
    platform: string;
    pushname: string;
    secret: string;
    serverToken: string;
    wid: string;
  };
}

export interface WhatsAppStreamPayload {
  0: "Stream";
  1: "update";
  2: boolean;
  3: string;
}

export interface WhatsAppPropsPayload {
  0: "Props";
  1: {
    imageMaxKBytes: 1024;
    maxParticipants: 257;
    videoMaxEdge: 960;
  };
}

export interface WhatsAppUploadMediaURL {
  status: number;
  url: string;
}

export interface WhatsAppProfilePicPayload {
  eurl?: string;
  status?: number;
  tag: string;
}

export interface WhatsAppMediaUploadPayload {
  filehash: string;
  mimetype: string;
  size: string;
  type: "encrypted";
  url: string;
}

export interface WhatsAppGroupMetadataPayload {
  id: string;
  owner: string;
  subject: string;
  creation: number;
  participants: {
    id: string;
    isAdmin: boolean;
    isSuperAdmin: boolean;
  }[];
  subjectTime: number;
  subjectOwner: string;
}

export interface WhatsAppAdminTestPayload {
  0: "Pong";
  1: true;
}

export interface WAChat {
  count: string;
  jid: string;
  message?: string;
  modify_tag?: string;
  name: string;
  spam: string;
  read_only?: string;
  t: string;
}

export interface WAContact {
  jid: string;
  index?: string;
  name?: string;
  short?: string;
  verify?: string;
  vname?: string;
  notify?: string;
}

export interface WADecryptedMedia {
  type: "image" | "sticker" | "video" | "document" | "audio";
  buffer: Buffer;
  gifPlayback: boolean;
  caption?: string;
  contextInfo?: WAContextInfo;
}

export interface WAMedia {
  fileEncSha256: Uint8Array;
  fileLength: number;
  fileSha256: Uint8Array;
  mediaKey: Uint8Array;
  mimetype: string;
  url: string;
  jpegThumbnail?: Buffer;
  pngThumbnail?: Buffer;
  gifPlayback?: boolean;
  seconds?: number;
  caption?: string;
}

export interface WAReceiveMedia {
  directPath: string;
  fileEncSha256: Uint8Array;
  fileLength: number;
  fileSha256: Uint8Array;
  mediaKey: string;
  mediaKeyTimestamp: number;
  mimetype: string;
  url: string;
  caption?: string;
  gifPlayback: boolean;
  contextInfo?: WAContextInfo;
}

export interface WAReceiveDocumentMessage extends WAReceiveMedia {
  fileName: string;
}

export interface WAContactMessage {
  displayName: string;
  vcard: string;
  contextInfo?: WAContextInfo;
}

export interface WAMessageKey {
  remoteJid?: string | null;
  fromMe?: boolean | null;
  id?: string | null;
  participant?: string | null;
  name?: string;
}

export interface WAExtendedTextMessage {
  /** ExtendedTextMessage text */
  text?: string | null;

  /** ExtendedTextMessage matchedText */
  matchedText?: string | null;

  /** ExtendedTextMessage canonicalUrl */
  canonicalUrl?: string | null;

  /** ExtendedTextMessage description */
  description?: string | null;

  /** ExtendedTextMessage title */
  title?: string | null;

  /** ExtendedTextMessage textArgb */
  textArgb?: number | null;

  /** ExtendedTextMessage backgroundArgb */
  backgroundArgb?: number | null;

  /** ExtendedTextMessage jpegThumbnail */
  jpegThumbnail?: Uint8Array | null;

  /** ExtendedTextMessage contextInfo */
  contextInfo?: WAContextInfo | null;
}

export interface WAContextInfo {
  /** ContextInfo stanzaId */
  stanzaId?: string | null;

  /** ContextInfo participant */
  participant?: string | null;

  /** ContextInfo quotedMessage */
  quotedMessage?: WAMessage | null;

  /** ContextInfo remoteJid */
  remoteJid?: string | null;

  /** ContextInfo mentionedJid */
  mentionedJid?: string[] | null;

  /** ContextInfo conversionSource */
  conversionSource?: string | null;

  /** ContextInfo conversionData */
  conversionData?: Uint8Array | null;

  /** ContextInfo conversionDelaySeconds */
  conversionDelaySeconds?: number | null;

  /** ContextInfo forwardingScore */
  forwardingScore?: number | null;

  /** ContextInfo isForwarded */
  isForwarded?: boolean | null;

  /** ContextInfo placeholderKey */
  placeholderKey?: WAMessageKey | null;

  /** ContextInfo expiration */
  expiration?: number | null;
}

export interface WAProtocolMessage {
  key?: WAMessageKey | null;
  type?: "REVOKE" | "EPHEMERAL_SETTING" | null;
  ephemeralExpiration?: number | null;
}

export interface WALocationMessage {
  degreesLatitude: number;
  degreesLongitude: number;
  jpegThumbnail?: string;
  contextInfo?: WAContextInfo;
}

export interface WAMessage {
  conversation?: string | null;
  extendedTextMessage?: WAExtendedTextMessage | null;
  decryptedMediaMessage?: WADecryptedMedia;
  documentMessage?: WAReceiveDocumentMessage | null;
  imageMessage?: WAReceiveMedia | null;
  audioMessage?: WAReceiveMedia | null;
  videoMessage?: WAReceiveMedia | null;
  stickerMessage?: WAReceiveMedia | null;
  contactMessage?: WAContactMessage | null;
  protocolMessage?: WAProtocolMessage | null;
  locationMessage?: WALocationMessage | null;
}

export interface WAWebMessage {
  key: WAMessageKey;
  message: WAMessage;
  messageTimestamp?: number | Long | null;
  status?:
    | "ERROR"
    | "PENDING"
    | "SERVER_ACK"
    | "DELIVERY_ACK"
    | "READ"
    | "PLAYED"
    | null;
  participant?: string | null;
  author?: string;
}

export interface WAStubMessage {
  key: WAMessageKey;
  messageTimestamp: number | Long;
  participant?: string | null;
  messageStubType:
    | "UNKNOWN"
    | "REVOKE"
    | "CIPHERTEXT"
    | "FUTUREPROOF"
    | "NON_VERIFIED_TRANSITION"
    | "UNVERIFIED_TRANSITION"
    | "VERIFIED_TRANSITION"
    | "VERIFIED_LOW_UNKNOWN"
    | "VERIFIED_HIGH"
    | "VERIFIED_INITIAL_UNKNOWN"
    | "VERIFIED_INITIAL_LOW"
    | "VERIFIED_INITIAL_HIGH"
    | "VERIFIED_TRANSITION_ANY_TO_NONE"
    | "VERIFIED_TRANSITION_ANY_TO_HIGH"
    | "VERIFIED_TRANSITION_HIGH_TO_LOW"
    | "VERIFIED_TRANSITION_HIGH_TO_UNKNOWN"
    | "VERIFIED_TRANSITION_UNKNOWN_TO_LOW"
    | "VERIFIED_TRANSITION_LOW_TO_UNKNOWN"
    | "VERIFIED_TRANSITION_NONE_TO_LOW"
    | "VERIFIED_TRANSITION_NONE_TO_UNKNOWN"
    | "GROUP_CREATE"
    | "GROUP_CHANGE_SUBJECT"
    | "GROUP_CHANGE_ICON"
    | "GROUP_CHANGE_INVITE_LINK"
    | "GROUP_CHANGE_DESCRIPTION"
    | "GROUP_CHANGE_RESTRICT"
    | "GROUP_CHANGE_ANNOUNCE"
    | "GROUP_PARTICIPANT_ADD"
    | "GROUP_PARTICIPANT_REMOVE"
    | "GROUP_PARTICIPANT_PROMOTE"
    | "GROUP_PARTICIPANT_DEMOTE"
    | "GROUP_PARTICIPANT_INVITE"
    | "GROUP_PARTICIPANT_LEAVE"
    | "GROUP_PARTICIPANT_CHANGE_NUMBER"
    | "BROADCAST_CREATE"
    | "BROADCAST_ADD"
    | "BROADCAST_REMOVE"
    | "GENERIC_NOTIFICATION"
    | "E2E_IDENTITY_CHANGED"
    | "E2E_ENCRYPTED"
    | "CALL_MISSED_VOICE"
    | "CALL_MISSED_VIDEO"
    | "INDIVIDUAL_CHANGE_NUMBER"
    | "GROUP_DELETE"
    | "GROUP_ANNOUNCE_MODE_MESSAGE_BOUNCE"
    | "CALL_MISSED_GROUP_VOICE"
    | "CALL_MISSED_GROUP_VIDEO"
    | "PAYMENT_CIPHERTEXT"
    | "PAYMENT_FUTUREPROOF"
    | "PAYMENT_TRANSACTION_STATUS_UPDATE_FAILED"
    | "PAYMENT_TRANSACTION_STATUS_UPDATE_REFUNDED"
    | "PAYMENT_TRANSACTION_STATUS_UPDATE_REFUND_FAILED"
    | "PAYMENT_TRANSACTION_STATUS_RECEIVER_PENDING_SETUP"
    | "PAYMENT_TRANSACTION_STATUS_RECEIVER_SUCCESS_AFTER_HICCUP"
    | "PAYMENT_ACTION_ACCOUNT_SETUP_REMINDER"
    | "PAYMENT_ACTION_SEND_PAYMENT_REMINDER"
    | "PAYMENT_ACTION_SEND_PAYMENT_INVITATION"
    | "PAYMENT_ACTION_REQUEST_DECLINED"
    | "PAYMENT_ACTION_REQUEST_EXPIRED"
    | "PAYMENT_ACTION_REQUEST_CANCELLED"
    | "BIZ_VERIFIED_TRANSITION_TOP_TO_BOTTOM"
    | "BIZ_VERIFIED_TRANSITION_BOTTOM_TO_TOP"
    | "BIZ_INTRO_TOP"
    | "BIZ_INTRO_BOTTOM"
    | "BIZ_NAME_CHANGE"
    | "BIZ_MOVE_TO_CONSUMER_APP"
    | "BIZ_TWO_TIER_MIGRATION_TOP"
    | "BIZ_TWO_TIER_MIGRATION_BOTTOM"
    | "OVERSIZED"
    | "GROUP_CHANGE_NO_FREQUENTLY_FORWARDED"
    | "GROUP_V4_ADD_INVITE_SENT"
    | "GROUP_PARTICIPANT_ADD_REQUEST_JOIN"
    | null;
  messageStubParameters: string[] | null;
}

export interface WASendMedia extends WAMedia {
  id: string;
  msgType: string;
  blob: Buffer;
}

export default class WhatsApp {
  private apiSocket: WebSocket;

  private keysPath?: string;
  private qrPath: string;
  private clientId?: string;
  private loginMsgId: string;

  public myWid?: string;

  private messageSentCount = 0;

  private keyPair: {
    public: Uint8Array;
    private: Uint8Array;
  } | null;

  private clientToken: string | null = null;
  private serverToken: string | null = null;
  private encKey: Uint8Array = new Uint8Array();
  private macKey: Uint8Array = new Uint8Array();

  chatList: WAChat[] = [];
  contactList: WAContact[] = [];

  isLoggedIn: boolean = false;

  private messageListeners: ((
    msg: WAWebMessage,
    description: string
  ) => void)[] = [];
  private messageStubListeners: ((msg: WAStubMessage) => void)[] = [];
  private noNetworkListeners: (() => void)[] = [];
  private loggedOutListeners: (() => void)[] = [];
  private eventListeners: {
    [key: string]: (e: WebSocket.MessageEvent) => void;
  } = {};
  private readyListeners: (() => void)[] = [];
  private qrCodeListeners: (() => void)[] = [];

  constructor(
    qrPath = "./qrcode.png",
    restoreSession = false,
    keysPath = "./keys.json"
  ) {
    const loginMsgId = "" + Date.now();

    this.apiSocket = new WebSocket("wss://web.whatsapp.com/ws", {
      headers: { Origin: "https://web.whatsapp.com" }
    });

    this.keyPair = null;

    this.qrPath = resolvePath(".", qrPath);

    if (restoreSession) {
      this.keysPath = resolvePath(".", keysPath);
    }

    this.apiSocket.onopen = this.init(loginMsgId, restoreSession);
    this.loginMsgId = loginMsgId;

    if (restoreSession) {
      doesFileExist(this.keysPath!).then(doesExist => {
        if (!doesExist) {
          this.apiSocket.onmessage = this.onMessage(loginMsgId);
        }
      });
    } else {
      this.apiSocket.onmessage = this.onMessage(loginMsgId);
    }
  }

  public on(
    event:
      | "message"
      | "ready"
      | "stubMessage"
      | "qrCode"
      | "noNetwork"
      | "loggedOut",
    cb:
      | (() => void)
      | ((msg: WAWebMessage, description: string) => void)
      | ((msg: WAStubMessage) => void)
  ) {
    switch (event) {
      case "message":
        this.messageListeners.push(cb as ((
          msg: WAWebMessage,
          description: string
        ) => void));
        break;
      case "stubMessage":
        this.messageStubListeners.push(cb as ((msg: WAStubMessage) => void));
        break;
      case "ready":
        this.readyListeners.push(cb as () => void);
        break;
      case "qrCode":
        this.qrCodeListeners.push(cb as () => void);
      case "noNetwork":
        this.noNetworkListeners.push(cb as () => void);
      case "loggedOut":
        this.loggedOutListeners.push(cb as () => void);
      default:
        break;
    }
  }

  private addEventListener(
    cb: (e: WebSocket.MessageEvent) => void,
    id: string
  ) {
    this.eventListeners[id] = cb;
  }

  private saveKeys() {
    writeFile(
      this.keysPath!,
      JSON.stringify({
        clientId: this.clientId,
        clientToken: this.clientToken,
        serverToken: this.serverToken,
        macKey: Array.from(this.macKey),
        encKey: Array.from(this.encKey)
      }),
      err => console.error(err)
    );
  }

  private async getKeys() {
    return new Promise((resolve, reject) => {
      readFile(this.keysPath!, "utf-8", (err, data) => {
        if (err) reject(err);

        const {
          clientId,
          clientToken,
          serverToken,
          macKey,
          encKey
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

  private async restoreSession(loginMsgId: string) {
    this.apiSocket.send(
      `${loginMsgId},["admin","login","${this.clientToken}","${this.serverToken}","${this.clientId}","takeover"]`
    );

    this.apiSocket.onmessage = e => {
      if (typeof e.data === "string") {
        const receivedMessageId = e.data.substring(0, e.data.indexOf(","));

        if (receivedMessageId === loginMsgId && e.data !== `${loginMsgId},`) {
          const data = JSON.parse(
            e.data.substring(e.data.indexOf(",") + 1)
          ) as { status: number };

          if (data.status === 200) {
            this.apiSocket.onmessage = this.onMessage(loginMsgId);
          } else {
            this.loggedOutListeners.forEach(func => func());
          }
        }
      }
    };
  }

  private keepAlive() {
    if (this.apiSocket) {
      this.apiSocket.send("?,,");
      setTimeout(this.keepAlive.bind(this), 20 * 1000);
    }
  }

  public disconnect() {
    this.apiSocket.send(`goodbye,,["admin","Conn","disconnect"]`);
  }

  private async sendSocketAsync(messageTag: string, data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this.apiSocket.send(data);

      this.addEventListener(async e => {
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

  private onMessage(loginMsgId: string) {
    return async (e: WebSocket.MessageEvent) => {
      Object.values(this.eventListeners).forEach(func => func(e));

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
              serverToken
            } = (data as WhatsAppConnPayload)[1];
            this.isLoggedIn = true;
            this.clientToken = clientToken;
            this.serverToken = serverToken;
            this.myWid = (data as WhatsAppConnPayload)[1].wid;

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
        await this.decryptMessage(result);
      }
    };
  }

  private async decryptMessage(result: Uint8Array) {
    const delimPos = result.indexOf(44); //look for index of comma because there is a message tag before it
    const messageContent = result.slice(delimPos + 1);
    const hmacValidation = HmacSha256(this.macKey, messageContent.slice(32));

    if (!arraysEqual(hmacValidation, messageContent.slice(0, 32))) {
      throw new Error(`hmac mismatch
      ${Buffer.from(hmacValidation).toString("hex")},
      ${Buffer.from(messageContent.slice(0, 32)).toString("hex")}`);
    }

    const data = AESDecrypt(this.encKey, messageContent.slice(32));
    const allMsgs = await whatsappReadBinary(data, true);

    if (allMsgs.description === "action") {
      this.readyListeners.forEach(func => func());
      this.readyListeners = [];
    }

    (allMsgs.content as WANode[]).forEach(async node => {
      if (
        node.description === "user" &&
        ((node.attributes as unknown) as WAContact).jid.endsWith("c.us")
      ) {
        this.contactList.push((node.attributes as unknown) as WAContact);
      } else if (
        node.description === "chat" &&
        ((node.attributes as unknown) as WAChat).jid.endsWith("g.us")
      ) {
        this.chatList.push((node.attributes as unknown) as WAChat);
      } else if (((node as unknown) as WAWebMessage).message) {
        const msg = (node as unknown) as WAWebMessage;
        const remoteJid = msg.key!.remoteJid!.replace(
          "@s.whatsapp.net",
          "@c.us"
        );

        if (msg.participant) {
          const userJid = msg.participant.replace("@s.whatsapp.net", "@c.us");
          const contact = this.contactList.find(
            contact => contact.jid.replace("\0", "") === userJid
          );

          if (contact) {
            msg.author = contact.name
              ? contact.name
              : contact.vname || contact.notify;
          }
        } else {
          const userJid = msg.key.remoteJid!.replace(
            "@s.whatsapp.net",
            "@c.us"
          );
          const contact = this.contactList.find(
            contact => contact.jid.replace("\0", "") === userJid
          );

          if (contact) {
            msg.author = contact.name
              ? contact.name
              : contact.vname || contact.notify;
          }
        }

        const chat = this.chatList.find(
          chat => chat.jid.replace("\0", "") === remoteJid
        );

        if (chat) {
          msg.key.name = chat.name;
        }

        if (msg.message.stickerMessage) {
          msg.message.decryptedMediaMessage = await this.decryptMedia(
            msg.message.stickerMessage as WAReceiveMedia,
            "sticker"
          ).catch(err => {
            throw err;
          });
        } else if (msg.message.imageMessage) {
          msg.message.decryptedMediaMessage = await this.decryptMedia(
            msg.message.imageMessage as WAReceiveMedia,
            "image"
          ).catch(err => {
            throw err;
          });
        } else if (msg.message.videoMessage) {
          msg.message.decryptedMediaMessage = await this.decryptMedia(
            msg.message.videoMessage as WAReceiveMedia,
            "video"
          ).catch(err => {
            throw err;
          });
        } else if (msg.message.audioMessage) {
          msg.message.decryptedMediaMessage = await this.decryptMedia(
            msg.message.audioMessage as WAReceiveMedia,
            "audio"
          ).catch(err => {
            throw err;
          });
        } else if (msg.message.documentMessage) {
          msg.message.decryptedMediaMessage = await this.decryptMedia(
            msg.message.documentMessage as WAReceiveMedia,
            "document"
          ).catch(err => {
            throw err;
          });
        }

        this.messageListeners.forEach(func => func(msg, allMsgs.description));
      } else if (((node as unknown) as WAStubMessage).messageStubType) {
        const msg = (node as unknown) as WAStubMessage;

        if (
          msg.messageStubType === "GROUP_PARTICIPANT_ADD" &&
          msg.messageStubParameters!.includes(
            this.myWid!.replace("c.us", "s.whatsapp.net")
          )
        ) {
          const chat = this.chatList.find(
            chat => chat.jid === msg.key.remoteJid!
          );

          if (chat) {
            const i = this.chatList.indexOf(chat);

            chat.read_only = "false";
            this.chatList[i] = chat;
          } else {
            const chat = await this.getGroupMetadata(msg.key.remoteJid!);

            this.chatList.push({
              name: chat.subject,
              jid: msg.key.remoteJid!,
              spam: "false",
              count: "0",
              t: "" + chat.creation
            });
          }
        } else if (
          msg.messageStubType === "GROUP_PARTICIPANT_REMOVE" &&
          msg.messageStubParameters!.includes(
            this.myWid!.replace("c.us", "s.whatsapp.net")
          )
        ) {
          const chat = this.chatList.find(
            chat => chat.jid === msg.key.remoteJid!
          );

          if (chat) {
            this.chatList.splice(this.chatList.indexOf(chat), 1);
          }
        }
        this.messageStubListeners.forEach(func => func(msg));
      }
    });
  }

  private async sendAdminTest() {
    const id = randHex(10).toUpperCase();
    const timeout = setTimeout(() => {
      this.noNetworkListeners.forEach(func => func());
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

  private async sendProto(
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
      await this.sendAdminTest().then(async isLoggedIn => {
        this.isLoggedIn = isLoggedIn;
      });
    }, 2 * 1000);

    return await this.sendSocketAsync(id, payload).then(data => {
      clearTimeout(timeout);
      return data;
    });
  }

  private async sendMessage(
    content: WAMessage,
    remoteJid: string,
    msgId?: string
  ) {
    const id = msgId ? msgId : "3EB0" + randHex(8).toUpperCase();
    const msgParams = {
      key: {
        id,
        remoteJid,
        fromMe: true
      },
      messageTimestamp: Math.round(Date.now() / 1000),
      status: 1,
      message: content
    };
    const msgData: WAMessageNode = {
      description: "action",
      attributes: {
        type: "relay",
        epoch: "" + this.messageSentCount
      },
      content: [
        {
          description: "message",
          content: await WAWebMessageInfo.encode(msgParams)
        }
      ]
    };

    await this.sendProto(msgData, id);

    return { id, content };
  }

  private async getGroupMetadata(
    remoteJid: string
  ): Promise<WhatsAppGroupMetadataPayload> {
    const id = randHex(10).toUpperCase();

    return await this.sendSocketAsync(
      id,
      `${id},,["query","GroupMetadata","${remoteJid}"]`
    );
  }

  public async getGroupParticipants(remoteJid: string) {
    return await this.getGroupMetadata(remoteJid).then(
      (data: WhatsAppGroupMetadataPayload) => {
        return data.participants;
      }
    );
  }

  public async getGroupSubject(remoteJid: string) {
    return await this.getGroupMetadata(remoteJid).then(
      (data: WhatsAppGroupMetadataPayload) => {
        return data.subject;
      }
    );
  }

  public async setGroupPhoto(image: Buffer, remoteJid: string) {
    const id = `${Math.round(Date.now() / 1000)}.--${this.messageSentCount}`;
    const content: WAMessageNode = {
      description: "picture",
      attributes: {
        id,
        jid: remoteJid,
        type: "set"
      },
      content: [
        {
          description: "image",
          content: Uint8Array.from(image)
        },
        {
          description: "preview",
          content: Uint8Array.from(image)
        }
      ]
    };
    const msgData: WAMessageNode = {
      description: "action",
      attributes: {
        type: "set",
        epoch: "" + this.messageSentCount
      },
      content: [content]
    };

    await this.sendProto(msgData, id, "PIC");

    return { id, content };
  }

  public async sendTextMessage(
    text: string,
    remoteJid: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    if (!mentionedJid) {
      return await this.sendMessage(
        {
          conversation: text
        },
        remoteJid
      );
    } else {
      return await this.sendMessage(
        {
          extendedTextMessage: {
            contextInfo: {
              mentionedJid
            },
            text
          }
        },
        remoteJid
      );
    }
  }

  private async sendQuotedMessage(
    content: WAMessage,
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    const contextInfo = {
      mentionedJid: mentionedJid
        ? quotedMsg.extendedTextMessage
          ? quotedMsg.extendedTextMessage.contextInfo
            ? quotedMsg.extendedTextMessage.contextInfo.mentionedJid
              ? quotedMsg.extendedTextMessage.contextInfo.mentionedJid.concat(
                  mentionedJid
                )
              : mentionedJid
            : mentionedJid
          : mentionedJid
        : [],
      stanzaId: quotedMsgId,
      participant: quotedAuthorJid,
      quotedMessage: quotedMsg.extendedTextMessage
        ? {
            conversation: quotedMsg.extendedTextMessage.text
          }
        : quotedMsg
    };

    if (content.conversation) {
      return await this.sendMessage(
        {
          extendedTextMessage: {
            contextInfo,
            text: content.conversation
          }
        },
        remoteJid
      );
    } else {
      const quotingContent = Object.assign({}, content);
      const innerContent = Object.keys(quotingContent)
        .map(_key => {
          const key: keyof typeof quotingContent = _key as any;
          return key !== "decryptedMediaMessage" && key !== "conversation"
            ? { key, content: quotingContent[key] }
            : undefined;
        })
        .filter(obj => obj !== undefined)[0]!;

      return await this.sendMessage(
        {
          [innerContent.key]: {
            contextInfo,
            ...innerContent.content
          }
        },
        remoteJid
      );
    }
  }

  public async sendQuotedTextMessage(
    text: string,
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    return await this.sendQuotedMessage(
      { conversation: text },
      remoteJid,
      quotedAuthorJid,
      quotedMsg,
      quotedMsgId,
      mentionedJid
    );
  }

  public async sendQuotedMediaMessage(
    file: Buffer,
    mimetype: string,
    msgType: "image" | "sticker" | "video" | "audio" | "document",
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    caption: string | undefined = undefined,
    duration: number | undefined = undefined,
    isGif: boolean = false,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ): Promise<{ id: string; content: WAMessage }> {
    const media = await this.encryptMedia(
      file,
      mimetype,
      msgType,
      caption,
      duration,
      isGif
    );

    return await this.sendQuotedMessage(
      media,
      remoteJid,
      quotedAuthorJid,
      quotedMsg,
      quotedMsgId,
      mentionedJid
    );
  }

  public async sendQuotedContactVCard(
    vcard: string,
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    const fullName = vcard.slice(
      vcard.indexOf("FN:") + 3,
      vcard.indexOf("\n", vcard.indexOf("FN:"))
    );

    return await this.sendQuotedMessage(
      {
        contactMessage: {
          vcard,
          displayName: fullName
        }
      },
      remoteJid,
      quotedAuthorJid,
      quotedMsg,
      quotedMsgId,
      mentionedJid
    );
  }

  public async sendQuotedContact(
    phoneNumber: string,
    firstName: string,
    lastName: string = "",
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    const fullName =
      lastName.length > 0 ? `${firstName} ${lastName}` : firstName;
    const vcard = `BEGIN:VCARD\nVERSION:3.0\nN:${lastName};${firstName};;\nFN:${fullName}\nTEL;TYPE=VOICE:${phoneNumber}\nEND:VCARD`;

    this.sendQuotedContactVCard(
      vcard,
      remoteJid,
      quotedAuthorJid,
      quotedMsg,
      quotedMsgId,
      mentionedJid
    );
  }

  public async sendQuotedLocation(
    latitude: number,
    longitude: number,
    remoteJid: string,
    quotedAuthorJid: string,
    quotedMsg: WAMessage,
    quotedMsgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    return await this.sendQuotedMessage(
      {
        locationMessage: {
          degreesLatitude: latitude,
          degreesLongitude: longitude
        }
      },
      remoteJid,
      quotedAuthorJid,
      quotedMsg,
      quotedMsgId,
      mentionedJid
    );
  }

  private async uploadMedia(uploadUrl: string, file: WASendMedia) {
    const body = new FormData();
    body.append("hash", Buffer.from(file.fileEncSha256).toString("base64"));
    body.append("file", file.blob, {
      filename: "blob",
      contentType: file.mimetype
    });

    return await fetch(`${uploadUrl}?f=j`, {
      body,
      method: "POST",
      headers: {
        ...body.getHeaders(),
        Origin: "https://web.whatsapp.com",
        Referer: "https://web.whatsapp.com/"
      }
    })
      .then(res => res.json())
      .then(async (res: WhatsAppMediaUploadPayload) => {
        return {
          url: res.url,
          mimetype: file.mimetype,
          mediaKey: file.mediaKey,
          fileLength: file.fileLength,
          fileSha256: file.fileSha256,
          fileEncSha256: file.fileEncSha256,
          jpegThumbnail: file.jpegThumbnail,
          pngThumbnail: file.pngThumbnail,
          seconds: file.seconds,
          caption: file.caption,
          gifPlayback: file.gifPlayback
        };
      });
  }

  private async encryptMedia(
    file: Buffer,
    mimetype: string,
    msgType: "image" | "sticker" | "video" | "audio" | "document",
    caption: string | undefined = undefined,
    duration: number | undefined = undefined,
    isGif: boolean = false
  ): Promise<WAMessage> {
    return new Promise(async resolve => {
      const messageTag = randHex(12).toUpperCase();
      const mediaKey = Uint8Array.from(crypto.randomBytes(32));
      const mediaKeyExpanded = HKDF(mediaKey, 112, WAMediaAppInfo[msgType]);
      const iv = mediaKeyExpanded.slice(0, 16);
      const cipherKey = mediaKeyExpanded.slice(16, 48);
      const macKey = mediaKeyExpanded.slice(48, 80);
      const enc = AESEncrypt(cipherKey, Uint8Array.from(file), iv, false);
      const mac = HmacSha256(macKey, concatIntArray(iv, enc)).slice(0, 10);
      const fileSha256 = Sha256(file);
      const fileEncSha256 = Sha256(concatIntArray(enc, mac));
      const type =
        msgType.replace("Message", "") === "sticker"
          ? "image"
          : msgType.replace("Message", "");

      const mediaObj: WASendMedia = {
        msgType,
        caption,
        mimetype,
        url: "",
        mediaKey,
        fileSha256,
        fileEncSha256,
        id: messageTag,
        fileLength: file.byteLength,
        blob: Buffer.from(concatIntArray(enc, mac))
      };

      if (msgType === "sticker") {
        mediaObj.pngThumbnail = await sharp(file)
          .resize(100)
          .png()
          .toBuffer();
      } else if (msgType === "image") {
        mediaObj.jpegThumbnail = await sharp(file)
          .resize(100)
          .jpeg()
          .toBuffer();
      } else if (msgType === "audio") {
        if (duration) {
          mediaObj.seconds = duration;
        } else {
          throw new Error("Audio messages require duration");
        }
      } else if (msgType === "video") {
        mediaObj.gifPlayback = isGif;
      }

      await this.sendSocketAsync(
        messageTag,
        `${messageTag},["action", "encr_upload", "${type}", "${Buffer.from(
          fileEncSha256
        ).toString("base64")}"]`
      ).then(async (data: WhatsAppUploadMediaURL) => {
        const media = await this.uploadMedia(data.url, mediaObj);

        resolve({ [msgType + "Message"]: media });
      });
    });
  }

  public async sendMediaMessage(
    file: Buffer,
    mimetype: string,
    msgType: "image" | "sticker" | "video" | "audio" | "document",
    remoteJid: string,
    caption: string | undefined = undefined,
    duration: number | undefined = undefined,
    isGif: boolean = false,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ): Promise<{ id: string; content: WAMessage }> {
    const nextId = randHex(12).toUpperCase();
    const mediaProto = await this.encryptMedia(
      file,
      mimetype,
      msgType,
      caption,
      duration,
      isGif
    );
    const media = await this.sendMediaProto(
      (mediaProto[
        (msgType + "Message") as
          | "imageMessage"
          | "stickerMessage"
          | "videoMessage"
          | "audioMessage"
          | "documentMessage"
      ]! as unknown) as WAMedia,
      msgType,
      remoteJid,
      nextId,
      mentionedJid
    );

    return { id: nextId, content: media.content };
  }

  public async sendVCardContact(remoteJid: string, vcard: string) {
    const fullName = vcard.slice(
      vcard.indexOf("FN:") + 3,
      vcard.indexOf("\n", vcard.indexOf("FN:"))
    );

    return await this.sendMessage(
      {
        contactMessage: {
          vcard,
          displayName: fullName
        }
      },
      remoteJid
    );
  }

  public async sendContact(
    remoteJid: string,
    phoneNumber: string,
    firstName: string,
    lastName: string = ""
  ) {
    const fullName =
      lastName.length > 0 ? `${firstName} ${lastName}` : firstName;
    const vcard = `BEGIN:VCARD\nVERSION:3.0\nN:${lastName};${firstName};;\nFN:${fullName}\nTEL;TYPE=VOICE:${phoneNumber}\nEND:VCARD`;

    return await this.sendVCardContact(remoteJid, vcard);
  }

  public async sendLocation(
    remoteJid: string,
    latitude: number,
    longitude: number
  ) {
    return await this.sendMessage(
      {
        locationMessage: {
          degreesLatitude: latitude,
          degreesLongitude: longitude
        }
      },
      remoteJid
    );
  }

  private async sendMediaProto(
    mediaFile: WAMedia,
    msgType: string,
    remoteJid: string,
    msgId: string,
    mentionedJid?: WAContextInfo["mentionedJid"]
  ) {
    if (!mentionedJid) {
      return await this.sendMessage(
        {
          [msgType + "Message"]: mediaFile
        },
        remoteJid,
        msgId
      );
    } else {
      return await this.sendMessage(
        {
          [msgType + "Message"]: {
            ...mediaFile,
            contextInfo: {
              mentionedJid
            }
          }
        },
        remoteJid,
        msgId
      );
    }
  }

  private async decryptMedia(
    mediaObj: WAReceiveMedia,
    type: "image" | "sticker" | "video" | "audio" | "document"
  ): Promise<WADecryptedMedia> {
    const mediaKey = Uint8Array.from(Buffer.from(mediaObj.mediaKey, "base64"));
    const mediaKeyExpanded = HKDF(mediaKey, 112, WAMediaAppInfo[type]);
    const iv = mediaKeyExpanded.slice(0, 16);
    const cipherKey = mediaKeyExpanded.slice(16, 48);
    const macKey = mediaKeyExpanded.slice(48, 80);

    const rawFile = await fetch(mediaObj.url)
      .then(res => res.arrayBuffer())
      .then(arrayBuffer => Buffer.from(arrayBuffer))
      .then(buffer => Uint8Array.from(buffer));
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
      buffer: Buffer.from(AESDecrypt(cipherKey, concatIntArray(iv, file)))
    };
  }

  public async deleteMessage(remoteJid: string, msgId: string) {
    return await this.sendMessage(
      {
        protocolMessage: {
          key: {
            remoteJid,
            fromMe: true,
            id: msgId
          },
          type: "REVOKE"
        }
      },
      remoteJid
    );
  }

  public async getProfilePicThumb(
    jid: string
  ): Promise<{ id: string; content?: Buffer; status?: number }> {
    return new Promise(async resolve => {
      const msgId = randHex(12).toUpperCase();

      await this.sendSocketAsync(
        msgId,
        `${msgId},["query", "ProfilePicThumb", "${jid}"]`
      ).then(async (data: WhatsAppProfilePicPayload) => {
        if (data.eurl) {
          resolve({
            id: msgId,
            content: await fetch(data.eurl).then(res => res.buffer())
          });
        } else if (data.status) {
          resolve({ id: msgId, status: data.status });
        }
      });
    });
  }

  private setupEncryptionKeys(data: WhatsAppConnPayload) {
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

  private async setupQrCode(data: WhatsAppLoginPayload) {
    this.keyPair = generateKeyPair(Uint8Array.from(crypto.randomBytes(32)));
    const publicKeyBase64 = Buffer.from(this.keyPair.public).toString("base64");
    const qrCode = dataUrlToBuffer(
      await qrcode.toDataURL(`${data.ref},${publicKeyBase64},${this.clientId}`)
    );

    writeFile(this.qrPath, qrCode.data, err => {
      if (err) console.error(err);
      this.qrCodeListeners.forEach(func => func());
    });
  }

  private init(loginMsgId: string, restoreSession: boolean) {
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
        `${loginMsgId},["admin","init",[0,4,2080],["WhatsApp forwarder","WhatsAppForwarder"],"${this.clientId}",true]`
      );

      if (restoreSession && (await doesFileExist(this.keysPath!))) {
        this.restoreSession(loginMsgId);
      }
    };
  }
}
