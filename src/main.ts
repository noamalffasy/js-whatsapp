import fetch from "node-fetch";
import { TypedEmitter } from "tiny-typed-emitter";

import { randHex } from "./utils/encryption";
import { WAMessageNode } from "./binary/writer";
import WABaseClient from "./baseClient";
import {
  WhatsAppGroupMetadataPayload,
  WAContextInfo,
  WAMessage,
  WAMedia,
  WhatsAppProfilePicPayload,
  WAChat,
  WAContact,
  WAWebMessage,
  WAStubMessage,
  WAReceiveMedia,
} from "./types";
import { WANode } from "./binary/reader";
import { sendMediaMessage, sendQuotedMediaMessage } from "./media";

interface WAListeners {
  node: (node: WANode) => void;
  message: (msg: WAWebMessage, description: string) => void;
  messageStub: (msg: WAStubMessage) => void;
  noNetwork: () => void;
  loggedOut: () => void;
  ready: () => void;
  qrCode: () => void;
}

export default class WhatsApp extends TypedEmitter<WAListeners> {
  myWid?: string;

  apiClient: WABaseClient;

  chatList: WAChat[] = [];
  contactList: WAContact[] = [];

  constructor(
    opts: { qrPath: string; restoreSession: boolean; keysPath: string } = {
      qrPath: "./qrcode.png",
      restoreSession: false,
      keysPath: "./keys.json",
    }
  ) {
    super();

    this.apiClient = new WABaseClient(opts);
    this.myWid = this.apiClient.myWid;

    this.apiClient.on("node", (node) => {
      this.handleNodes(node);
      this.emit("node", node);
    });
    this.apiClient.on("qrCode", () => this.emit("qrCode"));
    this.apiClient.on("ready", () => {
      this.emit("ready");
    });
    this.apiClient.on("myWid", (wid) => {
      this.myWid = wid;
    });
    this.apiClient.on("message", (msg, description) =>
      this.emit("message", msg, description)
    );
    this.apiClient.on("messageStub", (msg) => this.emit("messageStub", msg));
    this.apiClient.on("noNetwork", () => this.emit("noNetwork"));
    this.apiClient.on("loggedOut", () => this.emit("loggedOut"));
  }

  protected async handleNodes(allNodes: WANode) {
    // Run all ready listeners
    if (allNodes.description === "action") {
      this.emit("ready");
      this.removeAllListeners("ready");
    }

    // Iterate over all of the messages and update the data accordingly
    (allNodes.content as WANode[]).forEach(async (node) => {
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
            (contact) => contact.jid.replace("\0", "") === userJid
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
            (contact) => contact.jid.replace("\0", "") === userJid
          );

          if (contact) {
            msg.author = contact.name ?? contact.vname ?? contact.notify;
          }
        }

        const chat = this.chatList.find(
          (chat) => chat.jid.replace("\0", "") === remoteJid
        );

        if (chat) {
          msg.key.name = chat.name;
        }

        const mediaType = Object.keys(msg.message)
          .find((key) => key.endsWith("Message"))
          ?.replace("Message", "") as WAMediaTypes | undefined;

        if (mediaType) {
          msg.message.decryptedMediaMessage = await this.apiClient
            .decryptMedia(
              msg.message[
                `${mediaType}Message` as `${WAMediaTypes}Message`
              ] as WAReceiveMedia,
              mediaType
            )
            .catch((err) => {
              throw err;
            });
        }

        this.emit("message", msg, allNodes.description);
      } else if (((node as unknown) as WAStubMessage).messageStubType) {
        const msg = (node as unknown) as WAStubMessage;

        if (
          msg.messageStubType === "GROUP_PARTICIPANT_ADD" &&
          msg.messageStubParameters!.includes(
            this.apiClient.myWid!.replace("c.us", "s.whatsapp.net")
          )
        ) {
          const chat = this.chatList.find(
            (chat) => chat.jid === msg.key.remoteJid!
          );

          if (chat) {
            const i = this.chatList.indexOf(chat);

            chat.read_only = "false";
            this.chatList[i] = chat;
          } else {
            const chat = await this.apiClient.getGroupMetadata(
              msg.key.remoteJid!
            );

            this.chatList.push({
              name: chat.subject,
              jid: msg.key.remoteJid!,
              spam: "false",
              count: "0",
              t: "" + chat.creation,
            });
          }
        } else if (
          msg.messageStubType === "GROUP_PARTICIPANT_REMOVE" &&
          msg.messageStubParameters!.includes(
            this.apiClient.myWid!.replace("c.us", "s.whatsapp.net")
          )
        ) {
          const chat = this.chatList.find(
            (chat) => chat.jid === msg.key.remoteJid!
          );

          if (chat) {
            this.chatList.splice(this.chatList.indexOf(chat), 1);
          }
        }

        this.emit("messageStub", msg);
      }
    });
  }

  /**
   * Gets a group's participants
   * @param {Parameters<WhatsApp["getGroupParticipants"]>[0]} jid The JID of the group
   */
  public async getGroupParticipants(jid: string) {
    return await this.apiClient
      .getGroupMetadata(jid)
      .then((data: WhatsAppGroupMetadataPayload) => {
        return data.participants;
      });
  }

  /**
   * Gets a group's subject
   * @param {Parameters<WhatsApp["getGroupSubject"]>[0]} jid The JID of the group
   */
  public async getGroupSubject(jid: string) {
    return await this.apiClient
      .getGroupMetadata(jid)
      .then((data: WhatsAppGroupMetadataPayload) => {
        return data.subject;
      });
  }

  /**
   * Sets a group's photo
   * @param {Parameters<WhatsApp["setGroupPhoto"]>[0]} jid The JID of the group
   */
  public async setGroupPhoto(image: Buffer, jid: string) {
    const id = `${Math.round(Date.now() / 1000)}.--${
      this.apiClient.messageSentCount
    }`;
    const content: WAMessageNode = {
      description: "picture",
      attributes: {
        id,
        jid: jid,
        type: "set",
      },
      content: [
        {
          description: "image",
          content: Uint8Array.from(image),
        },
        {
          description: "preview",
          content: Uint8Array.from(image),
        },
      ],
    };
    const msgData: WAMessageNode = {
      description: "action",
      attributes: {
        type: "set",
        epoch: "" + this.apiClient.messageSentCount,
      },
      content: [content],
    };

    await this.apiClient.encryptAndSendNode(msgData, id, "PIC");

    return { id, content };
  }

  /**
   * Sends a text message to a wanted chat
   * @param {Parameters<WhatsApp["sendTextMessage"]>[0]} msg The msg object to send
   * @param {Parameters<WhatsApp["sendTextMessage"]>[1]} remoteJid The chat JID to send to
   */
  public async sendTextMessage(
    msg: { text: string; mentionedJids?: WAContextInfo["mentionedJid"] },
    remoteJid: string
  ) {
    if (!msg.mentionedJids) {
      return await this.apiClient.sendMessage(
        {
          conversation: msg.text,
        },
        remoteJid
      );
    } else {
      return await this.apiClient.sendMessage(
        {
          extendedTextMessage: {
            contextInfo: {
              mentionedJid: msg.mentionedJids,
            },
            text: msg.text,
          },
        },
        remoteJid
      );
    }
  }

  /**
   * Sends a quoted text message to a wanted chat
   * @param {Parameters<WhatsApp["sendQuotedTextMessage"]>[0]} msg The message object to send
   * @param {Parameters<WhatsApp["sendQuotedTextMessage"]>[1]} remoteJid The chat JID to send to
   * @param {Parameters<WhatsApp["sendQuotedTextMessage"]>[2]} quotedInfo The info needed for quoting a message
   */
  public async sendQuotedTextMessage(
    msg: Parameters<WhatsApp["sendTextMessage"]>[0],
    remoteJid: Parameters<WhatsApp["sendTextMessage"]>[1],
    quotedInfo: Parameters<WABaseClient["sendQuotedMessage"]>[2]
  ) {
    return await this.apiClient.sendQuotedMessage(
      { conversation: msg.text },
      remoteJid,
      quotedInfo,
      msg.mentionedJids
    );
  }

  public sendMediaMessage = sendMediaMessage;
  public sendQuotedMediaMessage = sendQuotedMediaMessage;

  /**
   * Sends a contact (in VCard format) to a wanted chat JID
   * @param {Parameters<WhatsApp["sendContactVCard"]>[0]} vcard The VCard to send
   * @param {Parameters<WhatsApp["sendContactVCard"]>[1]} remoteJid The chat JID to send to
   */
  public async sendContactVCard(vcard: string, remoteJid: string) {
    const fullName = vcard.slice(
      vcard.indexOf("FN:") + 3,
      vcard.indexOf("\n", vcard.indexOf("FN:"))
    );

    return await this.apiClient.sendMessage(
      {
        contactMessage: {
          vcard,
          displayName: fullName,
        },
      },
      remoteJid
    );
  }

  /**
   * Sends a quoted contact (in VCard format) to a wanted chat JID
   * @param {Parameters<WhatsApp["sendQuotedContactVCard"]>[0]} vcard The VCard to send
   * @param {Parameters<WhatsApp["sendQuotedContactVCard"]>[1]} remoteJid The chat JID to send to
   * @param {Parameters<WhatsApp["sendQuotedContactVCard"]>[2]} quotedInfo The info needed for quoting a message
   */
  public async sendQuotedContactVCard(
    vcard: string,
    remoteJid: string,
    quotedInfo: Parameters<WABaseClient["sendQuotedMessage"]>[2]
  ) {
    const fullName = vcard.slice(
      vcard.indexOf("FN:") + 3,
      vcard.indexOf("\n", vcard.indexOf("FN:"))
    );

    return await this.apiClient.sendQuotedMessage(
      {
        contactMessage: {
          vcard,
          displayName: fullName,
        },
      },
      remoteJid,
      quotedInfo
    );
  }

  /**
   * Sends a contact to a wanted chat JID
   * @param {Parameters<WhatsApp["sendContact"]>[0]} contactObj The contact object to send
   * @param {Parameters<WhatsApp["sendContact"]>[1]} remoteJid The chat JID to send to
   */
  public async sendContact(
    contactObj: { phoneNumber: string; firstName: string; lastName: string },
    remoteJid: string
  ) {
    const fullName =
      contactObj.lastName.length > 0
        ? `${contactObj.firstName} ${contactObj.lastName}`
        : contactObj.firstName;
    const vcard = `BEGIN:VCARD\nVERSION:3.0\nN:${contactObj.lastName};${contactObj.firstName};;\nFN:${fullName}\nTEL;TYPE=VOICE:${contactObj.phoneNumber}\nEND:VCARD`;

    return await this.sendContactVCard(remoteJid, vcard);
  }

  /**
   * Sends a quoted contact to a wanted chat JID
   * @param {Parameters<WhatsApp["sendQuotedContact"]>[0]} contactObj The contact object to send
   * @param {Parameters<WhatsApp["sendQuotedContact"]>[1]} remoteJid The chat JID to send to
   * @param {Parameters<WhatsApp["sendQuotedContact"]>[2]} quotedInfo The info needed for quoting a message
   */
  public async sendQuotedContact(
    contactObj: {
      phoneNumber: string;
      firstName: string;
      lastName: string;
    },
    remoteJid: string,
    quotedInfo: Parameters<WABaseClient["sendQuotedMessage"]>[2]
  ) {
    const fullName =
      contactObj.lastName.length > 0
        ? `${contactObj.firstName} ${contactObj.lastName}`
        : contactObj.firstName;
    const vcard = `BEGIN:VCARD\nVERSION:3.0\nN:${contactObj.lastName};${contactObj.firstName};;\nFN:${fullName}\nTEL;TYPE=VOICE:${contactObj.phoneNumber}\nEND:VCARD`;

    this.sendQuotedContactVCard(vcard, remoteJid, quotedInfo);
  }

  /**
   * Sends a location to a wanted chat JID
   * @param {Parameters<WhatsApp["sendLocation"]>[0]} locationObj The location object to send
   * @param {Parameters<WhatsApp["sendLocation"]>[1]} remoteJid The chat JID to send to
   */
  public async sendLocation(
    locationObj: { latitude: number; longitude: number },
    remoteJid: string
  ) {
    return await this.apiClient.sendMessage(
      {
        locationMessage: {
          degreesLatitude: locationObj.latitude,
          degreesLongitude: locationObj.longitude,
        },
      },
      remoteJid
    );
  }

  /**
   * Sends a quoted location to a wanted chat JID
   * @param {Parameters<WhatsApp["sendQuotedLocation"]>[0]} locationObj The location object to send
   * @param {Parameters<WhatsApp["sendQuotedLocation"]>[1]} remoteJid The chat JID to send to
   * @param {Parameters<WhatsApp["sendQuotedLocation"]>[2]} quotedInfo The info needed for quoting a message
   */
  public async sendQuotedLocation(
    locationObj: { latitude: number; longitude: number },
    remoteJid: string,
    quotedInfo: Parameters<WABaseClient["sendQuotedMessage"]>[2]
  ) {
    return await this.apiClient.sendQuotedMessage(
      {
        locationMessage: {
          degreesLatitude: locationObj.latitude,
          degreesLongitude: locationObj.longitude,
        },
      },
      remoteJid,
      quotedInfo
    );
  }

  /**
   * Deletes a wanted message
   * @param {Parameters<WhatsApp["deleteMessage"]>[0]} remoteJid The chat JID to send to
   * @param {Parameters<WhatsApp["deleteMessage"]>[1]} msgId The id of the message to delete
   */
  public async deleteMessage(remoteJid: string, msgId: string) {
    return await this.apiClient.sendMessage(
      {
        protocolMessage: {
          key: {
            remoteJid,
            fromMe: true,
            id: msgId,
          },
          type: "REVOKE",
        },
      },
      remoteJid
    );
  }

  /**
   * Gets a user's profile picture
   * @param {Parameters<WhatsApp["getProfilePicThumb"]>[0]} jid The JID of the user
   */
  public async getProfilePicThumb(
    jid: string
  ): Promise<{ id: string; content?: Buffer; status?: number }> {
    return new Promise(async (resolve) => {
      const msgId = randHex(12).toUpperCase();

      await this.apiClient
        .sendSocketAsync(
          msgId,
          JSON.stringify(["query", "ProfilePicThumb", jid])
        )
        .then(async (data: WhatsAppProfilePicPayload) => {
          if (data.eurl) {
            resolve({
              id: msgId,
              content: await fetch(data.eurl).then((res) => res.buffer()),
            });
          } else if (data.status) {
            resolve({ id: msgId, status: data.status });
          }
        });
    });
  }
}
