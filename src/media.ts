import WABaseClient from "./baseClient";
import WhatsApp from "./main";
import { WAMessage, WAMedia, WAMediaTypes } from "./types";
import { randHex } from "./utils/encryption";

/**
 * Sends a media message to a wanted chat JID
 * @param {Parameters<WhatsApp["sendMediaMessage"]>[0]} mediaObj The media object to send
 * @param {Parameters<WhatsApp["sendMediaMessage"]>[1]} remoteJid The chat JID to send to
 */
export async function sendMediaMessage(
  this: WhatsApp,
  mediaObj: Parameters<WABaseClient["encryptMedia"]>[0],
  remoteJid: string
): Promise<{ id: string; content: WAMessage }> {
  const nextId = randHex(12).toUpperCase();
  const mediaProto = await this.apiClient.encryptMedia(mediaObj);

  if (!mediaProto) {
    throw "Unable to upload media";
  }

  const media = await this.apiClient.sendMediaProto({
    remoteJid,
    mediaFile: (mediaProto[
      (mediaObj.msgType + "Message") as `${WAMediaTypes}Message`
    ]! as unknown) as WAMedia,
    msgType: mediaObj.msgType,
    msgId: nextId,
    mentionedJids:
      "caption" in mediaObj ? mediaObj.caption.mentionedJids : undefined,
  });

  return { id: nextId, content: media.content };
}

/**
 * Sends a quoted media message to a wanted chat JID
 * @param {Parameters<WhatsApp["sendQuotedMediaMessage"]>[0]} mediaObj The media object to send
 * @param {Parameters<WhatsApp["sendQuotedMediaMessage"]>[1]} remoteJid The chat JID to send to
 * @param {Parameters<WhatsApp["sendQuotedMediaMessage"]>[2]} quotedInfo The info needed for quoting a message
 */
export async function sendQuotedMediaMessage(
  this: WhatsApp,
  mediaObj: Parameters<typeof sendMediaMessage>[0],
  remoteJid: Parameters<typeof sendMediaMessage>[1],
  quotedInfo: Parameters<WABaseClient["sendQuotedMessage"]>[2]
): Promise<{ id: string; content: WAMessage }> {
  const media = await this.apiClient.encryptMedia(mediaObj);

  if (!media) {
    throw "Unable to upload media";
  }

  return await this.apiClient.sendQuotedMessage(
    media,
    remoteJid,
    quotedInfo,
    "caption" in mediaObj ? mediaObj.caption.mentionedJids : undefined
  );
}
