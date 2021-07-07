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

export interface WhatsAppChallengePayload {
  0: "Cmd";
  1: {
    type: "challenge";
    challenge: string;
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

export interface WhatsAppMediaConnPayload {
  status: number;
  media_conn: {
    auth: string;
    ttl: number;
    hosts: {
      hostname: string;
      ips: {
        ip4: string;
        ip6: string;
      }[];
    }[];
  };
}

export interface WhatsAppMediaUploadPayload {
  direct_path: string;
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
  id?: string | null;
  displayName?: string | null;
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

export type WAMediaTypes = "image" | "sticker" | "video" | "audio" | "document";

export interface WADecryptedMedia {
  type: WAMediaTypes;
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

  /** ExtendedTextMessage font */
  font?:
    | "SANS_SERIF"
    | "SERIF"
    | "NORICAN_REGULAR"
    | "BRYDAN_WRITE"
    | "BEBASNEUE_REGULAR"
    | "OSWALD_HEAVY"
    | null;

  /** ExtendedTextMessage previewType */
  previewType?: "NONE" | "VIDEO" | null;

  /** ExtendedTextMessage jpegThumbnail */
  jpegThumbnail?: Uint8Array | null;

  /** ExtendedTextMessage contextInfo */
  contextInfo?: WAContextInfo | null;

  /** ExtendedTextMessage doNotPlayInline */
  doNotPlayInline?: boolean | null;
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

  /** ContextInfo ephemeralSettingTimestamp */
  ephemeralSettingTimestamp?: number | null;
}

export interface WAProtocolMessage {
  key?: WAMessageKey | null;
  type?:
    | "REVOKE"
    | "EPHEMERAL_SETTING"
    | "EPHEMERAL_SYNC_RESPONSE"
    | "HISTORY_SYNC_NOTIFICATION"
    | null;
  ephemeralExpiration?: number | null;
  ephemeralSettingTimestamp?: number | null;
  historySyncNotification?: WAHistorySyncNotification | null;
}

export interface WAHistorySyncNotification {
  fileSha256?: Uint8Array | null;
  fileLength?: number | null;
  mediaKey?: Uint8Array | null;
  fileEncSha256?: Uint8Array | null;
  directPath?: string | null;
  syncType?:
    | "INITIAL_BOOTSTRAP"
    | "INITIAL_STATUS_V3"
    | "FULL"
    | "RECENT"
    | null;
  chunkOrder: number;
}

export interface WALocationMessage {
  degreesLatitude: number;
  degreesLongitude: number;
  name?: string;
  address?: string;
  url?: string;
  isLive?: boolean;
  accuracyInMeter?: number;
  speedInMps?: number;
  degreesClockwiseFromMagneticNorth?: number;
  comment?: string;
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
  groupInviteMessage?: WAGroupInviteMessage | null;
}

export interface WAGroupInviteMessage {
  groupJid: string;
  inviteCode: string;
  inviteExpiration: number;
  groupName: string;
  jpegThumbnail: Uint8Array;
  caption: string;
  contextInfo: WAContextInfo;
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
    | "CHANGE_EPHEMERAL_SETTING"
    | null;
  messageStubParameters: string[] | null;
}
