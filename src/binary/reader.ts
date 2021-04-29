import {
  WATags,
  WASingleByteTokens,
  WADoubleByteTokens,
  WAWebMessageInfo
} from "./tokens";
import { concatIntArray } from "../utils/arrays";

export interface WANode {
  description: string;
  attributes?: { [k: string]: string | null };
  content?: WANode[] | Uint8Array;
}

export class WABinaryReader {
  data: Uint8Array;
  index: number;

  constructor(data: Uint8Array) {
    this.data = data;
    this.index = 0;
  }

  checkEOS(length: number) {
    if (this.index + length > this.data.length) {
      throw Error("End of stream reached");
    }
  }

  readByte() {
    this.checkEOS(1);
    const ret = this.data[this.index];
    this.index++;
    return ret;
  }

  readIntN(n: number, littleEndian: boolean = false) {
    this.checkEOS(n);
    let ret = 0;

    for (let i = 0; i < n; i++) {
      const currShift = littleEndian ? i : n - 1 - i;
      ret |= this.data[this.index + i] << (currShift * 8);
    }
    this.index += n;
    return ret;
  }

  readInt16(littleEndian: boolean = false) {
    return this.readIntN(2, littleEndian);
  }

  readInt20() {
    this.checkEOS(3);
    const ret =
      ((this.data[this.index] & 15) << 16) +
      (this.data[this.index + 1] << 8) +
      this.data[this.index + 2];
    this.index += 3;
    return ret;
  }

  readInt32(littleEndian: boolean = false) {
    return this.readIntN(4, littleEndian);
  }

  readInt64(littleEndian: boolean = false) {
    return this.readIntN(8, littleEndian);
  }

  readPacked8(tag: number) {
    const startByte = this.readByte();
    let ret = "";

    for (let i = 0; i < (startByte & 127); i++) {
      const currByte = this.readByte();
      ret +=
        this.unpackByte(tag, (currByte & 0xf0) >> 4)! +
        this.unpackByte(tag, currByte & 0x0f)!;
    }

    if (startByte >> 7 !== 0) {
      ret = ret.substr(0, ret.length - 1);
    }

    return ret;
  }

  unpackByte(tag: number, value: number) {
    if (tag === WATags.NIBBLE_8) {
      return this.unpackNibble(value);
    } else if (tag === WATags.HEX_8) {
      return this.unpackHex(value);
    }
    throw new Error(`unpackByte with unknown tag ${tag}`);
  }

  unpackNibble(value: number) {
    if (value >= 0 && value <= 9) {
      return "" + value;
    } else if (value === 10) {
      return "-";
    } else if (value === 11) {
      return ".";
    } else if (value === 15) {
      return "\0";
    }
    throw new Error(`Invalid nibble to unpack: ${value}`);
  }

  unpackHex(value: number) {
    if (value < 0 || value > 15) {
      throw new Error(`Invalid hex to unpack: ${value}`);
    }
    if (value < 10) {
      return "" + value;
    }
    return String.fromCharCode("A".charCodeAt(0) + value - 10);
  }

  isListTag(tag: number) {
    return (
      tag === WATags.LIST_EMPTY ||
      tag === WATags.LIST_8 ||
      tag === WATags.LIST_16
    );
  }

  readListSize(tag: number) {
    if (tag === WATags.LIST_EMPTY) {
      return 0;
    } else if (tag === WATags.LIST_8) {
      return this.readByte();
    } else if (tag === WATags.LIST_16) {
      return this.readInt16();
    }
    throw new Error(
      `Invalid tag for list size: ${tag} at position ${this.index}`
    );
  }

  readString(tag: number): Uint8Array {
    if (tag >= 3 && tag <= WASingleByteTokens.length) {
      const token = this.getToken(tag);

      if (token === "s.whatsapp.net") {
        return new TextEncoder().encode("c.us");
      }
      return new TextEncoder().encode(token);
    }

    if (
      tag === WATags.DICTIONARY_0 ||
      tag === WATags.DICTIONARY_1 ||
      tag === WATags.DICTIONARY_2 ||
      tag === WATags.DICTIONARY_3
    ) {
      return this.getDoubleToken(tag - WATags.DICTIONARY_0, this.readByte());
    } else if (tag === WATags.LIST_EMPTY) {
      return new TextEncoder().encode("");
    } else if (tag === WATags.BINARY_8) {
      return this.readStringFromChars(this.readByte());
    } else if (tag === WATags.BINARY_20) {
      return this.readStringFromChars(this.readInt20());
    } else if (tag === WATags.BINARY_32) {
      return this.readStringFromChars(this.readInt32());
    } else if (tag === WATags.JID_PAIR) {
      const i = this.readString(this.readByte());
      const j = this.readString(this.readByte());

      if (!i || !j) {
        throw new Error(`Invalid jid pair: ${i}, ${j}`);
      }
      return concatIntArray(i, new TextEncoder().encode("@"), j);
    } else if (tag === WATags.NIBBLE_8 || tag === WATags.HEX_8) {
      return new TextEncoder().encode(this.readPacked8(tag));
    } else {
      throw new Error(`Invalid string with tag ${tag}`);
    }
  }

  readStringFromChars(length: number) {
    this.checkEOS(length);
    const ret = this.data.slice(this.index, this.index + length);
    this.index += length;
    return ret;
  }

  readAttributes(n: number) {
    let ret: { [k: string]: string } = {};
    if (n === 0) {
      return;
    }
    for (let i = 0; i < n; i++) {
      const index = new TextDecoder().decode(this.readString(this.readByte())!);
      ret[index] = new TextDecoder().decode(this.readString(this.readByte()));
    }
    return ret;
  }

  readList(tag: number) {
    const listSize = this.readListSize(tag);
    let ret = [];

    for (let i = 0; i < listSize; i++) {
      ret.push(this.readNode());
    }

    return ret;
  }

  readNode(): WANode {
    const listSize = this.readListSize(this.readByte());
    const descrTag = this.readByte();

    if (descrTag === WATags.STREAM_END) {
      throw new Error("Unexpected stream end");
    }

    const description = new TextDecoder().decode(this.readString(descrTag));

    if (listSize === 0 || description === "") {
      throw new Error("Invalid node");
    }

    const attributes = this.readAttributes((listSize - 1) >> 1);

    if (listSize % 2 === 1) {
      return { description, attributes };
    }

    const tag = this.readByte();

    if (this.isListTag(tag)) {
      return {
        description,
        attributes,
        content: this.readList(tag)
      };
    } else if (tag === WATags.BINARY_8) {
      return {
        description,
        attributes,
        content: this.readBytes(this.readByte())
      };
    } else if (tag === WATags.BINARY_20) {
      return {
        description,
        attributes,
        content: this.readBytes(this.readInt20())
      };
    } else if (tag === WATags.BINARY_32) {
      return {
        description,
        attributes,
        content: this.readBytes(this.readInt32())
      };
    }
    return {
      description,
      attributes,
      content: this.readString(tag)!
    };
  }

  readBytes(n: number) {
    let ret = [];

    for (let i = 0; i < n; i++) {
      ret.push(this.readByte());
    }

    return Uint8Array.from(ret);
  }

  getToken(index: number) {
    if (index < 3 || index >= WASingleByteTokens.length) {
      throw new Error(`Invalid token index: ${index}`);
    }
    return WASingleByteTokens[index];
  }

  getDoubleToken(index1: number, index2: number) {
    const n = 256 * index1 + index2;

    if (n < 0 || n >= WADoubleByteTokens.length) {
      throw new Error(`Invalid token index: ${n}`);
    }
    return WADoubleByteTokens[n];
  }
}

export async function whatsappReadMessageArray(msgs: WANode["content"]) {
  if (!Array.isArray(msgs)) {
    return msgs;
  }

  let ret = [];

  for (const msg of msgs!) {
    ret.push(
      msg.description === "message"
        ? await WAWebMessageInfo.decode(msg.content as Uint8Array)
        : msg
    );
  }

  return ret;
}

export async function whatsappReadBinary(
  data: Uint8Array,
  withMessages: boolean = false
) {
  const node = new WABinaryReader(data).readNode();

  if (
    withMessages &&
    node &&
    node.attributes &&
    node.content &&
    node.description === "action"
  ) {
    node.content = await whatsappReadMessageArray(node.content).then(
      res => res as WANode["content"]
    );
  }
  return node;
}
