import { WATags, WASingleByteTokens } from "./tokens";
import { WANode } from "./reader";

class WABinaryWriter {
  data: number[] = [];

  getData() {
    return Uint8Array.from(this.data);
  }

  pushByte(value: number) {
    this.data.push(value);
  }

  pushBytes(bytes: number[]) {
    this.data = this.data.concat(bytes);
  }

  pushIntN(value: number, n: number, littleEndian = false) {
    for (let i = 0; i < n; i++) {
      const currShift = littleEndian ? i : n - i - 1;
      this.data.push((value >> (currShift * 8)) & 0xff);
    }
  }

  pushInt8(value: number) {
    this.pushIntN(value, 1);
  }

  pushInt16(value: number) {
    this.pushIntN(value, 2);
  }

  pushInt20(value: number) {
    this.pushBytes([(value >> 16) & 0x0f, (value >> 8) & 0xff, value & 0xff]);
  }

  pushInt32(value: number) {
    this.pushIntN(value, 4);
  }

  pushInt64(value: number) {
    this.pushIntN(value, 8);
  }

  pushString(str: string) {
    this.pushBytes(Array.from(new TextEncoder().encode(str)));
  }

  writeByteLength(length: number) {
    if (length >= Number.MAX_VALUE) {
      throw new Error(`string too large to encode (len = ${length})`);
    }

    if (length >= 1 << 20) {
      this.pushByte(WATags.BINARY_32);
      this.pushInt32(length);
    } else if (length >= 256) {
      this.pushByte(WATags.BINARY_20);
      this.pushInt20(length);
    } else {
      this.pushByte(WATags.BINARY_8);
      this.pushByte(length);
    }
  }

  writeNode(node: WAMessageNode | null) {
    if (!node) {
      return;
    }

    if (!node.description && !node.content) {
      throw new Error("Invalid node");
    }

    const numAttributes = node.attributes
      ? Object.keys(node.attributes).filter(key => node.attributes![key]).length
      : 0;

    this.writeListStart(2 * numAttributes + 1 + (node.content ? 1 : 0));
    this.writeString(node.description);
    this.writeAttributes(node.attributes);
    this.writeChildren(node.content!);
  }

  writeString(token: string, i = false) {
    if (!i && token === "c.us") {
      this.writeToken(WASingleByteTokens.indexOf("s.whatsapp.net"));
      return;
    }

    const tokenIndex = WASingleByteTokens.indexOf(token);

    if (tokenIndex === -1) {
      const jidSepIndex = token.indexOf("@");

      if (jidSepIndex < 1) {
        this.writeStringRaw(token);
      } else {
        this.writeJid(
          token.slice(0, jidSepIndex),
          token.slice(jidSepIndex + 1)
        );
      }
    } else if (tokenIndex < WATags.SINGLE_BYTE_MAX) {
      this.writeToken(tokenIndex);
    } else {
      const singleByteOverflow = tokenIndex - WATags.SINGLE_BYTE_MAX;
      const dictionaryIndex = singleByteOverflow >> 8;

      if (dictionaryIndex < 0 || dictionaryIndex > 3) {
        throw new Error(
          `Double byte dictionary token out of range ${token} ${tokenIndex}`
        );
      }

      this.writeToken(WATags.DICTIONARY_0 + dictionaryIndex);
      this.writeToken(singleByteOverflow % 256);
    }
  }

  writeStringRaw(value: string) {
    this.writeByteLength(value.length);
    this.pushString(value);
  }

  writeJid(jidLeft: string, jidRight: string) {
    this.pushByte(WATags.JID_PAIR);

    if (jidLeft && jidLeft.length > 0) {
      this.writeString(jidLeft);
    } else {
      this.writeToken(WATags.LIST_EMPTY);
    }
    this.writeString(jidRight);
  }

  writeToken(token: number) {
    if (token < WASingleByteTokens.length) {
      this.pushByte(token);
    } else if (token <= 500) {
      throw new Error("Invalid token");
    }
  }

  writeAttributes(attrs: WANode["attributes"]) {
    if (!attrs) {
      return;
    }

    for (const key in attrs) {
      if (attrs[key]) {
        this.writeString(key);
        this.writeString(attrs[key]!);
      }
    }
  }

  writeChildren(children: string | Uint8Array | WAMessageNode[] | undefined) {
    if (children) {
      if (typeof children === "string") {
        this.writeString(children as string, true);
      } else if (children instanceof Uint8Array) {
        this.writeByteLength(children.length);
        this.pushBytes(Array.from(children as Uint8Array));
      } else if (Array.isArray(children)) {
        this.writeListStart((children as WAMessageNode[]).length);

        for (const child of children) {
          this.writeNode(child);
        }
      } else {
        throw new Error("Invalid children");
      }
    }
  }

  writeListStart(listSize: number) {
    if (listSize === 0) {
      this.pushByte(WATags.LIST_EMPTY);
    } else if (listSize < 256) {
      this.pushBytes([WATags.LIST_8, listSize]);
    } else {
      this.pushBytes([WATags.LIST_16, listSize]);
    }
  }

  writePackedBytes(value: string) {
    try {
      this.writePackedBytesImpl(value, WATags.NIBBLE_8);
    } catch {
      this.writePackedBytesImpl(value, WATags.HEX_8);
    }
  }

  writePackedBytesImpl(value: string, dataType: number) {
    const numBytes = value.length;

    if (numBytes > WATags.PACKED_MAX) {
      throw new Error(`Too many bytes to nibble encode, length: ${numBytes}`);
    }

    this.pushByte(dataType);
    this.pushByte((numBytes % 2 > 0 ? 128 : 0) | Math.ceil(numBytes / 2));

    for (let i = 0; i < Math.floor(numBytes / 2); i++) {
      this.pushByte(
        this.packBytePair(dataType, value[2 * i], value[2 * i + 1])
      );
    }

    if (numBytes % 2 !== 0) {
      this.pushByte(this.packBytePair(dataType, value[numBytes - 1], "\x00"));
    }
  }

  packBytePair(packType: number, part1: string, part2: string) {
    if (packType === WATags.NIBBLE_8) {
      return (this.packNibble(part1) << 4) | this.packNibble(part2);
    } else if (packType === WATags.HEX_8) {
      return (this.packHex(part1) << 4) | this.packHex(part2);
    } else {
      throw new Error(`Invalid byte pack type: ${packType}`);
    }
  }

  packNibble(value: string) {
    if (value >= "0" && value <= "9") {
      return parseInt(value);
    } else if (value === "-") {
      return 10;
    } else if (value === ".") {
      return 11;
    } else if (value === "\x00") {
      return 15;
    }
    throw new Error(`Invalid byte to pack as nibble ${value}`);
  }

  packHex(value: string) {
    if (
      (value >= "0" && value <= "9") ||
      (value >= "A" && value <= "F") ||
      (value >= "a" && value <= "f")
    ) {
      return parseInt(value, 16);
    } else if (value === "\x00") {
      return 15;
    }
    throw new Error(`Invalid byte to pack as hex: ${value}`);
  }
}

export interface WAMessageNode {
  description: WANode["description"];
  attributes?: WANode["attributes"];
  content?: Uint8Array | WAMessageNode[];
}

export async function whatsappWriteBinary(node: WAMessageNode) {
  const stream = new WABinaryWriter();
  stream.writeNode(node);
  return stream.getData();
}
