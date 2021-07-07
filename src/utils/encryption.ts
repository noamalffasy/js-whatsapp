import crypto from "crypto";
import { Readable } from "stream";

import { concatIntArray } from "./arrays";

const AES_BLOCK_SIZE = 16;

export function uintArrayToStream(binary: Uint8Array) {
  return new Readable({
    read() {
      this.push(binary);
      this.push(null);
    },
  });
}

export function dataUrlToBuffer(dataString: string) {
  const matches = dataString.match(
    /^data:image\/([A-Za-z-+\/]+);base64,(.+)$/
  )!;

  const type = matches[1];
  const data = Buffer.from(matches[2], "base64");

  return { type, data };
}

export function randHex(n: number) {
  if (n <= 0) {
    return "";
  }
  var rs = "";
  try {
    rs = crypto
      .randomBytes(Math.ceil(n / 2))
      .toString("hex")
      .slice(0, n);
    /* note: could do this non-blocking, but still might fail */
  } catch (ex) {
    /* known exception cause: depletion of entropy info for randomBytes */
    console.error("Exception generating random string: " + ex);
    /* weaker random fallback */
    rs = "";
    var r = n % 8,
      q = (n - r) / 8,
      i;
    for (i = 0; i < q; i++) {
      rs += Math.random().toString(16).slice(2);
    }
    if (r > 0) {
      rs += Math.random().toString(16).slice(2, i);
    }
  }
  return rs;
}

export function AESPad(src: Uint8Array) {
  const pad = AES_BLOCK_SIZE - (src.length % AES_BLOCK_SIZE);
  return concatIntArray(src, repeatedNumToBits(pad, pad));
}

export function AESUnpad(src: Uint8Array) {
  return src
    .slice(0, src.length - src[src.length - 1])
    .filter((_, i) => (i + 1) % 4 === 0);
}

export function AESEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  _iv: Uint8Array | null = null,
  includeIv = true
) {
  const iv = _iv ? _iv : Uint8Array.from(crypto.randomBytes(AES_BLOCK_SIZE));
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return includeIv
    ? concatIntArray(iv, Uint8Array.from(encrypted))
    : Uint8Array.from(encrypted);
}

export function AESDecrypt(key: Uint8Array, cipherbits: Uint8Array) {
  const iv = cipherbits.slice(0, AES_BLOCK_SIZE);
  const prp = crypto.createDecipheriv("aes-256-cbc", key, iv);
  prp.setAutoPadding(false);
  const decrypted = Buffer.concat([
    prp.update(cipherbits.slice(AES_BLOCK_SIZE)),
    prp.final(),
  ]);

  return Uint8Array.from(decrypted);
}

export function numToBits(n: number): Uint8Array {
  return Uint8Array.from(
    Buffer.from((n < 16 ? "0" : "") + n.toString(16), "hex")
  );
}

export function repeatedNumToBits(n: number, repeats: number): Uint8Array {
  let nBits = numToBits(n);
  let ret = new Uint8Array();

  for (let i = 0; i < repeats; i++) {
    ret = concatIntArray(ret, nBits);
  }

  return ret;
}

export function HmacSha256(
  keyBits: Uint8Array,
  signBits: Uint8Array
): Uint8Array {
  return Uint8Array.from(
    crypto.createHmac("sha256", keyBits).update(signBits).digest()
  );
}

export function Sha256(signBits: Uint8Array) {
  return Uint8Array.from(crypto.createHash("sha256").update(signBits).digest());
}

export function HKDF(
  _key: Uint8Array,
  length: number,
  appInfo = ""
): Uint8Array {
  const key = HmacSha256(repeatedNumToBits(0, 32), _key);
  let keyStream = new Uint8Array();
  let keyBlock = new Uint8Array();
  let blockIndex = 1;

  while (keyStream.length < length) {
    keyBlock = HmacSha256(
      key,
      concatIntArray(
        keyBlock,
        new TextEncoder().encode(appInfo),
        numToBits(blockIndex)
      )
    );
    blockIndex += 1;
    keyStream = concatIntArray(keyStream, keyBlock);
  }

  return keyStream.slice(0, length);
}

export function toArrayBuffer(buf: Buffer) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}
