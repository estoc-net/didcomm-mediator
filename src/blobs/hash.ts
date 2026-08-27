/**
 * Two strings name a blob, for two purposes. The **hash** — a sha2-256
 * multihash in multibase base32 lower, `b` + base32(0x12 0x20 <32-byte
 * digest>), 56 characters, the same string an object-share package carries
 * as `data.hash` — is what the bytes are checked against on the way in.
 * The **id** — 20 random bytes, base32 lower, 32 characters — is where they
 * are served: `/b/<id>`. The id says nothing about the bytes or who put
 * them, and two mediations putting the same hash get two ids. Both are
 * decoded and encoded here by hand: fixed shapes, not worth a multiformats
 * dependency.
 */

const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const SHA256_PREFIX = [0x12, 0x20];
export const BLOB_NAME_PATTERN = /^b[a-z2-7]{55}$/;
export const BLOB_ID_PATTERN = /^[a-z2-7]{32}$/;
const ID_BYTES = 20;

function base32(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

function unbase32(text: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of text) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) {
      throw new Error("not base32");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** A fresh blob id: 20 random bytes as base32. */
export function mintBlobId(): string {
  return base32(crypto.getRandomValues(new Uint8Array(ID_BYTES)));
}

/** The blob name for a sha-256 digest. */
export function blobName(digest: Uint8Array): string {
  if (digest.length !== 32) {
    throw new Error("sha-256 digests are 32 bytes");
  }
  return "b" + base32(Uint8Array.from([...SHA256_PREFIX, ...digest]));
}

/** The digest a blob name encodes, or null if the string is not a name. */
export function blobDigest(name: string): Uint8Array | null {
  if (!BLOB_NAME_PATTERN.test(name)) {
    return null;
  }
  const bytes = unbase32(name.slice(1));
  if (
    bytes.length !== 34 ||
    bytes[0] !== SHA256_PREFIX[0] ||
    bytes[1] !== SHA256_PREFIX[1]
  ) {
    return null;
  }
  // The name must be canonical: re-encoding must give the same string.
  return blobName(bytes.subarray(2)) === name ? bytes.subarray(2) : null;
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
