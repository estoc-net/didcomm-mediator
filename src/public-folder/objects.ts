/**
 * Relay-side helpers on top of @estoc/signed-dir (which owns the object
 * model: raw file CIDs, dag-json dir nodes, root cards). What lives here
 * is only what the relay role needs beyond the trust layer: wire media
 * types, non-throwing validators for untrusted input, and the multihash
 * form a DIDComm links attachment carries.
 */

import bs58 from "bs58";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";

export {
  compareNames,
  decodeDirNode,
  encodeDirNode,
  fileCid,
  isDirCid,
  type DirEntry,
} from "@estoc/signed-dir";

export const RAW_MEDIA_TYPE = "application/vnd.ipld.raw";
export const DAG_JSON_MEDIA_TYPE = "application/vnd.ipld.dag-json";

/** Is this a well-formed CID at all? Throwing parsers make poor validators. */
export function isCid(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  try {
    CID.parse(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Do these bytes hash to this CID (under the CID's own codec)? The relay's
 * one integrity check: an object is stored or served only under a name its
 * bytes actually earn.
 */
export async function bytesMatchCid(cid: string, bytes: Uint8Array): Promise<boolean> {
  let parsed: CID;
  try {
    parsed = CID.parse(cid);
  } catch {
    return false;
  }
  const digest = await sha256.digest(bytes);
  return CID.create(1, parsed.code, digest).toString() === cid;
}

/**
 * The CID's multihash as a multibase (base58btc) string — what a DIDComm
 * links attachment carries in `data.hash`. Redundant with the attachment id
 * being the CID, but required by the attachment format, and it lets generic
 * DIDComm tooling check integrity without knowing CIDs.
 */
export function multihashOf(cid: string): string {
  return `z${bs58.encode(CID.parse(cid).multihash.bytes)}`;
}

/**
 * Split a `/`-separated relative path, rejecting anything unsafe.
 * (@estoc/signed-dir keeps its path splitting internal — the relay
 * validates query paths itself before ever touching a tree.)
 */
export function segmentsOf(path: string): string[] {
  const segments = path.split("/").filter((s) => s !== "");
  if (segments.length === 0) {
    throw new Error("empty path");
  }
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw new Error(`unsafe path segment in ${path}`);
    }
  }
  return segments;
}
