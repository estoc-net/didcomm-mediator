/**
 * public-folder objects: the two object kinds and their CIDs.
 *
 * File object  = the bare bytes, named by a CIDv1 with the raw codec and
 *                sha-256. Dir object = dag-json bytes `{"entries":[…]}`,
 *                named by a CIDv1 with the dag-json codec; dag-json brings
 *                canonical encoding and a native link type.
 *
 * Copied lineage from @estoc/signed-dir (packages/signed-dir in the estoc
 * monorepo) — keep fixes in sync; switch to the npm package once published.
 */

import bs58 from "bs58";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import * as raw from "multiformats/codecs/raw";
import * as dagJson from "@ipld/dag-json";

/** One row of a directory node; `hash` is the entry's CID string. */
export interface DirEntry {
  name: string;
  type: "file" | "dir";
  hash: string;
  size: number;
}

export const RAW_MEDIA_TYPE = "application/vnd.ipld.raw";
export const DAG_JSON_MEDIA_TYPE = "application/vnd.ipld.dag-json";

/** CID string (raw codec, sha-256) naming these bare bytes. */
export async function fileCid(bytes: Uint8Array): Promise<string> {
  const digest = await sha256.digest(bytes);
  return CID.create(1, raw.code, digest).toString();
}

/** Does this CID name a directory node (dag-json) rather than file bytes? */
export function isDirCid(cid: string): boolean {
  return CID.parse(cid).code === dagJson.code;
}

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
 * Compare names as UTF-8 byte sequences — the sort order of directory
 * entries. (Plain JS string comparison is UTF-16 code-unit order.)
 */
export function compareNames(a: string, b: string): number {
  const encoder = new TextEncoder();
  const ab = encoder.encode(a);
  const bb = encoder.encode(b);
  const n = Math.min(ab.length, bb.length);
  for (let i = 0; i < n; i++) {
    const d = (ab[i] as number) - (bb[i] as number);
    if (d !== 0) return d;
  }
  return ab.length - bb.length;
}

function checkName(name: string): void {
  if (name === "" || name === "." || name === ".." || name.includes("/")) {
    throw new Error(`invalid entry name: ${JSON.stringify(name)}`);
  }
}

/**
 * Encode a directory node from its entries: sorted by name (UTF-8 byte
 * order), `hash` strings as dag-json links. The relay itself never builds
 * trees — this exists for tests and future tooling, and pins the encoding
 * the wild trees use.
 */
export async function encodeDirNode(
  entries: DirEntry[]
): Promise<{ cid: string; bytes: Uint8Array }> {
  const sorted = [...entries].sort((a, b) => compareNames(a.name, b.name));
  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i] as DirEntry;
    checkName(entry.name);
    if (i > 0 && (sorted[i - 1] as DirEntry).name === entry.name) {
      throw new Error(`duplicate entry name: ${JSON.stringify(entry.name)}`);
    }
  }
  const node = {
    entries: sorted.map((e) => ({
      name: e.name,
      type: e.type,
      hash: CID.parse(e.hash),
      size: e.size,
    })),
  };
  const bytes = dagJson.encode(node);
  const digest = await sha256.digest(bytes);
  const cid = CID.create(1, dagJson.code, digest).toString();
  return { cid, bytes };
}

/** Decode a directory node, checking shape. Integrity is bytesMatchCid's job. */
export function decodeDirNode(bytes: Uint8Array): DirEntry[] {
  let node: unknown;
  try {
    node = dagJson.decode(bytes);
  } catch {
    throw new Error("not a dag-json directory node");
  }
  const entries = (node as { entries?: unknown }).entries;
  if (!Array.isArray(entries)) {
    throw new Error("directory node has no entries array");
  }
  return entries.map((e: unknown): DirEntry => {
    const { name, type, hash, size } = (e ?? {}) as Record<string, unknown>;
    if (
      typeof name !== "string" ||
      (type !== "file" && type !== "dir") ||
      !(hash instanceof CID) ||
      typeof size !== "number"
    ) {
      throw new Error("malformed directory entry");
    }
    checkName(name);
    return { name, type, hash: hash.toString(), size };
  });
}

/** Split a `/`-separated relative path, rejecting anything unsafe. */
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
