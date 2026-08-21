import bs58 from "bs58";
import type { IMessage } from "didcomm-node";
import { base64urlToBytes, bytesToBase64url } from "@estoc/did-peer";

import { didOf, type DIDCommContext, type Unpacked } from "../didcomm/didcomm.js";
import { verifyCard, type RootCard } from "@estoc/signed-dir";
import {
  DAG_JSON_MEDIA_TYPE,
  RAW_MEDIA_TYPE,
  bytesMatchCid,
  decodeDirNode,
  isCid,
  isDirCid,
  multihashOf,
  segmentsOf,
  type DirEntry,
} from "../public-folder/objects.js";
import type { MediationStore } from "../store/types.js";
import type { HandlerContext, Reply } from "./types.js";
import { PROBLEM_REPORT } from "./problem-report.js";

/**
 * public-folder/1.0 — https://didcomm.org/public-folder/1.0 (relay role).
 *
 * The relay holds, per owner DID, one signed root card and the
 * content-addressed objects of the tree the card's `root` names. `query` is
 * the anonymous read (card + proof chain for a path); `publish` is the
 * owner's write (card in, missing CIDs out, `published` receipt when the
 * closure is complete). The relay never interprets tree contents — every
 * check here is hashing, signature verification, or size arithmetic.
 *
 * Publish policy is the relay-inside-mediator one line: a mediation
 * relationship grants publish rights, for the account's own DID or any
 * recipient DID bound to it.
 */

export const QUERY = "https://didcomm.org/public-folder/1.0/query";
export const ANSWER = "https://didcomm.org/public-folder/1.0/answer";
export const PUBLISH = "https://didcomm.org/public-folder/1.0/publish";
export const PUBLISH_RESULT =
  "https://didcomm.org/public-folder/1.0/publish-result";
export const PUBLISHED = "https://didcomm.org/public-folder/1.0/published";

/** Attachments up to this many bytes ride inline; larger ones go by link. */
const INLINE_ATTACHMENT_LIMIT = 256 * 1024;

/** Closure ceiling — a structural backstop, far above any sane folder. */
const MAX_PUBLICATION_OBJECTS = 10_000;

/** Missing-CID lists are paged so a huge first round stays one sane message. */
const MISSING_PAGE_LIMIT = 256;

function problem(code: string, comment: string, args?: unknown[]): Reply {
  return {
    type: PROBLEM_REPORT,
    body: { code, comment, ...(args !== undefined ? { args } : {}) },
  };
}

/**
 * The raw Ed25519 key a card's kid names, from the kid's own DID document —
 * the kid must be one of that document's authentication methods. Whether the
 * card's payload `did` matches the kid's DID is checked after verification.
 */
async function authenticationKey(
  ctx: DIDCommContext,
  kid: string
): Promise<Uint8Array | null> {
  const did = didOf(kid);
  if (did === null) {
    return null;
  }
  const doc = await ctx.resolve(did);
  if (doc === null || !doc.authentication.includes(kid)) {
    return null;
  }
  const method = doc.verificationMethod.find((m) => m.id === kid);
  if (method === undefined) {
    return null;
  }
  const jwk = method.publicKeyJwk as
    | { kty?: unknown; crv?: unknown; x?: unknown }
    | undefined;
  if (jwk?.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
    return base64urlToBytes(jwk.x);
  }
  // did:peer documents carry multibase keys: base58btc with an ed25519-pub
  // multicodec prefix (0xed 0x01).
  if (
    typeof method.publicKeyMultibase === "string" &&
    method.publicKeyMultibase.startsWith("z")
  ) {
    try {
      const decoded = bs58.decode(method.publicKeyMultibase.slice(1));
      if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
        return decoded.slice(2);
      }
    } catch {
      return null;
    }
  }
  return null;
}

type Walk =
  | { kind: "ok"; missing: string[]; closure: string[] }
  | { kind: "too-large"; total: number }
  | { kind: "malformed"; reason: string };

/**
 * Walk the tree from `root` through whatever directory nodes the store
 * already holds: every reachable CID joins the closure, every absent one
 * joins `missing` (an absent directory node also hides its subtree — later
 * rounds surface it). Size is enforced twice: the root node's declared total
 * before any content travels, and the actual stored bytes as they land, so
 * a tree lying about its sizes still cannot exceed the limit.
 */
async function walkClosure(
  root: string,
  store: MediationStore,
  maxBytes: number
): Promise<Walk> {
  const missing: string[] = [];
  const closure: string[] = [root];
  const seen = new Set<string>([root]);
  const dirs: string[] = [root];
  let storedBytes = 0;

  while (dirs.length > 0) {
    const cid = dirs.shift() as string;
    const bytes = await store.getObject(cid);
    if (bytes === null) {
      missing.push(cid);
      continue;
    }
    storedBytes += bytes.length;

    let entries: DirEntry[];
    try {
      entries = decodeDirNode(bytes);
    } catch (err) {
      return {
        kind: "malformed",
        reason: err instanceof Error ? err.message : String(err),
      };
    }

    if (cid === root) {
      const declared = entries.reduce((sum, entry) => sum + entry.size, 0);
      if (declared > maxBytes) {
        return { kind: "too-large", total: declared };
      }
    }

    const files: string[] = [];
    for (const entry of entries) {
      if ((entry.type === "dir") !== isDirCid(entry.hash)) {
        return {
          kind: "malformed",
          reason: `entry ${entry.name} links the wrong object kind for its type`,
        };
      }
      if (seen.has(entry.hash)) {
        continue;
      }
      seen.add(entry.hash);
      closure.push(entry.hash);
      if (closure.length > MAX_PUBLICATION_OBJECTS) {
        return {
          kind: "malformed",
          reason: `publication exceeds ${MAX_PUBLICATION_OBJECTS} objects`,
        };
      }
      (entry.type === "dir" ? dirs : files).push(entry.hash);
    }

    const present = await store.objectsPresent(files);
    for (const file of files) {
      const size = present.get(file);
      if (size === undefined) {
        missing.push(file);
      } else {
        storedBytes += size;
      }
    }
    if (storedBytes > maxBytes) {
      return { kind: "too-large", total: storedBytes };
    }
  }

  return { kind: "ok", missing, closure };
}

export async function publish(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  const { ctx, store, config, sender } = context;
  // An unauthenticated publish gets the same silence as any other anonymous
  // non-forward message — there is no proven sender to refuse.
  if (sender === null) {
    return null;
  }
  if (!(await store.isMediated(sender))) {
    return problem(
      "e.p.unauthorized",
      "Publishing requires a mediation relationship with this relay"
    );
  }

  const jws = incoming.message.body.card;
  if (typeof jws !== "string") {
    return problem("e.p.card.invalid", "publish requires body.card, a compact JWS");
  }

  let card: RootCard;
  let kid: string;
  try {
    ({ card, kid } = await verifyCard(jws, (k) => authenticationKey(ctx, k)));
  } catch (err) {
    return problem(
      "e.p.card.invalid",
      err instanceof Error ? err.message : String(err)
    );
  }
  if (didOf(kid) !== card.did) {
    return problem("e.p.card.invalid", "card.did does not match the signing kid");
  }
  if (card.root !== null && !(isCid(card.root) && isDirCid(card.root))) {
    return problem(
      "e.p.card.invalid",
      "card.root is not a dag-json directory CID"
    );
  }
  if (card.did !== sender && (await store.ownerOf(card.did)) !== sender) {
    return problem(
      "e.p.unauthorized",
      "The card's did is neither your account nor a recipient DID bound to it"
    );
  }

  // Objects ride along as attachments, id = CID. Anything whose bytes do not
  // hash to the id it claims is discarded, per spec — quietly, since a valid
  // publish round never depends on it.
  const attachments = Array.isArray(incoming.message.attachments)
    ? incoming.message.attachments
    : [];
  for (const attachment of attachments) {
    const id = (attachment as { id?: unknown }).id;
    const base64 = (attachment as { data?: { base64?: unknown } }).data?.base64;
    if (!isCid(id) || typeof base64 !== "string") {
      continue;
    }
    let bytes: Uint8Array;
    try {
      bytes = base64urlToBytes(base64);
    } catch {
      continue;
    }
    // Size limits are enforced by the closure walk below (declared total at
    // the root, actual bytes as they land) — a staged object that never joins
    // an accepted closure is reclaimed by the purge.
    if (await bytesMatchCid(id, bytes)) {
      await store.putObject(id, bytes);
    }
  }

  // A takedown card publishes "nothing": a null root, nothing can be missing,
  // so the exchange collapses straight to the receipt and the previous version
  // stops being served (its closure loses protection at once).
  if (card.root === null) {
    await store.putCard(card.did, jws, null, []);
    return { type: PUBLISHED, body: { did: card.did, card_id: card.id } };
  }

  const walk = await walkClosure(card.root, store, config.maxPublicationBytes);
  if (walk.kind === "too-large") {
    return problem(
      "e.p.publish.too-large",
      `Publication is {1} bytes; limit is {2}`,
      [walk.total, config.maxPublicationBytes]
    );
  }
  if (walk.kind === "malformed") {
    return problem("e.p.publish.refused", walk.reason);
  }
  if (walk.missing.length > 0) {
    return {
      type: PUBLISH_RESULT,
      body: { missing: walk.missing.slice(0, MISSING_PAGE_LIMIT) },
    };
  }

  await store.putCard(card.did, jws, card.root, walk.closure);
  // No retain_until: this relay never collects a live publication, which the
  // spec spells as omitting the field. (Unreferenced objects are the only
  // thing purged, and only after the staging grace period.)
  return { type: PUBLISHED, body: { did: card.did, card_id: card.id } };
}

function toAttachment(
  publicUrl: string
): (object: { cid: string; bytes: Uint8Array }) => NonNullable<IMessage["attachments"]>[number] {
  return ({ cid, bytes }) => ({
    id: cid,
    media_type: isDirCid(cid) ? DAG_JSON_MEDIA_TYPE : RAW_MEDIA_TYPE,
    data:
      bytes.length <= INLINE_ATTACHMENT_LIMIT
        ? { base64: bytesToBase64url(bytes) }
        : {
            links: [new URL(`/objects/${cid}`, publicUrl).href],
            hash: multihashOf(cid),
          },
  });
}

export async function query(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  const { store, publicUrl } = context;
  const body = incoming.message.body;
  const did = body.did;
  if (typeof did !== "string") {
    return problem("e.p.msg", "query requires body.did");
  }

  const stored = await store.getCard(did);
  if (stored === null) {
    return problem("e.p.did.unknown", `This relay holds no card for ${did}`);
  }

  // A takedown card answers every query, whatever the path: the owner's
  // signed "nothing is published" outranks an unsigned error. card_only is
  // the HEAD of the protocol — the card and nothing else.
  if (stored.root === null || body.card_only === true) {
    return { type: ANSWER, body: { card: stored.card } };
  }

  const chain: { cid: string; bytes: Uint8Array }[] = [];
  const rootBytes = await store.getObject(stored.root);
  if (rootBytes === null) {
    return problem("e.p.me.res.storage", "The published root is not on hand");
  }
  chain.push({ cid: stored.root, bytes: rootBytes });

  if (typeof body.path === "string" && body.path !== "") {
    let segments: string[];
    try {
      segments = segmentsOf(body.path);
    } catch {
      return problem("e.p.path.not-found", `No such path: ${body.path}`);
    }

    let entries = decodeDirNode(rootBytes);
    for (let i = 0; i < segments.length; i++) {
      const entry = entries.find((e) => e.name === segments[i]);
      // A file in the middle of the path is as absent as a missing name.
      if (entry === undefined || (i < segments.length - 1 && entry.type !== "dir")) {
        return problem("e.p.path.not-found", `No such path: ${body.path}`);
      }
      const bytes = await store.getObject(entry.hash);
      if (bytes === null) {
        return problem("e.p.me.res.storage", `Object ${entry.hash} is not on hand`);
      }
      chain.push({ cid: entry.hash, bytes });
      if (i < segments.length - 1) {
        entries = decodeDirNode(bytes);
      }
    }
  }

  return {
    type: ANSWER,
    body: { card: stored.card },
    attachments: chain.map(toAttachment(publicUrl)),
  };
}
