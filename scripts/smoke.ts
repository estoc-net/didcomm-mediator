import { randomUUID } from "node:crypto";
import { Message } from "didcomm-node";
import type { IMessage } from "didcomm-node";
import WebSocket from "ws";

import { DIDCommContext } from "../src/didcomm/didcomm.js";
import { resolveDIDCommDoc } from "../src/didcomm/did-resolver.js";
import { mintIdentity } from "../src/identity-core.js";
import { createCard, type RootCard } from "@estoc/signed-dir";
import {
  encodeDirNode,
  fileCid,
  type DirEntry,
} from "../src/public-folder/objects.js";

/**
 * Drive a full client flow against a *running* mediator — the deploy
 * verification tool. Exercises mediation grant, keylist binding, anonymous
 * forward, the pickup loop, WebSocket live delivery (asserting text frames,
 * the thing headless clients never catch), and the public-folder relay:
 * publish rounds, anonymous query, HTTP object/card reads, takedown.
 *
 *   npm run smoke -- http://127.0.0.1:8787
 */

const base = process.argv[2];
if (base === undefined || !base.startsWith("http")) {
  console.error("usage: npm run smoke -- <mediator-url>");
  process.exit(1);
}

const ENCRYPTED = "application/didcomm-encrypted+json";

function check(condition: boolean, label: string): void {
  if (!condition) {
    throw new Error(`FAILED: ${label}`);
  }
  console.log(`ok: ${label}`);
}

/** didcomm-rust re-serializes JSON with sorted keys, so compare unordered. */
function sameJson(a: unknown, b: unknown): boolean {
  const canonical = (value: unknown): string =>
    JSON.stringify(value, (_key, v: unknown) =>
      v !== null && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(Object.entries(v).sort(([x], [y]) => (x < y ? -1 : 1)))
        : v
    );
  return canonical(a) === canonical(b);
}

const { did: mediatorDid, invitationUrl } = (await (
  await fetch(base)
).json()) as { did: string; invitationUrl: string };
console.log(`mediator: ${mediatorDid}`);

{
  const res = await fetch(`${base}/invitation`);
  const invitation = (await res.json()) as { type: string; from: string };
  check(
    res.ok &&
      invitation.type === "https://didcomm.org/out-of-band/2.0/invitation" &&
      invitation.from === mediatorDid,
    "OOB invitation served at /invitation"
  );

  const oob = new URL(invitationUrl).searchParams.get("_oob");
  check(
    oob !== null &&
      sameJson(JSON.parse(Buffer.from(oob, "base64url").toString("utf8")), invitation),
    "invitation URL _oob decodes to the same invitation"
  );
}

const alice = await mintIdentity("https://smoke-alice.test/didcomm");
const ctx = new DIDCommContext(alice.did, alice.didDoc, alice.secrets);

function plaintext(type: string, body: Record<string, unknown>): IMessage {
  return {
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    type,
    from: alice.did,
    to: [mediatorDid],
    created_time: Math.floor(Date.now() / 1000),
    // messagepickup 3.0: every request must declare the return route.
    return_route: "all",
    body,
  };
}

async function send(
  type: string,
  body: Record<string, unknown>
): Promise<IMessage> {
  const packed = await ctx.packEncrypted(plaintext(type, body), mediatorDid);
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  check(res.ok, `POST ${type.split("/").pop()} → ${res.status}`);
  const { message } = await ctx.unpack(await res.text());
  return message;
}

async function forwardAnonymously(next: string, inner: unknown): Promise<number> {
  const msg = new Message(
    plaintext("https://didcomm.org/routing/2.0/forward", { next })
  );
  // Anoncrypt with an attachment — how a stranger's mail arrives. A forward
  // is one-way, so it carries no return_route.
  const withAttachment = new Message({
    ...msg.as_value(),
    from: undefined,
    return_route: undefined,
    attachments: [{ id: randomUUID(), data: { json: inner } }],
  } as IMessage);
  const [packed] = await withAttachment.pack_encrypted(
    mediatorDid,
    null,
    null,
    { resolve: resolveDIDCommDoc },
    { get_secret: async () => null, find_secrets: async () => [] },
    { forward: false }
  );
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  return res.status;
}

// --- Mediation + pickup loop over HTTP ---------------------------------

const grant = await send(
  "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
  {}
);
check(
  grant.type === "https://didcomm.org/coordinate-mediation/3.0/mediate-grant",
  "mediation granted"
);

const alias = `did:example:smoke-${randomUUID().slice(0, 8)}`;
const updated = await send(
  "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
  { updates: [{ recipient_did: alias, action: "add" }] }
);
check(
  (updated.body.updated as { result: string }[])[0].result === "success",
  "recipient bound"
);

const inner = { smoke: "hello over http", at: Date.now() };
check((await forwardAnonymously(alias, inner)) === 202, "anonymous forward accepted");

const status = await send(
  "https://didcomm.org/messagepickup/3.0/status-request",
  {}
);
check(status.body.message_count === 1, "one message waiting");

const delivery = await send(
  "https://didcomm.org/messagepickup/3.0/delivery-request",
  { limit: 10 }
);
const attachments = delivery.attachments as { id: string; data: { base64: string } }[];
check(
  delivery.type === "https://didcomm.org/messagepickup/3.0/delivery" &&
    sameJson(
      JSON.parse(Buffer.from(attachments[0].data.base64, "base64url").toString("utf8")),
      inner
    ),
  "delivery carries the forwarded message, base64url"
);

const afterAck = await send(
  "https://didcomm.org/messagepickup/3.0/messages-received",
  { message_id_list: attachments.map((a) => a.id) }
);
check(afterAck.body.message_count === 0, "acknowledged messages deleted");

// --- Live delivery over WebSocket --------------------------------------

const wsUrl = base.replace(/^http/, "ws");
const ws = new WebSocket(wsUrl);
await new Promise<void>((resolve, reject) => {
  ws.once("open", () => resolve());
  ws.once("error", reject);
});

function nextTextFrame(label: string): Promise<string> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data, isBinary) => {
      try {
        check(!isBinary, `${label} arrived as a text frame`);
      } catch (err) {
        reject(err);
        return;
      }
      resolve(data.toString());
    });
    setTimeout(() => reject(new Error(`FAILED: no frame for ${label}`)), 8000);
  });
}

const statusFrame = nextTextFrame("live-delivery-change status");
ws.send(
  await ctx.packEncrypted(
    plaintext("https://didcomm.org/messagepickup/3.0/live-delivery-change", {
      live_delivery: true,
    }),
    mediatorDid
  )
);
const liveStatus = (await ctx.unpack(await statusFrame)).message;
check(liveStatus.body.live_delivery === true, "live delivery enabled");

const pushFrame = nextTextFrame("live delivery push");
const liveInner = { smoke: "hello live", at: Date.now() };
check(
  (await forwardAnonymously(alias, liveInner)) === 202,
  "anonymous forward while socket open"
);
const push = (await ctx.unpack(await pushFrame)).message;
const pushAttachments = push.attachments as { id: string; data: { base64: string } }[];
check(
  push.type === "https://didcomm.org/messagepickup/3.0/delivery" &&
    sameJson(
      JSON.parse(
        Buffer.from(pushAttachments[0].data.base64, "base64url").toString("utf8")
      ),
      liveInner
    ),
  "push carries the live message"
);

const afterLiveAck = await send(
  "https://didcomm.org/messagepickup/3.0/messages-received",
  { message_id_list: pushAttachments.map((a) => a.id) }
);
check(afterLiveAck.body.message_count === 0, "live message acknowledged over http");
ws.close();

// --- public-folder: publish rounds, anonymous query, HTTP reads ---------

const PF = "https://didcomm.org/public-folder/1.0";

const fileBytes = new TextEncoder().encode(`{"smoke":true,"at":${Date.now()}}`);
const leafCid = await fileCid(fileBytes);
const dirEntries: DirEntry[] = [
  { name: "profile.json", type: "file", hash: leafCid, size: fileBytes.length },
];
const { cid: rootCid, bytes: rootBytes } = await encodeDirNode(dirEntries);

const edSecret = alice.secrets.find(
  (s) => s.id.startsWith(alice.did) && s.privateKeyJwk?.crv === "Ed25519"
);
if (edSecret?.privateKeyJwk === undefined) {
  throw new Error("FAILED: smoke identity has no Ed25519 secret");
}
const signer = {
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
      "jwk",
      edSecret.privateKeyJwk as JsonWebKey,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    return new Uint8Array(
      await crypto.subtle.sign("Ed25519", key, data as Uint8Array<ArrayBuffer>)
    );
  },
};
const card: RootCard = {
  did: alice.did,
  id: randomUUID(),
  expires: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(),
  root: rootCid,
};
const cardJws = await createCard(card, signer, edSecret.id);

async function publishRound(
  attachments?: { id: string; data: { base64: string } }[]
): Promise<IMessage> {
  const packed = await ctx.packEncrypted(
    {
      ...plaintext(`${PF}/publish`, { card: cardJws }),
      ...(attachments !== undefined ? { attachments } : {}),
    },
    mediatorDid
  );
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  check(res.ok, `POST publish → ${res.status}`);
  return (await ctx.unpack(await res.text())).message;
}

const round1 = await publishRound();
check(
  round1.type === `${PF}/publish-result` &&
    sameJson(round1.body.missing, [rootCid]),
  "publish round 1: root reported missing"
);

const receipt = await publishRound([
  { id: rootCid, data: { base64: Buffer.from(rootBytes).toString("base64url") } },
  { id: leafCid, data: { base64: Buffer.from(fileBytes).toString("base64url") } },
]);
check(
  receipt.type === `${PF}/published` &&
    receipt.body.did === alice.did &&
    receipt.body.card_id === card.id,
  "publish complete: published receipt echoes did and card_id"
);

// An anonymous reader: fresh DID, anoncrypt query, answer sealed to it.
const reader = await mintIdentity("https://smoke-reader.test/didcomm");
const readerCtx = new DIDCommContext(reader.did, reader.didDoc, reader.secrets);
{
  const query = new Message({
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    type: `${PF}/query`,
    from: reader.did,
    to: [mediatorDid],
    created_time: Math.floor(Date.now() / 1000),
    return_route: "all",
    body: { did: alice.did, path: "profile.json" },
  } as IMessage);
  const [packed] = await query.pack_encrypted(
    mediatorDid,
    null,
    null,
    { resolve: resolveDIDCommDoc },
    { get_secret: async () => null, find_secrets: async () => [] },
    { forward: false }
  );
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  check(res.ok, `anonymous query → ${res.status}`);
  const answer = (await readerCtx.unpack(await res.text())).message;
  const chain = answer.attachments as { id: string; data: { base64: string } }[];
  check(
    answer.type === `${PF}/answer` &&
      answer.body.card === cardJws &&
      chain.length === 2 &&
      chain[0].id === rootCid &&
      chain[1].id === leafCid &&
      Buffer.from(chain[1].data.base64, "base64url").equals(Buffer.from(fileBytes)),
    "answer carries the card and the verified proof chain"
  );
}

{
  const res = await fetch(`${base}/objects/${leafCid}`);
  check(
    res.ok &&
      res.headers.get("content-type") === "application/vnd.ipld.raw" &&
      Buffer.from(await res.arrayBuffer()).equals(Buffer.from(fileBytes)),
    "GET /objects/<cid> serves the raw bytes"
  );
  const cardRes = await fetch(`${base}/card/${encodeURIComponent(alice.did)}`);
  check(
    cardRes.ok &&
      cardRes.headers.get("content-type") === "application/jose" &&
      (await cardRes.text()) === cardJws,
    "GET /card/<did> serves the compact JWS"
  );
}

// Takedown last — also keeps smoke runs from accreting objects on the
// mediator: the card-only closure frees them for the purge.
{
  const takedown: RootCard = {
    did: alice.did,
    id: randomUUID(),
    expires: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
    root: null,
  };
  const takedownJws = await createCard(takedown, signer, edSecret.id);
  const packed = await ctx.packEncrypted(
    plaintext(`${PF}/publish`, { card: takedownJws }),
    mediatorDid
  );
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  const done = (await ctx.unpack(await res.text())).message;
  check(done.type === `${PF}/published`, "takedown card published immediately");

  const gone = await send(`${PF}/query`, { did: alice.did, path: "profile.json" });
  check(
    gone.type === `${PF}/answer` &&
      gone.body.card === takedownJws &&
      gone.attachments === undefined,
    "queries after takedown answer with the signed card and nothing else"
  );
}

// --- Edges --------------------------------------------------------------

const problem = await send("https://didcomm.org/nonsense/1.0/x", {});
check(
  problem.type === "https://didcomm.org/report-problem/2.0/problem-report",
  "unsupported type answered with problem-report"
);

const garbage = await fetch(base, {
  method: "POST",
  headers: { "content-type": ENCRYPTED },
  body: "not an envelope",
});
check(garbage.status === 400, "garbage refused with 400");

console.log("\nsmoke: all green");
