import { randomUUID } from "node:crypto";
import { Message } from "didcomm-node";
import type { IMessage } from "didcomm-node";
import WebSocket from "ws";

import { DIDCommContext } from "../src/didcomm/didcomm.js";
import { resolveDIDCommDoc } from "../src/didcomm/did-resolver.js";
import { mintIdentity } from "../src/identity.js";

/**
 * Drive a full client flow against a *running* mediator — the deploy
 * verification tool. Exercises mediation grant, keylist binding, anonymous
 * forward, the pickup loop, and WebSocket live delivery (asserting binary
 * frames, the thing headless clients never catch).
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
  await fetch(`${base}/.well-known/did`)
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

const alice = mintIdentity("https://smoke-alice.test/didcomm");
const ctx = new DIDCommContext(alice.did, alice.didDoc, alice.secrets);

function plaintext(type: string, body: Record<string, unknown>): IMessage {
  return {
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    type,
    from: alice.did,
    to: [mediatorDid],
    created_time: Math.floor(Date.now() / 1000),
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
  // Anoncrypt with an attachment — how a stranger's mail arrives.
  const withAttachment = new Message({
    ...msg.as_value(),
    from: undefined,
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

function nextBinaryFrame(label: string): Promise<string> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data, isBinary) => {
      try {
        check(isBinary, `${label} arrived as a binary frame`);
      } catch (err) {
        reject(err);
        return;
      }
      resolve(data.toString());
    });
    setTimeout(() => reject(new Error(`FAILED: no frame for ${label}`)), 8000);
  });
}

const statusFrame = nextBinaryFrame("live-delivery-change status");
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

const pushFrame = nextBinaryFrame("live delivery push");
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
