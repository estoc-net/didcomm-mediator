import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import bs58 from "bs58";
import { Message } from "didcomm-node";
import type { IMessage } from "didcomm-node";
import WebSocket from "ws";

import { buildServer, type MediatorServer } from "../src/server.js";
import { loadOrCreateIdentity, type MediatorIdentity } from "../src/identity.js";
import { encodeLongForm } from "@estoc/did-peer";
import { resolveDIDCommDoc } from "../src/didcomm/did-resolver.js";
import type { Secret } from "@estoc/did-peer";
import { TEST_CONFIG, memoryStore } from "./helpers.js";

/**
 * Our didcomm-demo's wire behavior, message for message — the same DID
 * shapes (Multikey did:peer:4 long form; the mediator-facing DID has no
 * service), the same envelope choices (`forward: true` on everything,
 * `return_route: "all"` on every mediator request, live-delivery-change as
 * the first frame on a fresh WebSocket), the same pickup loop. What the
 * browser demo does, this file does over real HTTP and a real socket; if it
 * passes, the demo's only remaining failure modes are browser-side (CORS,
 * atob).
 */

const PORT = 18099;
const BASE = `http://127.0.0.1:${PORT}`;

let server: MediatorServer;
let mediator: MediatorIdentity;
let dataDir: string;

/** A demo agent's key pair as the demo builds them: Multikey verification methods. */
function demoKeys() {
  const ed = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  const x = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  const multibase = (prefix: number[], b64: string) =>
    `z${bs58.encode(Buffer.concat([Buffer.from(prefix), Buffer.from(b64, "base64url")]))}`;
  return {
    ed,
    x,
    edMultibase: multibase([0xed, 0x01], ed.x as string),
    xMultibase: multibase([0xec, 0x01], x.x as string),
  };
}

/** mintIdentity from the demo, verbatim shape: null serviceUri, no service. */
function demoDid(serviceUri: string | null) {
  const keys = demoKeys();
  const did = encodeLongForm({
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    verificationMethod: [
      { id: "#key-1", type: "Multikey", publicKeyMultibase: keys.edMultibase },
      { id: "#key-2", type: "Multikey", publicKeyMultibase: keys.xMultibase },
    ],
    authentication: ["#key-1"],
    capabilityDelegation: ["#key-1"],
    ...(serviceUri === null
      ? {}
      : {
          service: [
            {
              type: "DIDCommMessaging",
              id: "#service",
              serviceEndpoint: {
                uri: serviceUri,
                accept: ["didcomm/v2"],
              },
            },
          ],
        }),
    keyAgreement: ["#key-2"],
  });

  const secrets: Secret[] = [
    {
      id: `${did}#key-1`,
      type: "JsonWebKey2020",
      privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: keys.ed.x, d: keys.ed.d },
    },
    {
      id: `${did}#key-2`,
      type: "JsonWebKey2020",
      privateKeyJwk: { kty: "OKP", crv: "X25519", x: keys.x.x, d: keys.x.d },
    },
  ];
  return { did, secrets };
}

interface DemoAgent {
  didForMediator: { did: string; secrets: Secret[] };
  did: string | null;
  secrets: Secret[];
}

const didResolver = { resolve: resolveDIDCommDoc };

function secretsResolverFor(agent: DemoAgent) {
  const all = new Map(
    [...agent.didForMediator.secrets, ...agent.secrets].map((s) => [s.id, s])
  );
  return {
    get_secret: async (id: string) => all.get(id) ?? null,
    find_secrets: async (ids: string[]) => ids.filter((id) => all.has(id)),
  };
}

/** prepareMessage: uuid, epoch-seconds created_time, body defaulted, forward: true. */
async function demoPack(
  agent: DemoAgent,
  to: string,
  from: string,
  message: { type: string; body?: Record<string, unknown> }
): Promise<{ packed: string; endpoint: string }> {
  const msg = new Message({
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    from,
    to: [to],
    body: message.body ?? {},
    created_time: Math.floor(Date.now() / 1000),
    type: message.type,
    // The demo's packForMediator declares the return route on every request
    // to the mediator; messages to contacts carry no such header.
    ...(to === mediator.did ? { return_route: "all" } : {}),
  } as IMessage);

  const [packed, meta] = await msg.pack_encrypted(
    to,
    from,
    null,
    didResolver,
    secretsResolverFor(agent),
    { forward: true }
  );

  return {
    packed,
    // The demo falls back to the recipient's http endpoint when no forward
    // was wrapped (messages straight to the mediator).
    endpoint: meta.messaging_service?.service_endpoint ?? BASE,
  };
}

async function demoUnpack(agent: DemoAgent, packed: string): Promise<IMessage> {
  const [msg] = await Message.unpack(
    packed,
    didResolver,
    secretsResolverFor(agent),
    {}
  );
  return msg.as_value();
}

/** sendMessageAndExpectReply: POST, insist on ok, unpack the body. */
async function sendAndExpectReply(
  agent: DemoAgent,
  to: string,
  from: string,
  message: { type: string; body?: Record<string, unknown> }
): Promise<IMessage> {
  const { packed, endpoint } = await demoPack(agent, to, from, message);
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/didcomm-encrypted+json" },
    body: packed,
  });
  expect(response.ok).toBe(true);
  return demoUnpack(agent, await response.text());
}

/** establishMediation from the demo's worker, step for step. */
async function establishMediation(agent: DemoAgent): Promise<void> {
  const grant = await sendAndExpectReply(
    agent,
    mediator.did,
    agent.didForMediator.did,
    { type: "https://didcomm.org/coordinate-mediation/3.0/mediate-request" }
  );
  expect(grant.type).toBe(
    "https://didcomm.org/coordinate-mediation/3.0/mediate-grant"
  );
  const routingDid = (grant.body.routing_did as string[])[0];
  expect(routingDid).toBe(mediator.did);

  const publicIdentity = demoDid(routingDid);
  agent.did = publicIdentity.did;
  agent.secrets = publicIdentity.secrets;

  const updated = await sendAndExpectReply(
    agent,
    mediator.did,
    agent.didForMediator.did,
    {
      type: "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      body: { updates: [{ recipient_did: agent.did, action: "add" }] },
    }
  );
  expect(updated.type).toBe(
    "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response"
  );
  expect(updated.body.updated).toEqual([
    { recipient_did: agent.did, action: "add", result: "success" },
  ]);
}

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "mediator-ts-demo-test-"));
  mediator = loadOrCreateIdentity(dataDir, BASE, "peer2", () => {});
  server = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: { ...TEST_CONFIG, publicUrl: BASE, host: "127.0.0.1", port: PORT },
  });
  await server.listen();
});

afterAll(async () => {
  await server.close();
  rmSync(dataDir, { recursive: true, force: true });
});

describe("didcomm-demo wire behavior", () => {
  const alice: DemoAgent = {
    didForMediator: demoDid(null),
    did: null,
    secrets: [],
  };
  const bob: DemoAgent = {
    didForMediator: demoDid(null),
    did: null,
    secrets: [],
  };

  it("establishes mediation for both agents", async () => {
    await establishMediation(alice);
    await establishMediation(bob);
  });

  it("routes a message from Bob to Alice through the pickup loop", async () => {
    // Bob packs to Alice's public DID; its service endpoint is the mediator's
    // DID, so didcomm-rust wraps the forward itself and names the mediator's
    // HTTP endpoint — exactly what the demo's sendMessage does.
    const { packed, endpoint } = await demoPack(bob, alice.did as string, bob.did as string, {
      type: "https://didcomm.org/basicmessage/2.0/message",
      body: { content: "hello alice, via the ts mediator" },
    });
    expect(endpoint).toBe(BASE);

    const posted = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/didcomm-encrypted+json" },
      body: packed,
    });
    expect(posted.status).toBe(202);

    // Alice's pickup loop: status → delivery-request(limit=count) → ack.
    const status = await sendAndExpectReply(
      alice,
      mediator.did,
      alice.didForMediator.did,
      { type: "https://didcomm.org/messagepickup/3.0/status-request" }
    );
    expect(status.type).toBe("https://didcomm.org/messagepickup/3.0/status");
    expect(status.body.message_count).toBe(1);

    const delivery = await sendAndExpectReply(
      alice,
      mediator.did,
      alice.didForMediator.did,
      {
        type: "https://didcomm.org/messagepickup/3.0/delivery-request",
        body: { limit: status.body.message_count as number },
      }
    );
    expect(delivery.type).toBe("https://didcomm.org/messagepickup/3.0/delivery");
    const attachments = delivery.attachments as {
      id: string;
      data: { base64: string };
    }[];
    expect(attachments).toHaveLength(1);

    // The attachment is the inner envelope, still sealed for Alice.
    const inner = await demoUnpack(
      alice,
      Buffer.from(attachments[0].data.base64, "base64url").toString("utf8")
    );
    expect(inner.type).toBe("https://didcomm.org/basicmessage/2.0/message");
    expect(inner.body.content).toBe("hello alice, via the ts mediator");
    expect(inner.from).toBe(bob.did);

    const after = await sendAndExpectReply(
      alice,
      mediator.did,
      alice.didForMediator.did,
      {
        type: "https://didcomm.org/messagepickup/3.0/messages-received",
        body: { message_id_list: attachments.map((a) => a.id) },
      }
    );
    expect(after.body.message_count).toBe(0);
  });

  it("pushes live over the demo's WebSocket ritual", async () => {
    // connect(): find the ws service in the mediator's DID, dial it bare.
    const doc = await resolveDIDCommDoc(mediator.did);
    const wsService = doc?.service
      .map((s) => (typeof s.serviceEndpoint === "string" ? s.serviceEndpoint : s.serviceEndpoint.uri))
      .find((uri) => uri.startsWith("ws"));
    expect(wsService).toBe(`ws://127.0.0.1:${PORT}`);

    const ws = new WebSocket(wsService as string);
    await new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });

    // onopen: live-delivery-change is the first frame the socket ever sends.
    const { packed: live } = await demoPack(
      alice,
      mediator.did,
      alice.didForMediator.did,
      {
        type: "https://didcomm.org/messagepickup/3.0/live-delivery-change",
        body: { live_delivery: true },
      }
    );
    const statusFrame = new Promise<string>((resolve, reject) => {
      ws.once("message", (data, isBinary) => {
        // Text frames arrive as plain strings in every environment; the
        // demo accepts both, but text is what we promise to send.
        expect(isBinary).toBe(false);
        resolve(data.toString());
      });
      setTimeout(() => reject(new Error("no status frame")), 5000);
    });
    ws.send(live);
    const status = await demoUnpack(alice, await statusFrame);
    expect(status.type).toBe("https://didcomm.org/messagepickup/3.0/status");
    expect(status.body.live_delivery).toBe(true);

    // Bob writes while Alice's socket is open; the delivery must be pushed.
    const pushFrame = new Promise<string>((resolve, reject) => {
      ws.once("message", (data, isBinary) => {
        expect(isBinary).toBe(false);
        resolve(data.toString());
      });
      setTimeout(() => reject(new Error("no live delivery push")), 5000);
    });
    const { packed, endpoint } = await demoPack(bob, alice.did as string, bob.did as string, {
      type: "https://didcomm.org/basicmessage/2.0/message",
      body: { content: "live one" },
    });
    await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/didcomm-encrypted+json" },
      body: packed,
    });

    const push = await demoUnpack(alice, await pushFrame);
    expect(push.type).toBe("https://didcomm.org/messagepickup/3.0/delivery");
    const attachments = push.attachments as {
      id: string;
      data: { base64: string };
    }[];
    const inner = await demoUnpack(
      alice,
      Buffer.from(attachments[0].data.base64, "base64url").toString("utf8")
    );
    expect(inner.body.content).toBe("live one");

    // The demo acks over HTTP even when the delivery came over the socket.
    const after = await sendAndExpectReply(
      alice,
      mediator.did,
      alice.didForMediator.did,
      {
        type: "https://didcomm.org/messagepickup/3.0/messages-received",
        body: { message_id_list: attachments.map((a) => a.id) },
      }
    );
    expect(after.body.message_count).toBe(0);
    ws.close();
  });
});
