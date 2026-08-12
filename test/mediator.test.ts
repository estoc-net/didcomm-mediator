import { beforeAll, afterAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { IMessage } from "didcomm-node";

import { buildServer } from "../src/server.js";
import { loadOrCreateIdentity, type MediatorIdentity } from "../src/identity.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TEST_CONFIG,
  agent,
  memoryStore,
  packAnonymous,
  plaintext,
  type TestAgent,
} from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";

let app: FastifyInstance;
let mediator: MediatorIdentity;
let alice: TestAgent;
let bob: TestAgent;
let dataDir: string;

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "mediator-ts-test-"));
  mediator = loadOrCreateIdentity(dataDir, TEST_CONFIG.publicUrl, () => {});
  alice = agent("alice");
  bob = agent("bob");
  app = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: TEST_CONFIG,
    logger: false,
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  rmSync(dataDir, { recursive: true, force: true });
});

/** Authcrypt `message` from `sender` to the mediator, POST it, unpack the reply. */
async function send(
  sender: TestAgent,
  type: string,
  body: Record<string, unknown>
): Promise<{ status: number; reply: IMessage | null }> {
  const packed = await sender.ctx.packEncrypted(
    plaintext(type, body, { from: sender.did, to: [mediator.did] }),
    mediator.did
  );

  const res = await app.inject({
    method: "POST",
    url: "/",
    headers: { "content-type": ENCRYPTED },
    payload: packed,
  });

  if (res.statusCode === 202) {
    return { status: res.statusCode, reply: null };
  }

  const { message } = await sender.ctx.unpack(res.body);
  return { status: res.statusCode, reply: message };
}

describe("coordinate-mediation/3.0", () => {
  it("grants mediation and answers with the mediator as routing DID", async () => {
    const { status, reply } = await send(
      alice,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );

    expect(status).toBe(200);
    expect(reply?.type).toBe(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-grant"
    );
    expect(reply?.body.routing_did).toEqual([mediator.did]);
  });

  it("binds recipient DIDs, exclusively and first-come", async () => {
    await send(
      bob,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );

    const first = await send(
      alice,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      { updates: [{ recipient_did: "did:example:alias-1", action: "add" }] }
    );
    expect(first.reply?.body.updated).toEqual([
      { recipient_did: "did:example:alias-1", action: "add", result: "success" },
    ]);

    const stolen = await send(
      bob,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      { updates: [{ recipient_did: "did:example:alias-1", action: "add" }] }
    );
    expect(stolen.reply?.body.updated).toEqual([
      {
        recipient_did: "did:example:alias-1",
        action: "add",
        result: "client_error",
      },
    ]);
  });

  it("refuses squatting on the mediator or on a registered account", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      {
        updates: [
          { recipient_did: mediator.did, action: "add" },
          { recipient_did: bob.did, action: "add" },
          { recipient_did: "not-a-did", action: "add" },
        ],
      }
    );

    const updated = reply?.body.updated as { result: string }[];
    expect(updated.map((u) => u.result)).toEqual([
      "client_error",
      "client_error",
      "client_error",
    ]);
  });

  it("pages the recipient list", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-query",
      { paginate: { limit: 10, offset: 0 } }
    );

    expect(reply?.type).toBe(
      "https://didcomm.org/coordinate-mediation/3.0/recipient"
    );
    expect(reply?.body.dids).toEqual([
      { recipient_did: "did:example:alias-1" },
    ]);
    expect(reply?.body.pagination).toEqual({
      count: 1,
      offset: 0,
      remaining: 0,
    });
  });
});

describe("routing/2.0 + messagepickup/3.0", () => {
  const innerMessage = { fake: "packed envelope for alice" };

  it("accepts an anonymous forward for a bound recipient", async () => {
    const packed = await packAnonymous(
      plaintext("https://didcomm.org/routing/2.0/forward", {
        next: "did:example:alias-1",
      }, {
        attachments: [{ data: { json: innerMessage } }],
      }),
      mediator.did
    );

    const res = await app.inject({
      method: "POST",
      url: "/",
      headers: { "content-type": ENCRYPTED },
      payload: packed,
    });
    expect(res.statusCode).toBe(202);
  });

  it("counts the waiting message", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/messagepickup/3.0/status-request",
      {}
    );

    expect(reply?.type).toBe("https://didcomm.org/messagepickup/3.0/status");
    expect(reply?.body.message_count).toBe(1);
  });

  it("delivers it, base64url-encoded, and threads the reply", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/messagepickup/3.0/delivery-request",
      { limit: 10 }
    );

    expect(reply?.type).toBe("https://didcomm.org/messagepickup/3.0/delivery");
    const attachments = reply?.attachments as {
      id: string;
      data: { base64: string };
    }[];
    expect(attachments).toHaveLength(1);
    const decoded = Buffer.from(attachments[0].data.base64, "base64url").toString(
      "utf8"
    );
    expect(JSON.parse(decoded)).toEqual(innerMessage);
  });

  it("deletes acknowledged messages", async () => {
    const delivery = await send(
      alice,
      "https://didcomm.org/messagepickup/3.0/delivery-request",
      { limit: 10 }
    );
    const attachments = delivery.reply?.attachments as { id: string }[];

    const { reply } = await send(
      alice,
      "https://didcomm.org/messagepickup/3.0/messages-received",
      { message_id_list: attachments.map((a) => a.id) }
    );

    expect(reply?.type).toBe("https://didcomm.org/messagepickup/3.0/status");
    expect(reply?.body.message_count).toBe(0);
  });

  it("drops a forward for an unknown recipient without an answer", async () => {
    const packed = await packAnonymous(
      plaintext("https://didcomm.org/routing/2.0/forward", {
        next: "did:example:nobody",
      }, {
        attachments: [{ data: { json: { x: 1 } } }],
      }),
      mediator.did
    );

    const res = await app.inject({
      method: "POST",
      url: "/",
      headers: { "content-type": ENCRYPTED },
      payload: packed,
    });
    expect(res.statusCode).toBe(202);
    expect(res.body).toBe("");
  });

  it("delivers to a registered account DID over any squatted binding", async () => {
    // Bob squats Carol's DID before she registers…
    const carol = agent("carol");
    await send(
      bob,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      { updates: [{ recipient_did: carol.did, action: "add" }] }
    );

    // …then Carol registers herself, which must win.
    await send(
      carol,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );

    const packed = await packAnonymous(
      plaintext("https://didcomm.org/routing/2.0/forward", {
        next: carol.did,
      }, {
        attachments: [{ data: { json: { for: "carol" } } }],
      }),
      mediator.did
    );
    await app.inject({
      method: "POST",
      url: "/",
      headers: { "content-type": ENCRYPTED },
      payload: packed,
    });

    const carolStatus = await send(
      carol,
      "https://didcomm.org/messagepickup/3.0/status-request",
      {}
    );
    expect(carolStatus.reply?.body.message_count).toBe(1);

    const bobStatus = await send(
      bob,
      "https://didcomm.org/messagepickup/3.0/status-request",
      {}
    );
    expect(bobStatus.reply?.body.message_count).toBe(0);
  });

  it("refuses live delivery over plain HTTP with the spec's problem code", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/messagepickup/3.0/live-delivery-change",
      { live_delivery: true }
    );

    expect(reply?.type).toBe(
      "https://didcomm.org/report-problem/2.0/problem-report"
    );
    expect(reply?.body.code).toBe("e.m.live-mode-not-supported");
  });
});

describe("supporting protocols", () => {
  it("answers trust-ping on the ping's thread", async () => {
    const packed = await alice.ctx.packEncrypted(
      plaintext("https://didcomm.org/trust-ping/2.0/ping", {
        response_requested: true,
      }, { from: alice.did, to: [mediator.did], id: "ping-1" }),
      mediator.did
    );
    const res = await app.inject({
      method: "POST",
      url: "/",
      headers: { "content-type": ENCRYPTED },
      payload: packed,
    });

    const { message } = await alice.ctx.unpack(res.body);
    expect(message.type).toBe("https://didcomm.org/trust-ping/2.0/ping-response");
    expect(message.thid).toBe("ping-1");
  });

  it("discloses its protocols", async () => {
    const { reply } = await send(
      alice,
      "https://didcomm.org/discover-features/2.0/queries",
      { queries: [{ "feature-type": "protocol", match: "https://didcomm.org/*" }] }
    );

    const disclosures = reply?.body.disclosures as { id: string }[];
    expect(disclosures.map((d) => d.id)).toContain(
      "https://didcomm.org/coordinate-mediation/3.0"
    );
    expect(disclosures).toHaveLength(5);
  });

  it("problem-reports an unsupported type to a proven sender", async () => {
    const { reply } = await send(alice, "https://didcomm.org/nonsense/1.0/x", {});
    expect(reply?.type).toBe(
      "https://didcomm.org/report-problem/2.0/problem-report"
    );
    expect(reply?.body.code).toBe("e.p.msg.unsupported");
  });

  it("rejects garbage with a 400", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/",
      headers: { "content-type": ENCRYPTED },
      payload: "not an envelope",
    });
    expect(res.statusCode).toBe(400);
  });

  it("publishes its DID", async () => {
    const res = await app.inject({ method: "GET", url: "/.well-known/did" });
    expect(res.json().did).toBe(mediator.did);
  });
});
