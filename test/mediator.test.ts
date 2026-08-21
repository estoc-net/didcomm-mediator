import { beforeAll, afterAll, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import type { IMessage } from "didcomm-node";

import { buildServer } from "../src/server.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import {
  TEST_CONFIG,
  agent,
  memoryStore,
  packAnonymous,
  plaintext,
  type TestAgent,
} from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";

let app: Hono;
let mediator: MediatorIdentity;
let alice: TestAgent;
let bob: TestAgent;

beforeAll(async () => {
  mediator = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
  alice = await agent("alice");
  bob = await agent("bob");
  app = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: TEST_CONFIG,
  }).app;
});

afterAll(() => {
});

/** Authcrypt `message` from `sender` to the mediator, POST it, unpack the reply. */
async function send(
  sender: TestAgent,
  type: string,
  body: Record<string, unknown>
): Promise<{ status: number; reply: IMessage | null }> {
  const packed = await sender.ctx.packEncrypted(
    plaintext(type, body, {
      from: sender.did,
      to: [mediator.did],
      return_route: "all",
    }),
    mediator.did
  );

  const res = await app.request("/", {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });

  if (res.status === 202) {
    return { status: res.status, reply: null };
  }

  const { message } = await sender.ctx.unpack(await res.text());
  return { status: res.status, reply: message };
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

    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
    });
    expect(res.status).toBe(202);
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

    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
    });
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
  });

  it("delivers to a registered account DID over any squatted binding", async () => {
    // Bob squats Carol's DID before she registers…
    const carol = await agent("carol");
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
    await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
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
      }, { from: alice.did, to: [mediator.did], id: "ping-1", return_route: "all" }),
      mediator.did
    );
    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
    });

    const { message } = await alice.ctx.unpack(await res.text());
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
    expect(disclosures).toHaveLength(6);
  });

  it("problem-reports an unsupported type to a proven sender", async () => {
    const { reply } = await send(alice, "https://didcomm.org/nonsense/1.0/x", {});
    expect(reply?.type).toBe(
      "https://didcomm.org/report-problem/2.0/problem-report"
    );
    expect(reply?.body.code).toBe("e.p.msg.unsupported");
  });

  it("rejects garbage with a 400", async () => {
    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: "not an envelope",
    });
    expect(res.status).toBe(400);
  });

});

describe("return-route extension", () => {
  it("drops the reply — but not the side effects — without return_route", async () => {
    const carol = await agent("carol");
    const packed = await carol.ctx.packEncrypted(
      plaintext(
        "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
        {},
        { from: carol.did, to: [mediator.did] }
      ),
      mediator.did
    );

    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
    });
    expect(res.status).toBe(202);

    // The grant still happened: a follow-up that does declare a return route
    // reads its own account state back.
    const { reply } = await send(
      carol,
      "https://didcomm.org/messagepickup/3.0/status-request",
      {}
    );
    expect(reply?.type).toBe("https://didcomm.org/messagepickup/3.0/status");
  });
});

describe("out-of-band/2.0", () => {
  const INVITATION = "https://didcomm.org/out-of-band/2.0/invitation";

  it("serves the invitation as a plaintext JWM at /invitation", async () => {
    const res = await app.request("/invitation");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain(
      "application/didcomm-plain+json"
    );

    const invitation = (await res.json()) as {
      type: string;
      id: string;
      from: string;
      body: { goal_code: string; accept: string[] };
    };
    expect(invitation.type).toBe(INVITATION);
    expect(invitation.from).toBe(mediator.did);
    expect(invitation.body.goal_code).toBe("request-mediate");
    expect(invitation.body.accept).toEqual(["didcomm/v2"]);
    expect(invitation.id.length).toBeGreaterThan(0);
  });

  it("publishes an invitation URL whose _oob decodes to the invitation", async () => {
    const { invitationUrl } = (await (
      await app.request("/")
    ).json()) as { invitationUrl: string };
    expect(invitationUrl.startsWith(TEST_CONFIG.publicUrl)).toBe(true);

    const oob = new URL(invitationUrl).searchParams.get("_oob");
    expect(oob).not.toBeNull();
    const decoded: unknown = JSON.parse(
      Buffer.from(oob as string, "base64url").toString("utf8")
    );
    expect(decoded).toEqual(await (await app.request("/invitation")).json());
  });

  it("is deterministic — the QR printed today still matches tomorrow", async () => {
    const [a, b] = await Promise.all([
      app.request("/invitation").then((r) => r.json()),
      app.request("/invitation").then((r) => r.json()),
    ]);
    expect(a).toEqual(b);
  });

  it("shows human-readable instructions when a browser opens the invitation URL", async () => {
    const res = await app.request("/?_oob=ignored", {
      headers: { accept: "text/html,application/xhtml+xml" },
    });
    expect(res.headers.get("content-type")).toContain("text/html");
    const page = await res.text();
    expect(page).toContain(mediator.did);
    expect(page).toContain("_oob=");
  });

  it("keeps GET / as JSON for non-browser probes", async () => {
    const res = await app.request("/");
    expect(res.headers.get("content-type")).toContain("application/json");
    const { did, invitationUrl } = (await res.json()) as {
      did: string;
      invitationUrl: string;
    };
    expect(did).toBe(mediator.did);
    expect(invitationUrl).toContain("_oob=");
  });
});
