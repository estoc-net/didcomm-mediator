import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket from "ws";

import { buildServer, type MediatorServer } from "../src/server.js";
import { loadOrCreateIdentity, type MediatorIdentity } from "../src/identity.js";
import {
  TEST_CONFIG,
  agent,
  memoryStore,
  packAnonymous,
  plaintext,
  type TestAgent,
} from "./helpers.js";

/**
 * The full live-delivery path over a real socket: grant + live mode over WS,
 * an anonymous forward over HTTP, and the delivery arriving as a push on the
 * open socket — the one flow app.inject cannot exercise.
 */

let server: MediatorServer;
let mediator: MediatorIdentity;
let alice: TestAgent;
let baseUrl: string;
let dataDir: string;

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "mediator-ts-ws-test-"));
  mediator = loadOrCreateIdentity(dataDir, TEST_CONFIG.publicUrl, () => {});
  alice = agent("alice-live");
  server = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: TEST_CONFIG,
  });
  const port = await server.listen();
  baseUrl = `127.0.0.1:${port}`;
});

afterAll(async () => {
  await server.close();
  rmSync(dataDir, { recursive: true, force: true });
});

function nextMessage(ws: WebSocket): Promise<string> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data) => resolve(data.toString()));
    ws.once("error", reject);
    setTimeout(() => reject(new Error("timed out waiting for a frame")), 5000);
  });
}

async function request(
  ws: WebSocket,
  sender: TestAgent,
  type: string,
  body: Record<string, unknown>
) {
  const packed = await sender.ctx.packEncrypted(
    plaintext(type, body, {
      from: sender.did,
      to: [mediator.did],
      return_route: "all",
    }),
    mediator.did
  );
  const waiting = nextMessage(ws);
  ws.send(packed);
  const { message } = await sender.ctx.unpack(await waiting);
  return message;
}

describe("live delivery over WebSocket", () => {
  it("pushes a forwarded message to the open socket", async () => {
    const ws = new WebSocket(`ws://${baseUrl}/`);
    await new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });

    const grant = await request(
      ws,
      alice,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );
    expect(grant.type).toBe(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-grant"
    );

    const status = await request(
      ws,
      alice,
      "https://didcomm.org/messagepickup/3.0/live-delivery-change",
      { live_delivery: true }
    );
    expect(status.type).toBe("https://didcomm.org/messagepickup/3.0/status");
    expect(status.body.live_delivery).toBe(true);

    // A stranger forwards to Alice over plain HTTP while her socket is open.
    const inner = { hello: "alice, live" };
    const forward = await packAnonymous(
      plaintext("https://didcomm.org/routing/2.0/forward", {
        next: alice.did,
      }, {
        attachments: [{ data: { json: inner } }],
      }),
      mediator.did
    );
    const pushWaiting = nextMessage(ws);
    const res = await fetch(`http://${baseUrl}/`, {
      method: "POST",
      headers: { "content-type": "application/didcomm-encrypted+json" },
      body: forward,
    });
    expect(res.status).toBe(202);

    const { message: push } = await alice.ctx.unpack(await pushWaiting);
    expect(push.type).toBe("https://didcomm.org/messagepickup/3.0/delivery");
    const attachments = push.attachments as {
      id: string;
      data: { base64: string };
    }[];
    expect(attachments).toHaveLength(1);
    expect(
      JSON.parse(
        Buffer.from(attachments[0].data.base64, "base64url").toString("utf8")
      )
    ).toEqual(inner);

    // The push is an offer, not a handoff: the message stays queued until
    // acknowledged, so a client that crashed mid-push loses nothing.
    const count = await request(
      ws,
      alice,
      "https://didcomm.org/messagepickup/3.0/status-request",
      {}
    );
    expect(count.body.message_count).toBe(1);

    await request(
      ws,
      alice,
      "https://didcomm.org/messagepickup/3.0/messages-received",
      { message_id_list: attachments.map((a) => a.id) }
    );

    ws.close();
  });
});
