import { describe, expect, it } from "vitest";
import type { IMessage } from "didcomm-node";

import { DIDCommContext } from "../src/didcomm/didcomm.js";
import {
  didWebFromUrl,
  identityFor,
  loadOrCreateSecrets,
  mintIdentity,
  type MediatorIdentity,
} from "../src/identity-core.js";
import { buildServer } from "../src/server.js";
import { longToShort } from "@estoc/did-peer";
import {
  TEST_CONFIG,
  agent,
  memoryStore,
  plaintext,
  type TestAgent,
} from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";

describe("did:web derivation", () => {
  it("names the host", () => {
    expect(didWebFromUrl("https://mediator.example.com")).toBe(
      "did:web:mediator.example.com"
    );
  });

  it("percent-encodes a port and colon-joins path segments", () => {
    expect(didWebFromUrl("https://mediator.example.com:8443/didcomm/v2")).toBe(
      "did:web:mediator.example.com%3A8443:didcomm:v2"
    );
  });

  it("refuses non-loopback http — no resolver would ever fetch it", () => {
    expect(() => didWebFromUrl("http://mediator.example.com")).toThrow(/https/);
  });

  it("allows loopback http — wrangler dev's world", () => {
    expect(didWebFromUrl("http://localhost:8787")).toBe(
      "did:web:localhost%3A8787"
    );
  });
});

describe("minted identities", () => {
  it.each(["peer2", "peer4", "web"] as const)(
    "%s: document id matches the DID, #key-1 agrees, #key-2 authenticates, services carry both transports",
    async (method) => {
      const identity = await mintIdentity(TEST_CONFIG.publicUrl, method);

      expect(identity.didDoc.id).toBe(identity.did);
      expect(identity.didDoc.keyAgreement).toEqual([`${identity.did}#key-1`]);
      expect(identity.didDoc.authentication).toEqual([`${identity.did}#key-2`]);

      const uris = identity.didDoc.service.map((s) =>
        typeof s.serviceEndpoint === "string"
          ? s.serviceEndpoint
          : s.serviceEndpoint.uri
      );
      expect(uris).toEqual(["https://mediator.test", "wss://mediator.test"]);
    }
  );

  it("peer4 mints the long form", async () => {
    const identity = await mintIdentity(TEST_CONFIG.publicUrl, "peer4");
    expect(identity.did).toMatch(/^did:peer:4zQm[1-9A-HJ-NP-Za-km-z]+:z/);
    expect(identity.webDidDoc).toBeNull();
  });

  it("web publishes a document with absolute references and no private key material", async () => {
    const identity = await mintIdentity(TEST_CONFIG.publicUrl, "web");
    expect(identity.did).toBe("did:web:mediator.test");

    const doc = identity.webDidDoc;
    expect(doc).not.toBeNull();
    expect(doc?.id).toBe(identity.did);

    const methods = doc?.verificationMethod as {
      id: string;
      controller: string;
      publicKeyJwk: Record<string, unknown>;
    }[];
    expect(methods.map((m) => m.id)).toEqual([
      "did:web:mediator.test#key-1",
      "did:web:mediator.test#key-2",
    ]);
    for (const method of methods) {
      expect(method.controller).toBe(identity.did);
      expect(method.publicKeyJwk).not.toHaveProperty("d");
    }
  });

  it("peer2 serves no did.json document", async () => {
    const identity = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
    expect(identity.webDidDoc).toBeNull();
  });
});

/** A mediator built around `identity`, and a client whose resolver pins it. */
async function harness(identity: MediatorIdentity) {
  const { app } = buildServer({
    identity,
    store: memoryStore(),
    config: TEST_CONFIG,
  });

  const alice: TestAgent = await agent("alice");
  // A did:web document cannot be decoded offline, so the test client pins the
  // mediator's document instead of fetching it — exactly what a deployed
  // client's resolver does over the network.
  const ctx = new DIDCommContext(
    alice.did,
    alice.identity.didDoc,
    alice.identity.secrets,
    { pinned: [identity.didDoc, ...identity.aliases.map((a) => a.didDoc)] }
  );

  const send = async (
    type: string,
    body: Record<string, unknown>,
    to: string = identity.did
  ): Promise<IMessage> => {
    const packed = await ctx.packEncrypted(
      plaintext(type, body, {
        from: alice.did,
        to: [to],
        return_route: "all",
      }),
      to
    );
    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: packed,
    });
    expect(res.status).toBe(200);
    const { message } = await ctx.unpack(await res.text());
    return message;
  };

  return { app, send };
}

const identityByMethod = {
  peer4: await mintIdentity(TEST_CONFIG.publicUrl, "peer4"),
  web: await mintIdentity(TEST_CONFIG.publicUrl, "web"),
};

describe.each(["peer4", "web"] as const)("a %s mediator", (method) => {
  const identity = identityByMethod[method];

  it("grants mediation and routes through its own DID", async () => {
    const { send } = await harness(identity);
    const reply = await send(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );
    expect(reply.type).toBe(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-grant"
    );
    expect(reply.body.routing_did).toEqual([identity.did]);
  });

  it("still refuses binding the mediator's own DID", async () => {
    const { send } = await harness(identity);
    await send("https://didcomm.org/coordinate-mediation/3.0/mediate-request", {});

    const updates = [{ recipient_did: identity.did, action: "add" }];
    if (method === "peer4") {
      // The short form hashes to the same document — squatting it would be
      // squatting the mediator under an alias.
      updates.push({ recipient_did: longToShort(identity.did), action: "add" });
    }

    const reply = await send(
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      { updates }
    );
    const updated = reply.body.updated as { result: string }[];
    expect(updated.map((u) => u.result)).toEqual(
      updates.map(() => "client_error")
    );
  });
});

// peer2 primary, did:web riding as an alias off the same keys.
const bothMethods = await mintIdentity(TEST_CONFIG.publicUrl, ["peer2", "web"]);

describe("simultaneous methods", () => {
  const identity = bothMethods;
  const webDid = identity.aliases[0]?.did;

  it("derives every name from the one stored key set", () => {
    expect(identity.did).toMatch(/^did:peer:2\./);
    expect(webDid).toBe("did:web:mediator.test");
    expect(identity.dids).toEqual([identity.did, webDid]);
    // One private key entry per name, so didcomm-rust finds it under either kid.
    expect(identity.secrets.map((s) => s.id)).toEqual([
      `${identity.did}#key-1`,
      `${identity.did}#key-2`,
      `${webDid}#key-1`,
      `${webDid}#key-2`,
    ]);
    expect(identity.webDidDoc?.id).toBe(webDid);
  });

  it("answers each name as that name", async () => {
    const { send } = await harness(identity);

    const viaPeer = await send(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );
    expect(viaPeer.from).toBe(identity.did);
    expect(viaPeer.body.routing_did).toEqual([identity.did]);

    const viaWeb = await send(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {},
      webDid
    );
    expect(viaWeb.from).toBe(webDid);
    expect(viaWeb.body.routing_did).toEqual([webDid]);
  });

  it("refuses binding any of its names", async () => {
    const { send } = await harness(identity);
    await send("https://didcomm.org/coordinate-mediation/3.0/mediate-request", {});

    const reply = await send(
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      {
        updates: identity.dids.map((did) => ({
          recipient_did: did,
          action: "add",
        })),
      }
    );
    const updated = reply.body.updated as { result: string }[];
    expect(updated.map((u) => u.result)).toEqual(["client_error", "client_error"]);
  });

  it("advertises the primary, lists every name, serves did.json", async () => {
    const { app } = await harness(identity);

    const probe = (await (await app.request("/")).json()) as {
      did: string;
      dids: string[];
    };
    expect(probe.did).toBe(identity.did);
    expect(probe.dids).toEqual(identity.dids);

    const doc = (await (
      await app.request("/.well-known/did.json")
    ).json()) as { id: string };
    expect(doc.id).toBe(webDid);
  });

  it("flipping the order flips the advertised DID — same names, same keys", async () => {
    // Minted as did:web this time, so the peer2 alias exercises re-derivation
    // from the stored secrets in earnest.
    const flipped = await mintIdentity(TEST_CONFIG.publicUrl, ["web", "peer2"]);
    expect(flipped.did).toBe("did:web:mediator.test");
    expect(flipped.aliases[0].did).toMatch(/^did:peer:2\./);

    const { send } = await harness(flipped);
    const viaAlias = await send(
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {},
      flipped.aliases[0].did
    );
    expect(viaAlias.from).toBe(flipped.aliases[0].did);
    expect(viaAlias.body.routing_did).toEqual([flipped.aliases[0].did]);
  });
});

describe("keys in the store", () => {
  it("mints once and every later load returns the same keys", async () => {
    const store = memoryStore();
    const minted = await loadOrCreateSecrets(store);
    const reloaded = await loadOrCreateSecrets(store);
    expect(reloaded).toEqual(minted);

    // Same keys, same names — a restart cannot rename the mediator.
    const first = identityFor(minted, TEST_CONFIG.publicUrl, ["peer2"]);
    const again = identityFor(reloaded, TEST_CONFIG.publicUrl, ["peer2"]);
    expect(again.did).toBe(first.did);
  });

  it("a lost race yields the winner's keys, not the loser's mint", async () => {
    const store = memoryStore();
    const winner = await store.initIdentity('[{"id":"#key-1"}]');
    const loser = await store.initIdentity('[{"id":"#other"}]');
    expect(winner).toBe('[{"id":"#key-1"}]');
    expect(loser).toBe('[{"id":"#key-1"}]');
  });

  it("one key set answers as a different did:web on every URL — the Workers story", async () => {
    const store = memoryStore();
    const secrets = await loadOrCreateSecrets(store);

    const workersDev = identityFor(secrets, "https://demo.example.workers.dev", ["web"]);
    const custom = identityFor(secrets, "https://mediator.example.com", ["web"]);
    expect(workersDev.did).toBe("did:web:demo.example.workers.dev");
    expect(custom.did).toBe("did:web:mediator.example.com");

    // Different names, same #key-1 — one mediator behind every door.
    const jwkOf = (identity: MediatorIdentity) =>
      (identity.webDidDoc?.verificationMethod as { publicKeyJwk: unknown }[])[0]
        .publicKeyJwk;
    expect(jwkOf(workersDev)).toEqual(jwkOf(custom));
  });
});

describe("did.json routes", () => {
  it("serves the did:web document at both derivation paths", async () => {
    const identity = await mintIdentity(TEST_CONFIG.publicUrl, "web");
    const { app } = await harness(identity);

    for (const path of ["/.well-known/did.json", "/did.json"]) {
      const res = await app.request(path);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("application/did+ld+json");
      const doc = (await res.json()) as { id: string };
      expect(doc.id).toBe(identity.did);
    }
  });

  it("does not exist for a peer-method identity", async () => {
    const { app } = await harness(await mintIdentity(TEST_CONFIG.publicUrl, "peer2"));
    expect((await app.request("/.well-known/did.json")).status).toBe(404);
    expect((await app.request("/did.json")).status).toBe(404);
  });
});
