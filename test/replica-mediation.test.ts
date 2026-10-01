import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import type { IMessage } from "@estoc/didcomm-node";
import { CompactSign, importJWK } from "jose";

import type { MediatorConfig } from "../src/config.js";
import type { DIDCommContext } from "../src/didcomm/didcomm.js";
import { buildServer } from "../src/server.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import type { SqliteStore } from "../src/store/sqlite.js";
import {
  ENCRYPTED,
  TEST_CONFIG,
  agent,
  memoryStore,
  packAnonymous,
  peer4Agent,
  plaintext,
  signedBy,
  type Peer4Agent,
} from "./helpers.js";

const PROTOCOL = "https://estoc.dev/replica-mediation/1.0";
const REGISTER = `${PROTOCOL}/register`;
const REGISTERED = `${PROTOCOL}/registered`;
const LIST = `${PROTOCOL}/list`;
const REPLICAS = `${PROTOCOL}/replicas`;
const PROBLEM = "https://didcomm.org/report-problem/2.0/problem-report";
const MEDIATE_REQUEST = "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
const MEDIATE_GRANT = "https://didcomm.org/coordinate-mediation/3.0/mediate-grant";
const MEDIATE_DENY = "https://didcomm.org/coordinate-mediation/3.0/mediate-deny";
const RECIPIENT_UPDATE = "https://didcomm.org/coordinate-mediation/3.0/recipient-update";

const problem = (suffix: string) => `e.estoc.replica-mediation.${suffix}`;

let app: Hono;
let store: SqliteStore;
let mediator: MediatorIdentity;
let account: Peer4Agent;
let mediationId: string;

function uuidv7(): string {
  const hex = randomUUID().replaceAll("-", "");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20)}`;
}

function serve(config: Partial<MediatorConfig> = {}): Hono {
  return buildServer({ identity: mediator, store, config: { ...TEST_CONFIG, ...config } }).app;
}

beforeEach(async () => {
  mediator = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
  store = memoryStore();
  app = serve();
  account = await peer4Agent(null);
  mediationId = uuidv7();
});

interface Speaker {
  did: string;
  ctx: DIDCommContext;
}

const firstContact = (who: Peer4Agent): Speaker => ({ did: who.longForm, ctx: who.ctx });
const known = (who: Peer4Agent): Speaker => ({ did: who.did, ctx: who.shortCtx });

async function send(
  speaker: Speaker,
  type: string,
  body: Record<string, unknown>,
  overrides: Partial<IMessage> = {},
  to: Hono = app
): Promise<IMessage | null> {
  const packed = await speaker.ctx.packEncrypted(
    plaintext(type, body, {
      from: speaker.did,
      to: [mediator.did],
      return_route: "all",
      ...overrides,
    }),
    mediator.did
  );
  const res = await to.request("/", {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  if (res.status !== 200) {
    return null;
  }
  return (await speaker.ctx.unpack(await res.text())).message;
}

interface Enrollment {
  replica: Peer4Agent;
  replicaId: string;
  payload: Record<string, string>;
  grant: string;
}

async function enrollment(
  of: Peer4Agent = account,
  changes: Record<string, string> = {}
): Promise<Enrollment> {
  const replica = await peer4Agent(mediator.did);
  const replicaId = uuidv7();
  const payload = {
    account: of.did,
    mediation_id: mediationId,
    mediator: mediator.did,
    replica_id: replicaId,
    replica_did: replica.did,
    replica_long_form: replica.longForm,
    ...changes,
  };
  return { replica, replicaId, payload, grant: await signedBy(of, payload) };
}

async function register(grant: string, speaker: Speaker = firstContact(account)) {
  return send(speaker, REGISTER, { grant });
}

async function roster(speaker: Speaker = known(account), limit = 2, cursor: string | null = null) {
  return send(speaker, LIST, { cursor, limit });
}

async function expectProblem(reply: IMessage | null, suffix: string) {
  expect(reply?.type).toBe(PROBLEM);
  expect(reply?.body.code).toBe(problem(suffix));
}

describe("register", () => {
  it("creates the account and its first replica with no mediation grant before it", async () => {
    const first = await enrollment();
    const reply = await register(first.grant);

    expect(reply?.type).toBe(REGISTERED);
    expect(reply?.body).toEqual({
      account: account.did,
      mediation_id: mediationId,
      routing_did: mediator.did,
      replica_id: first.replicaId,
      replica_did: first.replica.did,
      state: "active",
      registered_time: expect.any(Number),
      limits: {
        message_retention_seconds: TEST_CONFIG.messageTtlSeconds,
        max_message_bytes: TEST_CONFIG.maxMessageBytes,
        max_active_replicas: TEST_CONFIG.maxActiveReplicas,
        max_membership_page: TEST_CONFIG.maxMembershipPage,
        max_shared_recipients: TEST_CONFIG.maxSharedRecipients,
        max_retained_bytes: TEST_CONFIG.maxRetainedBytes,
        max_retained_messages: TEST_CONFIG.maxMessagesPerAccount,
        max_deliveries_per_request: 10,
      },
    });
    expect(await store.isMediated(account.did)).toBe(false);
    expect(await store.isMediated(account.longForm)).toBe(false);
  });

  it("answers a repeat with the first registration, in either spelling of the account", async () => {
    const first = await enrollment();
    const original = await register(first.grant);
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const retried = await register(first.grant);
    const later = await register(first.grant, known(account));

    expect(retried?.body).toEqual(original?.body);
    expect(later?.body).toEqual(original?.body);
    expect((await roster())?.body.entries).toHaveLength(1);
  });

  it("enrolls a further replica in the account it already has", async () => {
    const first = await enrollment();
    const second = await enrollment();
    await register(first.grant);

    const reply = await register(second.grant, known(account));

    expect(reply?.type).toBe(REGISTERED);
    expect(reply?.body.replica_did).toBe(second.replica.did);
    expect((await roster())?.body.entries).toEqual([
      { grant: first.grant, state: "active", registered_time: expect.any(Number) },
      { grant: second.grant, state: "active", registered_time: expect.any(Number) },
    ]);
  });

  it("gives two first registrations racing for one account the same account", async () => {
    const [first, second] = await Promise.all([enrollment(), enrollment()]);

    const replies = await Promise.all([register(first.grant), register(second.grant)]);

    expect(replies.map((reply) => reply?.type)).toEqual([REGISTERED, REGISTERED]);
    expect((await roster())?.body.entries).toHaveLength(2);
  });

  it("keeps the long forms, so the account and its replicas resolve by their short ones", async () => {
    const first = await enrollment();
    await register(first.grant);

    expect(await store.resolutionMaterial(account.did)).toBe(account.longForm);
    expect(await store.resolutionMaterial(first.replica.did)).toBe(first.replica.longForm);
  });

  it("refuses an unknown account that does not introduce itself by its long form", async () => {
    const first = await enrollment();
    expect(await register(first.grant, known(account))).toBeNull();
    await expectProblem(await roster(firstContact(account)), "unknown-account");
  });

  it("says nothing to a sender it cannot name", async () => {
    const first = await enrollment();
    const res = await app.request("/", {
      method: "POST",
      headers: { "content-type": ENCRYPTED },
      body: await packAnonymous(plaintext(REGISTER, { grant: first.grant }), mediator.did),
    });
    expect(res.status).toBe(202);
    await expectProblem(await roster(firstContact(account)), "unknown-account");
  });

  describe("refuses a grant", () => {
    async function refused(grant: string, speaker: Speaker = firstContact(account)) {
      await expectProblem(await register(grant, speaker), "invalid-grant");
      await expectProblem(await roster(firstContact(account)), "unknown-account");
    }

    it("the account did not sign", async () => {
      const { replica, payload } = await enrollment();
      await refused(await signedBy(replica, payload, { kid: `${account.did}#key-1` }));
      await refused(await signedBy(replica, payload));
    });

    it("signed for another account", async () => {
      const other = await peer4Agent(null);
      const { grant } = await enrollment(other);
      await refused(grant);
    });

    it("sent by the replica it names", async () => {
      const { replica, grant } = await enrollment();
      await refused(grant, firstContact(replica));
    });

    it("naming another mediator", async () => {
      const { grant } = await enrollment(account, { mediator: "did:web:elsewhere.test" });
      await refused(grant);
    });

    it("whose replica document is served by another mediator", async () => {
      const elsewhere = await peer4Agent("did:web:elsewhere.test");
      const { grant } = await enrollment(account, {
        replica_did: elsewhere.did,
        replica_long_form: elsewhere.longForm,
      });
      await refused(grant);
    });

    it("whose long form is not the replica DID's", async () => {
      const other = await peer4Agent(mediator.did);
      const { grant } = await enrollment(account, { replica_long_form: other.longForm });
      await refused(grant);
    });

    it("naming the account as its own replica", async () => {
      const selfServed = await peer4Agent(mediator.did);
      const { grant } = await enrollment(selfServed, {
        replica_did: selfServed.did,
        replica_long_form: selfServed.longForm,
      });
      await expectProblem(await register(grant, firstContact(selfServed)), "invalid-grant");
    });

    it("with IDs that are not UUIDv7", async () => {
      await refused((await enrollment(account, { replica_id: randomUUID() })).grant);
      await refused((await enrollment(account, { mediation_id: "1" })).grant);
    });

    it("with a field too many, a field too few, or another spelling of its JSON", async () => {
      const { payload } = await enrollment();
      const { mediator: _, ...short } = payload;
      await refused(await signedBy(account, { ...payload, iat: "1" }));
      await refused(await signedBy(account, short));

      const spaced = new TextEncoder().encode(JSON.stringify(payload, null, 1));
      await refused(
        await new CompactSign(spaced)
          .setProtectedHeader({
            alg: "EdDSA",
            typ: "estoc/replica-grant+jws",
            kid: `${account.did}#key-1`,
          })
          .sign(await importJWK(account.signingKey, "EdDSA"))
      );
    });

    it("of another type, or carrying where to fetch a key", async () => {
      const { payload } = await enrollment();
      await refused(await signedBy(account, payload, { typ: "JWT" }));
      await refused(await signedBy(account, payload, { jku: "https://keys.test/set" }));
      await refused(await signedBy(account, payload, { kid: `${account.did}#key-2` }));
    });

    it("whose payload was changed after signing", async () => {
      const { grant, payload } = await enrollment();
      const [header, , signature] = grant.split(".");
      const altered = Buffer.from(
        JSON.stringify({ ...payload, replica_id: uuidv7() })
      ).toString("base64url");
      await refused(`${header}.${altered}.${signature}`);
    });
  });

  it("refuses a request whose body or addressing is not exactly a registration", async () => {
    const { grant } = await enrollment();
    const speaker = firstContact(account);
    const other = await agent("other");

    await expectProblem(await send(speaker, REGISTER, { grant, replica_id: "x" }), "invalid-message");
    await expectProblem(await send(speaker, REGISTER, {}), "invalid-message");
    await expectProblem(
      await send(speaker, REGISTER, { grant }, { to: [mediator.did, other.did] }),
      "invalid-message"
    );
    await expectProblem(await roster(firstContact(account)), "unknown-account");
  });

  describe("refuses a conflicting identity without changing anything", () => {
    it("a replica ID bound to another DID, or a DID under another ID", async () => {
      const first = await enrollment();
      await register(first.grant);

      const sameId = await enrollment(account, { replica_id: first.replicaId });
      const sameDid = await enrollment(account, {
        replica_did: first.replica.did,
        replica_long_form: first.replica.longForm,
      });

      await expectProblem(await register(sameId.grant), "identity-conflict");
      await expectProblem(await register(sameDid.grant), "identity-conflict");
      expect((await roster())?.body.entries).toHaveLength(1);
    });

    it("another mediation ID for the account", async () => {
      await register((await enrollment()).grant);
      const moved = await enrollment(account, { mediation_id: uuidv7() });

      await expectProblem(await register(moved.grant), "identity-conflict");
      expect((await roster())?.body.entries).toHaveLength(1);
    });

    it("a replica another account enrolled, or another account itself", async () => {
      const first = await enrollment();
      await register(first.grant);
      const other = await peer4Agent(null);

      const taken = await enrollment(other, {
        replica_did: first.replica.did,
        replica_long_form: first.replica.longForm,
      });
      await expectProblem(await register(taken.grant, firstContact(other)), "identity-conflict");
      await expectProblem(await roster(firstContact(other)), "unknown-account");

      const selfServed = await peer4Agent(mediator.did);
      await register((await enrollment(selfServed)).grant, firstContact(selfServed));
      const asReplica = await enrollment(account, {
        replica_did: selfServed.did,
        replica_long_form: selfServed.longForm,
      });
      await expectProblem(await register(asReplica.grant), "identity-conflict");
    });

    it("an account or a replica that holds ordinary mediation", async () => {
      const ordinary = await send(firstContact(account), MEDIATE_REQUEST, {});
      expect(ordinary?.type).toBe(MEDIATE_GRANT);
      await expectProblem(await register((await enrollment()).grant), "identity-conflict");

      const other = await peer4Agent(null);
      const mediated = await enrollment(other);
      await send(firstContact(mediated.replica), MEDIATE_REQUEST, {});
      await expectProblem(await register(mediated.grant, firstContact(other)), "identity-conflict");
      await expectProblem(await roster(firstContact(other)), "unknown-account");
    });

    it("a replica that is an ordinary account's recipient", async () => {
      const holder = await agent("holder");
      const bound = await enrollment();
      await send(holder, MEDIATE_REQUEST, {});
      await send(holder, RECIPIENT_UPDATE, {
        updates: [{ recipient_did: bound.replica.did, action: "add" }],
      });

      await expectProblem(await register(bound.grant), "identity-conflict");
      await expectProblem(await roster(firstContact(account)), "unknown-account");
    });
  });

  it("stops enrolling at the replica limit and still answers the ones it has", async () => {
    const enrolled = [];
    for (let i = 0; i < TEST_CONFIG.maxActiveReplicas; i++) {
      enrolled.push(await enrollment());
      expect((await register(enrolled[i].grant))?.type).toBe(REGISTERED);
    }

    await expectProblem(await register((await enrollment()).grant), "quota");
    expect((await register(enrolled[0].grant))?.type).toBe(REGISTERED);
  });

  it("creates no account where registration is closed", async () => {
    const closed = serve({ openRegistration: false });
    const { grant } = await enrollment();

    await expectProblem(
      await send(firstContact(account), REGISTER, { grant }, {}, closed),
      "account-refused"
    );
    await expectProblem(await roster(firstContact(account)), "unknown-account");
  });

  it("is an unsupported type where replica mediation is off", async () => {
    const off = serve({ replicaMediation: false });
    const { grant } = await enrollment();

    const reply = await send(firstContact(account), REGISTER, { grant }, {}, off);
    expect(reply?.body.code).toBe("e.p.msg.unsupported");

    const described = (await (await off.request("/")).json()) as { protocols: string[] };
    expect(described.protocols).not.toContain(PROTOCOL);
    expect(((await (await app.request("/")).json()) as { protocols: string[] }).protocols).toContain(
      PROTOCOL
    );
  });
});

describe("list", () => {
  it("pages one fixed roster, oldest first, whoever enrolls meanwhile", async () => {
    const grants = [];
    for (let i = 0; i < 2; i++) {
      grants.push((await enrollment()).grant);
      await register(grants[i]);
    }

    const first = await roster(known(account), 1);
    expect(first?.type).toBe(REPLICAS);
    expect((first?.body.entries as { grant: string }[]).map((entry) => entry.grant)).toEqual([
      grants[0],
    ]);

    await register((await enrollment()).grant);

    const second = await roster(known(account), 2, first?.body.next_cursor as string);
    expect((second?.body.entries as { grant: string }[]).map((entry) => entry.grant)).toEqual([
      grants[1],
    ]);
    expect(second?.body.next_cursor).toBeNull();

    const again = await roster(known(account), 2, first?.body.next_cursor as string);
    expect(again?.body).toEqual(second?.body);
    expect((await roster())?.body.next_cursor).not.toBeNull();
  });

  it("refuses a limit past the page size, a cursor it did not write, and another account's", async () => {
    await register((await enrollment()).grant);
    await register((await enrollment()).grant);
    const other = await peer4Agent(null);
    await register((await enrollment(other)).grant, firstContact(other));
    await register((await enrollment(other)).grant, firstContact(other));
    const foreign = (await roster(known(other), 1))?.body.next_cursor as string;
    expect(foreign).toEqual(expect.any(String));

    await expectProblem(await roster(known(account), 3), "invalid-message");
    await expectProblem(await roster(known(account), 0), "invalid-message");
    await expectProblem(await roster(known(account), 1, "bm9uc2Vuc2U"), "invalid-message");
    await expectProblem(await roster(known(account), 1, foreign), "invalid-message");
    await expectProblem(await send(known(account), LIST, { limit: 1 }), "invalid-message");
  });

  it("discloses nothing of an account to a replica of it", async () => {
    const first = await enrollment();
    await register(first.grant);

    await expectProblem(await roster(known(first.replica)), "unknown-account");
  });
});

describe("a replica-mediation account beside ordinary mediation", () => {
  it("is never granted ordinary mediation, under either spelling", async () => {
    const first = await enrollment();
    await register(first.grant);

    for (const speaker of [firstContact(account), known(account), known(first.replica)]) {
      expect((await send(speaker, MEDIATE_REQUEST, {}))?.type).toBe(MEDIATE_DENY);
    }
    expect((await roster())?.body.entries).toHaveLength(1);
  });

  it("cannot be bound as an ordinary account's recipient", async () => {
    const first = await enrollment();
    await register(first.grant);
    const holder = await agent("holder");
    await send(holder, MEDIATE_REQUEST, {});

    const reply = await send(holder, RECIPIENT_UPDATE, {
      updates: [account.did, account.longForm, first.replica.did, first.replica.longForm].map(
        (recipient_did) => ({ recipient_did, action: "add" })
      ),
    });

    expect((reply?.body.updated as { result: string }[]).map((update) => update.result)).toEqual([
      "client_error",
      "client_error",
      "client_error",
      "client_error",
    ]);
  });

  it("is told that pickup is a replica's to ask for", async () => {
    await register((await enrollment()).grant);

    for (const [type, body] of [
      ["status-request", {}],
      ["delivery-request", { limit: 1 }],
      ["messages-received", { message_id_list: [] }],
      ["live-delivery-change", { live_delivery: true }],
    ] as const) {
      await expectProblem(
        await send(known(account), `https://didcomm.org/messagepickup/3.0/${type}`, body),
        "replica-required"
      );
    }
  });
});
