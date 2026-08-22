import { randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import type { IMessage } from "didcomm-node";
import { base64urlToBytes, bytesToBase64url } from "@estoc/did-peer";

import { buildServer } from "../src/server.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import { createCard, verifyCard, type RootCard } from "@estoc/signed-dir";
import {
  DAG_JSON_MEDIA_TYPE,
  RAW_MEDIA_TYPE,
  encodeDirNode,
  fileCid,
  type DirEntry,
} from "../src/public-folder/objects.js";
import {
  TEST_CONFIG,
  agent,
  memoryStore,
  packAnonymous,
  plaintext,
  type TestAgent,
} from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";

const QUERY = "https://didcomm.org/public-folder/1.0/query";
const ANSWER = "https://didcomm.org/public-folder/1.0/answer";
const PUBLISH = "https://didcomm.org/public-folder/1.0/publish";
const PUBLISH_RESULT = "https://didcomm.org/public-folder/1.0/publish-result";
const PUBLISHED = "https://didcomm.org/public-folder/1.0/published";
const PROBLEM = "https://didcomm.org/report-problem/2.0/problem-report";

/** Hash a flat path → content snapshot into objects, the test-side hashTree. */
async function buildTree(
  files: Record<string, string>
): Promise<{ root: string; objects: Map<string, Uint8Array> }> {
  const objects = new Map<string, Uint8Array>();
  const encoder = new TextEncoder();

  interface Dir {
    dirs: Map<string, Dir>;
    files: Map<string, Uint8Array>;
  }
  const newDir = (): Dir => ({ dirs: new Map(), files: new Map() });
  const top = newDir();
  for (const [path, content] of Object.entries(files)) {
    const segments = path.split("/");
    let dir = top;
    for (const segment of segments.slice(0, -1)) {
      let child = dir.dirs.get(segment);
      if (!child) {
        child = newDir();
        dir.dirs.set(segment, child);
      }
      dir = child;
    }
    dir.files.set(segments[segments.length - 1], encoder.encode(content));
  }

  async function hashDir(dir: Dir): Promise<{ cid: string; size: number }> {
    const entries: DirEntry[] = [];
    for (const [name, bytes] of dir.files) {
      const cid = await fileCid(bytes);
      objects.set(cid, bytes);
      entries.push({ name, type: "file", hash: cid, size: bytes.length });
    }
    for (const [name, child] of dir.dirs) {
      const sub = await hashDir(child);
      entries.push({ name, type: "dir", hash: sub.cid, size: sub.size });
    }
    const { cid, bytes } = await encodeDirNode(entries);
    objects.set(cid, bytes);
    return { cid, size: entries.reduce((sum, e) => sum + e.size, 0) };
  }

  const { cid: root } = await hashDir(top);
  return { root, objects };
}

/** The agent's Ed25519 key as a card signer, plus the kid naming it. */
function cardSigner(a: TestAgent): {
  kid: string;
  sign: (data: Uint8Array) => Promise<Uint8Array>;
} {
  const secret = a.identity.secrets.find(
    (s) => s.id.startsWith(a.did) && s.privateKeyJwk?.crv === "Ed25519"
  );
  if (secret?.privateKeyJwk === undefined) {
    throw new Error("test agent has no Ed25519 secret");
  }
  const jwk = secret.privateKeyJwk;
  return {
    kid: secret.id,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk as JsonWebKey,
        { name: "Ed25519" },
        false,
        ["sign"]
      );
      return new Uint8Array(
        await crypto.subtle.sign("Ed25519", key, data as Uint8Array<ArrayBuffer>)
      );
    },
  };
}

async function signCard(owner: TestAgent, card: RootCard): Promise<string> {
  const { kid, sign } = cardSigner(owner);
  return createCard(card, { sign }, kid);
}

function objectAttachment(cid: string, bytes: Uint8Array) {
  return { id: cid, data: { base64: bytesToBase64url(bytes) } };
}

let app: Hono;
let mediator: MediatorIdentity;
let owner: TestAgent;
let outsider: TestAgent;
let reader: TestAgent;
let tree: { root: string; objects: Map<string, Uint8Array> };

/** Authcrypt to the mediator, POST, unpack the reply. */
async function send(
  sender: TestAgent,
  type: string,
  body: Record<string, unknown>,
  attachments?: IMessage["attachments"],
  target: Hono = app
): Promise<IMessage | null> {
  const packed = await sender.ctx.packEncrypted(
    plaintext(type, body, {
      from: sender.did,
      to: [mediator.did],
      return_route: "all",
      ...(attachments !== undefined ? { attachments } : {}),
    }),
    mediator.did
  );
  const res = await target.request("/", {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  if (res.status === 202) {
    return null;
  }
  const { message } = await sender.ctx.unpack(await res.text());
  return message;
}

async function publishRound(
  sender: TestAgent,
  card: string,
  attachments?: IMessage["attachments"],
  target: Hono = app
): Promise<IMessage | null> {
  return send(sender, PUBLISH, { card }, attachments, target);
}

beforeAll(async () => {
  mediator = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
  owner = await agent("owner");
  outsider = await agent("outsider");
  reader = await agent("reader");
  tree = await buildTree({
    "profile.json": '{"displayName":"Owner"}',
    "posts/hello.md": "# hello world",
    "posts/index.json": '["hello.md"]',
  });
  app = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: TEST_CONFIG,
  }).app;

  await send(
    owner,
    "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
    {}
  );
});

function freshCard(root?: string): RootCard {
  return {
    did: owner.did,
    id: randomUUID(),
    expires: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(),
    root: root ?? null,
  };
}

describe("public-folder/1.0 publish", () => {
  it("negotiates missing objects round by round, then issues a receipt", async () => {
    const card = freshCard(tree.root);
    const jws = await signCard(owner, card);

    // Round 1: nothing attached — everything reachable is missing, which so
    // far is only the root itself.
    const first = await publishRound(owner, jws);
    expect(first?.type).toBe(PUBLISH_RESULT);
    expect(first?.body.missing).toEqual([tree.root]);

    // Round 2: the root node reveals its children as the next frontier.
    const second = await publishRound(owner, jws, [
      objectAttachment(tree.root, tree.objects.get(tree.root)!),
    ]);
    expect(second?.type).toBe(PUBLISH_RESULT);
    const missing = second?.body.missing as string[];
    expect(missing).not.toContain(tree.root);
    expect(missing.length).toBeGreaterThan(0);

    // Round 3: everything else — completion is a stored receipt.
    const rest = [...tree.objects.entries()]
      .filter(([cid]) => cid !== tree.root)
      .map(([cid, bytes]) => objectAttachment(cid, bytes));
    const done = await publishRound(owner, jws, rest);
    expect(done?.type).toBe(PUBLISHED);
    expect(done?.body.did).toBe(owner.did);
    expect(done?.body.card_id).toBe(card.id);
    // The lease promise is required — always a date, never absent.
    const retainUntil = Date.parse(done?.body.retain_until as string);
    expect(retainUntil).toBeGreaterThan(Date.now());
  });

  it("is idempotent: re-sending the current card yields a fresh receipt", async () => {
    const stored = await app.request(
      `/card/${encodeURIComponent(owner.did)}`
    );
    const jws = await stored.text();
    const again = await publishRound(owner, jws);
    expect(again?.type).toBe(PUBLISHED);
  });

  it("discards attachments whose bytes do not hash to their claimed CID", async () => {
    const smallTree = await buildTree({ "a.txt": "unpublished content" });
    const jws = await signCard(owner, freshCard(smallTree.root));

    const lying = await publishRound(owner, jws, [
      objectAttachment(smallTree.root, new TextEncoder().encode("not those bytes")),
    ]);
    expect(lying?.type).toBe(PUBLISH_RESULT);
    expect(lying?.body.missing).toEqual([smallTree.root]);
  });

  it("refuses a sender with no mediation relationship", async () => {
    const jws = await signCard(owner, freshCard(tree.root));
    const reply = await send(outsider, PUBLISH, { card: jws });
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.unauthorized");
  });

  it("refuses a card signed by a key outside the card's did", async () => {
    const card = freshCard(tree.root);
    const { kid, sign } = cardSigner(outsider);
    const forged = await createCard(card, { sign }, kid);
    const reply = await send(owner, PUBLISH, { card: forged });
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.card.invalid");
  });

  it("refuses a card missing the root field — null is the only takedown encoding", async () => {
    const { root: _root, ...fieldless } = freshCard(tree.root);
    const { kid, sign } = cardSigner(owner);
    const jws = await createCard(fieldless as RootCard, { sign }, kid);
    const reply = await send(owner, PUBLISH, { card: jws });
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.card.invalid");
  });

  it("refuses publishing for a did that is not yours and not bound to you", async () => {
    await send(
      outsider,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {}
    );
    // outsider now has an account, but the card is the owner's.
    const jws = await signCard(owner, freshCard(tree.root));
    const reply = await send(outsider, PUBLISH, { card: jws });
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.unauthorized");
  });

  it("allows publishing for a recipient DID bound to the account", async () => {
    const alias = await agent("alias");
    await send(
      owner,
      "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
      { updates: [{ recipient_did: alias.did, action: "add" }] }
    );
    const aliasTree = await buildTree({ "hi.txt": "alias content" });
    const card: RootCard = {
      did: alias.did,
      id: randomUUID(),
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
      root: aliasTree.root,
    };
    const jws = await signCard(alias, card);
    const done = await publishRound(
      owner,
      jws,
      [...aliasTree.objects.entries()].map(([cid, bytes]) =>
        objectAttachment(cid, bytes)
      )
    );
    expect(done?.type).toBe(PUBLISHED);
    expect(done?.body.did).toBe(alias.did);
  });

  it("refuses a publication whose root declares more bytes than the limit", async () => {
    const tiny = buildServer({
      identity: mediator,
      store: memoryStore(),
      config: { ...TEST_CONFIG, maxPublicationBytes: 4 },
    }).app;
    await send(
      owner,
      "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
      {},
      undefined,
      tiny
    );

    const jws = await signCard(owner, freshCard(tree.root));
    const reply = await publishRound(
      owner,
      jws,
      [objectAttachment(tree.root, tree.objects.get(tree.root)!)],
      tiny
    );
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.publish.too-large");
    expect(reply?.body.args?.[1]).toBe(4);
  });
});

describe("public-folder/1.0 query", () => {
  it("answers an anonymous query with the card and the proof chain", async () => {
    const packed = await packAnonymous(
      plaintext(QUERY, { did: owner.did, path: "posts/hello.md" }, {
        from: reader.did,
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
    expect(res.status).toBe(200);
    const { message } = await reader.ctx.unpack(await res.text());
    expect(message.type).toBe(ANSWER);

    // The reader can verify end to end: card signature, then each hop.
    const { kid } = cardSigner(owner);
    const verified = await verifyCard(message.body.card as string, (k) =>
      k === kid ? ownerPublicKey() : null
    );
    expect(verified.card.did).toBe(owner.did);
    expect(verified.card.root).toBe(tree.root);

    const chain = message.attachments!;
    expect(chain[0].id).toBe(tree.root);
    expect(chain[0].media_type).toBe(DAG_JSON_MEDIA_TYPE);
    expect(chain).toHaveLength(3);
    const leaf = chain[2];
    expect(leaf.media_type).toBe(RAW_MEDIA_TYPE);
    const leafBytes = base64urlToBytes(
      (leaf.data as { base64: string }).base64
    );
    expect(new TextDecoder().decode(leafBytes)).toBe("# hello world");
  });

  it("answers a pathless query with the card and the root node", async () => {
    const reply = await send(reader, QUERY, { did: owner.did });
    expect(reply?.type).toBe(ANSWER);
    expect(reply?.attachments).toHaveLength(1);
    expect(reply?.attachments?.[0].id).toBe(tree.root);
  });

  it("card_only elides the attachments", async () => {
    const reply = await send(reader, QUERY, { did: owner.did, card_only: true });
    expect(reply?.type).toBe(ANSWER);
    expect(reply?.attachments).toBeUndefined();
  });

  it("reports an unknown did and a missing path distinctly", async () => {
    const unknown = await send(reader, QUERY, { did: "did:example:nobody" });
    expect(unknown?.type).toBe(PROBLEM);
    expect(unknown?.body.code).toBe("e.p.did.unknown");

    const missing = await send(reader, QUERY, {
      did: owner.did,
      path: "posts/nope.md",
    });
    expect(missing?.type).toBe(PROBLEM);
    expect(missing?.body.code).toBe("e.p.path.not-found");
  });
});

describe("public-folder/1.0 takedown", () => {
  it("a rootless card publishes 'nothing' and every query answers with it", async () => {
    const takedown = await signCard(owner, freshCard());
    const done = await publishRound(owner, takedown);
    expect(done?.type).toBe(PUBLISHED);
    // A takedown card is a leased publication too: same required promise.
    expect(Date.parse(done?.body.retain_until as string)).toBeGreaterThan(Date.now());

    // Whatever the path, the signed "nothing is published" is the answer.
    const reply = await send(reader, QUERY, {
      did: owner.did,
      path: "posts/hello.md",
    });
    expect(reply?.type).toBe(ANSWER);
    expect(reply?.body.card).toBe(takedown);
    expect(reply?.attachments).toBeUndefined();
  });

  it("republishing content after a takedown restores the folder", async () => {
    const jws = await signCard(owner, freshCard(tree.root));
    // The objects were never purged (grace period), so one round suffices.
    const done = await publishRound(owner, jws);
    expect(done?.type).toBe(PUBLISHED);
    const reply = await send(reader, QUERY, { did: owner.did, path: "profile.json" });
    expect(reply?.type).toBe(ANSWER);
  });
});

describe("public-folder HTTP reads", () => {
  it("serves objects by CID with the codec's media type, immutable", async () => {
    const res = await app.request(`/objects/${tree.root}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe(DAG_JSON_MEDIA_TYPE);
    expect(res.headers.get("cache-control")).toContain("immutable");
    expect(Array.from(new Uint8Array(await res.arrayBuffer()))).toEqual(
      Array.from(tree.objects.get(tree.root)!)
    );

    const nothing = await app.request(
      "/objects/bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
    );
    expect(nothing.status).toBe(404);

    const garbage = await app.request("/objects/not-a-cid");
    expect(garbage.status).toBe(400);
  });

  it("serves the current card as a compact JWS", async () => {
    const res = await app.request(`/card/${encodeURIComponent(owner.did)}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/jose");
    const verified = await verifyCard(await res.text(), () => ownerPublicKey());
    expect(verified.card.did).toBe(owner.did);

    const nothing = await app.request(
      `/card/${encodeURIComponent("did:example:nobody")}`
    );
    expect(nothing.status).toBe(404);
  });
});

describe("operator serve policy", () => {
  const MEDIATE_REQUEST =
    "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
  let store: ReturnType<typeof memoryStore>;
  let policed: Hono;
  let deny: Hono;

  const allObjects = () =>
    [...tree.objects].map(([cid, bytes]) => objectAttachment(cid, bytes));

  beforeAll(async () => {
    store = memoryStore();
    policed = buildServer({ identity: mediator, store, config: TEST_CONFIG }).app;
    // Same store, inverted default: what an allowlist-only deployment serves.
    deny = buildServer({
      identity: mediator,
      store,
      config: { ...TEST_CONFIG, publicationServeDefault: "deny" },
    }).app;
    await send(owner, MEDIATE_REQUEST, {}, undefined, policed);
    const jws = await signCard(owner, freshCard(tree.root));
    const done = await publishRound(owner, jws, allObjects(), policed);
    expect(done?.type).toBe(PUBLISHED);
  });

  it("a blocked DID answers exactly as an unknown one", async () => {
    await store.setPolicyRule({
      kind: "did",
      subject: owner.did,
      mode: "block",
      holdUntil: null,
      note: null,
    });

    const reply = await send(reader, QUERY, { did: owner.did }, undefined, policed);
    expect(reply?.type).toBe(PROBLEM);
    expect(reply?.body.code).toBe("e.p.did.unknown");
    expect(
      (await policed.request(`/card/${encodeURIComponent(owner.did)}`)).status
    ).toBe(404);

    // A further publish is refused — with no reason — before bytes can land.
    const jws = await signCard(owner, freshCard(tree.root));
    const refused = await publishRound(owner, jws, undefined, policed);
    expect(refused?.type).toBe(PROBLEM);
    expect(refused?.body.code).toBe("e.p.publish.refused");

    await store.clearPolicyRule("did", owner.did);
    expect(
      (await policed.request(`/card/${encodeURIComponent(owner.did)}`)).status
    ).toBe(200);
  });

  it("legal mode may say so on HTTP; DIDComm stays silent", async () => {
    await store.setPolicyRule({
      kind: "did",
      subject: owner.did,
      mode: "legal",
      holdUntil: null,
      note: "court order #42",
    });

    expect(
      (await policed.request(`/card/${encodeURIComponent(owner.did)}`)).status
    ).toBe(451);
    const reply = await send(reader, QUERY, { did: owner.did }, undefined, policed);
    expect(reply?.body.code).toBe("e.p.did.unknown");

    await store.clearPolicyRule("did", owner.did);
  });

  it("a blocked CID reads as absent wherever it appears", async () => {
    const cid = await fileCid(new TextEncoder().encode("# hello world"));
    await store.setPolicyRule({
      kind: "cid",
      subject: cid,
      mode: "block",
      holdUntil: null,
      note: null,
    });

    expect((await policed.request(`/objects/${cid}`)).status).toBe(404);
    // In a proof chain it is a storage hole — same answer its absence gives.
    const hole = await send(
      reader,
      QUERY,
      { did: owner.did, path: "posts/hello.md" },
      undefined,
      policed
    );
    expect(hole?.type).toBe(PROBLEM);
    expect(hole?.body.code).toBe("e.p.me.res.storage");
    // The rest of the folder is untouched.
    const fine = await send(
      reader,
      QUERY,
      { did: owner.did, path: "profile.json" },
      undefined,
      policed
    );
    expect(fine?.type).toBe(ANSWER);

    await store.clearPolicyRule("cid", cid);
  });

  it("a barred CID's bytes are refused, never stored", async () => {
    const fresh = memoryStore();
    const target = buildServer({
      identity: mediator,
      store: fresh,
      config: TEST_CONFIG,
    }).app;
    await send(owner, MEDIATE_REQUEST, {}, undefined, target);
    const cid = await fileCid(new TextEncoder().encode("# hello world"));
    await fresh.setPolicyRule({
      kind: "cid",
      subject: cid,
      mode: "block",
      holdUntil: null,
      note: null,
    });

    // The publish offers every object; the barred one is skipped, so the
    // closure never completes and the bytes are never in possession.
    const jws = await signCard(owner, freshCard(tree.root));
    const reply = await publishRound(owner, jws, allObjects(), target);
    expect(reply?.type).toBe(PUBLISH_RESULT);
    expect(reply?.body.missing).toContain(cid);
    expect(await fresh.getObject(cid)).toBeNull();
    fresh.close();
  });

  it("a deny default serves nothing but allowlisted DIDs", async () => {
    expect(
      (await deny.request(`/card/${encodeURIComponent(owner.did)}`)).status
    ).toBe(404);
    expect((await deny.request(`/objects/${tree.root}`)).status).toBe(404);
    const hidden = await send(reader, QUERY, { did: owner.did }, undefined, deny);
    expect(hidden?.type).toBe(PROBLEM);
    expect(hidden?.body.code).toBe("e.p.did.unknown");

    await store.setPolicyRule({
      kind: "did",
      subject: owner.did,
      mode: "allow",
      holdUntil: null,
      note: null,
    });
    expect(
      (await deny.request(`/card/${encodeURIComponent(owner.did)}`)).status
    ).toBe(200);
    // Objects are servable through the allowlisted owner's references.
    expect((await deny.request(`/objects/${tree.root}`)).status).toBe(200);
    const served = await send(
      reader,
      QUERY,
      { did: owner.did, path: "profile.json" },
      undefined,
      deny
    );
    expect(served?.type).toBe(ANSWER);

    await store.clearPolicyRule("did", owner.did);
  });
});

/** The owner's raw Ed25519 public key, as a reader's resolver would yield it. */
function ownerPublicKey(): Uint8Array {
  const secret = owner.identity.secrets.find(
    (s) => s.id.startsWith(owner.did) && s.privateKeyJwk?.crv === "Ed25519"
  );
  return base64urlToBytes(secret!.privateKeyJwk!.x as string);
}
