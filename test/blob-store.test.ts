import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import type { IMessage } from "didcomm-node";

import { BLOB_ID_PATTERN, blobDigest, blobName, mintBlobId } from "../src/blobs/hash.js";
import { buildServer } from "../src/server.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import { SqliteStore } from "../src/store/sqlite.js";
import { TEST_CONFIG, agent, memoryStore, plaintext, type TestAgent } from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";
const PUT = "https://estoc.dev/blob-store/1.0/put";
const DELETE = "https://estoc.dev/blob-store/1.0/delete";
const PROBLEM = "https://didcomm.org/report-problem/2.0/problem-report";

let dir: string;
let app: Hono;
let mediator: MediatorIdentity;
let alice: TestAgent;
let bob: TestAgent;
let stranger: TestAgent;

function nameOf(bytes: Uint8Array): string {
  return blobName(createHash("sha256").update(bytes).digest());
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "mediator-blobs-"));
  mediator = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
  alice = await agent("alice");
  bob = await agent("bob");
  stranger = await agent("stranger");
  app = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: { ...TEST_CONFIG, blobDir: dir },
  }).app;
  await send(alice, "https://didcomm.org/coordinate-mediation/3.0/mediate-request", {});
  await send(bob, "https://didcomm.org/coordinate-mediation/3.0/mediate-request", {});
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function send(
  sender: TestAgent,
  type: string,
  body: Record<string, unknown>
): Promise<IMessage> {
  const packed = await sender.ctx.packEncrypted(
    plaintext(type, body, { from: sender.did, to: [mediator.did], return_route: "all" }),
    mediator.did
  );
  const res = await app.request("/", {
    method: "POST",
    headers: { "content-type": ENCRYPTED },
    body: packed,
  });
  expect(res.status).toBe(200);
  return (await sender.ctx.unpack(await res.text())).message;
}

function path(url: string): string {
  const u = new URL(url);
  return u.pathname + u.search;
}

describe("blob names", () => {
  it("round-trips a sha-256 digest through base32 multihash", () => {
    const digest = randomBytes(32);
    const name = blobName(digest);
    expect(name).toMatch(/^b[a-z2-7]{55}$/);
    expect(Buffer.from(blobDigest(name)!)).toEqual(digest);
    expect(blobDigest("b" + "a".repeat(55))).toBeNull();
    expect(blobDigest(name.toUpperCase())).toBeNull();
  });

  it("mints ids that are random, base32, and never a blob name", () => {
    const a = mintBlobId();
    const b = mintBlobId();
    expect(a).toMatch(BLOB_ID_PATTERN);
    expect(a).not.toBe(b);
    expect(blobDigest(a)).toBeNull();
  });
});

describe("blob-store/1.0", () => {
  it("advertises its limits and protocol", async () => {
    const res = await app.request("/");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.protocols).toContain("https://estoc.dev/blob-store/1.0");
    expect(body.blobs).toEqual({ retainSeconds: 3600, maxBytes: 4096, quotaBytes: 6000 });
  });

  it("puts, uploads, serves with ranges, renews, deletes", async () => {
    const bytes = randomBytes(3000);
    const hash = nameOf(bytes);

    const result = await send(alice, PUT, { hash, size: bytes.length });
    expect(result.type).toBe("https://estoc.dev/blob-store/1.0/put-result");
    expect(result.body.hash).toBe(hash);
    // The URL is a random id under the public URL: it says nothing about the hash.
    const url = result.body.url as string;
    const id = url.slice(`${TEST_CONFIG.publicUrl}/b/`.length);
    expect(id).toMatch(BLOB_ID_PATTERN);
    expect(url).not.toContain(hash);
    expect(Date.parse(result.body.retain_until as string)).toBeGreaterThan(Date.now());
    const upload = result.body.upload as { url: string; expires: string };
    expect(upload.url.startsWith(`${url}?token=`)).toBe(true);
    const at = path(url);

    // Nothing to read before the bytes arrive; the hash is not an address.
    expect((await app.request(at)).status).toBe(404);
    expect((await app.request(`/b/${hash}`)).status).toBe(404);

    // Wrong bytes under the token: refused, token spent, still 404.
    const wrong = await app.request(path(upload.url), {
      method: "PUT",
      headers: { "content-length": String(bytes.length) },
      body: randomBytes(3000),
    });
    expect(wrong.status).toBe(400);
    expect((await app.request(at)).status).toBe(404);

    // A fresh put hands out a fresh token at the same URL; the right bytes land.
    const again = await send(alice, PUT, { hash, size: bytes.length });
    expect(again.body.url).toBe(url);
    const upload2 = again.body.upload as { url: string };
    expect(upload2.url.startsWith(`${url}?token=`)).toBe(true);
    const ok = await app.request(path(upload2.url), {
      method: "PUT",
      headers: { "content-length": String(bytes.length) },
      body: bytes,
    });
    expect(ok.status).toBe(204);
    // The token is one-time.
    expect(
      (
        await app.request(path(upload2.url), {
          method: "PUT",
          headers: { "content-length": String(bytes.length) },
          body: bytes,
        })
      ).status
    ).toBe(404);

    const whole = await app.request(at);
    expect(whole.status).toBe(200);
    expect(whole.headers.get("accept-ranges")).toBe("bytes");
    expect(Buffer.from(await whole.arrayBuffer())).toEqual(bytes);

    const head = await app.request(at, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe("3000");

    const part = await app.request(at, { headers: { range: "bytes=100-199" } });
    expect(part.status).toBe(206);
    expect(part.headers.get("content-range")).toBe("bytes 100-199/3000");
    expect(Buffer.from(await part.arrayBuffer())).toEqual(bytes.subarray(100, 200));

    const tail = await app.request(at, { headers: { range: "bytes=2990-" } });
    expect(tail.status).toBe(206);
    expect(Buffer.from(await tail.arrayBuffer())).toEqual(bytes.subarray(2990));

    const beyond = await app.request(at, { headers: { range: "bytes=5000-" } });
    expect(beyond.status).toBe(416);

    // Renewal: no upload, same URL.
    const renewed = await send(alice, PUT, { hash, size: bytes.length });
    expect(renewed.body.upload).toBeUndefined();
    expect(renewed.body.url).toBe(url);

    // Delete: the URL is dead and the bytes are gone at once.
    const deleted = await send(alice, DELETE, { hash });
    expect(deleted.type).toBe("https://estoc.dev/blob-store/1.0/delete-result");
    expect(deleted.body).toEqual({ hash });
    expect((await app.request(at)).status).toBe(404);
    expect(readdirSync(dir)).not.toContain(id);
    // Deleting again is not an error.
    expect((await send(alice, DELETE, { hash })).body).toEqual({ hash });
  });

  it("keeps one mediation's blob apart from another's, same hash or not", async () => {
    const bytes = randomBytes(1000);
    const hash = nameOf(bytes);
    const put = async (who: TestAgent) => {
      const result = await send(who, PUT, { hash, size: bytes.length });
      expect(result.type).toBe("https://estoc.dev/blob-store/1.0/put-result");
      const upload = result.body.upload as { url: string };
      // Each must upload its own copy: nothing is shared or deduplicated.
      expect(upload).toBeDefined();
      const ok = await app.request(path(upload.url), {
        method: "PUT",
        headers: { "content-length": String(bytes.length) },
        body: bytes,
      });
      expect(ok.status).toBe(204);
      return path(result.body.url as string);
    };
    const alices = await put(alice);
    const bobs = await put(bob);
    expect(alices).not.toBe(bobs);
    expect((await app.request(alices)).status).toBe(200);
    expect((await app.request(bobs)).status).toBe(200);

    // Alice's delete is final for her URL and nothing to Bob's.
    await send(alice, DELETE, { hash });
    expect((await app.request(alices)).status).toBe(404);
    expect((await app.request(bobs)).status).toBe(200);
    // And Alice can put the same hash again: a new blob at a new URL.
    const anew = await send(alice, PUT, { hash, size: bytes.length });
    expect(anew.body.upload).toBeDefined();
    expect(path(anew.body.url as string)).not.toBe(alices);
    await send(alice, DELETE, { hash });
    await send(bob, DELETE, { hash });
  });

  it("refuses over the per-blob limit and over quota", async () => {
    const big = await send(alice, PUT, { hash: nameOf(randomBytes(1)), size: 4097 });
    expect(big.type).toBe(PROBLEM);
    expect(big.body.code).toBe("e.p.blob.too-large");

    const first = await send(alice, PUT, { hash: nameOf(randomBytes(2)), size: 4000 });
    expect(first.type).toBe("https://estoc.dev/blob-store/1.0/put-result");
    const over = await send(alice, PUT, { hash: nameOf(randomBytes(3)), size: 2500 });
    expect(over.type).toBe(PROBLEM);
    expect(over.body.code).toBe("e.p.blob.quota");
    // Releasing frees the quota at once.
    await send(alice, DELETE, { hash: first.body.hash });
    const fits = await send(alice, PUT, { hash: nameOf(randomBytes(3)), size: 2500 });
    expect(fits.type).toBe("https://estoc.dev/blob-store/1.0/put-result");
  });

  it("refuses bad names, mismatched sizes and strangers", async () => {
    const bad = await send(alice, PUT, { hash: "not-a-name", size: 10 });
    expect(bad.body.code).toBe("e.p.blob.refused");

    const hash = nameOf(randomBytes(4));
    await send(alice, PUT, { hash, size: 10 });
    const differs = await send(alice, PUT, { hash, size: 11 });
    expect(differs.body.code).toBe("e.p.blob.refused");

    const outsider = await send(stranger, PUT, { hash: nameOf(randomBytes(5)), size: 10 });
    expect(outsider.type).toBe(PROBLEM);
    expect(outsider.body.code).toBe("e.p.blob.refused");
  });

  it("purges what has expired or lost its mediation", async () => {
    const store = memoryStore();
    await store.grantMediation("did:example:a");
    await store.grantMediation("did:example:b");
    await store.keepBlob("x", "did:example:a", "hx", 10, Date.now() - 1);
    await store.keepBlob("y", "did:example:b", "hy", 10, Date.now() + 60_000);
    await store.keepBlob("z", "did:example:a", "hy", 10, Date.now() - 1);
    expect(await store.blobUsage("did:example:a")).toBe(0);
    expect(await store.blobUsage("did:example:b")).toBe(10);
    // A later keep only ever extends.
    await store.keepBlob("ignored", "did:example:a", "hx", 10, Date.now() + 60_000);
    expect((await store.blobOf("did:example:a", "hx"))?.id).toBe("x");
    expect(await store.blobUsage("did:example:a")).toBe(10);
    expect((await store.purgeBlobs()).sort()).toEqual(["z"]);
    expect(await store.blobById("z")).toBeNull();
    expect((await store.blobById("y"))?.ownerDid).toBe("did:example:b");
    // Ending the mediation ends its blobs too, and purge still learns their ids.
    await store.revokeMediation("did:example:b");
    expect(await store.purgeBlobs()).toEqual(["y"]);
    expect(await store.dropBlob("did:example:a", "hx")).toBe("x");
    expect(await store.dropBlob("did:example:a", "hx")).toBeNull();
    store.close();
  });

  it("resets a database carrying the first, hash-keyed blob schema", async () => {
    const file = join(dir, "old.sqlite");
    const raw = new Database(file);
    raw.exec(
      "CREATE TABLE accounts (did TEXT PRIMARY KEY, created_at INTEGER NOT NULL);" +
        "CREATE TABLE blobs (hash TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL, uploaded_at INTEGER);" +
        "CREATE TABLE blob_holds (owner_did TEXT NOT NULL, hash TEXT NOT NULL, retain_until INTEGER NOT NULL, PRIMARY KEY (owner_did, hash));" +
        "CREATE TABLE blob_uploads (token TEXT PRIMARY KEY, hash TEXT NOT NULL, expires_at INTEGER NOT NULL);" +
        "INSERT INTO blobs VALUES ('bold', 1, 0, 0);"
    );
    raw.close();
    const store = new SqliteStore(file);
    await store.keepBlob("n", "did:example:a", "hn", 1, Date.now() + 1000);
    expect((await store.blobById("n"))?.hash).toBe("hn");
    store.close();
    const check = new Database(file);
    const tables = check.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[];
    expect(tables.map((t) => t.name)).not.toContain("blob_holds");
    expect(check.prepare("SELECT count(*) AS n FROM blobs").get()).toEqual({ n: 1 });
    check.close();
  });

  it("is absent without a blob directory", async () => {
    const bare = buildServer({
      identity: mediator,
      store: memoryStore(),
      config: TEST_CONFIG,
    }).app;
    const body = (await (await bare.request("/")).json()) as Record<string, unknown>;
    expect(body.blobs).toBeUndefined();
    expect(body.protocols).not.toContain("https://estoc.dev/blob-store/1.0");
    expect((await bare.request("/b/" + nameOf(randomBytes(6)))).status).toBe(404);
  });
});
