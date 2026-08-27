import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Hono } from "hono";
import type { IMessage } from "didcomm-node";

import { blobDigest, blobName } from "../src/blobs/hash.js";
import { buildServer } from "../src/server.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import { TEST_CONFIG, agent, memoryStore, plaintext, type TestAgent } from "./helpers.js";

const ENCRYPTED = "application/didcomm-encrypted+json";
const PUT = "https://estoc.dev/blob-store/1.0/put";
const DELETE = "https://estoc.dev/blob-store/1.0/delete";
const PROBLEM = "https://didcomm.org/report-problem/2.0/problem-report";

let dir: string;
let app: Hono;
let mediator: MediatorIdentity;
let alice: TestAgent;
let stranger: TestAgent;

function nameOf(bytes: Uint8Array): string {
  return blobName(createHash("sha256").update(bytes).digest());
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "mediator-blobs-"));
  mediator = await mintIdentity(TEST_CONFIG.publicUrl, "peer2");
  alice = await agent("alice");
  stranger = await agent("stranger");
  app = buildServer({
    identity: mediator,
    store: memoryStore(),
    config: { ...TEST_CONFIG, blobDir: dir },
  }).app;
  await send(alice, "https://didcomm.org/coordinate-mediation/3.0/mediate-request", {});
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
    expect(result.body.url).toBe(`${TEST_CONFIG.publicUrl}/b/${hash}`);
    expect(Date.parse(result.body.retain_until as string)).toBeGreaterThan(Date.now());
    const upload = result.body.upload as { url: string; expires: string };
    expect(upload.url.startsWith(`${TEST_CONFIG.publicUrl}/b/${hash}?token=`)).toBe(true);

    // Nothing to read before the bytes arrive.
    expect((await app.request(`/b/${hash}`)).status).toBe(404);

    // Wrong bytes under the token: refused, token spent, still 404.
    const wrong = await app.request(path(upload.url), {
      method: "PUT",
      headers: { "content-length": String(bytes.length) },
      body: randomBytes(3000),
    });
    expect(wrong.status).toBe(400);
    expect((await app.request(`/b/${hash}`)).status).toBe(404);

    // A fresh put hands out a fresh token; the right bytes land.
    const again = await send(alice, PUT, { hash, size: bytes.length });
    const upload2 = again.body.upload as { url: string };
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

    const whole = await app.request(`/b/${hash}`);
    expect(whole.status).toBe(200);
    expect(whole.headers.get("accept-ranges")).toBe("bytes");
    expect(Buffer.from(await whole.arrayBuffer())).toEqual(bytes);

    const head = await app.request(`/b/${hash}`, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe("3000");

    const part = await app.request(`/b/${hash}`, { headers: { range: "bytes=100-199" } });
    expect(part.status).toBe(206);
    expect(part.headers.get("content-range")).toBe("bytes 100-199/3000");
    expect(Buffer.from(await part.arrayBuffer())).toEqual(bytes.subarray(100, 200));

    const tail = await app.request(`/b/${hash}`, { headers: { range: "bytes=2990-" } });
    expect(tail.status).toBe(206);
    expect(Buffer.from(await tail.arrayBuffer())).toEqual(bytes.subarray(2990));

    const beyond = await app.request(`/b/${hash}`, { headers: { range: "bytes=5000-" } });
    expect(beyond.status).toBe(416);

    // Renewal: no upload, same URL.
    const renewed = await send(alice, PUT, { hash, size: bytes.length });
    expect(renewed.body.upload).toBeUndefined();
    expect(renewed.body.url).toBe(result.body.url);

    // Delete releases the hold; unheld, the blob is gone from the URL.
    const deleted = await send(alice, DELETE, { hash });
    expect(deleted.type).toBe("https://estoc.dev/blob-store/1.0/delete-result");
    expect(deleted.body).toEqual({ hash });
    expect((await app.request(`/b/${hash}`)).status).toBe(404);
    // Deleting again is not an error.
    expect((await send(alice, DELETE, { hash })).body).toEqual({ hash });
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

  it("purges what nobody holds any more", async () => {
    const store = memoryStore();
    await store.grantMediation("did:example:a");
    await store.grantMediation("did:example:b");
    await store.holdBlob("did:example:a", "x", 10, Date.now() - 1);
    await store.holdBlob("did:example:b", "y", 10, Date.now() + 60_000);
    await store.holdBlob("did:example:a", "y", 10, Date.now() - 1);
    expect(await store.blobUsage("did:example:a")).toBe(0);
    expect(await store.blobUsage("did:example:b")).toBe(10);
    expect(await store.purgeBlobs()).toEqual(["x"]);
    expect(await store.blobInfo("x")).toBeNull();
    expect((await store.blobInfo("y"))?.size).toBe(10);
    // Ending the mediation ends its holds too.
    await store.revokeMediation("did:example:b");
    expect(await store.purgeBlobs()).toEqual(["y"]);
    store.close();
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
