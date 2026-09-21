import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";

import { SqliteStore } from "../src/store/sqlite.js";

const ALICE = "did:example:alice";
const key = (forwardId: string) => ({ next: ALICE, forwardId });

describe("SqliteStore", () => {
  it("binds a recipient to one owner only", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation("did:example:alice");
    await store.grantMediation("did:example:bob");

    expect(await store.addRecipient("did:example:alice", "did:example:alias")).toBe(
      "added"
    );
    expect(await store.addRecipient("did:example:alice", "did:example:alias")).toBe(
      "already-yours"
    );
    expect(await store.addRecipient("did:example:bob", "did:example:alias")).toBe(
      "taken"
    );
    expect(await store.ownerOf("did:example:alias")).toBe("did:example:alice");
    store.close();
  });

  it("stops storing past the per-account quota", async () => {
    const store = new SqliteStore(":memory:", { maxMessagesPerAccount: 2 });
    await store.grantMediation("did:example:alice");

    expect((await store.storeMessage(ALICE, key("1"), "one")).outcome).toBe("stored");
    expect((await store.storeMessage(ALICE, key("2"), "two")).outcome).toBe("stored");
    expect((await store.storeMessage(ALICE, key("3"), "three")).outcome).toBe("full");
    expect((await store.storeMessage(ALICE, key("2"), "two")).outcome).toBe("repeated");
    expect(await store.messageCount("did:example:alice")).toBe(2);
    store.close();
  });

  it("keeps the first bytes a key was given, per recipient and per account", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation(ALICE);
    await store.grantMediation("did:example:bob");

    expect((await store.storeMessage(ALICE, key("1"), "first")).outcome).toBe("stored");
    expect((await store.storeMessage(ALICE, key("1"), "second")).outcome).toBe("conflict");
    expect(
      (await store.storeMessage(ALICE, { next: "did:example:alias", forwardId: "1" }, "second")).outcome
    ).toBe("stored");
    expect((await store.storeMessage("did:example:bob", key("1"), "second")).outcome).toBe("stored");

    expect((await store.messagesFor(ALICE, 10)).map((m) => m.packed)).toEqual(["first", "second"]);
    store.close();
  });

  it("lets a key be taken again once the mail under it has expired", async () => {
    const store = new SqliteStore(":memory:", { messageTtlSeconds: -1 });
    await store.grantMediation(ALICE);

    expect((await store.storeMessage(ALICE, key("1"), "old")).outcome).toBe("stored");
    expect((await store.storeMessage(ALICE, key("1"), "new")).outcome).toBe("stored");
    store.close();
  });

  it("keys a queue created before packages had keys, and keeps its mail", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mediator-store-"));
    const path = join(dir, "mediator.db");
    const old = new Database(path);
    old.exec(`
      CREATE TABLE accounts (did TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
      CREATE TABLE messages (
        id TEXT PRIMARY KEY,
        owner_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
        packed TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      INSERT INTO accounts VALUES ('${ALICE}', 1);
      INSERT INTO messages VALUES ('a', '${ALICE}', 'one', 1, ${Date.now() + 60_000});
      INSERT INTO messages VALUES ('b', '${ALICE}', 'two', 2, ${Date.now() + 60_000});
    `);
    old.close();

    const store = new SqliteStore(path);
    expect((await store.storeMessage(ALICE, key("1"), "three")).outcome).toBe("stored");
    expect((await store.storeMessage(ALICE, key("1"), "three")).outcome).toBe("repeated");
    expect((await store.messagesFor(ALICE, 10)).map((m) => m.packed)).toEqual(["one", "two", "three"]);
    store.close();

    const reopened = new SqliteStore(path);
    expect(await reopened.messageCount(ALICE)).toBe(3);
    reopened.close();
    rmSync(dir, { recursive: true });
  });

  it("scopes deletion to the owner", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation("did:example:alice");
    await store.grantMediation("did:example:bob");
    const stored = await store.storeMessage(ALICE, key("1"), "hers");
    if (stored.outcome !== "stored") throw new Error(stored.outcome);

    expect(await store.deleteMessages("did:example:bob", [stored.message.id])).toEqual([]);
    expect(await store.messageCount("did:example:alice")).toBe(1);
    store.close();
  });

  it("expires messages by TTL", async () => {
    const store = new SqliteStore(":memory:", { messageTtlSeconds: -1 });
    await store.grantMediation("did:example:alice");
    await store.storeMessage(ALICE, key("1"), "already old");

    expect(await store.messageCount("did:example:alice")).toBe(0);
    expect(await store.purgeExpired()).toBe(1);
    store.close();
  });

  it("takes the keylist and inbox down with the account", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation("did:example:alice");
    await store.addRecipient("did:example:alice", "did:example:alias");
    await store.storeMessage(ALICE, key("1"), "waiting");

    await store.revokeMediation("did:example:alice");
    expect(await store.ownerOf("did:example:alias")).toBeNull();
    expect(await store.isMediated("did:example:alice")).toBe(false);
    store.close();
  });
});
