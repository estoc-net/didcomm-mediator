import { describe, expect, it } from "vitest";

import { SqliteStore } from "../src/store/sqlite.js";

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

    expect(await store.storeMessage("did:example:alice", "one")).not.toBeNull();
    expect(await store.storeMessage("did:example:alice", "two")).not.toBeNull();
    expect(await store.storeMessage("did:example:alice", "three")).toBeNull();
    expect(await store.messageCount("did:example:alice")).toBe(2);
    store.close();
  });

  it("scopes deletion to the owner", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation("did:example:alice");
    await store.grantMediation("did:example:bob");
    const id = await store.storeMessage("did:example:alice", "hers");
    expect(id).not.toBeNull();

    expect(await store.deleteMessages("did:example:bob", [id as string])).toEqual(
      []
    );
    expect(await store.messageCount("did:example:alice")).toBe(1);
    store.close();
  });

  it("expires messages by TTL", async () => {
    const store = new SqliteStore(":memory:", { messageTtlSeconds: -1 });
    await store.grantMediation("did:example:alice");
    await store.storeMessage("did:example:alice", "already old");

    expect(await store.messageCount("did:example:alice")).toBe(0);
    expect(await store.purgeExpired()).toBe(1);
    store.close();
  });

  it("refcounts public-folder objects: referenced survive the purge, orphans go", async () => {
    const store = new SqliteStore(":memory:", { stagedObjectTtlSeconds: -1 });
    const bytes = new TextEncoder().encode("content");
    await store.putObject("cid-kept", bytes);
    await store.putObject("cid-orphan", bytes);
    await store.putCard("did:example:alice", "jws", "cid-kept", ["cid-kept"]);

    expect(await store.purgeExpired()).toBe(1);
    expect(await store.getObject("cid-kept")).not.toBeNull();
    expect(await store.getObject("cid-orphan")).toBeNull();

    // A new closure frees the old one's references.
    await store.putCard("did:example:alice", "jws2", null, []);
    expect(await store.purgeExpired()).toBe(1);
    expect(await store.getObject("cid-kept")).toBeNull();
    expect((await store.getCard("did:example:alice"))?.root).toBeNull();
    store.close();
  });

  it("takes the keylist and inbox down with the account", async () => {
    const store = new SqliteStore(":memory:");
    await store.grantMediation("did:example:alice");
    await store.addRecipient("did:example:alice", "did:example:alias");
    await store.storeMessage("did:example:alice", "waiting");

    await store.revokeMediation("did:example:alice");
    expect(await store.ownerOf("did:example:alias")).toBeNull();
    expect(await store.isMediated("did:example:alice")).toBe(false);
    store.close();
  });
});
