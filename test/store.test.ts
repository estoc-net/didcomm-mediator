import { describe, expect, it } from "vitest";

import { SqliteStore } from "../src/store/sqlite.js";

describe("SqliteStore", () => {
  it("binds a recipient to one owner only", () => {
    const store = new SqliteStore(":memory:");
    store.grantMediation("did:example:alice");
    store.grantMediation("did:example:bob");

    expect(store.addRecipient("did:example:alice", "did:example:alias")).toBe(
      "added"
    );
    expect(store.addRecipient("did:example:alice", "did:example:alias")).toBe(
      "already-yours"
    );
    expect(store.addRecipient("did:example:bob", "did:example:alias")).toBe(
      "taken"
    );
    expect(store.ownerOf("did:example:alias")).toBe("did:example:alice");
    store.close();
  });

  it("stops storing past the per-account quota", () => {
    const store = new SqliteStore(":memory:", { maxMessagesPerAccount: 2 });
    store.grantMediation("did:example:alice");

    expect(store.storeMessage("did:example:alice", "one")).not.toBeNull();
    expect(store.storeMessage("did:example:alice", "two")).not.toBeNull();
    expect(store.storeMessage("did:example:alice", "three")).toBeNull();
    expect(store.messageCount("did:example:alice")).toBe(2);
    store.close();
  });

  it("scopes deletion to the owner", () => {
    const store = new SqliteStore(":memory:");
    store.grantMediation("did:example:alice");
    store.grantMediation("did:example:bob");
    const id = store.storeMessage("did:example:alice", "hers");
    expect(id).not.toBeNull();

    expect(store.deleteMessages("did:example:bob", [id as string])).toEqual([]);
    expect(store.messageCount("did:example:alice")).toBe(1);
    store.close();
  });

  it("expires messages by TTL", () => {
    const store = new SqliteStore(":memory:", { messageTtlSeconds: -1 });
    store.grantMediation("did:example:alice");
    store.storeMessage("did:example:alice", "already old");

    expect(store.messageCount("did:example:alice")).toBe(0);
    expect(store.purgeExpired()).toBe(1);
    store.close();
  });

  it("takes the keylist and inbox down with the account", () => {
    const store = new SqliteStore(":memory:");
    store.grantMediation("did:example:alice");
    store.addRecipient("did:example:alice", "did:example:alias");
    store.storeMessage("did:example:alice", "waiting");

    store.revokeMediation("did:example:alice");
    expect(store.ownerOf("did:example:alias")).toBeNull();
    expect(store.isMediated("did:example:alice")).toBe(false);
    store.close();
  });
});
