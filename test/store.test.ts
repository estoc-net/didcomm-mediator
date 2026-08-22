import { randomUUID } from "node:crypto";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
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

  it("keeps every policy change on the audit trail", async () => {
    const store = new SqliteStore(":memory:");
    await store.setPolicyRule({
      kind: "did",
      subject: "did:example:bad",
      mode: "block",
      holdUntil: null,
      note: "report #1",
    });
    await store.setPolicyRule({
      kind: "cid",
      subject: "cid-evidence",
      mode: "block",
      holdUntil: Date.now() + 3600 * 1000,
      note: null,
    });

    const rules = await store.policyRules("did", ["did:example:bad"]);
    expect(rules.get("did:example:bad")?.mode).toBe("block");
    expect(rules.get("did:example:bad")?.note).toBe("report #1");
    expect((await store.listPolicyRules()).length).toBe(2);

    expect(await store.clearPolicyRule("did", "did:example:bad")).toBe(true);
    expect(await store.clearPolicyRule("did", "did:example:bad")).toBe(false);
    expect((await store.policyRules("did", ["did:example:bad"])).size).toBe(0);

    // Most recent first; the no-op clear left no line.
    const audit = await store.policyAudit(10);
    expect(audit.map((entry) => entry.action)).toEqual(["clear", "set", "set"]);
    expect(audit[0].subject).toBe("did:example:bad");
    expect(audit[1].holdUntil).not.toBeNull();
    store.close();
  });

  it("a policy hold pins an orphaned object through the purge", async () => {
    const store = new SqliteStore(":memory:", { stagedObjectTtlSeconds: -1 });
    const bytes = new TextEncoder().encode("evidence");
    await store.putObject("cid-held", bytes);
    await store.setPolicyRule({
      kind: "cid",
      subject: "cid-held",
      mode: "block",
      holdUntil: Date.now() + 3600 * 1000,
      note: null,
    });

    // Unreferenced and past the grace period — only the hold keeps it.
    expect(await store.purgeExpired()).toBe(0);
    expect(await store.getObject("cid-held")).not.toBeNull();

    // Hold lapsed (rule may stay): the object is reclaimable again.
    await store.setPolicyRule({
      kind: "cid",
      subject: "cid-held",
      mode: "block",
      holdUntil: Date.now() - 1,
      note: null,
    });
    expect(await store.purgeExpired()).toBe(1);
    expect(await store.getObject("cid-held")).toBeNull();
    store.close();
  });

  it("migrates a legacy pf_objects table, keeping stored objects", async () => {
    const path = join(tmpdir(), `mediator-migration-${randomUUID()}.db`);
    // The first public-folder version: bytes NOT NULL, no store column.
    const legacy = new Database(path);
    legacy.exec(`
      CREATE TABLE pf_objects (
        cid        TEXT PRIMARY KEY,
        bytes      BLOB NOT NULL,
        size       INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
    legacy
      .prepare("INSERT INTO pf_objects VALUES (?, ?, ?, ?)")
      .run("cid-legacy", Buffer.from("held"), 4, Date.now());
    legacy.close();

    const store = new SqliteStore(path);
    expect(Array.from(await store.getObject("cid-legacy") ?? [])).toEqual(
      Array.from(Buffer.from("held"))
    );
    await store.putObject("cid-new", new TextEncoder().encode("fresh"));
    expect(await store.getObject("cid-new")).not.toBeNull();
    expect((await store.objectsPresent(["cid-legacy", "cid-new"])).size).toBe(2);
    store.close();
    rmSync(path, { force: true });
    rmSync(`${path}-wal`, { force: true });
    rmSync(`${path}-shm`, { force: true });
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
