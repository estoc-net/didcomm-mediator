import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";

import { chunked } from "./types.js";
import type {
  AddRecipientResult,
  MediationStore,
  PolicyAuditEntry,
  PolicyKind,
  PolicyRule,
  RecipientPage,
  StoredCard,
  StoredMessage,
} from "./types.js";

export interface SqliteStoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
  /** Unreferenced public-folder objects older than this are purged. */
  stagedObjectTtlSeconds?: number;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;
const DEFAULT_STAGED_OBJECT_TTL_SECONDS = 7 * 24 * 60 * 60;

export class SqliteStore implements MediationStore {
  private db: Database.Database;
  private ttlMs: number;
  private maxMessages: number;
  private stagedTtlMs: number;

  /** `path` is a file path, or ":memory:" for tests. */
  constructor(path: string, options: SqliteStoreOptions = {}) {
    this.db = new Database(path);
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;
    this.stagedTtlMs =
      (options.stagedObjectTtlSeconds ?? DEFAULT_STAGED_OBJECT_TTL_SECONDS) * 1000;

    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS accounts (
        did        TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS keylist (
        recipient_did TEXT PRIMARY KEY,
        owner_did     TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
        created_at    INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS keylist_owner ON keylist(owner_did);
      CREATE TABLE IF NOT EXISTS messages (
        id         TEXT PRIMARY KEY,
        owner_did  TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
        packed     TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner_did, created_at);
      CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at);
      CREATE TABLE IF NOT EXISTS identity (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        secrets    TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pf_cards (
        owner_did  TEXT PRIMARY KEY,
        card       TEXT NOT NULL,
        root       TEXT,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pf_objects (
        cid        TEXT PRIMARY KEY,
        bytes      BLOB,
        size       INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        store      TEXT NOT NULL DEFAULT 'inline'
      );
      CREATE TABLE IF NOT EXISTS pf_refs (
        owner_did TEXT NOT NULL,
        cid       TEXT NOT NULL,
        PRIMARY KEY (owner_did, cid)
      );
      CREATE INDEX IF NOT EXISTS pf_refs_cid ON pf_refs(cid);
      CREATE TABLE IF NOT EXISTS pf_policy (
        kind       TEXT NOT NULL,
        subject    TEXT NOT NULL,
        mode       TEXT NOT NULL,
        hold_until INTEGER,
        note       TEXT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (kind, subject)
      );
      CREATE TABLE IF NOT EXISTS pf_audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        at         INTEGER NOT NULL,
        action     TEXT NOT NULL,
        kind       TEXT NOT NULL,
        subject    TEXT NOT NULL,
        mode       TEXT,
        hold_until INTEGER,
        note       TEXT
      );
    `);

    // Each row declares where its bytes live: 'inline' = the row's own bytes
    // column; other names are external backends (the Workers store has 'r2').
    // The first public-folder version predates the column and had bytes NOT
    // NULL — rebuild once, keeping every stored object.
    const table = this.db
      .prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pf_objects'"
      )
      .get() as { sql: string };
    if (/bytes\s+BLOB\s+NOT\s+NULL/i.test(table.sql)) {
      this.db.exec(`
        BEGIN;
        ALTER TABLE pf_objects RENAME TO pf_objects_legacy;
        CREATE TABLE pf_objects (
          cid        TEXT PRIMARY KEY,
          bytes      BLOB,
          size       INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          store      TEXT NOT NULL DEFAULT 'inline'
        );
        INSERT INTO pf_objects (cid, bytes, size, created_at, store)
          SELECT cid, bytes, size, created_at, 'inline' FROM pf_objects_legacy;
        DROP TABLE pf_objects_legacy;
        COMMIT;
      `);
    }
  }

  async loadIdentity(): Promise<string | null> {
    const row = this.db
      .prepare("SELECT secrets FROM identity WHERE id = 1")
      .get() as { secrets: string } | undefined;
    return row?.secrets ?? null;
  }

  async initIdentity(secretsJson: string): Promise<string> {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO identity (id, secrets, created_at) VALUES (1, ?, ?)"
      )
      .run(secretsJson, Date.now());
    const winner = await this.loadIdentity();
    if (winner === null) {
      throw new Error("The identity row vanished between insert and read");
    }
    return winner;
  }

  async grantMediation(did: string): Promise<void> {
    this.db
      .prepare("INSERT OR IGNORE INTO accounts (did, created_at) VALUES (?, ?)")
      .run(did, Date.now());
  }

  async revokeMediation(did: string): Promise<void> {
    // Cascades: the keylist entries and waiting messages go with the account.
    this.db.prepare("DELETE FROM accounts WHERE did = ?").run(did);
  }

  async isMediated(did: string): Promise<boolean> {
    return (
      this.db.prepare("SELECT 1 FROM accounts WHERE did = ?").get(did) !==
      undefined
    );
  }

  async addRecipient(
    ownerDid: string,
    recipientDid: string
  ): Promise<AddRecipientResult> {
    const existing = this.db
      .prepare("SELECT owner_did FROM keylist WHERE recipient_did = ?")
      .get(recipientDid) as { owner_did: string } | undefined;

    if (existing !== undefined) {
      return existing.owner_did === ownerDid ? "already-yours" : "taken";
    }

    this.db
      .prepare(
        "INSERT INTO keylist (recipient_did, owner_did, created_at) VALUES (?, ?, ?)"
      )
      .run(recipientDid, ownerDid, Date.now());
    return "added";
  }

  async removeRecipient(ownerDid: string, recipientDid: string): Promise<boolean> {
    return (
      this.db
        .prepare(
          "DELETE FROM keylist WHERE recipient_did = ? AND owner_did = ?"
        )
        .run(recipientDid, ownerDid).changes > 0
    );
  }

  async listRecipients(
    ownerDid: string,
    offset: number,
    limit: number
  ): Promise<RecipientPage> {
    const rows = this.db
      .prepare(
        "SELECT recipient_did FROM keylist WHERE owner_did = ? " +
          "ORDER BY created_at, recipient_did LIMIT ? OFFSET ?"
      )
      .all(ownerDid, limit, offset) as { recipient_did: string }[];

    const total = (
      this.db
        .prepare("SELECT COUNT(*) AS n FROM keylist WHERE owner_did = ?")
        .get(ownerDid) as { n: number }
    ).n;

    return {
      recipients: rows.map((row) => row.recipient_did),
      remaining: Math.max(0, total - offset - rows.length),
    };
  }

  async ownerOf(recipientDid: string): Promise<string | null> {
    const row = this.db
      .prepare("SELECT owner_did FROM keylist WHERE recipient_did = ?")
      .get(recipientDid) as { owner_did: string } | undefined;
    return row?.owner_did ?? null;
  }

  async storeMessage(ownerDid: string, packed: string): Promise<string | null> {
    if (this.countNow(ownerDid) >= this.maxMessages) {
      return null;
    }

    const id = randomUUID();
    const now = Date.now();
    this.db
      .prepare(
        "INSERT INTO messages (id, owner_did, packed, created_at, expires_at) " +
          "VALUES (?, ?, ?, ?, ?)"
      )
      .run(id, ownerDid, packed, now, now + this.ttlMs);
    return id;
  }

  async messageCount(ownerDid: string): Promise<number> {
    return this.countNow(ownerDid);
  }

  private countNow(ownerDid: string): number {
    return (
      this.db
        .prepare(
          "SELECT COUNT(*) AS n FROM messages WHERE owner_did = ? AND expires_at > ?"
        )
        .get(ownerDid, Date.now()) as { n: number }
    ).n;
  }

  async messagesFor(ownerDid: string, limit: number): Promise<StoredMessage[]> {
    const rows = this.db
      .prepare(
        "SELECT id, packed, created_at FROM messages " +
          "WHERE owner_did = ? AND expires_at > ? ORDER BY created_at LIMIT ?"
      )
      .all(ownerDid, Date.now(), limit) as {
      id: string;
      packed: string;
      created_at: number;
    }[];

    return rows.map((row) => ({
      id: row.id,
      packed: row.packed,
      createdAt: row.created_at,
    }));
  }

  async deleteMessages(ownerDid: string, ids: string[]): Promise<string[]> {
    const remove = this.db.prepare(
      "DELETE FROM messages WHERE id = ? AND owner_did = ?"
    );

    const deleted: string[] = [];
    const all = this.db.transaction((wanted: string[]) => {
      for (const id of wanted) {
        if (remove.run(id, ownerDid).changes > 0) {
          deleted.push(id);
        }
      }
    });
    all(ids);
    return deleted;
  }

  async getCard(ownerDid: string): Promise<StoredCard | null> {
    const row = this.db
      .prepare("SELECT card, root FROM pf_cards WHERE owner_did = ?")
      .get(ownerDid) as { card: string; root: string | null } | undefined;
    return row === undefined ? null : { card: row.card, root: row.root };
  }

  async putCard(
    ownerDid: string,
    cardJws: string,
    root: string | null,
    closure: string[]
  ): Promise<void> {
    const upsert = this.db.prepare(
      "INSERT INTO pf_cards (owner_did, card, root, updated_at) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT(owner_did) DO UPDATE SET card = excluded.card, " +
        "root = excluded.root, updated_at = excluded.updated_at"
    );
    const clear = this.db.prepare("DELETE FROM pf_refs WHERE owner_did = ?");
    const ref = this.db.prepare(
      "INSERT OR IGNORE INTO pf_refs (owner_did, cid) VALUES (?, ?)"
    );

    this.db.transaction(() => {
      upsert.run(ownerDid, cardJws, root, Date.now());
      clear.run(ownerDid);
      for (const cid of closure) {
        ref.run(ownerDid, cid);
      }
    })();
  }

  async putObject(cid: string, bytes: Uint8Array): Promise<void> {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO pf_objects (cid, bytes, size, created_at, store) " +
          "VALUES (?, ?, ?, ?, 'inline')"
      )
      .run(cid, Buffer.from(bytes), bytes.length, Date.now());
  }

  async getObject(cid: string): Promise<Uint8Array | null> {
    const row = this.db
      .prepare("SELECT bytes, store FROM pf_objects WHERE cid = ?")
      .get(cid) as { bytes: Buffer | null; store: string } | undefined;
    if (row === undefined) {
      return null;
    }
    // A backend this build cannot reach (or a corrupt inline row) is a
    // storage hole; the protocol layer reports it as e.p.me.res.storage.
    if (row.store !== "inline" || row.bytes === null) {
      return null;
    }
    return new Uint8Array(row.bytes);
  }

  async objectsPresent(cids: string[]): Promise<Map<string, number>> {
    const present = new Map<string, number>();
    for (const chunk of chunked(cids)) {
      const rows = this.db
        .prepare(
          `SELECT cid, size FROM pf_objects WHERE cid IN (${chunk.map(() => "?").join(", ")})`
        )
        .all(...chunk) as { cid: string; size: number }[];
      for (const row of rows) {
        present.set(row.cid, row.size);
      }
    }
    return present;
  }

  async purgeExpired(): Promise<number> {
    const messages = this.db
      .prepare("DELETE FROM messages WHERE expires_at <= ?")
      .run(Date.now()).changes;
    // Objects nothing references any more: staged for a publish that never
    // finished, or freed when a newer card replaced their closure. The grace
    // period keeps multi-round publishes and the cache courtesy alive. A
    // live policy hold pins the object regardless — quarantined evidence
    // outlives its references.
    const objects = this.db
      .prepare(
        "DELETE FROM pf_objects WHERE created_at <= ? " +
          "AND cid NOT IN (SELECT cid FROM pf_refs) " +
          "AND cid NOT IN (SELECT subject FROM pf_policy WHERE kind = 'cid' AND hold_until > ?)"
      )
      .run(Date.now() - this.stagedTtlMs, Date.now()).changes;
    return messages + objects;
  }

  async setPolicyRule(rule: Omit<PolicyRule, "createdAt">): Promise<void> {
    const now = Date.now();
    this.db.transaction(() => {
      this.db
        .prepare(
          "INSERT INTO pf_policy (kind, subject, mode, hold_until, note, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT(kind, subject) DO UPDATE SET mode = excluded.mode, " +
            "hold_until = excluded.hold_until, note = excluded.note"
        )
        .run(rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note, now);
      this.db
        .prepare(
          "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
            "VALUES (?, 'set', ?, ?, ?, ?, ?)"
        )
        .run(now, rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note);
    })();
  }

  async clearPolicyRule(kind: PolicyKind, subject: string): Promise<boolean> {
    let existed = false;
    this.db.transaction(() => {
      existed =
        this.db
          .prepare("DELETE FROM pf_policy WHERE kind = ? AND subject = ?")
          .run(kind, subject).changes > 0;
      if (existed) {
        this.db
          .prepare(
            "INSERT INTO pf_audit (at, action, kind, subject) VALUES (?, 'clear', ?, ?)"
          )
          .run(Date.now(), kind, subject);
      }
    })();
    return existed;
  }

  async policyRules(
    kind: PolicyKind,
    subjects: string[]
  ): Promise<Map<string, PolicyRule>> {
    const rules = new Map<string, PolicyRule>();
    for (const chunk of chunked(subjects)) {
      const rows = this.db
        .prepare(
          "SELECT subject, mode, hold_until, note, created_at FROM pf_policy " +
            `WHERE kind = ? AND subject IN (${chunk.map(() => "?").join(", ")})`
        )
        .all(kind, ...chunk) as {
        subject: string;
        mode: string;
        hold_until: number | null;
        note: string | null;
        created_at: number;
      }[];
      for (const row of rows) {
        rules.set(row.subject, {
          kind,
          subject: row.subject,
          mode: row.mode as PolicyRule["mode"],
          holdUntil: row.hold_until,
          note: row.note,
          createdAt: row.created_at,
        });
      }
    }
    return rules;
  }

  async listPolicyRules(): Promise<PolicyRule[]> {
    const rows = this.db
      .prepare(
        "SELECT kind, subject, mode, hold_until, note, created_at FROM pf_policy " +
          "ORDER BY created_at, kind, subject"
      )
      .all() as {
      kind: string;
      subject: string;
      mode: string;
      hold_until: number | null;
      note: string | null;
      created_at: number;
    }[];
    return rows.map((row) => ({
      kind: row.kind as PolicyKind,
      subject: row.subject,
      mode: row.mode as PolicyRule["mode"],
      holdUntil: row.hold_until,
      note: row.note,
      createdAt: row.created_at,
    }));
  }

  async policyAudit(limit: number): Promise<PolicyAuditEntry[]> {
    const rows = this.db
      .prepare(
        "SELECT at, action, kind, subject, mode, hold_until, note FROM pf_audit " +
          "ORDER BY id DESC LIMIT ?"
      )
      .all(limit) as {
      at: number;
      action: string;
      kind: string;
      subject: string;
      mode: string | null;
      hold_until: number | null;
      note: string | null;
    }[];
    return rows.map((row) => ({
      at: row.at,
      action: row.action as PolicyAuditEntry["action"],
      kind: row.kind as PolicyKind,
      subject: row.subject,
      mode: row.mode as PolicyAuditEntry["mode"],
      holdUntil: row.hold_until,
      note: row.note,
    }));
  }

  async referencingOwners(cid: string): Promise<string[]> {
    const rows = this.db
      .prepare("SELECT owner_did FROM pf_refs WHERE cid = ?")
      .all(cid) as { owner_did: string }[];
    return rows.map((row) => row.owner_did);
  }

  async closureOf(ownerDid: string): Promise<string[]> {
    const rows = this.db
      .prepare("SELECT cid FROM pf_refs WHERE owner_did = ?")
      .all(ownerDid) as { cid: string }[];
    return rows.map((row) => row.cid);
  }

  close(): void {
    this.db.close();
  }
}
