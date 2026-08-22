/**
 * One mediator store, many SQLite dialects.
 *
 * better-sqlite3 and Cloudflare D1 *are* SQLite — the schema and every query
 * are identical, so the store is written once against the narrowest contract
 * the backends share: a batch of statements that runs in order as one
 * transaction. That is D1's only transaction shape; better-sqlite3's
 * transactions are a superset, and every transactional path here fits it.
 * Drivers translate only the calling convention. Object bytes may live in an
 * external BlobStore (the Workers target's R2) — the rows keep the metadata
 * and each row's `store` column declares where its bytes went.
 *
 * The schema is ensured lazily on first use instead of by a migrations step,
 * so a fresh deploy needs nothing beyond an empty database; a failed ensure
 * (D1 hiccup, lost migration race) must not poison the process — the next
 * call retries from scratch.
 */

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

export type SqlValue = string | number | null | Uint8Array;

export interface SqlStatement {
  sql: string;
  params?: SqlValue[];
}

export interface SqlResult {
  rows: Record<string, unknown>[];
  /**
   * Rows the statement modified. A driver that cannot know (wrangler's JSON
   * omits it) reports 0 — fine for the policy CLI, whose paths never read it.
   */
  changes: number;
}

/** What a backend must do: run a list of statements as ONE transaction. */
export interface SqlDriver {
  batch(statements: SqlStatement[]): Promise<SqlResult[]>;
  close(): void;
}

/** An external home for object bytes; the pf_objects row keeps the metadata. */
export interface BlobStore {
  /** The backend name rows written through this store declare in `store`. */
  name: string;
  put(cid: string, bytes: Uint8Array): Promise<void>;
  get(cid: string): Promise<Uint8Array | null>;
  delete(cids: string[]): Promise<void>;
}

export interface SqlStoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
  /** Unreferenced public-folder objects older than this are purged. */
  stagedObjectTtlSeconds?: number;
  /** External home for object bytes; without it they live as row blobs. */
  blobs?: BlobStore;
  /**
   * The live mediator ensures its schema on first use (the default); an
   * admin tool visiting a database the mediator owns can skip the round trip.
   */
  ensureSchema?: boolean;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;
const DEFAULT_STAGED_OBJECT_TTL_SECONDS = 7 * 24 * 60 * 60;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS accounts (
     did        TEXT PRIMARY KEY,
     created_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS keylist (
     recipient_did TEXT PRIMARY KEY,
     owner_did     TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
     created_at    INTEGER NOT NULL
   )`,
  "CREATE INDEX IF NOT EXISTS keylist_owner ON keylist(owner_did)",
  `CREATE TABLE IF NOT EXISTS messages (
     id         TEXT PRIMARY KEY,
     owner_did  TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
     packed     TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  "CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner_did, created_at)",
  "CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at)",
  `CREATE TABLE IF NOT EXISTS identity (
     id         INTEGER PRIMARY KEY CHECK (id = 1),
     secrets    TEXT NOT NULL,
     created_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS pf_cards (
     owner_did  TEXT PRIMARY KEY,
     card       TEXT NOT NULL,
     root       TEXT,
     updated_at INTEGER NOT NULL
   )`,
  // Each row declares where its bytes live: 'inline' = the row's own bytes
  // column (then bytes is non-null), other names are external backends (the
  // Workers store's 'r2'). Future backends add names, never NULL conventions.
  `CREATE TABLE IF NOT EXISTS pf_objects (
     cid        TEXT PRIMARY KEY,
     bytes      BLOB,
     size       INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     store      TEXT NOT NULL DEFAULT 'inline'
   )`,
  `CREATE TABLE IF NOT EXISTS pf_refs (
     owner_did TEXT NOT NULL,
     cid       TEXT NOT NULL,
     PRIMARY KEY (owner_did, cid)
   )`,
  "CREATE INDEX IF NOT EXISTS pf_refs_cid ON pf_refs(cid)",
  `CREATE TABLE IF NOT EXISTS pf_policy (
     kind       TEXT NOT NULL,
     subject    TEXT NOT NULL,
     mode       TEXT NOT NULL,
     hold_until INTEGER,
     note       TEXT,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (kind, subject)
   )`,
  `CREATE TABLE IF NOT EXISTS pf_audit (
     id         INTEGER PRIMARY KEY AUTOINCREMENT,
     at         INTEGER NOT NULL,
     action     TEXT NOT NULL,
     kind       TEXT NOT NULL,
     subject    TEXT NOT NULL,
     mode       TEXT,
     hold_until INTEGER,
     note       TEXT
   )`,
];

/*
 * Two earlier pf_objects schemas exist in the wild. The first public-folder
 * version had `bytes BLOB NOT NULL` — fatal under an external blob backend,
 * because the metadata rows insert bytes as NULL and INSERT OR IGNORE
 * swallows the constraint violation *silently*; rebuild to the current
 * shape, keeping every stored object. The brief second version made bytes
 * nullable but encoded the backend implicitly as bytes-IS-NULL; give it the
 * explicit store column and backfill. Each migration is one batch = one
 * transaction; if a concurrent isolate wins the race this one throws, the
 * next call retries, and the re-read sees the new schema.
 */
async function ensureSchema(driver: SqlDriver): Promise<void> {
  await driver.batch(SCHEMA.map((sql) => ({ sql })));

  const [probe] = await driver.batch([
    {
      sql: "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pf_objects'",
    },
  ]);
  const table = probe.rows[0] as { sql: string } | undefined;
  if (table !== undefined && /bytes\s+BLOB\s+NOT\s+NULL/i.test(table.sql)) {
    await driver.batch(
      [
        "ALTER TABLE pf_objects RENAME TO pf_objects_legacy",
        `CREATE TABLE pf_objects (
           cid        TEXT PRIMARY KEY,
           bytes      BLOB,
           size       INTEGER NOT NULL,
           created_at INTEGER NOT NULL,
           store      TEXT NOT NULL DEFAULT 'inline'
         )`,
        "INSERT INTO pf_objects (cid, bytes, size, created_at, store) " +
          "SELECT cid, bytes, size, created_at, 'inline' FROM pf_objects_legacy",
        "DROP TABLE pf_objects_legacy",
      ].map((sql) => ({ sql }))
    );
  } else if (table !== undefined && !/store\s+TEXT/i.test(table.sql)) {
    await driver.batch([
      {
        sql: "ALTER TABLE pf_objects ADD COLUMN store TEXT NOT NULL DEFAULT 'inline'",
      },
      { sql: "UPDATE pf_objects SET store = 'r2' WHERE bytes IS NULL" },
    ]);
  }
}

/**
 * Blob columns come back as Buffer (better-sqlite3), ArrayBuffer, or a plain
 * number array (D1 has answered with both across versions).
 */
function toBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value as number[]);
  }
  return null;
}

export class SqlStore implements MediationStore {
  private ttlMs: number;
  private maxMessages: number;
  private stagedTtlMs: number;
  private blobs: BlobStore | null;
  private ensure: boolean;
  private ready: Promise<void> | null = null;

  constructor(
    private driver: SqlDriver,
    options: SqlStoreOptions = {}
  ) {
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;
    this.stagedTtlMs =
      (options.stagedObjectTtlSeconds ?? DEFAULT_STAGED_OBJECT_TTL_SECONDS) * 1000;
    this.blobs = options.blobs ?? null;
    this.ensure = options.ensureSchema ?? true;
  }

  private init(): Promise<void> {
    if (this.ready === null) {
      this.ready = this.ensure ? ensureSchema(this.driver) : Promise.resolve();
      this.ready.catch(() => {
        this.ready = null;
      });
    }
    return this.ready;
  }

  private async batch(statements: SqlStatement[]): Promise<SqlResult[]> {
    await this.init();
    if (statements.length === 0) {
      return [];
    }
    return this.driver.batch(statements);
  }

  private async all<T>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    const [result] = await this.batch([{ sql, params }]);
    return result.rows as T[];
  }

  private async first<T>(sql: string, params: SqlValue[] = []): Promise<T | null> {
    const rows = await this.all<T>(sql, params);
    return rows[0] ?? null;
  }

  /** Runs one statement; returns its changes count. */
  private async run(sql: string, params: SqlValue[] = []): Promise<number> {
    const [result] = await this.batch([{ sql, params }]);
    return result.changes;
  }

  async loadIdentity(): Promise<string | null> {
    const row = await this.first<{ secrets: string }>(
      "SELECT secrets FROM identity WHERE id = 1"
    );
    return row?.secrets ?? null;
  }

  async initIdentity(secretsJson: string): Promise<string> {
    await this.run(
      "INSERT OR IGNORE INTO identity (id, secrets, created_at) VALUES (1, ?, ?)",
      [secretsJson, Date.now()]
    );
    const winner = await this.loadIdentity();
    if (winner === null) {
      throw new Error("The identity row vanished between insert and read");
    }
    return winner;
  }

  async grantMediation(did: string): Promise<void> {
    await this.run(
      "INSERT OR IGNORE INTO accounts (did, created_at) VALUES (?, ?)",
      [did, Date.now()]
    );
  }

  async revokeMediation(did: string): Promise<void> {
    // Cascades: the keylist entries and waiting messages go with the account.
    await this.run("DELETE FROM accounts WHERE did = ?", [did]);
  }

  async isMediated(did: string): Promise<boolean> {
    const row = await this.first("SELECT 1 AS one FROM accounts WHERE did = ?", [
      did,
    ]);
    return row !== null;
  }

  async addRecipient(
    ownerDid: string,
    recipientDid: string
  ): Promise<AddRecipientResult> {
    const existing = await this.first<{ owner_did: string }>(
      "SELECT owner_did FROM keylist WHERE recipient_did = ?",
      [recipientDid]
    );

    if (existing !== null) {
      return existing.owner_did === ownerDid ? "already-yours" : "taken";
    }

    await this.run(
      "INSERT INTO keylist (recipient_did, owner_did, created_at) VALUES (?, ?, ?)",
      [recipientDid, ownerDid, Date.now()]
    );
    return "added";
  }

  async removeRecipient(
    ownerDid: string,
    recipientDid: string
  ): Promise<boolean> {
    const changes = await this.run(
      "DELETE FROM keylist WHERE recipient_did = ? AND owner_did = ?",
      [recipientDid, ownerDid]
    );
    return changes > 0;
  }

  async listRecipients(
    ownerDid: string,
    offset: number,
    limit: number
  ): Promise<RecipientPage> {
    const [page, count] = await this.batch([
      {
        sql:
          "SELECT recipient_did FROM keylist WHERE owner_did = ? " +
          "ORDER BY created_at, recipient_did LIMIT ? OFFSET ?",
        params: [ownerDid, limit, offset],
      },
      {
        sql: "SELECT COUNT(*) AS n FROM keylist WHERE owner_did = ?",
        params: [ownerDid],
      },
    ]);

    const recipients = (page.rows as { recipient_did: string }[]).map(
      (row) => row.recipient_did
    );
    const total = (count.rows as { n: number }[])[0].n;

    return {
      recipients,
      remaining: Math.max(0, total - offset - recipients.length),
    };
  }

  async ownerOf(recipientDid: string): Promise<string | null> {
    const row = await this.first<{ owner_did: string }>(
      "SELECT owner_did FROM keylist WHERE recipient_did = ?",
      [recipientDid]
    );
    return row?.owner_did ?? null;
  }

  /*
   * The quota check is read-then-insert without a transaction; two writers
   * racing can overshoot the quota by a message or two, which is a soft
   * limit doing its job either way.
   */
  async storeMessage(ownerDid: string, packed: string): Promise<string | null> {
    if ((await this.messageCount(ownerDid)) >= this.maxMessages) {
      return null;
    }

    const id = crypto.randomUUID();
    const now = Date.now();
    await this.run(
      "INSERT INTO messages (id, owner_did, packed, created_at, expires_at) " +
        "VALUES (?, ?, ?, ?, ?)",
      [id, ownerDid, packed, now, now + this.ttlMs]
    );
    return id;
  }

  async messageCount(ownerDid: string): Promise<number> {
    const row = await this.first<{ n: number }>(
      "SELECT COUNT(*) AS n FROM messages WHERE owner_did = ? AND expires_at > ?",
      [ownerDid, Date.now()]
    );
    return row?.n ?? 0;
  }

  async messagesFor(ownerDid: string, limit: number): Promise<StoredMessage[]> {
    const rows = await this.all<{
      id: string;
      packed: string;
      created_at: number;
    }>(
      "SELECT id, packed, created_at FROM messages " +
        "WHERE owner_did = ? AND expires_at > ? ORDER BY created_at LIMIT ?",
      [ownerDid, Date.now(), limit]
    );

    return rows.map((row) => ({
      id: row.id,
      packed: row.packed,
      createdAt: row.created_at,
    }));
  }

  async deleteMessages(ownerDid: string, ids: string[]): Promise<string[]> {
    const results = await this.batch(
      ids.map((id) => ({
        sql: "DELETE FROM messages WHERE id = ? AND owner_did = ?",
        params: [id, ownerDid],
      }))
    );
    return ids.filter((_, i) => results[i].changes > 0);
  }

  async getCard(ownerDid: string): Promise<StoredCard | null> {
    const row = await this.first<{ card: string; root: string | null }>(
      "SELECT card, root FROM pf_cards WHERE owner_did = ?",
      [ownerDid]
    );
    return row === null ? null : { card: row.card, root: row.root };
  }

  async putCard(
    ownerDid: string,
    cardJws: string,
    root: string | null,
    closure: string[]
  ): Promise<void> {
    // One batch = one transaction: the card and its closure references land
    // together or not at all.
    await this.batch([
      {
        sql:
          "INSERT INTO pf_cards (owner_did, card, root, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_did) DO UPDATE SET card = excluded.card, " +
          "root = excluded.root, updated_at = excluded.updated_at",
        params: [ownerDid, cardJws, root, Date.now()],
      },
      { sql: "DELETE FROM pf_refs WHERE owner_did = ?", params: [ownerDid] },
      ...chunked(closure).map((chunk) => ({
        sql:
          "INSERT OR IGNORE INTO pf_refs (owner_did, cid) VALUES " +
          chunk.map(() => "(?, ?)").join(", "),
        params: chunk.flatMap((cid) => [ownerDid, cid]),
      })),
    ]);
  }

  async putObject(cid: string, bytes: Uint8Array): Promise<void> {
    if (this.blobs !== null) {
      // Bytes to the blob store first, then the metadata row. A crash in
      // between leaves a blob no row points at — invisible, and the next
      // publish of the same content re-puts it (content-addressed, so
      // idempotent). The reverse order could leave a row claiming bytes
      // that never landed.
      await this.blobs.put(cid, bytes);
      await this.run(
        "INSERT OR IGNORE INTO pf_objects (cid, bytes, size, created_at, store) " +
          "VALUES (?, NULL, ?, ?, ?)",
        [cid, bytes.length, Date.now(), this.blobs.name]
      );
      return;
    }
    await this.run(
      "INSERT OR IGNORE INTO pf_objects (cid, bytes, size, created_at, store) " +
        "VALUES (?, ?, ?, ?, 'inline')",
      [cid, bytes, bytes.length, Date.now()]
    );
  }

  async getObject(cid: string): Promise<Uint8Array | null> {
    // The row is the source of truth for presence; its store column names
    // where the bytes live. Inline rows written before a blob backend was
    // added keep serving as-is.
    const row = await this.first<{ bytes: unknown; store: string }>(
      "SELECT bytes, store FROM pf_objects WHERE cid = ?",
      [cid]
    );
    if (row === null) {
      return null;
    }
    if (row.store === "inline") {
      return toBytes(row.bytes);
    }
    if (this.blobs !== null && row.store === this.blobs.name) {
      // A null miss (bucket gone, or the binding was removed) is a storage
      // hole the protocol layer reports as e.p.me.res.storage.
      return this.blobs.get(cid);
    }
    // A backend this build cannot reach — same storage hole.
    return null;
  }

  async objectsPresent(cids: string[]): Promise<Map<string, number>> {
    const present = new Map<string, number>();
    const results = await this.batch(
      chunked(cids).map((chunk) => ({
        sql: `SELECT cid, size FROM pf_objects WHERE cid IN (${chunk.map(() => "?").join(", ")})`,
        params: chunk,
      }))
    );
    for (const result of results) {
      for (const row of result.rows as { cid: string; size: number }[]) {
        present.set(row.cid, row.size);
      }
    }
    return present;
  }

  async purgeExpired(): Promise<number> {
    // Objects nothing references any more: staged for a publish that never
    // finished, or freed when a newer card replaced their closure. The grace
    // period keeps multi-round publishes and the cache courtesy alive. A
    // live policy hold pins the object regardless — quarantined evidence
    // outlives its references.
    const orphans =
      "created_at <= ? AND cid NOT IN (SELECT cid FROM pf_refs) " +
      "AND cid NOT IN (SELECT subject FROM pf_policy WHERE kind = 'cid' AND hold_until > ?)";
    const cutoff = Date.now() - this.stagedTtlMs;

    if (this.blobs === null) {
      const [messages, objects] = await this.batch([
        { sql: "DELETE FROM messages WHERE expires_at <= ?", params: [Date.now()] },
        { sql: `DELETE FROM pf_objects WHERE ${orphans}`, params: [cutoff, Date.now()] },
      ]);
      return messages.changes + objects.changes;
    }

    // With an external blob store the two are reclaimed in row-first order:
    // a crash after the row deletes leaves invisible blobs, which the same
    // idempotent re-put heals; deleting blobs first could leave rows
    // claiming lost bytes.
    const doomed = await this.all<{ cid: string; store: string }>(
      `SELECT cid, store FROM pf_objects WHERE ${orphans}`,
      [cutoff, Date.now()]
    );
    if (doomed.length > 0) {
      await this.batch(
        chunked(doomed.map((row) => row.cid)).map((chunk) => ({
          sql: `DELETE FROM pf_objects WHERE cid IN (${chunk.map(() => "?").join(", ")})`,
          params: chunk,
        }))
      );
      // Only rows that declared the external backend have bytes there.
      await this.blobs.delete(
        doomed.filter((row) => row.store === this.blobs?.name).map((row) => row.cid)
      );
    }

    const messages = await this.run("DELETE FROM messages WHERE expires_at <= ?", [
      Date.now(),
    ]);
    return messages + doomed.length;
  }

  async setPolicyRule(rule: Omit<PolicyRule, "createdAt">): Promise<void> {
    await this.setPolicyRules([rule]);
  }

  /**
   * Upsert many rules, each with its audit line in the same transaction —
   * chunked so a huge quarantine closure never rides one giant batch.
   */
  async setPolicyRules(rules: Omit<PolicyRule, "createdAt">[]): Promise<void> {
    for (const chunk of chunked(rules, 40)) {
      const now = Date.now();
      await this.batch(
        chunk.flatMap((rule) => [
          {
            sql:
              "INSERT INTO pf_policy (kind, subject, mode, hold_until, note, created_at) " +
              "VALUES (?, ?, ?, ?, ?, ?) " +
              "ON CONFLICT(kind, subject) DO UPDATE SET mode = excluded.mode, " +
              "hold_until = excluded.hold_until, note = excluded.note",
            params: [rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note, now],
          },
          {
            sql:
              "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
              "VALUES (?, 'set', ?, ?, ?, ?, ?)",
            params: [now, rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note],
          },
        ])
      );
    }
  }

  async clearPolicyRule(kind: PolicyKind, subject: string): Promise<boolean> {
    // One transaction; the audit line rides only when the delete removed
    // something (changes() sees the previous statement of the same batch),
    // and the leading SELECT — not driver metadata, which wrangler lacks —
    // answers whether the rule existed.
    const [existing] = await this.batch([
      {
        sql: "SELECT 1 AS present FROM pf_policy WHERE kind = ? AND subject = ?",
        params: [kind, subject],
      },
      {
        sql: "DELETE FROM pf_policy WHERE kind = ? AND subject = ?",
        params: [kind, subject],
      },
      {
        sql:
          "INSERT INTO pf_audit (at, action, kind, subject) " +
          "SELECT ?, 'clear', ?, ? WHERE changes() > 0",
        params: [Date.now(), kind, subject],
      },
    ]);
    return existing.rows.length > 0;
  }

  async policyRules(
    kind: PolicyKind,
    subjects: string[]
  ): Promise<Map<string, PolicyRule>> {
    const rules = new Map<string, PolicyRule>();
    const results = await this.batch(
      chunked(subjects).map((chunk) => ({
        sql:
          "SELECT subject, mode, hold_until, note, created_at FROM pf_policy " +
          `WHERE kind = ? AND subject IN (${chunk.map(() => "?").join(", ")})`,
        params: [kind, ...chunk],
      }))
    );
    for (const result of results) {
      for (const row of result.rows as {
        subject: string;
        mode: string;
        hold_until: number | null;
        note: string | null;
        created_at: number;
      }[]) {
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
    const rows = await this.all<{
      kind: string;
      subject: string;
      mode: string;
      hold_until: number | null;
      note: string | null;
      created_at: number;
    }>(
      "SELECT kind, subject, mode, hold_until, note, created_at FROM pf_policy " +
        "ORDER BY created_at, kind, subject"
    );
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
    const rows = await this.all<{
      at: number;
      action: string;
      kind: string;
      subject: string;
      mode: string | null;
      hold_until: number | null;
      note: string | null;
    }>(
      "SELECT at, action, kind, subject, mode, hold_until, note FROM pf_audit " +
        "ORDER BY id DESC LIMIT ?",
      [limit]
    );
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
    const rows = await this.all<{ owner_did: string }>(
      "SELECT owner_did FROM pf_refs WHERE cid = ?",
      [cid]
    );
    return rows.map((row) => row.owner_did);
  }

  async closureOf(ownerDid: string): Promise<string[]> {
    const rows = await this.all<{ cid: string }>(
      "SELECT cid FROM pf_refs WHERE owner_did = ?",
      [ownerDid]
    );
    return rows.map((row) => row.cid);
  }

  close(): void {
    this.driver.close();
  }
}
