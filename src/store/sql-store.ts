/**
 * One mediator store, many SQLite dialects.
 *
 * better-sqlite3 and Cloudflare D1 *are* SQLite — the schema and every query
 * are identical, so the store is written once against the narrowest contract
 * the backends share: a batch of statements that runs in order as one
 * transaction. That is D1's only transaction shape; better-sqlite3's
 * transactions are a superset, and every transactional path here fits it.
 * Drivers translate only the calling convention.
 *
 * The schema is ensured lazily on first use instead of by a migrations step,
 * so a fresh deploy needs nothing beyond an empty database; a failed ensure
 * (D1 hiccup, lost migration race) must not poison the process — the next
 * call retries from scratch.
 */

import type {
  AddRecipientResult,
  BlobRow,
  MediationStore,
  RecipientPage,
  StoredMessage,
  UploadGrant,
} from "./types.js";

export type SqlValue = string | number | null | Uint8Array;

export interface SqlStatement {
  sql: string;
  params?: SqlValue[];
}

export interface SqlResult {
  rows: Record<string, unknown>[];
  /** Rows the statement modified; a driver that cannot know reports 0. */
  changes: number;
}

/** What a backend must do: run a list of statements as ONE transaction. */
export interface SqlDriver {
  batch(statements: SqlStatement[]): Promise<SqlResult[]>;
  close(): void;
}

export interface SqlStoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
  /**
   * The live mediator ensures its schema on first use (the default); an
   * admin tool visiting a database the mediator owns can skip the round trip.
   */
  ensureSchema?: boolean;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;

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
  // owner_did deliberately has no foreign key: a blob must outlive its
  // account's row long enough for purge to learn its id and delete the bytes.
  `CREATE TABLE IF NOT EXISTS blobs (
     id           TEXT PRIMARY KEY,
     owner_did    TEXT NOT NULL,
     hash         TEXT NOT NULL,
     size         INTEGER NOT NULL,
     created_at   INTEGER NOT NULL,
     uploaded_at  INTEGER,
     retain_until INTEGER NOT NULL,
     UNIQUE (owner_did, hash)
   )`,
  "CREATE INDEX IF NOT EXISTS blobs_expiry ON blobs(retain_until)",
  `CREATE TABLE IF NOT EXISTS blob_uploads (
     token      TEXT PRIMARY KEY,
     blob_id    TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
     expires_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS identity (
     id         INTEGER PRIMARY KEY CHECK (id = 1),
     secrets    TEXT NOT NULL,
     created_at INTEGER NOT NULL
   )`,
];

export class SqlStore implements MediationStore {
  private ttlMs: number;
  private maxMessages: number;
  private ensure: boolean;
  private ready: Promise<void> | null = null;

  constructor(
    private driver: SqlDriver,
    options: SqlStoreOptions = {}
  ) {
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;
    this.ensure = options.ensureSchema ?? true;
  }

  private init(): Promise<void> {
    if (this.ready === null) {
      this.ready = this.ensure
        ? this.dropOldBlobTables().then(() =>
            this.driver.batch(SCHEMA.map((sql) => ({ sql }))).then(() => {})
          )
        : Promise.resolve();
      this.ready.catch(() => {
        this.ready = null;
      });
    }
    return this.ready;
  }

  /**
   * The first blob-store schema (2026-08-26/27) keyed blobs by hash with a
   * `blob_holds` table shared between mediations. Blobs are temporary by
   * design, so a database still carrying that shape is simply reset: the
   * three tables go and are recreated. Their bytes in storage are not
   * reachable from here and are the operator's to sweep.
   */
  private async dropOldBlobTables(): Promise<void> {
    const [found] = await this.driver.batch([
      {
        sql: "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'blobs'",
      },
    ]);
    const row = (found.rows as { sql: string }[])[0];
    if (row !== undefined && !row.sql.includes("owner_did")) {
      await this.driver.batch(
        ["blob_uploads", "blob_holds", "blobs"].map((table) => ({
          sql: `DROP TABLE IF EXISTS ${table}`,
        }))
      );
    }
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

  async purgeExpired(): Promise<number> {
    return this.run("DELETE FROM messages WHERE expires_at <= ?", [Date.now()]);
  }

  private static readonly BLOB_COLUMNS =
    "id, owner_did, hash, size, uploaded_at, retain_until";

  private static blobRow(row: Record<string, unknown>): BlobRow {
    return {
      id: row.id as string,
      ownerDid: row.owner_did as string,
      hash: row.hash as string,
      size: row.size as number,
      uploadedAt: row.uploaded_at as number | null,
      retainUntil: row.retain_until as number,
    };
  }

  async blobOf(ownerDid: string, hash: string): Promise<BlobRow | null> {
    const row = await this.first<Record<string, unknown>>(
      `SELECT ${SqlStore.BLOB_COLUMNS} FROM blobs WHERE owner_did = ? AND hash = ?`,
      [ownerDid, hash]
    );
    return row === null ? null : SqlStore.blobRow(row);
  }

  async blobById(id: string): Promise<BlobRow | null> {
    const row = await this.first<Record<string, unknown>>(
      `SELECT ${SqlStore.BLOB_COLUMNS} FROM blobs WHERE id = ?`,
      [id]
    );
    return row === null ? null : SqlStore.blobRow(row);
  }

  async blobUsage(ownerDid: string): Promise<number> {
    const row = await this.first<{ n: number | null }>(
      "SELECT SUM(size) AS n FROM blobs WHERE owner_did = ? AND retain_until > ?",
      [ownerDid, Date.now()]
    );
    return row?.n ?? 0;
  }

  async keepBlob(
    id: string,
    ownerDid: string,
    hash: string,
    size: number,
    retainUntil: number
  ): Promise<void> {
    await this.run(
      "INSERT INTO blobs (id, owner_did, hash, size, created_at, retain_until) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT (owner_did, hash) DO UPDATE SET " +
        "retain_until = MAX(retain_until, excluded.retain_until)",
      [id, ownerDid, hash, size, Date.now(), retainUntil]
    );
  }

  async dropBlob(ownerDid: string, hash: string): Promise<string | null> {
    const [found] = await this.batch([
      { sql: "SELECT id FROM blobs WHERE owner_did = ? AND hash = ?", params: [ownerDid, hash] },
      { sql: "DELETE FROM blobs WHERE owner_did = ? AND hash = ?", params: [ownerDid, hash] },
    ]);
    const row = (found.rows as { id: string }[])[0];
    return row === undefined ? null : row.id;
  }

  async grantUpload(id: string, expiresAt: number): Promise<string> {
    const token = crypto.randomUUID();
    await this.run(
      "INSERT INTO blob_uploads (token, blob_id, expires_at) VALUES (?, ?, ?)",
      [token, id, expiresAt]
    );
    return token;
  }

  async claimUpload(token: string): Promise<UploadGrant | null> {
    const [found] = await this.batch([
      {
        sql:
          "SELECT b.id, b.hash, b.size FROM blob_uploads u JOIN blobs b ON b.id = u.blob_id " +
          "WHERE u.token = ? AND u.expires_at > ?",
        params: [token, Date.now()],
      },
      { sql: "DELETE FROM blob_uploads WHERE token = ?", params: [token] },
    ]);
    const row = (found.rows as { id: string; hash: string; size: number }[])[0];
    return row === undefined ? null : { id: row.id, hash: row.hash, size: row.size };
  }

  async markUploaded(id: string): Promise<void> {
    await this.run("UPDATE blobs SET uploaded_at = ? WHERE id = ? AND uploaded_at IS NULL", [
      Date.now(),
      id,
    ]);
  }

  async purgeBlobs(): Promise<string[]> {
    const now = Date.now();
    const dead =
      "retain_until <= ? OR owner_did NOT IN (SELECT did FROM accounts)";
    const [found] = await this.batch([
      { sql: `SELECT id FROM blobs WHERE ${dead}`, params: [now] },
      { sql: `DELETE FROM blobs WHERE ${dead}`, params: [now] },
      { sql: "DELETE FROM blob_uploads WHERE expires_at <= ?", params: [now] },
    ]);
    return (found.rows as { id: string }[]).map((row) => row.id);
  }

  close(): void {
    this.driver.close();
  }
}
