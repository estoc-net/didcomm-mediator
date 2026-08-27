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
  BlobInfo,
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
  `CREATE TABLE IF NOT EXISTS blobs (
     hash        TEXT PRIMARY KEY,
     size        INTEGER NOT NULL,
     created_at  INTEGER NOT NULL,
     uploaded_at INTEGER
   )`,
  `CREATE TABLE IF NOT EXISTS blob_holds (
     owner_did    TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
     hash         TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
     retain_until INTEGER NOT NULL,
     PRIMARY KEY (owner_did, hash)
   )`,
  "CREATE INDEX IF NOT EXISTS blob_holds_hash ON blob_holds(hash)",
  `CREATE TABLE IF NOT EXISTS blob_uploads (
     token      TEXT PRIMARY KEY,
     hash       TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
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
        ? this.driver.batch(SCHEMA.map((sql) => ({ sql }))).then(() => {})
        : Promise.resolve();
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

  async purgeExpired(): Promise<number> {
    return this.run("DELETE FROM messages WHERE expires_at <= ?", [Date.now()]);
  }

  async blobInfo(hash: string): Promise<BlobInfo | null> {
    const row = await this.first<{
      size: number;
      uploaded_at: number | null;
      retain_until: number | null;
    }>(
      "SELECT b.size, b.uploaded_at, " +
        "(SELECT MAX(retain_until) FROM blob_holds h WHERE h.hash = b.hash) AS retain_until " +
        "FROM blobs b WHERE b.hash = ?",
      [hash]
    );
    if (row === null) {
      return null;
    }
    return {
      hash,
      size: row.size,
      uploadedAt: row.uploaded_at,
      retainUntil: row.retain_until ?? 0,
    };
  }

  async blobUsage(ownerDid: string): Promise<number> {
    const row = await this.first<{ n: number | null }>(
      "SELECT SUM(b.size) AS n FROM blob_holds h JOIN blobs b ON b.hash = h.hash " +
        "WHERE h.owner_did = ? AND h.retain_until > ?",
      [ownerDid, Date.now()]
    );
    return row?.n ?? 0;
  }

  async holdBlob(
    ownerDid: string,
    hash: string,
    size: number,
    retainUntil: number
  ): Promise<void> {
    await this.batch([
      {
        sql: "INSERT OR IGNORE INTO blobs (hash, size, created_at) VALUES (?, ?, ?)",
        params: [hash, size, Date.now()],
      },
      {
        // A hold is only ever extended, never shortened by a later put.
        sql:
          "INSERT INTO blob_holds (owner_did, hash, retain_until) VALUES (?, ?, ?) " +
          "ON CONFLICT (owner_did, hash) DO UPDATE SET " +
          "retain_until = MAX(retain_until, excluded.retain_until)",
        params: [ownerDid, hash, retainUntil],
      },
    ]);
  }

  async blobHeld(ownerDid: string, hash: string): Promise<boolean> {
    const row = await this.first(
      "SELECT 1 AS one FROM blob_holds WHERE owner_did = ? AND hash = ? AND retain_until > ?",
      [ownerDid, hash, Date.now()]
    );
    return row !== null;
  }

  async releaseBlob(ownerDid: string, hash: string): Promise<void> {
    await this.run("DELETE FROM blob_holds WHERE owner_did = ? AND hash = ?", [
      ownerDid,
      hash,
    ]);
  }

  async grantUpload(hash: string, expiresAt: number): Promise<string> {
    const token = crypto.randomUUID();
    await this.run(
      "INSERT INTO blob_uploads (token, hash, expires_at) VALUES (?, ?, ?)",
      [token, hash, expiresAt]
    );
    return token;
  }

  async claimUpload(token: string): Promise<UploadGrant | null> {
    const [found] = await this.batch([
      {
        sql:
          "SELECT u.hash, b.size FROM blob_uploads u JOIN blobs b ON b.hash = u.hash " +
          "WHERE u.token = ? AND u.expires_at > ?",
        params: [token, Date.now()],
      },
      { sql: "DELETE FROM blob_uploads WHERE token = ?", params: [token] },
    ]);
    const row = (found.rows as { hash: string; size: number }[])[0];
    return row === undefined ? null : { hash: row.hash, size: row.size };
  }

  async markUploaded(hash: string): Promise<void> {
    await this.run(
      "UPDATE blobs SET uploaded_at = ? WHERE hash = ? AND uploaded_at IS NULL",
      [Date.now(), hash]
    );
  }

  async purgeBlobs(): Promise<string[]> {
    const now = Date.now();
    const [, , orphans] = await this.batch([
      { sql: "DELETE FROM blob_holds WHERE retain_until <= ?", params: [now] },
      { sql: "DELETE FROM blob_uploads WHERE expires_at <= ?", params: [now] },
      {
        sql:
          "SELECT hash FROM blobs b WHERE NOT EXISTS " +
          "(SELECT 1 FROM blob_holds h WHERE h.hash = b.hash)",
      },
    ]);
    const hashes = (orphans.rows as { hash: string }[]).map((row) => row.hash);
    await this.batch(
      hashes.map((hash) => ({ sql: "DELETE FROM blobs WHERE hash = ?", params: [hash] }))
    );
    return hashes;
  }

  close(): void {
    this.driver.close();
  }
}
