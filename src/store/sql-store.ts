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
  MediationStore,
  RecipientPage,
  StoredMessage,
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

  close(): void {
    this.driver.close();
  }
}
