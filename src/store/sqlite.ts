import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";

import type {
  AddRecipientResult,
  MediationStore,
  RecipientPage,
  StoredMessage,
} from "./types.js";

export interface SqliteStoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;

export class SqliteStore implements MediationStore {
  private db: Database.Database;
  private ttlMs: number;
  private maxMessages: number;

  /** `path` is a file path, or ":memory:" for tests. */
  constructor(path: string, options: SqliteStoreOptions = {}) {
    this.db = new Database(path);
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;

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
    `);
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

  async purgeExpired(): Promise<number> {
    return this.db
      .prepare("DELETE FROM messages WHERE expires_at <= ?")
      .run(Date.now()).changes;
  }

  close(): void {
    this.db.close();
  }
}
