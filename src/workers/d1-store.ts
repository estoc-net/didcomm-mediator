import type {
  AddRecipientResult,
  MediationStore,
  RecipientPage,
  StoredMessage,
} from "../store/types.js";

export interface D1StoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;

/**
 * The same three tables as the SQLite store, on Cloudflare D1 — which *is*
 * SQLite, so the schema and queries carry over verbatim; only the API is
 * async and the process boundary is real. The schema is ensured lazily on
 * first use (once per isolate) instead of by a migrations step, so a fresh
 * deploy needs nothing beyond an empty database.
 *
 * The quota check is read-then-insert without a transaction; two isolates
 * racing can overshoot the quota by a message or two, which is a soft limit
 * doing its job either way.
 */
export class D1Store implements MediationStore {
  private ttlMs: number;
  private maxMessages: number;
  private ready: Promise<unknown> | null = null;

  constructor(
    private db: D1Database,
    options: D1StoreOptions = {}
  ) {
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;
  }

  private init(): Promise<unknown> {
    this.ready ??= this.db.batch([
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS accounts (
           did        TEXT PRIMARY KEY,
           created_at INTEGER NOT NULL
         )`
      ),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS keylist (
           recipient_did TEXT PRIMARY KEY,
           owner_did     TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
           created_at    INTEGER NOT NULL
         )`
      ),
      this.db.prepare(
        "CREATE INDEX IF NOT EXISTS keylist_owner ON keylist(owner_did)"
      ),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS messages (
           id         TEXT PRIMARY KEY,
           owner_did  TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
           packed     TEXT NOT NULL,
           created_at INTEGER NOT NULL,
           expires_at INTEGER NOT NULL
         )`
      ),
      this.db.prepare(
        "CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner_did, created_at)"
      ),
      this.db.prepare(
        "CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at)"
      ),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS identity (
           id         INTEGER PRIMARY KEY CHECK (id = 1),
           secrets    TEXT NOT NULL,
           created_at INTEGER NOT NULL
         )`
      ),
    ]);
    return this.ready;
  }

  async loadIdentity(): Promise<string | null> {
    await this.init();
    const row = await this.db
      .prepare("SELECT secrets FROM identity WHERE id = 1")
      .first<{ secrets: string }>();
    return row?.secrets ?? null;
  }

  async initIdentity(secretsJson: string): Promise<string> {
    await this.init();
    await this.db
      .prepare(
        "INSERT OR IGNORE INTO identity (id, secrets, created_at) VALUES (1, ?, ?)"
      )
      .bind(secretsJson, Date.now())
      .run();
    const winner = await this.loadIdentity();
    if (winner === null) {
      throw new Error("The identity row vanished between insert and read");
    }
    return winner;
  }

  async grantMediation(did: string): Promise<void> {
    await this.init();
    await this.db
      .prepare("INSERT OR IGNORE INTO accounts (did, created_at) VALUES (?, ?)")
      .bind(did, Date.now())
      .run();
  }

  async revokeMediation(did: string): Promise<void> {
    await this.init();
    // Cascades: the keylist entries and waiting messages go with the account.
    await this.db.prepare("DELETE FROM accounts WHERE did = ?").bind(did).run();
  }

  async isMediated(did: string): Promise<boolean> {
    await this.init();
    const row = await this.db
      .prepare("SELECT 1 AS one FROM accounts WHERE did = ?")
      .bind(did)
      .first();
    return row !== null;
  }

  async addRecipient(
    ownerDid: string,
    recipientDid: string
  ): Promise<AddRecipientResult> {
    await this.init();
    const existing = await this.db
      .prepare("SELECT owner_did FROM keylist WHERE recipient_did = ?")
      .bind(recipientDid)
      .first<{ owner_did: string }>();

    if (existing !== null) {
      return existing.owner_did === ownerDid ? "already-yours" : "taken";
    }

    await this.db
      .prepare(
        "INSERT INTO keylist (recipient_did, owner_did, created_at) VALUES (?, ?, ?)"
      )
      .bind(recipientDid, ownerDid, Date.now())
      .run();
    return "added";
  }

  async removeRecipient(
    ownerDid: string,
    recipientDid: string
  ): Promise<boolean> {
    await this.init();
    const result = await this.db
      .prepare("DELETE FROM keylist WHERE recipient_did = ? AND owner_did = ?")
      .bind(recipientDid, ownerDid)
      .run();
    return result.meta.changes > 0;
  }

  async listRecipients(
    ownerDid: string,
    offset: number,
    limit: number
  ): Promise<RecipientPage> {
    await this.init();
    const [page, count] = await this.db.batch([
      this.db
        .prepare(
          "SELECT recipient_did FROM keylist WHERE owner_did = ? " +
            "ORDER BY created_at, recipient_did LIMIT ? OFFSET ?"
        )
        .bind(ownerDid, limit, offset),
      this.db
        .prepare("SELECT COUNT(*) AS n FROM keylist WHERE owner_did = ?")
        .bind(ownerDid),
    ]);

    const recipients = (page.results as { recipient_did: string }[]).map(
      (row) => row.recipient_did
    );
    const total = (count.results as { n: number }[])[0].n;

    return {
      recipients,
      remaining: Math.max(0, total - offset - recipients.length),
    };
  }

  async ownerOf(recipientDid: string): Promise<string | null> {
    await this.init();
    const row = await this.db
      .prepare("SELECT owner_did FROM keylist WHERE recipient_did = ?")
      .bind(recipientDid)
      .first<{ owner_did: string }>();
    return row?.owner_did ?? null;
  }

  async storeMessage(ownerDid: string, packed: string): Promise<string | null> {
    await this.init();
    if ((await this.messageCount(ownerDid)) >= this.maxMessages) {
      return null;
    }

    const id = crypto.randomUUID();
    const now = Date.now();
    await this.db
      .prepare(
        "INSERT INTO messages (id, owner_did, packed, created_at, expires_at) " +
          "VALUES (?, ?, ?, ?, ?)"
      )
      .bind(id, ownerDid, packed, now, now + this.ttlMs)
      .run();
    return id;
  }

  async messageCount(ownerDid: string): Promise<number> {
    await this.init();
    const row = await this.db
      .prepare(
        "SELECT COUNT(*) AS n FROM messages WHERE owner_did = ? AND expires_at > ?"
      )
      .bind(ownerDid, Date.now())
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async messagesFor(ownerDid: string, limit: number): Promise<StoredMessage[]> {
    await this.init();
    const { results } = await this.db
      .prepare(
        "SELECT id, packed, created_at FROM messages " +
          "WHERE owner_did = ? AND expires_at > ? ORDER BY created_at LIMIT ?"
      )
      .bind(ownerDid, Date.now(), limit)
      .all<{ id: string; packed: string; created_at: number }>();

    return results.map((row) => ({
      id: row.id,
      packed: row.packed,
      createdAt: row.created_at,
    }));
  }

  async deleteMessages(ownerDid: string, ids: string[]): Promise<string[]> {
    await this.init();
    if (ids.length === 0) {
      return [];
    }

    const results = await this.db.batch(
      ids.map((id) =>
        this.db
          .prepare("DELETE FROM messages WHERE id = ? AND owner_did = ?")
          .bind(id, ownerDid)
      )
    );
    return ids.filter((_, i) => results[i].meta.changes > 0);
  }

  async purgeExpired(): Promise<number> {
    await this.init();
    const result = await this.db
      .prepare("DELETE FROM messages WHERE expires_at <= ?")
      .bind(Date.now())
      .run();
    return result.meta.changes;
  }

  close(): void {
    // D1 has no connection to close.
  }
}
