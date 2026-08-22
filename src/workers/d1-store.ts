import { chunked } from "../store/types.js";
import type {
  AddRecipientResult,
  MediationStore,
  PolicyAuditEntry,
  PolicyKind,
  PolicyRule,
  RecipientPage,
  StoredCard,
  StoredMessage,
} from "../store/types.js";

export interface D1StoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
  /** Unreferenced public-folder objects older than this are purged. */
  stagedObjectTtlSeconds?: number;
  /**
   * Optional R2 bucket for public-folder object bytes. Without it the bytes
   * live as D1 blobs — fine for light use, but D1 caps a database at 500 MB
   * on the free plan and the whole mediator shares it. With it, D1 keeps only
   * the metadata rows (cid, size, refcounts — the relational half) and R2
   * holds the bytes. Objects already stored as blobs keep serving from D1,
   * so the binding can be added to a live deployment; removing it later
   * orphans any R2-held bytes (their rows would claim presence), so don't —
   * or clear pf_objects/pf_cards/pf_refs when you do.
   */
  objects?: R2Bucket;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_MAX_MESSAGES = 1000;
const DEFAULT_STAGED_OBJECT_TTL_SECONDS = 7 * 24 * 60 * 60;

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

  private stagedTtlMs: number;
  private objects: R2Bucket | null;

  constructor(
    private db: D1Database,
    options: D1StoreOptions = {}
  ) {
    this.ttlMs = (options.messageTtlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;
    this.maxMessages = options.maxMessagesPerAccount ?? DEFAULT_MAX_MESSAGES;
    this.stagedTtlMs =
      (options.stagedObjectTtlSeconds ?? DEFAULT_STAGED_OBJECT_TTL_SECONDS) * 1000;
    this.objects = options.objects ?? null;
  }

  private init(): Promise<unknown> {
    if (this.ready === null) {
      this.ready = this.initTables();
      // A failed init (D1 hiccup, lost migration race) must not poison the
      // isolate — the next request retries from scratch.
      this.ready.catch(() => {
        this.ready = null;
      });
    }
    return this.ready;
  }

  private async initTables(): Promise<void> {
    await this.db.batch([
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
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS pf_cards (
           owner_did  TEXT PRIMARY KEY,
           card       TEXT NOT NULL,
           root       TEXT,
           updated_at INTEGER NOT NULL
         )`
      ),
      this.db.prepare(
        // Each row declares where its bytes live: 'inline' = the row's own
        // bytes column (then bytes is non-null), 'r2' = the PF_OBJECTS
        // bucket. Future backends add names, never new NULL conventions.
        `CREATE TABLE IF NOT EXISTS pf_objects (
           cid        TEXT PRIMARY KEY,
           bytes      BLOB,
           size       INTEGER NOT NULL,
           created_at INTEGER NOT NULL,
           store      TEXT NOT NULL DEFAULT 'inline'
         )`
      ),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS pf_refs (
           owner_did TEXT NOT NULL,
           cid       TEXT NOT NULL,
           PRIMARY KEY (owner_did, cid)
         )`
      ),
      this.db.prepare("CREATE INDEX IF NOT EXISTS pf_refs_cid ON pf_refs(cid)"),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS pf_policy (
           kind       TEXT NOT NULL,
           subject    TEXT NOT NULL,
           mode       TEXT NOT NULL,
           hold_until INTEGER,
           note       TEXT,
           created_at INTEGER NOT NULL,
           PRIMARY KEY (kind, subject)
         )`
      ),
      this.db.prepare(
        `CREATE TABLE IF NOT EXISTS pf_audit (
           id         INTEGER PRIMARY KEY AUTOINCREMENT,
           at         INTEGER NOT NULL,
           action     TEXT NOT NULL,
           kind       TEXT NOT NULL,
           subject    TEXT NOT NULL,
           mode       TEXT,
           hold_until INTEGER,
           note       TEXT
         )`
      ),
    ]);

    // Two earlier pf_objects schemas exist in the wild. The first public-
    // folder version had `bytes BLOB NOT NULL` — fatal under R2, because the
    // metadata rows insert bytes as NULL and INSERT OR IGNORE swallows the
    // constraint violation *silently*; rebuild to the current shape, keeping
    // every stored object. The brief second version made bytes nullable but
    // encoded the backend implicitly as bytes-IS-NULL; give it the explicit
    // store column and backfill. Each migration is one batch = one
    // transaction; if a concurrent isolate wins the race this one throws,
    // init retries, and the re-read sees the new schema.
    const table = await this.db
      .prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pf_objects'"
      )
      .first<{ sql: string }>();
    if (table !== null && /bytes\s+BLOB\s+NOT\s+NULL/i.test(table.sql)) {
      await this.db.batch([
        this.db.prepare("ALTER TABLE pf_objects RENAME TO pf_objects_legacy"),
        this.db.prepare(
          `CREATE TABLE pf_objects (
             cid        TEXT PRIMARY KEY,
             bytes      BLOB,
             size       INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             store      TEXT NOT NULL DEFAULT 'inline'
           )`
        ),
        this.db.prepare(
          "INSERT INTO pf_objects (cid, bytes, size, created_at, store) " +
            "SELECT cid, bytes, size, created_at, 'inline' FROM pf_objects_legacy"
        ),
        this.db.prepare("DROP TABLE pf_objects_legacy"),
      ]);
    } else if (table !== null && !/store\s+TEXT/i.test(table.sql)) {
      await this.db.batch([
        this.db.prepare(
          "ALTER TABLE pf_objects ADD COLUMN store TEXT NOT NULL DEFAULT 'inline'"
        ),
        this.db.prepare(
          "UPDATE pf_objects SET store = 'r2' WHERE bytes IS NULL"
        ),
      ]);
    }
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

  async getCard(ownerDid: string): Promise<StoredCard | null> {
    await this.init();
    const row = await this.db
      .prepare("SELECT card, root FROM pf_cards WHERE owner_did = ?")
      .bind(ownerDid)
      .first<{ card: string; root: string | null }>();
    return row === null ? null : { card: row.card, root: row.root };
  }

  async putCard(
    ownerDid: string,
    cardJws: string,
    root: string | null,
    closure: string[]
  ): Promise<void> {
    await this.init();
    // One batch = one transaction: the card and its closure references land
    // together or not at all.
    await this.db.batch([
      this.db
        .prepare(
          "INSERT INTO pf_cards (owner_did, card, root, updated_at) VALUES (?, ?, ?, ?) " +
            "ON CONFLICT(owner_did) DO UPDATE SET card = excluded.card, " +
            "root = excluded.root, updated_at = excluded.updated_at"
        )
        .bind(ownerDid, cardJws, root, Date.now()),
      this.db.prepare("DELETE FROM pf_refs WHERE owner_did = ?").bind(ownerDid),
      ...chunked(closure).map((chunk) =>
        this.db
          .prepare(
            "INSERT OR IGNORE INTO pf_refs (owner_did, cid) VALUES " +
              chunk.map(() => "(?, ?)").join(", ")
          )
          .bind(...chunk.flatMap((cid) => [ownerDid, cid]))
      ),
    ]);
  }

  async putObject(cid: string, bytes: Uint8Array): Promise<void> {
    await this.init();
    // D1 and R2 both take ArrayBuffers; slice out exactly the view's bytes.
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength
    );
    if (this.objects !== null) {
      // Bytes to R2 first, then the metadata row. A crash in between leaves
      // an R2 blob no row points at — invisible, and the next publish of the
      // same content re-puts it (content-addressed, so idempotent). The
      // reverse order could leave a row claiming bytes that never landed.
      await this.objects.put(cid, buffer as ArrayBuffer);
      await this.db
        .prepare(
          "INSERT OR IGNORE INTO pf_objects (cid, bytes, size, created_at, store) " +
            "VALUES (?, NULL, ?, ?, 'r2')"
        )
        .bind(cid, bytes.length, Date.now())
        .run();
      return;
    }
    await this.db
      .prepare(
        "INSERT OR IGNORE INTO pf_objects (cid, bytes, size, created_at, store) " +
          "VALUES (?, ?, ?, ?, 'inline')"
      )
      .bind(cid, buffer, bytes.length, Date.now())
      .run();
  }

  async getObject(cid: string): Promise<Uint8Array | null> {
    await this.init();
    // The row is the source of truth for presence; its store column names
    // where the bytes live. Inline rows written before an R2 binding was
    // added keep serving as-is.
    const row = await this.db
      .prepare("SELECT bytes, store FROM pf_objects WHERE cid = ?")
      .bind(cid)
      .first<{ bytes: ArrayBuffer | null; store: string }>();
    if (row === null) {
      return null;
    }
    if (row.store === "inline") {
      return row.bytes === null ? null : new Uint8Array(row.bytes);
    }
    if (row.store === "r2") {
      // A null miss (bucket gone, or the binding was removed) is a storage
      // hole the protocol layer reports as e.p.me.res.storage.
      const object = await this.objects?.get(cid);
      return object == null ? null : new Uint8Array(await object.arrayBuffer());
    }
    // A backend this build does not know — same storage hole.
    return null;
  }

  async objectsPresent(cids: string[]): Promise<Map<string, number>> {
    await this.init();
    const present = new Map<string, number>();
    if (cids.length === 0) {
      return present;
    }
    const results = await this.db.batch(
      chunked(cids).map((chunk) =>
        this.db
          .prepare(
            `SELECT cid, size FROM pf_objects WHERE cid IN (${chunk.map(() => "?").join(", ")})`
          )
          .bind(...chunk)
      )
    );
    for (const result of results) {
      for (const row of result.results as { cid: string; size: number }[]) {
        present.set(row.cid, row.size);
      }
    }
    return present;
  }

  async purgeExpired(): Promise<number> {
    await this.init();
    // Objects nothing references any more: staged for a publish that never
    // finished, or freed when a newer card replaced their closure. The
    // grace period keeps multi-round publishes and the cache courtesy alive.
    // A live policy hold pins the object regardless — quarantined evidence
    // outlives its references.
    const orphans =
      "created_at <= ? AND cid NOT IN (SELECT cid FROM pf_refs) " +
      "AND cid NOT IN (SELECT subject FROM pf_policy WHERE kind = 'cid' AND hold_until > ?)";
    const cutoff = Date.now() - this.stagedTtlMs;

    if (this.objects === null) {
      const [messages, objects] = await this.db.batch([
        this.db
          .prepare("DELETE FROM messages WHERE expires_at <= ?")
          .bind(Date.now()),
        this.db
          .prepare(`DELETE FROM pf_objects WHERE ${orphans}`)
          .bind(cutoff, Date.now()),
      ]);
      return messages.meta.changes + objects.meta.changes;
    }

    // With R2 the two stores are reclaimed in row-first order: a crash after
    // the row deletes leaves invisible R2 blobs, which the same idempotent
    // re-put heals; deleting R2 first could leave rows claiming lost bytes.
    const { results } = await this.db
      .prepare(`SELECT cid, store FROM pf_objects WHERE ${orphans}`)
      .bind(cutoff, Date.now())
      .all<{ cid: string; store: string }>();
    const cids = results.map((row) => row.cid);
    if (cids.length > 0) {
      await this.db.batch(
        chunked(cids).map((chunk) =>
          this.db
            .prepare(
              `DELETE FROM pf_objects WHERE cid IN (${chunk.map(() => "?").join(", ")})`
            )
            .bind(...chunk)
        )
      );
      // Only rows that declared R2 have bytes there; bulk delete takes up
      // to 1000 keys.
      const r2Cids = results
        .filter((row) => row.store === "r2")
        .map((row) => row.cid);
      for (const chunk of chunked(r2Cids, 1000)) {
        await this.objects.delete(chunk);
      }
    }

    const messages = await this.db
      .prepare("DELETE FROM messages WHERE expires_at <= ?")
      .bind(Date.now())
      .run();
    return messages.meta.changes + cids.length;
  }

  async setPolicyRule(rule: Omit<PolicyRule, "createdAt">): Promise<void> {
    await this.init();
    const now = Date.now();
    // One batch = one transaction: no rule change without its audit line.
    await this.db.batch([
      this.db
        .prepare(
          "INSERT INTO pf_policy (kind, subject, mode, hold_until, note, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT(kind, subject) DO UPDATE SET mode = excluded.mode, " +
            "hold_until = excluded.hold_until, note = excluded.note"
        )
        .bind(rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note, now),
      this.db
        .prepare(
          "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
            "VALUES (?, 'set', ?, ?, ?, ?, ?)"
        )
        .bind(now, rule.kind, rule.subject, rule.mode, rule.holdUntil, rule.note),
    ]);
  }

  async clearPolicyRule(kind: PolicyKind, subject: string): Promise<boolean> {
    await this.init();
    const result = await this.db
      .prepare("DELETE FROM pf_policy WHERE kind = ? AND subject = ?")
      .bind(kind, subject)
      .run();
    if (result.meta.changes === 0) {
      return false;
    }
    await this.db
      .prepare(
        "INSERT INTO pf_audit (at, action, kind, subject) VALUES (?, 'clear', ?, ?)"
      )
      .bind(Date.now(), kind, subject)
      .run();
    return true;
  }

  async policyRules(
    kind: PolicyKind,
    subjects: string[]
  ): Promise<Map<string, PolicyRule>> {
    await this.init();
    const rules = new Map<string, PolicyRule>();
    if (subjects.length === 0) {
      return rules;
    }
    const results = await this.db.batch(
      chunked(subjects).map((chunk) =>
        this.db
          .prepare(
            "SELECT subject, mode, hold_until, note, created_at FROM pf_policy " +
              `WHERE kind = ? AND subject IN (${chunk.map(() => "?").join(", ")})`
          )
          .bind(kind, ...chunk)
      )
    );
    for (const result of results) {
      for (const row of result.results as {
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
    await this.init();
    const { results } = await this.db
      .prepare(
        "SELECT kind, subject, mode, hold_until, note, created_at FROM pf_policy " +
          "ORDER BY created_at, kind, subject"
      )
      .all<{
        kind: string;
        subject: string;
        mode: string;
        hold_until: number | null;
        note: string | null;
        created_at: number;
      }>();
    return results.map((row) => ({
      kind: row.kind as PolicyKind,
      subject: row.subject,
      mode: row.mode as PolicyRule["mode"],
      holdUntil: row.hold_until,
      note: row.note,
      createdAt: row.created_at,
    }));
  }

  async policyAudit(limit: number): Promise<PolicyAuditEntry[]> {
    await this.init();
    const { results } = await this.db
      .prepare(
        "SELECT at, action, kind, subject, mode, hold_until, note FROM pf_audit " +
          "ORDER BY id DESC LIMIT ?"
      )
      .bind(limit)
      .all<{
        at: number;
        action: string;
        kind: string;
        subject: string;
        mode: string | null;
        hold_until: number | null;
        note: string | null;
      }>();
    return results.map((row) => ({
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
    await this.init();
    const { results } = await this.db
      .prepare("SELECT owner_did FROM pf_refs WHERE cid = ?")
      .bind(cid)
      .all<{ owner_did: string }>();
    return results.map((row) => row.owner_did);
  }

  async closureOf(ownerDid: string): Promise<string[]> {
    await this.init();
    const { results } = await this.db
      .prepare("SELECT cid FROM pf_refs WHERE owner_did = ?")
      .bind(ownerDid)
      .all<{ cid: string }>();
    return results.map((row) => row.cid);
  }

  close(): void {
    // D1 has no connection to close.
  }
}
