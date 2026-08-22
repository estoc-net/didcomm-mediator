import { chunked } from "../store/types.js";
import { SqlStore } from "../store/sql-store.js";
import type {
  BlobStore,
  SqlDriver,
  SqlResult,
  SqlStatement,
} from "../store/sql-store.js";

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

/**
 * D1 *is* SQLite behind an async API, so the shared store's contract maps
 * directly: `batch()` is D1's batch, its only transaction shape. Blob
 * parameters travel as ArrayBuffers sliced to exactly the view's bytes.
 */
class D1Driver implements SqlDriver {
  constructor(private db: D1Database) {}

  async batch(statements: SqlStatement[]): Promise<SqlResult[]> {
    const prepared = statements.map(({ sql, params = [] }) =>
      this.db.prepare(sql).bind(
        ...params.map((value) =>
          value instanceof Uint8Array
            ? value.buffer.slice(
                value.byteOffset,
                value.byteOffset + value.byteLength
              )
            : value
        )
      )
    );
    const results = await this.db.batch(prepared);
    return results.map((result) => ({
      rows: (result.results ?? []) as Record<string, unknown>[],
      changes: result.meta.changes ?? 0,
    }));
  }

  close(): void {
    // D1 has no connection to close.
  }
}

class R2Blobs implements BlobStore {
  readonly name = "r2";

  constructor(private bucket: R2Bucket) {}

  async put(cid: string, bytes: Uint8Array): Promise<void> {
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength
    );
    await this.bucket.put(cid, buffer as ArrayBuffer);
  }

  async get(cid: string): Promise<Uint8Array | null> {
    const object = await this.bucket.get(cid);
    return object == null ? null : new Uint8Array(await object.arrayBuffer());
  }

  async delete(cids: string[]): Promise<void> {
    // R2's bulk delete takes up to 1000 keys.
    for (const chunk of chunked(cids, 1000)) {
      await this.bucket.delete(chunk);
    }
  }
}

/** The Workers target's store: the shared SQL core over D1, bytes in R2. */
export class D1Store extends SqlStore {
  constructor(db: D1Database, options: D1StoreOptions = {}) {
    super(new D1Driver(db), {
      ...options,
      blobs: options.objects === undefined ? undefined : new R2Blobs(options.objects),
    });
  }
}
