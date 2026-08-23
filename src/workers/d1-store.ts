import { SqlStore } from "../store/sql-store.js";
import type { SqlDriver, SqlResult, SqlStatement } from "../store/sql-store.js";

export interface D1StoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
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

/** The Workers target's store: the shared SQL core over D1. */
export class D1Store extends SqlStore {
  constructor(db: D1Database, options: D1StoreOptions = {}) {
    super(new D1Driver(db), options);
  }
}
