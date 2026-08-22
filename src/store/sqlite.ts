import Database from "better-sqlite3";

import { SqlStore } from "./sql-store.js";
import type { SqlDriver, SqlResult, SqlStatement } from "./sql-store.js";

export interface SqliteStoreOptions {
  /** Messages older than this are purged. */
  messageTtlSeconds?: number;
  /** Past this many waiting messages an account stops receiving new ones. */
  maxMessagesPerAccount?: number;
  /** Unreferenced public-folder objects older than this are purged. */
  stagedObjectTtlSeconds?: number;
}

/** better-sqlite3 is synchronous; a batch is simply a transaction. */
class BetterSqliteDriver implements SqlDriver {
  private db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
  }

  async batch(statements: SqlStatement[]): Promise<SqlResult[]> {
    const results: SqlResult[] = [];
    this.db.transaction(() => {
      for (const { sql, params = [] } of statements) {
        const statement = this.db.prepare(sql);
        const args = params.map((value) =>
          value instanceof Uint8Array ? Buffer.from(value) : value
        );
        if (statement.reader) {
          results.push({
            rows: statement.all(...args) as Record<string, unknown>[],
            changes: 0,
          });
        } else {
          results.push({ rows: [], changes: statement.run(...args).changes });
        }
      }
    })();
    return results;
  }

  close(): void {
    this.db.close();
  }
}

/** The Node/Docker target's store: the shared SQL core over one local file. */
export class SqliteStore extends SqlStore {
  /** `path` is a file path, or ":memory:" for tests. */
  constructor(path: string, options: SqliteStoreOptions = {}) {
    super(new BetterSqliteDriver(path), options);
  }
}
