/**
 * Operator policy CLI — the admin face of the compliance core.
 *
 * One CLI, one store, two drivers, because both deployment targets host
 * content: `--db <path>` opens the Node/Docker target's SQLite file
 * directly, `--remote` reaches the Workers target's D1 through a driver
 * that renders each statement as literal SQL and ships the batch over
 * `wrangler d1 execute --command` (a multi-statement command runs as one
 * batch, D1's only transaction shape, and returns per-statement rows —
 * `--file` would not: it takes D1's import path, which returns only summary
 * statistics). Either way the commands run the same SqlStore code the
 * mediator itself runs, so every change writes its audit line in the same
 * transaction.
 *
 * The serve default is deliberately not here: it's deployment
 * configuration (`MEDIATOR_PUBLICATION_SERVE_DEFAULT`), not a rule.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { isCid } from "./public-folder/objects.js";
import { SqlStore } from "./store/sql-store.js";
import type { SqlDriver, SqlResult, SqlStatement, SqlValue } from "./store/sql-store.js";
import { SqliteStore } from "./store/sqlite.js";
import type { PolicyAuditEntry, PolicyKind, PolicyRule } from "./store/types.js";

/** A user mistake, reported with the usage text; everything else is a bug. */
export class UsageError extends Error {}

export function usage(): string {
  return `Operator policy for a didcomm-mediator (public-folder compliance core).

Usage:
  npm run policy -- --db <path/to/mediator.db> <command>
  npm run policy -- --remote [--database <name>] [--env <name>] <command>

Commands (the subject's kind — DID or CID — is inferred from its shape):
  list                                          every rule
  audit [--limit <n>]                           operator-action trail, newest first
  status <did|cid>                              is it on this mediator? metadata only,
                                                never the bytes (exit 1 = not stored)
  block <did|cid> [--hold <t>] [--note <text>]  serve (and publish) as if absent
  legal <did|cid> [--hold <t>] [--note <text>]  same, but HTTP reads may say 451
  allow <did|cid> [--note <text>]               allowlist under a deny default
  clear <did|cid>                               remove the rule (audited)
  quarantine <did> [--hold <t>] [--note <text>] block the DID and hold every object
                                                in its current closure (default 365d)

--hold takes a duration (365d, 12h) or a date; a held object survives the
purge unreferenced until then. --remote wraps \`wrangler d1 execute\` against
the database named in wrangler.jsonc (override with --database / --env).`;
}

export function kindOf(subject: string): PolicyKind {
  if (subject.startsWith("did:")) {
    return "did";
  }
  if (isCid(subject)) {
    return "cid";
  }
  throw new UsageError(`${subject} is neither a DID nor a CID`);
}

/** `365d` / `12h` relative to now, or anything Date.parse reads; epoch ms. */
export function parseHold(value: string, now: number): number {
  const relative = /^(\d+)([dh])$/.exec(value);
  if (relative !== null) {
    const unit = relative[2] === "d" ? 86_400_000 : 3_600_000;
    return now + Number(relative[1]) * unit;
  }
  const absolute = Date.parse(value);
  if (!Number.isNaN(absolute)) {
    return absolute;
  }
  throw new UsageError(`--hold takes a duration (365d, 12h) or a date, not "${value}"`);
}

/* ---------------------------------------------------------------- remote */

/** SQL literal — D1 over wrangler has no bound parameters. */
export function sqlLiteral(value: SqlValue): string {
  if (value === null) {
    return "NULL";
  }
  if (typeof value === "number") {
    return String(value);
  }
  if (typeof value === "string") {
    return `'${value.replace(/'/g, "''")}'`;
  }
  throw new Error("Blob parameters do not travel over wrangler");
}

/** Interpolates a statement's parameters as escaped literals. */
export function renderStatement({ sql, params = [] }: SqlStatement): string {
  const parts = sql.split("?");
  if (parts.length !== params.length + 1) {
    throw new Error(`Parameter count mismatch in: ${sql}`);
  }
  return parts
    .slice(1)
    .reduce((acc, part, i) => acc + sqlLiteral(params[i]) + part, parts[0]);
}

export interface RemoteTarget {
  database: string;
  env: string | null;
}

/**
 * The Workers target's driver: one `wrangler d1 execute` round trip per
 * batch. Wrangler's JSON reports rows per statement but no changes count,
 * so `changes` is always 0 — the policy paths never read it.
 */
class WranglerDriver implements SqlDriver {
  constructor(private target: RemoteTarget) {}

  async batch(statements: SqlStatement[]): Promise<SqlResult[]> {
    const sql = statements
      .map((statement) => `${renderStatement(statement)};`)
      .join("\n");
    const args = [
      "wrangler",
      "d1",
      "execute",
      this.target.database,
      "--remote",
      "--json",
      "--command",
      sql,
    ];
    if (this.target.env !== null) {
      args.push("--env", this.target.env);
    }
    const proc = spawnSync("npx", args, { encoding: "utf8" });
    if (proc.error) {
      throw proc.error;
    }
    if (proc.status !== 0) {
      throw new Error(
        `wrangler exited ${proc.status}:\n${proc.stderr || proc.stdout}`
      );
    }
    const start = proc.stdout.indexOf("[");
    const end = proc.stdout.lastIndexOf("]");
    if (start < 0 || end < start) {
      throw new Error(`wrangler returned no JSON:\n${proc.stdout}`);
    }
    const batches = JSON.parse(proc.stdout.slice(start, end + 1)) as {
      results?: Record<string, unknown>[];
    }[];
    return statements.map((_, i) => ({
      rows: batches[i]?.results ?? [],
      changes: 0,
    }));
  }

  close(): void {}
}

/* ------------------------------------------------------------- commands */

const iso = (ms: number) => new Date(ms).toISOString();

export function formatRule(rule: PolicyRule): string {
  const parts = [`${rule.kind.padEnd(3)} ${rule.mode.padEnd(5)} ${rule.subject}`];
  if (rule.holdUntil !== null) {
    parts.push(`hold until ${iso(rule.holdUntil)}`);
  }
  if (rule.note !== null) {
    parts.push(`# ${rule.note}`);
  }
  return parts.join("  ");
}

export function formatAudit(entry: PolicyAuditEntry): string {
  const parts = [
    `${iso(entry.at)}  ${entry.action.padEnd(5)} ` +
      `${entry.kind.padEnd(3)} ${(entry.mode ?? "").padEnd(5)} ${entry.subject}`,
  ];
  if (entry.holdUntil !== null) {
    parts.push(`hold until ${iso(entry.holdUntil)}`);
  }
  if (entry.note !== null) {
    parts.push(`# ${entry.note}`);
  }
  return parts.join("  ");
}

interface Parsed {
  flags: Map<string, string>;
  remote: boolean;
  positionals: string[];
}

const VALUE_FLAGS = new Set(["db", "database", "env", "limit", "hold", "note"]);

export function parseArgs(argv: string[]): Parsed {
  const flags = new Map<string, string>();
  const positionals: string[] = [];
  let remote = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (name === "remote") {
      remote = true;
      continue;
    }
    if (!VALUE_FLAGS.has(name)) {
      throw new UsageError(`Unknown flag ${arg}`);
    }
    const value = argv[++i];
    if (value === undefined) {
      throw new UsageError(`${arg} needs a value`);
    }
    flags.set(name, value);
  }
  return { flags, remote, positionals };
}

/** wrangler.jsonc's database_name, so --remote works bare from the repo. */
function configuredDatabase(): string | null {
  try {
    const jsonc = readFileSync("wrangler.jsonc", "utf8");
    const match = /"database_name"\s*:\s*"([^"]+)"/.exec(jsonc);
    return match === null ? null : match[1];
  } catch {
    return null;
  }
}

function storeFor(parsed: Parsed): SqlStore {
  const db = parsed.flags.get("db");
  if (db !== undefined && parsed.remote) {
    throw new UsageError("--db and --remote are two different mediators; pick one");
  }
  if (db !== undefined) {
    if (!existsSync(db)) {
      // better-sqlite3 would happily mint an empty database at a typo'd
      // path and every command would "work" against nothing.
      throw new UsageError(`No database at ${db}`);
    }
    return new SqliteStore(db);
  }
  if (parsed.remote) {
    const database = parsed.flags.get("database") ?? configuredDatabase();
    if (database === null) {
      throw new UsageError(
        "--remote found no wrangler.jsonc here; name the database with --database"
      );
    }
    const driver = new WranglerDriver({
      database,
      env: parsed.flags.get("env") ?? null,
    });
    // The live worker owns the schema; the CLI only visits.
    return new SqlStore(driver, { ensureSchema: false });
  }
  throw new UsageError("Pick a backend: --db <path> or --remote");
}

function subjectOf(parsed: Parsed): { kind: PolicyKind; subject: string } {
  const subject = parsed.positionals[1];
  if (subject === undefined) {
    throw new UsageError(`${parsed.positionals[0]} needs a subject`);
  }
  return { kind: kindOf(subject), subject };
}

export async function runPolicy(
  argv: string[],
  print: (line: string) => void
): Promise<number> {
  let parsed: Parsed;
  let store: SqlStore;
  try {
    parsed = parseArgs(argv);
    if (parsed.positionals.length === 0) {
      print(usage());
      return 1;
    }
    store = storeFor(parsed);
  } catch (error) {
    if (error instanceof UsageError) {
      print(error.message);
      print("");
      print(usage());
      return 1;
    }
    throw error;
  }

  try {
    const verb = parsed.positionals[0];
    const note = parsed.flags.get("note") ?? null;
    const holdFlag = parsed.flags.get("hold");

    switch (verb) {
      case "list": {
        const rules = await store.listPolicyRules();
        if (rules.length === 0) {
          print("No rules.");
        }
        for (const rule of rules) {
          print(formatRule(rule));
        }
        return 0;
      }
      case "audit": {
        const limit = Number(parsed.flags.get("limit") ?? "50");
        if (!Number.isInteger(limit) || limit <= 0) {
          throw new UsageError("--limit takes a positive integer");
        }
        const entries = await store.policyAudit(limit);
        if (entries.length === 0) {
          print("No audit entries.");
        }
        for (const entry of entries) {
          print(formatAudit(entry));
        }
        return 0;
      }
      case "status": {
        // The assessment tool: answers "do I possess this?" from metadata
        // alone. The public HTTP face can't (hidden and absent are the same
        // 404 by design), and fetching the object to check would put the
        // bytes in front of the operator — exactly what an abuse assessment
        // must not do.
        const { kind, subject } = subjectOf(parsed);
        const rule = (await store.policyRules(kind, [subject])).get(subject);
        if (kind === "did") {
          const card = await store.getCard(subject);
          if (card === null) {
            print("no card — this mediator holds nothing for that DID");
          } else if (card.root === null) {
            print("takedown card (root null) — publisher withdrew the folder");
          } else {
            const closure = await store.closureOf(subject);
            const present = await store.objectsPresent(closure);
            let bytes = 0;
            for (const size of present.values()) {
              bytes += size;
            }
            print(`card present, root ${card.root}`);
            print(
              `closure ${closure.length} object${closure.length === 1 ? "" : "s"}, ` +
                `${present.size} stored, ${bytes} bytes`
            );
          }
          print(rule === undefined ? "no rule" : `rule: ${formatRule(rule)}`);
          return card === null ? 1 : 0;
        }
        const size = (await store.objectsPresent([subject])).get(subject);
        if (size === undefined) {
          print("not stored");
        } else {
          print(`stored, ${size} bytes`);
          const owners = await store.referencingOwners(subject);
          print(
            owners.length === 0
              ? "referenced by no current publication"
              : `referenced by ${owners.join(", ")}`
          );
        }
        print(rule === undefined ? "no rule" : `rule: ${formatRule(rule)}`);
        return size === undefined ? 1 : 0;
      }
      case "block":
      case "legal":
      case "allow": {
        const { kind, subject } = subjectOf(parsed);
        const holdUntil =
          holdFlag === undefined ? null : parseHold(holdFlag, Date.now());
        await store.setPolicyRules([{ kind, subject, mode: verb, holdUntil, note }]);
        const hold = holdUntil === null ? "" : `, held until ${iso(holdUntil)}`;
        print(`${verb} ${subject}${hold}`);
        return 0;
      }
      case "clear": {
        const { kind, subject } = subjectOf(parsed);
        if (await store.clearPolicyRule(kind, subject)) {
          print(`Cleared ${subject}`);
          return 0;
        }
        print(`No rule for ${subject}`);
        return 1;
      }
      case "quarantine": {
        const { kind, subject } = subjectOf(parsed);
        if (kind !== "did") {
          throw new UsageError("quarantine takes a DID; to hold one object, block the CID with --hold");
        }
        const holdUntil = parseHold(holdFlag ?? "365d", Date.now());
        const closure = await store.closureOf(subject);
        const stamp = note ?? `quarantine ${subject}`;
        await store.setPolicyRules([
          // The DID rule blocks; holds only mean something on cid rules
          // (they pin objects through the purge), so they go there.
          { kind: "did", subject, mode: "block", holdUntil: null, note: stamp },
          ...closure.map((cid) => ({
            kind: "cid" as const,
            subject: cid,
            mode: "block" as const,
            holdUntil,
            note: stamp,
          })),
        ]);
        print(
          `Blocked ${subject}; ${closure.length} object${closure.length === 1 ? "" : "s"} ` +
            `held until ${iso(holdUntil)}`
        );
        return 0;
      }
      default:
        throw new UsageError(`Unknown command ${verb}`);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      print(error.message);
      return 1;
    }
    throw error;
  } finally {
    store.close();
  }
}

const invokedAs = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedAs) {
  runPolicy(process.argv.slice(2), (line) => console.log(line)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error);
      process.exitCode = 1;
    }
  );
}
