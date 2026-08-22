/**
 * Operator policy CLI — the admin face of the compliance core.
 *
 * One CLI, two backends, because both deployment targets host content:
 * `--db <path>` opens the Node/Docker target's SQLite file directly and
 * reuses the store (so every change writes its audit line in the same
 * transaction), `--remote` wraps `wrangler d1 execute` for the Workers
 * target (no interactive transactions there — the upsert and its audit
 * line travel in one batch instead).
 *
 * The serve default is deliberately not here: it's deployment
 * configuration (`MEDIATOR_PUBLICATION_SERVE_DEFAULT`), not a rule.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { isCid } from "./public-folder/objects.js";
import { SqliteStore } from "./store/sqlite.js";
import type {
  PolicyAuditEntry,
  PolicyKind,
  PolicyMode,
  PolicyRule,
} from "./store/types.js";

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

/*
 * What a backend must do — the five store calls the commands compose.
 * `set` takes a batch so quarantine's many rules go out in one round trip.
 */
export interface PolicyBackend {
  list(): Promise<PolicyRule[]>;
  audit(limit: number): Promise<PolicyAuditEntry[]>;
  set(rules: Omit<PolicyRule, "createdAt">[]): Promise<void>;
  clear(kind: PolicyKind, subject: string): Promise<boolean>;
  closure(ownerDid: string): Promise<string[]>;
  close(): void;
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

/* ---------------------------------------------------------------- SQLite */

class SqliteBackend implements PolicyBackend {
  private store: SqliteStore;

  constructor(path: string) {
    if (!existsSync(path)) {
      // better-sqlite3 would happily mint an empty database at a typo'd
      // path and every command would "work" against nothing.
      throw new UsageError(`No database at ${path}`);
    }
    this.store = new SqliteStore(path);
  }

  list() {
    return this.store.listPolicyRules();
  }

  audit(limit: number) {
    return this.store.policyAudit(limit);
  }

  async set(rules: Omit<PolicyRule, "createdAt">[]) {
    for (const rule of rules) {
      await this.store.setPolicyRule(rule);
    }
  }

  clear(kind: PolicyKind, subject: string) {
    return this.store.clearPolicyRule(kind, subject);
  }

  closure(ownerDid: string) {
    return this.store.closureOf(ownerDid);
  }

  close() {
    this.store.close();
  }
}

/* ---------------------------------------------------------------- remote */

/** SQL string/number literal — D1 over wrangler has no bound parameters. */
export function sqlLiteral(value: string | number | null): string {
  if (value === null) {
    return "NULL";
  }
  if (typeof value === "number") {
    return String(value);
  }
  return `'${value.replace(/'/g, "''")}'`;
}

/** The upsert + audit pair for each rule, mirroring setPolicyRule. */
export function setRulesSql(
  rules: Omit<PolicyRule, "createdAt">[],
  now: number
): string {
  return rules
    .flatMap((rule) => {
      const values = [
        sqlLiteral(rule.kind),
        sqlLiteral(rule.subject),
        sqlLiteral(rule.mode),
        sqlLiteral(rule.holdUntil),
        sqlLiteral(rule.note),
      ].join(", ");
      return [
        "INSERT INTO pf_policy (kind, subject, mode, hold_until, note, created_at) " +
          `VALUES (${values}, ${now}) ` +
          "ON CONFLICT(kind, subject) DO UPDATE SET mode = excluded.mode, " +
          "hold_until = excluded.hold_until, note = excluded.note;",
        "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
          `VALUES (${now}, 'set', ${values});`,
      ];
    })
    .join("\n");
}

/** The delete + audit pair, mirroring clearPolicyRule after an exists check. */
export function clearRuleSql(kind: PolicyKind, subject: string, now: number): string {
  const where = `kind = ${sqlLiteral(kind)} AND subject = ${sqlLiteral(subject)}`;
  return (
    `DELETE FROM pf_policy WHERE ${where};\n` +
    "INSERT INTO pf_audit (at, action, kind, subject) " +
    `VALUES (${now}, 'clear', ${sqlLiteral(kind)}, ${sqlLiteral(subject)});`
  );
}

export interface RemoteTarget {
  database: string;
  env: string | null;
}

interface RuleRow {
  kind: string;
  subject: string;
  mode: string;
  hold_until: number | null;
  note: string | null;
  created_at: number;
}

class RemoteBackend implements PolicyBackend {
  constructor(private target: RemoteTarget) {}

  /**
   * One `wrangler d1 execute` round trip. The SQL travels as a file — long
   * quarantine batches would burst the argument list — and wrangler sends a
   * multi-statement file as one batch, D1's only transaction shape.
   */
  private run(sql: string): Record<string, unknown>[] {
    const dir = mkdtempSync(join(tmpdir(), "mediator-policy-"));
    const file = join(dir, "policy.sql");
    try {
      writeFileSync(file, sql);
      const args = [
        "wrangler",
        "d1",
        "execute",
        this.target.database,
        "--remote",
        "--json",
        "--file",
        file,
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
      return batches.flatMap((batch) => batch.results ?? []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  async list(): Promise<PolicyRule[]> {
    const rows = this.run(
      "SELECT kind, subject, mode, hold_until, note, created_at FROM pf_policy " +
        "ORDER BY created_at, kind, subject;"
    ) as unknown as RuleRow[];
    return rows.map((row) => ({
      kind: row.kind as PolicyKind,
      subject: row.subject,
      mode: row.mode as PolicyMode,
      holdUntil: row.hold_until,
      note: row.note,
      createdAt: row.created_at,
    }));
  }

  async audit(limit: number): Promise<PolicyAuditEntry[]> {
    const rows = this.run(
      "SELECT at, action, kind, subject, mode, hold_until, note FROM pf_audit " +
        `ORDER BY id DESC LIMIT ${Math.trunc(limit)};`
    ) as unknown as (RuleRow & { at: number; action: string })[];
    return rows.map((row) => ({
      at: row.at,
      action: row.action as PolicyAuditEntry["action"],
      kind: row.kind as PolicyKind,
      subject: row.subject,
      mode: row.mode as PolicyMode | null,
      holdUntil: row.hold_until,
      note: row.note,
    }));
  }

  async set(rules: Omit<PolicyRule, "createdAt">[]): Promise<void> {
    // Chunked so a huge quarantine closure never rides one giant batch.
    for (let i = 0; i < rules.length; i += 40) {
      this.run(setRulesSql(rules.slice(i, i + 40), Date.now()));
    }
  }

  async clear(kind: PolicyKind, subject: string): Promise<boolean> {
    const exists = this.run(
      `SELECT 1 AS present FROM pf_policy WHERE kind = ${sqlLiteral(kind)} ` +
        `AND subject = ${sqlLiteral(subject)};`
    );
    if (exists.length === 0) {
      return false;
    }
    this.run(clearRuleSql(kind, subject, Date.now()));
    return true;
  }

  async closure(ownerDid: string): Promise<string[]> {
    const rows = this.run(
      `SELECT cid FROM pf_refs WHERE owner_did = ${sqlLiteral(ownerDid)};`
    ) as unknown as { cid: string }[];
    return rows.map((row) => row.cid);
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

function backendFor(parsed: Parsed): PolicyBackend {
  const db = parsed.flags.get("db");
  if (db !== undefined && parsed.remote) {
    throw new UsageError("--db and --remote are two different mediators; pick one");
  }
  if (db !== undefined) {
    return new SqliteBackend(db);
  }
  if (parsed.remote) {
    const database = parsed.flags.get("database") ?? configuredDatabase();
    if (database === null) {
      throw new UsageError(
        "--remote found no wrangler.jsonc here; name the database with --database"
      );
    }
    return new RemoteBackend({
      database,
      env: parsed.flags.get("env") ?? null,
    });
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
  let backend: PolicyBackend;
  try {
    parsed = parseArgs(argv);
    if (parsed.positionals.length === 0) {
      print(usage());
      return 1;
    }
    backend = backendFor(parsed);
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
        const rules = await backend.list();
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
        const entries = await backend.audit(limit);
        if (entries.length === 0) {
          print("No audit entries.");
        }
        for (const entry of entries) {
          print(formatAudit(entry));
        }
        return 0;
      }
      case "block":
      case "legal":
      case "allow": {
        const { kind, subject } = subjectOf(parsed);
        const holdUntil =
          holdFlag === undefined ? null : parseHold(holdFlag, Date.now());
        await backend.set([{ kind, subject, mode: verb, holdUntil, note }]);
        const hold = holdUntil === null ? "" : `, held until ${iso(holdUntil)}`;
        print(`${verb} ${subject}${hold}`);
        return 0;
      }
      case "clear": {
        const { kind, subject } = subjectOf(parsed);
        if (await backend.clear(kind, subject)) {
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
        const closure = await backend.closure(subject);
        const stamp = note ?? `quarantine ${subject}`;
        await backend.set([
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
    backend.close();
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
