import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import {
  kindOf,
  parseHold,
  renderStatement,
  runPolicy,
  sqlLiteral,
  UsageError,
} from "../src/policy-cli.js";
import { fileCid } from "../src/public-folder/objects.js";
import { SqliteStore } from "../src/store/sqlite.js";

const dir = mkdtempSync(join(tmpdir(), "policy-cli-test-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** Run the CLI against a db file, capturing output lines. */
async function cli(dbPath: string, ...args: string[]) {
  const lines: string[] = [];
  const code = await runPolicy(["--db", dbPath, ...args], (line) =>
    lines.push(line)
  );
  return { code, lines, output: lines.join("\n") };
}

describe("policy CLI plumbing", () => {
  it("infers the subject's kind from its shape", async () => {
    expect(kindOf("did:web:example.com")).toBe("did");
    expect(kindOf(await fileCid(new TextEncoder().encode("x")))).toBe("cid");
    expect(() => kindOf("banana")).toThrow(UsageError);
  });

  it("reads holds as durations or dates", () => {
    const now = 1_700_000_000_000;
    expect(parseHold("365d", now)).toBe(now + 365 * 86_400_000);
    expect(parseHold("12h", now)).toBe(now + 12 * 3_600_000);
    expect(parseHold("2027-08-22T00:00:00.000Z", now)).toBe(
      Date.parse("2027-08-22T00:00:00.000Z")
    );
    expect(() => parseHold("soon", now)).toThrow(UsageError);
  });

  it("renders remote statements as literal SQL, quotes escaped", () => {
    // The remote driver ships the store's own statements as literal SQL.
    const sql = renderStatement({
      sql:
        "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
        "VALUES (?, 'set', ?, ?, ?, ?, ?)",
      params: [456, "did", "did:web:evil.example", "block", 123, "O'Brien's report"],
    });
    expect(sql).toBe(
      "INSERT INTO pf_audit (at, action, kind, subject, mode, hold_until, note) " +
        "VALUES (456, 'set', 'did', 'did:web:evil.example', 'block', 123, " +
        "'O''Brien''s report')"
    );

    expect(sqlLiteral(null)).toBe("NULL");
    expect(sqlLiteral(7)).toBe("7");
    // A placeholder/parameter mismatch is a bug, never silently misrendered.
    expect(() => renderStatement({ sql: "VALUES (?, ?)", params: [1] })).toThrow();
    // Blobs never travel over wrangler.
    expect(() =>
      renderStatement({ sql: "VALUES (?)", params: [new Uint8Array([1])] })
    ).toThrow();
  });

  it("refuses to mint a database at a typo'd --db path", async () => {
    const missing = join(dir, "nope", "mediator.db");
    const { code, output } = await cli(missing, "list");
    expect(code).toBe(1);
    expect(output).toContain(`No database at ${missing}`);
  });
});

describe("policy CLI against a SQLite mediator", () => {
  it("walks the whole operator flow: block, list, quarantine, clear, audit", async () => {
    const dbPath = join(dir, "mediator.db");
    const owner = "did:web:owner.example";
    const rootCid = await fileCid(new TextEncoder().encode("root node"));
    const leafCid = await fileCid(new TextEncoder().encode("leaf bytes"));

    // Seed a mediator whose owner has a current publication closure.
    const seed = new SqliteStore(dbPath);
    await seed.putCard(owner, "jws-goes-here", rootCid, [rootCid, leafCid]);
    seed.close();

    // block with a note
    const blocked = await cli(
      dbPath, "block", "did:web:evil.example", "--note", "ticket 7"
    );
    expect(blocked.code).toBe(0);

    // quarantine: blocks the DID and holds its whole current closure
    const quarantined = await cli(dbPath, "quarantine", owner);
    expect(quarantined.code).toBe(0);
    expect(quarantined.output).toContain("2 objects held until");

    const list = await cli(dbPath, "list");
    expect(list.code).toBe(0);
    expect(list.output).toContain("did block did:web:evil.example");
    expect(list.output).toContain("# ticket 7");
    expect(list.output).toContain(`did block ${owner}`);
    expect(list.output).toContain(`cid block ${rootCid}`);
    expect(list.output).toContain(`cid block ${leafCid}`);
    expect(list.output).toContain(`# quarantine ${owner}`);

    // The cid rules carry the hold (about a year out); the did rules don't.
    const check = new SqliteStore(dbPath);
    const rules = await check.listPolicyRules();
    const holds = rules.filter((rule) => rule.holdUntil !== null);
    expect(holds.map((rule) => rule.kind)).toEqual(["cid", "cid"]);
    const yearOut = Date.now() + 365 * 86_400_000;
    for (const rule of holds) {
      expect(Math.abs(rule.holdUntil! - yearOut)).toBeLessThan(60_000);
    }
    check.close();

    // clear one rule; clearing it again finds nothing
    expect((await cli(dbPath, "clear", "did:web:evil.example")).code).toBe(0);
    const gone = await cli(dbPath, "clear", "did:web:evil.example");
    expect(gone.code).toBe(1);
    expect(gone.output).toContain("No rule for");

    // every action above left its audit line, newest first
    const audit = await cli(dbPath, "audit");
    expect(audit.code).toBe(0);
    expect(audit.lines[0]).toContain("clear");
    expect(audit.lines[0]).toContain("did:web:evil.example");
    expect(audit.output).toContain(leafCid);
    // 1 block + 3 quarantine sets + 1 clear
    expect(audit.lines).toHaveLength(5);
  });

  it("quarantine of a DID with no publication still blocks the DID", async () => {
    const dbPath = join(dir, "empty.db");
    new SqliteStore(dbPath).close();
    const result = await cli(dbPath, "quarantine", "did:web:quiet.example");
    expect(result.code).toBe(0);
    expect(result.output).toContain("0 objects");
    const store = new SqliteStore(dbPath);
    const rules = await store.listPolicyRules();
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      kind: "did",
      subject: "did:web:quiet.example",
      mode: "block",
    });
    store.close();
  });
});
