import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { configFromEnv } from "./config.js";
import { identityFor, loadOrCreateSecrets } from "./identity-core.js";
import { buildServer } from "./server.js";
import { SqliteStore } from "./store/sqlite.js";

const PURGE_INTERVAL_MS = 60 * 60 * 1000;

const config = configFromEnv();
mkdirSync(config.dataDir, { recursive: true });
const store = new SqliteStore(join(config.dataDir, "mediator.db"), {
  messageTtlSeconds: config.messageTtlSeconds,
  maxMessagesPerAccount: config.maxMessagesPerAccount,
});

// The keys live in the same SQLite file as everything else — the db *is* the
// mediator. peer2 is the Node default: it works on any URL, localhost included.
const secrets = await loadOrCreateSecrets(store, console.log);
const identity = identityFor(
  secrets,
  config.publicUrl,
  config.didMethods.length > 0 ? config.didMethods : ["peer2"]
);

const server = buildServer({
  identity,
  store,
  config,
  log: (msg, err) => console.warn(msg, err instanceof Error ? err.message : err),
});

const purger = setInterval(async () => {
  const purged = await store.purgeExpired();
  if (purged > 0) {
    console.log(`purged ${purged} expired messages`);
  }
}, PURGE_INTERVAL_MS);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, async () => {
    clearInterval(purger);
    await server.close();
    store.close();
    process.exit(0);
  });
}

console.log(`mediator identity ${identity.did}`);
const port = await server.listen();
console.log(`listening on ${config.host}:${port}`);
