import { join } from "node:path";

import { configFromEnv } from "./config.js";
import { loadOrCreateIdentity } from "./identity.js";
import { buildServer } from "./server.js";
import { SqliteStore } from "./store/sqlite.js";

const PURGE_INTERVAL_MS = 60 * 60 * 1000;

const config = configFromEnv();
const identity = loadOrCreateIdentity(
  config.dataDir,
  config.publicUrl,
  config.didMethods
);
const store = new SqliteStore(join(config.dataDir, "mediator.db"), {
  messageTtlSeconds: config.messageTtlSeconds,
  maxMessagesPerAccount: config.maxMessagesPerAccount,
});

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
