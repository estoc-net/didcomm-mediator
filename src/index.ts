import { join } from "node:path";

import { configFromEnv } from "./config.js";
import { loadOrCreateIdentity } from "./identity.js";
import { buildServer } from "./server.js";
import { SqliteStore } from "./store/sqlite.js";

const PURGE_INTERVAL_MS = 60 * 60 * 1000;

const config = configFromEnv();
const identity = loadOrCreateIdentity(config.dataDir, config.publicUrl);
const store = new SqliteStore(join(config.dataDir, "mediator.db"), {
  messageTtlSeconds: config.messageTtlSeconds,
  maxMessagesPerAccount: config.maxMessagesPerAccount,
});

const app = buildServer({ identity, store, config });

const purger = setInterval(() => {
  const purged = store.purgeExpired();
  if (purged > 0) {
    app.log.info({ purged }, "purged expired messages");
  }
}, PURGE_INTERVAL_MS);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, async () => {
    clearInterval(purger);
    await app.close();
    store.close();
    process.exit(0);
  });
}

app.log.info({ did: identity.did }, "mediator identity");
await app.listen({ host: config.host, port: config.port });
