import type { Hono } from "hono";

import { buildApp } from "../app.js";
import type { LiveSink } from "../protocols/types.js";
import { depsFromEnv, type Env } from "./env.js";

export { InboxHub } from "./inbox-hub.js";

/**
 * The Workers entry: the same shared Hono app as the Node server, except that
 * the isolate is stateless — WebSocket upgrades are handed to the inbox
 * Durable Object wholesale, and live-delivery pushes for messages that arrive
 * over plain HTTP travel to it as one internal call.
 */

function hub(env: Env) {
  return env.INBOX.get(env.INBOX.idFromName("hub"));
}

let cachedApp: Hono | null = null;

function appFor(env: Env): Hono {
  if (cachedApp !== null) {
    return cachedApp;
  }

  const { ctx, store, policy } = depsFromEnv(env);

  const sink: LiveSink = {
    async wantsPush(ownerDid) {
      const res = await hub(env).fetch(
        `https://inbox/live?did=${encodeURIComponent(ownerDid)}`
      );
      return ((await res.json()) as { live: boolean }).live;
    },
    async push(ownerDid, packedDelivery) {
      await hub(env).fetch("https://inbox/push", {
        method: "POST",
        body: JSON.stringify({ did: ownerDid, packed: packedDelivery }),
      });
    },
  };

  cachedApp = buildApp({
    ctx,
    store,
    policy,
    sessions: sink,
    log: (msg, err) => console.warn(msg, err),
  });
  return cachedApp;
}

export default {
  fetch(request: Request, env: Env): Response | Promise<Response> {
    if ((request.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      return hub(env).fetch(request);
    }
    return appFor(env).fetch(request);
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const purged = await depsFromEnv(env).store.purgeExpired();
    if (purged > 0) {
      console.log(`purged ${purged} expired messages`);
    }
  },
};
