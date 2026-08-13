import type { Hono } from "hono";

import { buildApp } from "../app.js";
import type { LiveSink } from "../protocols/types.js";
import { depsForOrigin, storeFromEnv, type Env } from "./env.js";

export { InboxHub } from "./inbox-hub.js";

/**
 * The Workers entry: the same shared Hono app as the Node server, except that
 * the isolate is stateless — WebSocket upgrades are handed to the inbox
 * Durable Object wholesale, and live-delivery pushes for messages that arrive
 * over plain HTTP travel to it as one internal call.
 *
 * There is one app per origin, not one per isolate: the deployment is
 * URL-agnostic, answering every host that routes to it as that host's own
 * did:web, so the identity — and the app built around it — is a function of
 * the origin the request arrived on.
 */

function hub(env: Env) {
  return env.INBOX.get(env.INBOX.idFromName("hub"));
}

const apps = new Map<string, Promise<Hono>>();

function appFor(env: Env, origin: string): Promise<Hono> {
  let app = apps.get(origin);
  if (app === undefined) {
    app = buildAppFor(env, origin);
    // A failed build (say, D1 unreachable) must not poison the origin.
    app.catch(() => apps.delete(origin));
    apps.set(origin, app);
  }
  return app;
}

async function buildAppFor(env: Env, origin: string): Promise<Hono> {
  const { ctx, store, policy, identity } = await depsForOrigin(env, origin);

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

  return buildApp({
    ctx,
    store,
    policy,
    sessions: sink,
    publicUrl: identity.publicUrl,
    webDidDoc: identity.webDidDoc,
    log: (msg, err) => console.warn(msg, err),
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if ((request.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      return hub(env).fetch(request);
    }
    const app = await appFor(env, new URL(request.url).origin);
    return app.fetch(request);
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const purged = await storeFromEnv(env).purgeExpired();
    if (purged > 0) {
      console.log(`purged ${purged} expired messages`);
    }
  },
};
