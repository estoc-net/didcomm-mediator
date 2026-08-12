import { Hono } from "hono";
import { cors } from "hono/cors";

import type { MediatorPolicy } from "./config.js";
import type { DIDCommContext } from "./didcomm/didcomm.js";
import { buildInvitation, invitationUrl } from "./oob.js";
import { dispatch } from "./protocols/dispatch.js";
import { SUPPORTED_PROTOCOLS } from "./protocols/discover-features.js";
import type { LiveSink } from "./protocols/types.js";
import type { MediationStore } from "./store/types.js";

export const ENCRYPTED = "application/didcomm-encrypted+json";
export const DIDCOMM_CONTENT_TYPES = [
  ENCRYPTED,
  "application/didcomm-signed+json",
  "application/didcomm-plain+json",
];

export interface AppDeps {
  ctx: DIDCommContext;
  store: MediationStore;
  policy: MediatorPolicy;
  sessions: LiveSink;
  /** The public base URL the OOB invitation URL is built on. */
  publicUrl: string;
  /** Where refused envelopes get logged; silent by default. */
  log?: (msg: string, err?: unknown) => void;
}

/**
 * The transport-independent wire surface, shared by the Node server and the
 * Workers entry: POST / for envelopes (reply in the response body — the
 * return-route pattern every standard client expects) plus the discovery
 * endpoints. The WebSocket upgrade also lives at GET /, but sockets are where
 * the runtimes genuinely differ, so each target mounts its own handler there
 * — the plain GET below steps aside for anything carrying an Upgrade header.
 */
export function buildApp({
  ctx,
  store,
  policy,
  sessions,
  publicUrl,
  log = () => {},
}: AppDeps): Hono {
  const app = new Hono();

  const invitation = buildInvitation(ctx.did);
  const oobUrl = invitationUrl(publicUrl, invitation);

  if (policy.corsOrigin !== false) {
    app.use(
      "*",
      cors({
        origin: policy.corsOrigin === true ? "*" : policy.corsOrigin,
        allowMethods: ["GET", "POST", "OPTIONS"],
      })
    );
  }

  app.post("/", async (c) => {
    const contentType = (c.req.header("content-type") ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (!DIDCOMM_CONTENT_TYPES.includes(contentType)) {
      return c.json(
        { error: `Content-Type must be one of: ${DIDCOMM_CONTENT_TYPES.join(", ")}` },
        415
      );
    }

    let packed: string | null;
    try {
      const unpacked = await ctx.unpack(await c.req.text());
      packed = await dispatch(unpacked, {
        ctx,
        store,
        config: policy,
        sessions,
        session: null,
        sender: unpacked.verifiedFrom,
      });
    } catch (err) {
      log("envelope refused", err);
      return c.json({ error: "Message could not be unpacked" }, 400);
    }

    if (packed === null) {
      return c.body(null, 202);
    }
    return c.body(packed, 200, { "content-type": ENCRYPTED });
  });

  const describe = () => ({
    did: ctx.did,
    invitationUrl: oobUrl,
    protocols: SUPPORTED_PROTOCOLS,
  });

  // Plain GET / answers humans and probes; an Upgrade request falls through
  // to whichever WebSocket handler the runtime mounted after this. A browser
  // lands here when someone opens the invitation URL (`?_oob=` rides on the
  // public URL), and the spec asks that URL to show human-readable
  // instructions — so browsers get a page, everything else gets JSON.
  app.get("/", async (c, next) => {
    if (c.req.header("upgrade")?.toLowerCase() === "websocket") {
      await next();
      return;
    }
    if (c.req.header("accept")?.includes("text/html")) {
      return c.html(invitationPage(ctx.did, oobUrl));
    }
    return c.json(describe());
  });

  // The invitation as a plaintext JWM — what the `_oob` parameter encodes.
  app.get("/invitation", (c) =>
    c.body(JSON.stringify(invitation), 200, {
      "content-type": "application/didcomm-plain+json",
    })
  );

  // The path Affinidi clients look at, and a convenient one for humans.
  app.get("/.well-known/did", (c) => c.json(describe()));
  app.get("/health", (c) => c.json({ status: "ok" }));

  return app;
}

/** What a human sees opening the invitation URL in a browser. */
function invitationPage(did: string, oobUrl: string): string {
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIDComm mediator</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
  code { word-break: break-all; background: #eee; padding: .1rem .3rem; border-radius: .2rem; }
</style>
<h1>DIDComm mediator</h1>
<p>This is a DIDComm v2 mediator. To use it, open the invitation below with a
compatible wallet or agent — it will request mediation and route its inbound
messages through here.</p>
<p>Invitation URL:</p>
<p><code>${oobUrl}</code></p>
<p>Mediator DID:</p>
<p><code>${did}</code></p>`;
}
