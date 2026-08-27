import { Hono, type Context } from "hono";
import { cors } from "hono/cors";

import type { BlobService } from "./blobs/service.js";
import type { MediatorPolicy } from "./config.js";
import type { DIDCommContext } from "./didcomm/didcomm.js";
import { buildInvitation, invitationUrl } from "./oob.js";
import { dispatch } from "./protocols/dispatch.js";
import { supportedProtocols } from "./protocols/discover-features.js";
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
  /** blob-store/1.0; absent, the mediator keeps no blobs and says so. */
  blobs?: BlobService | null;
  /** The public base URL the OOB invitation URL is built on. */
  publicUrl: string;
  /** The document served at the did:web paths; null unless the identity is did:web. */
  webDidDoc?: Record<string, unknown> | null;
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
function tooLarge(c: Context, limit: number) {
  return c.json({ error: `Envelope exceeds ${limit} bytes` }, 413);
}

/**
 * The size of one WebSocket frame's payload, before decoding — the same
 * ceiling the HTTP entry applies, for the runtimes' socket handlers.
 */
export function frameBytes(
  data: string | ArrayBufferLike | ArrayBufferView | Blob
): number {
  if (typeof data === "string") {
    return new TextEncoder().encode(data).byteLength;
  }
  if (data instanceof Blob) {
    return data.size;
  }
  return data.byteLength;
}

export function buildApp({
  ctx,
  store,
  policy,
  sessions,
  blobs = null,
  publicUrl,
  webDidDoc = null,
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
        allowMethods: ["GET", "HEAD", "PUT", "POST", "OPTIONS"],
        allowHeaders: ["Content-Type", "Range"],
        exposeHeaders: ["Content-Range", "Accept-Ranges", "Content-Length"],
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

    // Size is judged on the bytes received, before any parsing: the
    // Content-Length lets an oversize envelope be refused without reading
    // it, and the body length catches a chunked one after. The 413 reaches
    // the sender synchronously — which is the only bounce a forward gets,
    // since its DIDComm layer is anonymous and fire-and-forget.
    const declared = Number(c.req.header("content-length"));
    if (declared > policy.maxMessageBytes) {
      return tooLarge(c, policy.maxMessageBytes);
    }
    const raw = await c.req.arrayBuffer();
    if (raw.byteLength > policy.maxMessageBytes) {
      return tooLarge(c, policy.maxMessageBytes);
    }

    let packed: string | null;
    try {
      const unpacked = await ctx.unpack(new TextDecoder().decode(raw));
      packed = await dispatch(unpacked, {
        ctx,
        store,
        config: policy,
        sessions,
        blobs,
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
    // Every name this mediator answers to; `did` is the advertised one.
    dids: ctx.dids,
    invitationUrl: oobUrl,
    protocols: supportedProtocols(blobs !== null),
    // The wire ceiling, so a client can size an envelope before sending it.
    maxMessageBytes: policy.maxMessageBytes,
    // blob-store/1.0 limits, when blobs are kept at all.
    ...(blobs === null ? {} : { blobs: blobs.limits() }),
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
      return c.html(invitationPage(ctx.did, oobUrl, policy.abuseEmail));
    }
    return c.json(describe());
  });

  // The invitation as a plaintext JWM — what the `_oob` parameter encodes.
  app.get("/invitation", (c) =>
    c.body(JSON.stringify(invitation), 200, {
      "content-type": "application/didcomm-plain+json",
    })
  );

  // did:web resolution: a bare-domain DID is fetched at /.well-known/did.json,
  // one with path segments at <path>/did.json — which lands here at /did.json
  // when a proxy mounts the app under that path. Serving both costs nothing.
  if (webDidDoc !== null) {
    const body = JSON.stringify(webDidDoc);
    for (const path of ["/.well-known/did.json", "/did.json"]) {
      app.get(path, (c) =>
        c.body(body, 200, { "content-type": "application/did+ld+json" })
      );
    }
  }

  // blob-store/1.0's HTTP side: the bytes, under a random id. GET/HEAD to
  // anyone who has the URL (the content is ciphertext and the key went by
  // DIDComm); PUT only under a one-time token a put-result handed out.
  // Without blobs the routes are simply not there.
  if (blobs !== null) {
    app.on(["GET", "HEAD"], "/b/:id", (c) =>
      blobs.serve(c.req.param("id"), c.req.header("range") ?? null, c.req.method === "HEAD")
    );
    app.put("/b/:id", (c) => {
      const token = c.req.query("token");
      if (token === undefined) {
        return c.text("no such upload", 404);
      }
      return blobs.upload(c.req.param("id"), token, c.req.raw);
    });
  }

  app.get("/health", (c) => c.json({ status: "ok" }));

  return app;
}

/** What a human sees opening the invitation URL in a browser. */
function invitationPage(
  did: string,
  oobUrl: string,
  abuseEmail: string | null
): string {
  const footer =
    abuseEmail === null
      ? ""
      : `
<footer>Report abuse to <a href="mailto:${abuseEmail}">${abuseEmail}</a>.</footer>`;
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIDComm mediator</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
  code { word-break: break-all; background: #eee; padding: .1rem .3rem; border-radius: .2rem; }
  footer { margin-top: 2.5rem; font-size: .85rem; color: #777; }
</style>
<h1>DIDComm mediator</h1>
<p>This is a DIDComm v2 mediator. To use it, open the invitation below with a
compatible wallet or agent — it will request mediation and route its inbound
messages through here.</p>
<p>Invitation URL:</p>
<p><code>${oobUrl}</code></p>
<p>Mediator DID:</p>
<p><code>${did}</code></p>${footer}`;
}
