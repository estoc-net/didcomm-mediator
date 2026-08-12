import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import websocket from "@fastify/websocket";

import type { MediatorConfig } from "./config.js";
import { DIDCommContext } from "./didcomm/didcomm.js";
import type { MediatorIdentity } from "./identity.js";
import { dispatch } from "./protocols/dispatch.js";
import { SUPPORTED_PROTOCOLS } from "./protocols/discover-features.js";
import type { Session } from "./protocols/types.js";
import type { MediationStore } from "./store/types.js";
import { Sessions } from "./transport/sessions.js";

const ENCRYPTED = "application/didcomm-encrypted+json";
const DIDCOMM_CONTENT_TYPES = [
  ENCRYPTED,
  "application/didcomm-signed+json",
  "application/didcomm-plain+json",
];

export interface ServerOptions {
  identity: MediatorIdentity;
  store: MediationStore;
  config: MediatorConfig;
  logger?: boolean;
}

/**
 * The whole wire surface: POST / for envelopes (reply in the response body —
 * the return-route pattern every standard client expects), a WebSocket
 * upgrade on the same path for live delivery, and two discovery endpoints.
 * A standard client knows nothing but the service endpoint URI in the DID, so
 * everything must hang off it.
 */
export function buildServer({
  identity,
  store,
  config,
  logger = true,
}: ServerOptions): FastifyInstance {
  const app = Fastify({ logger });
  const ctx = new DIDCommContext(identity.did, identity.didDoc, identity.secrets);
  const sessions = new Sessions();

  app.register(cors, {
    origin: config.corsOrigin,
    methods: ["GET", "POST", "OPTIONS"],
  });

  // DIDComm media types arrive as opaque strings; unpack is the parser.
  for (const type of DIDCOMM_CONTENT_TYPES) {
    app.addContentTypeParser(type, { parseAs: "string" }, (_req, body, done) =>
      done(null, body)
    );
  }

  app.register(async (app) => {
    await app.register(websocket);

    app.post("/", async (request, reply) => {
      if (typeof request.body !== "string") {
        return reply
          .code(415)
          .send({ error: `Content-Type must be one of: ${DIDCOMM_CONTENT_TYPES.join(", ")}` });
      }

      let packed: string | null;
      try {
        const unpacked = await ctx.unpack(request.body);
        packed = await dispatch(unpacked, {
          ctx,
          store,
          config,
          sessions,
          session: null,
          sender: unpacked.verifiedFrom,
        });
      } catch (err) {
        request.log.info({ err }, "envelope refused");
        return reply.code(400).send({ error: "Message could not be unpacked" });
      }

      if (packed === null) {
        return reply.code(202).send();
      }
      return reply.code(200).header("content-type", ENCRYPTED).send(packed);
    });

    app.get("/", { websocket: true }, (socket, request) => {
      const session: Session = {
        did: null,
        liveDelivery: false,
        send(packed: string): boolean {
          if (socket.readyState !== socket.OPEN) {
            return false;
          }
          socket.send(packed);
          return true;
        },
      };

      socket.on("message", async (raw: Buffer) => {
        try {
          const unpacked = await ctx.unpack(raw.toString("utf8"));

          // The socket inherits the first proven identity and keeps it: live
          // delivery needs a DID to index the connection under, and a session
          // that could re-bind mid-flight could be walked onto someone else's
          // inbox by a single crafted envelope.
          if (session.did === null && unpacked.verifiedFrom !== null) {
            session.did = unpacked.verifiedFrom;
            sessions.bind(session.did, session);
          }

          const packed = await dispatch(unpacked, {
            ctx,
            store,
            config,
            sessions,
            session,
            sender: unpacked.verifiedFrom,
          });

          if (packed !== null) {
            session.send(packed);
          }
        } catch (err) {
          request.log.info({ err }, "websocket envelope refused");
        }
      });

      socket.on("close", () => {
        sessions.drop(session.did, session);
      });
    });
  });

  const describe = () => ({
    did: identity.did,
    protocols: SUPPORTED_PROTOCOLS,
  });

  // The path Affinidi clients look at, and a convenient one for humans.
  app.get("/.well-known/did", describe);
  app.get("/health", () => ({ status: "ok" }));

  return app;
}
