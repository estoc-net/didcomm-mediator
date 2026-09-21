import { serve } from "@hono/node-server";
import { createNodeWebSocket } from "@hono/node-ws";
import type { Hono } from "hono";
import type { Server } from "node:http";

import { buildApp, frameBytes } from "./app.js";
import { FsBlobStorage } from "./blobs/fs-storage.js";
import { BlobService } from "./blobs/service.js";
import type { MediatorConfig } from "./config.js";
import { DIDCommContext } from "./didcomm/didcomm.js";
import type { MediatorIdentity } from "./identity-core.js";
import { dispatch } from "./protocols/dispatch.js";
import type { Session } from "./protocols/types.js";
import type { MediationStore } from "./store/types.js";
import { Sessions } from "./transport/sessions.js";

export interface ServerOptions {
  identity: MediatorIdentity;
  store: MediationStore;
  config: MediatorConfig;
  /** Where refused envelopes get logged; silent by default. */
  log?: (msg: string, err?: unknown) => void;
}

export interface MediatorServer {
  app: Hono;
  /** Resolves to the actual bound port (useful with port 0). */
  listen(): Promise<number>;
  close(): Promise<void>;
  /** Drops blobs past their retention or without a mediation; 0 when blobs are off. */
  purgeBlobs(): Promise<number>;
}

/**
 * The Node shape of the mediator: the shared Hono app plus this runtime's
 * WebSocket story — one process, so live sessions are an in-memory registry
 * and the upgrade handler simply joins it. (On Workers the same app is served
 * by a stateless isolate and the socket work moves into a Durable Object.)
 */
export function buildServer({
  identity,
  store,
  config,
  log = () => {},
}: ServerOptions): MediatorServer {
  const ctx = new DIDCommContext(identity.did, identity.didDoc, identity.secrets, {
    aliases: identity.aliases,
  });
  const sessions = new Sessions();
  const blobs =
    config.blobDir === null
      ? null
      : new BlobService(store, new FsBlobStorage(config.blobDir), config, config.publicUrl);
  const app = buildApp({
    ctx,
    store,
    policy: config,
    sessions,
    blobs,
    publicUrl: config.publicUrl,
    webDidDoc: identity.webDidDoc,
    log,
  });
  const { injectWebSocket, upgradeWebSocket } = createNodeWebSocket({ app });

  app.get(
    "/",
    upgradeWebSocket(() => {
      const session: Session & { socket: WSLike | null } = {
        did: null,
        liveDelivery: false,
        returnRoute: false,
        socket: null,
        send(packed: string): boolean {
          if (this.socket === null || this.socket.readyState !== 1) {
            return false;
          }
          // Text frame: the spec is silent on frame type, and a text frame
          // reaches every receiver as a plain string (browser, RN, Node)
          // while binary arrives as Blob/Buffer/ArrayBuffer depending on
          // the environment. Send the most compatible; accept both.
          this.socket.send(packed);
          return true;
        },
      };

      return {
        onOpen(_evt, ws) {
          session.socket = ws;
        },
        async onMessage(evt, ws) {
          session.socket = ws;
          if (frameBytes(evt.data) > config.maxMessageBytes) {
            log("websocket envelope refused: too large");
            return;
          }
          try {
            const raw =
              typeof evt.data === "string"
                ? evt.data
                : new TextDecoder().decode(
                    evt.data instanceof Blob
                      ? new Uint8Array(await evt.data.arrayBuffer())
                      : new Uint8Array(evt.data)
                  );
            const unpacked = await ctx.unpack(raw);

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
              blobs,
              session,
              sender: unpacked.verifiedFrom,
              log,
            });

            if (packed !== null) {
              session.send(packed);
            }
          } catch (err) {
            log("websocket envelope refused", err);
          }
        },
        onClose() {
          sessions.drop(session.did, session);
        },
      };
    })
  );

  let server: Server | null = null;

  return {
    app,
    listen(): Promise<number> {
      return new Promise((resolve) => {
        server = serve(
          { fetch: app.fetch, hostname: config.host, port: config.port },
          (info) => resolve(info.port)
        ) as Server;
        injectWebSocket(server);
      });
    },
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        if (server === null) {
          resolve();
          return;
        }
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
    purgeBlobs(): Promise<number> {
      return blobs === null ? Promise.resolve(0) : blobs.purge();
    },
  };
}

interface WSLike {
  readyState: number;
  send(data: string): void;
}
