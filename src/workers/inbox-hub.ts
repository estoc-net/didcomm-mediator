import { dispatch } from "../protocols/dispatch.js";
import type { Session } from "../protocols/types.js";
import { Sessions } from "../transport/sessions.js";
import { depsFromEnv, type Env, type WorkerDeps } from "./env.js";

/**
 * The Durable Object holding every live WebSocket — the stateful heart the
 * stateless Worker cannot be.
 *
 * One instance for the whole mediator (idFromName("hub")), which is a direct
 * port of the Node server's in-memory session registry rather than the
 * per-account-object design: a session only learns which account it is *after*
 * its first authenticated frame, so connections cannot be routed to a
 * per-account object at upgrade time without a second registry anyway. At the
 * scale where one object's throughput becomes the bottleneck, that redesign
 * is the known next step.
 *
 * Sockets are hibernatable: the object can be evicted while connections stay
 * open, so each socket's proven DID and live-delivery flag ride along as its
 * serialized attachment, and the constructor rebuilds the registry from
 * whatever sockets survived.
 */

interface Attachment {
  did: string | null;
  liveDelivery: boolean;
  returnRoute: boolean;
}

interface HubSession extends Session {
  ws: WebSocket;
}

export class InboxHub {
  private deps: WorkerDeps;
  private sessions = new Sessions();
  private bySocket = new Map<WebSocket, HubSession>();

  constructor(
    private state: DurableObjectState,
    env: Env
  ) {
    this.deps = depsFromEnv(env);
    for (const ws of state.getWebSockets()) {
      this.adopt(ws);
    }
  }

  private adopt(ws: WebSocket): HubSession {
    const saved = (ws.deserializeAttachment() ?? null) as Attachment | null;
    let liveDelivery = saved?.liveDelivery ?? false;
    let returnRoute = saved?.returnRoute ?? false;

    const session: HubSession = {
      ws,
      did: saved?.did ?? null,
      get liveDelivery() {
        return liveDelivery;
      },
      set liveDelivery(value: boolean) {
        liveDelivery = value;
        persist();
      },
      get returnRoute() {
        return returnRoute;
      },
      set returnRoute(value: boolean) {
        returnRoute = value;
        persist();
      },
      send(packed: string): boolean {
        try {
          // Binary frame — browsers only wrap binary frames in a Blob, and
          // the DIF demo reads every frame with `event.data.text()`.
          ws.send(new TextEncoder().encode(packed));
          return true;
        } catch {
          return false;
        }
      },
    };
    const persist = () =>
      ws.serializeAttachment({
        did: session.did,
        liveDelivery,
        returnRoute,
      } satisfies Attachment);

    if (session.did !== null) {
      this.sessions.bind(session.did, session);
    }
    this.bySocket.set(ws, session);
    return session;
  }

  async fetch(request: Request): Promise<Response> {
    if ((request.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1]);
      this.adopt(pair[1]);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    // The Worker-facing side, unreachable from the internet (Durable Objects
    // only answer their binding): live-session queries and delivery pushes.
    const url = new URL(request.url);

    if (url.pathname === "/live") {
      const did = url.searchParams.get("did") ?? "";
      return Response.json({ live: this.sessions.wantsPush(did) });
    }

    if (url.pathname === "/push" && request.method === "POST") {
      const { did, packed } = (await request.json()) as {
        did: string;
        packed: string;
      };
      this.sessions.push(did, packed);
      return Response.json({ ok: true });
    }

    return new Response(null, { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    const session = this.bySocket.get(ws) ?? this.adopt(ws);
    try {
      const raw =
        typeof message === "string"
          ? message
          : new TextDecoder().decode(message);
      const unpacked = await this.deps.ctx.unpack(raw);

      // The socket inherits the first proven identity and keeps it: live
      // delivery needs a DID to index the connection under, and a session
      // that could re-bind mid-flight could be walked onto someone else's
      // inbox by a single crafted envelope.
      if (session.did === null && unpacked.verifiedFrom !== null) {
        session.did = unpacked.verifiedFrom;
        this.sessions.bind(session.did, session);
        ws.serializeAttachment({
          did: session.did,
          liveDelivery: session.liveDelivery,
          returnRoute: session.returnRoute,
        } satisfies Attachment);
      }

      const packed = await dispatch(unpacked, {
        ctx: this.deps.ctx,
        store: this.deps.store,
        config: this.deps.policy,
        sessions: this.sessions,
        session,
        sender: unpacked.verifiedFrom,
      });

      if (packed !== null) {
        session.send(packed);
      }
    } catch (err) {
      console.warn("websocket envelope refused", err);
    }
  }

  webSocketClose(ws: WebSocket) {
    this.drop(ws);
  }

  webSocketError(ws: WebSocket) {
    this.drop(ws);
  }

  private drop(ws: WebSocket) {
    const session = this.bySocket.get(ws);
    if (session !== undefined) {
      this.sessions.drop(session.did, session);
      this.bySocket.delete(ws);
    }
  }
}
