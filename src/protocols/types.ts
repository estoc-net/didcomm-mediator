import type { IMessage } from "didcomm-node";

import type { MediatorConfig } from "../config.js";
import type { DIDCommContext, Unpacked } from "../didcomm/didcomm.js";
import type { MediationStore } from "../store/types.js";

/**
 * One live connection (in practice: a WebSocket) a client is holding open.
 * HTTP requests are not sessions — their reply rides the response body and
 * that is the whole relationship.
 */
export interface Session {
  /** The account this session authenticated as, once it has. */
  did: string | null;
  liveDelivery: boolean;
  /** Push a packed message to the client; false once the connection is gone. */
  send(packed: string): boolean;
}

export interface SessionRegistry {
  /** Sessions authenticated as `did` that asked for live delivery. */
  liveSessionsFor(did: string): Session[];
}

export interface HandlerContext {
  ctx: DIDCommContext;
  store: MediationStore;
  config: MediatorConfig;
  sessions: SessionRegistry;
  /** The session the message arrived on; null for plain HTTP. */
  session: Session | null;
  /** The DID proven by the envelope (authcrypt or signature); null if anonymous. */
  sender: string | null;
}

/**
 * A handler's reply, if any — type and body only. Dispatch fills in the
 * envelope bookkeeping (id, typ, from, to, thid, created_time) so no handler
 * can get it wrong.
 */
export interface Reply {
  type: string;
  body: Record<string, unknown>;
  attachments?: IMessage["attachments"];
}

export type Handler = (
  incoming: Unpacked,
  context: HandlerContext
) => Promise<Reply | null> | Reply | null;
