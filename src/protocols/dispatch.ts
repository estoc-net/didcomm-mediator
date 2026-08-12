import { randomUUID } from "node:crypto";

import type { Unpacked } from "../didcomm/didcomm.js";
import type { Handler, HandlerContext, Reply } from "./types.js";
import {
  MEDIATE_REQUEST,
  RECIPIENT_QUERY,
  RECIPIENT_UPDATE,
  mediateRequest,
  recipientQuery,
  recipientUpdate,
} from "./coordinate-mediation.js";
import {
  DELIVERY_REQUEST,
  LIVE_DELIVERY_CHANGE,
  MESSAGES_RECEIVED,
  STATUS_REQUEST,
  deliveryRequest,
  liveDeliveryChange,
  messagesReceived,
  statusRequest,
} from "./pickup.js";
import { FORWARD, forward } from "./routing.js";
import { QUERIES, queries } from "./discover-features.js";
import { PING, ping } from "./trust-ping.js";
import { PROBLEM_REPORT } from "./problem-report.js";

const HANDLERS: Record<string, Handler> = {
  [MEDIATE_REQUEST]: mediateRequest,
  [RECIPIENT_UPDATE]: recipientUpdate,
  [RECIPIENT_QUERY]: recipientQuery,
  [STATUS_REQUEST]: statusRequest,
  [DELIVERY_REQUEST]: deliveryRequest,
  [MESSAGES_RECEIVED]: messagesReceived,
  [LIVE_DELIVERY_CHANGE]: liveDeliveryChange,
  [FORWARD]: forward,
  [QUERIES]: queries,
  [PING]: ping,
};

/**
 * A message type nobody handles gets a problem-report — but only when there is
 * a proven sender to address it to. An anonymous sender posting garbage gets
 * silence, which is also what an attacker probing for a mediator gets.
 */
function unknownType(incoming: Unpacked, { sender }: HandlerContext): Reply | null {
  if (sender === null) {
    return null;
  }
  return {
    type: PROBLEM_REPORT,
    body: {
      code: "e.p.msg.unsupported",
      comment: `Unsupported message type: ${incoming.message.type}`,
    },
  };
}

/**
 * Whether the reply may ride the connection the request came in on — the
 * return-route extension, which messagepickup 3.0 requires of clients. Over
 * HTTP the header must be on every message; over a WebSocket it is set once
 * and turns the socket into the return route for the rest of its life. A
 * request without it still runs (its side effects stand), but the reply has
 * nowhere to go and is dropped.
 */
function returnRouteOpen(incoming: Unpacked, { session }: HandlerContext): boolean {
  const requested = incoming.message.return_route === "all";
  if (session === null) {
    return requested;
  }
  if (requested) {
    session.returnRoute = true;
  }
  return session.returnRoute;
}

/**
 * Open envelope in, sealed reply out (or null when the exchange is one-way).
 *
 * The reply's threading and addressing are decided here for every handler at
 * once: thid continues the incoming thread, a problem-report also carries
 * pthid, and the reply is sealed to the DID the envelope *proved*, never the
 * one the plaintext claimed.
 */
export async function dispatch(
  incoming: Unpacked,
  context: HandlerContext
): Promise<string | null> {
  const routed = returnRouteOpen(incoming, context);
  const handler = HANDLERS[incoming.message.type] ?? unknownType;
  const reply = await handler(incoming, context);

  if (reply === null || context.sender === null || !routed) {
    return null;
  }

  const thid = incoming.message.thid ?? incoming.message.id;
  // Reply as the DID the sender addressed: a mediator answering to several
  // names must not reveal the others, and the sender's resolver may only
  // know the one it used.
  const asDid = context.ctx.asOwnDid(incoming.addressedTo);
  return context.ctx.packEncrypted(
    {
      id: randomUUID(),
      typ: "application/didcomm-plain+json",
      type: reply.type,
      from: asDid,
      to: [context.sender],
      created_time: Math.floor(Date.now() / 1000),
      thid,
      ...(reply.type === PROBLEM_REPORT ? { pthid: thid } : {}),
      body: reply.body,
      ...(reply.attachments !== undefined
        ? { attachments: reply.attachments }
        : {}),
    },
    context.sender,
    asDid
  );
}
