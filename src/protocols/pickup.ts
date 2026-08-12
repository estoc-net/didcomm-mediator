import { randomUUID } from "node:crypto";

import type { DIDCommContext, Unpacked } from "../didcomm/didcomm.js";
import type { StoredMessage } from "../store/types.js";
import type { HandlerContext, LiveSink, Reply } from "./types.js";
import { PROBLEM_REPORT } from "./problem-report.js";

/**
 * messagepickup/3.0 — https://didcomm.org/messagepickup/3.0
 *
 * One inbox per account: every message forwarded to any recipient DID an
 * account has bound lands in the same queue, and pickup always reads the
 * sender's own. `recipient_did` is accepted and echoed for spec conformance
 * but does not narrow the query — the DIF demo sends only `{limit}`, and an
 * account picking up someone else's queue is not a thing this store can
 * express in the first place.
 */

export const STATUS_REQUEST =
  "https://didcomm.org/messagepickup/3.0/status-request";
export const STATUS = "https://didcomm.org/messagepickup/3.0/status";
export const DELIVERY_REQUEST =
  "https://didcomm.org/messagepickup/3.0/delivery-request";
export const DELIVERY = "https://didcomm.org/messagepickup/3.0/delivery";
export const MESSAGES_RECEIVED =
  "https://didcomm.org/messagepickup/3.0/messages-received";
export const LIVE_DELIVERY_CHANGE =
  "https://didcomm.org/messagepickup/3.0/live-delivery-change";

const DELIVERY_PAGE_LIMIT = 10;

async function statusBody(
  { store, session, sender }: HandlerContext,
  recipientDid: unknown
): Promise<Record<string, unknown>> {
  return {
    message_count: sender === null ? 0 : await store.messageCount(sender),
    live_delivery: session?.liveDelivery ?? false,
    ...(typeof recipientDid === "string" ? { recipient_did: recipientDid } : {}),
  };
}

async function requireAccount({ store, sender }: HandlerContext): Promise<boolean> {
  return sender !== null && (await store.isMediated(sender));
}

export async function statusRequest(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  if (!(await requireAccount(context))) {
    return null;
  }
  return {
    type: STATUS,
    body: await statusBody(context, incoming.message.body.recipient_did),
  };
}

/** DIDComm attachments carry base64url, not standard base64. */
function toAttachment(message: StoredMessage) {
  return {
    id: message.id,
    data: { base64: Buffer.from(message.packed).toString("base64url") },
  };
}

export async function deliveryRequest(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  if (!(await requireAccount(context)) || context.sender === null) {
    return null;
  }

  const rawLimit = incoming.message.body.limit;
  const limit =
    typeof rawLimit === "number" && rawLimit > 0
      ? Math.min(Math.floor(rawLimit), DELIVERY_PAGE_LIMIT)
      : DELIVERY_PAGE_LIMIT;

  const messages = await context.store.messagesFor(context.sender, limit);
  if (messages.length === 0) {
    return {
      type: STATUS,
      body: await statusBody(context, incoming.message.body.recipient_did),
    };
  }

  const recipientDid = incoming.message.body.recipient_did;
  return {
    type: DELIVERY,
    body: typeof recipientDid === "string" ? { recipient_did: recipientDid } : {},
    attachments: messages.map(toAttachment),
  };
}

export async function messagesReceived(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  if (!(await requireAccount(context)) || context.sender === null) {
    return null;
  }

  const list = incoming.message.body.message_id_list;
  const ids = Array.isArray(list)
    ? list.filter((id): id is string => typeof id === "string")
    : [];

  await context.store.deleteMessages(context.sender, ids);
  return { type: STATUS, body: await statusBody(context, undefined) };
}

export async function liveDeliveryChange(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  if (!(await requireAccount(context))) {
    return null;
  }

  // Live delivery is a property of a connection that stays open; an HTTP
  // request is not one, and the spec names the problem code for saying so.
  if (context.session === null) {
    return {
      type: PROBLEM_REPORT,
      body: {
        code: "e.m.live-mode-not-supported",
        comment: "Live delivery requires a WebSocket connection",
      },
    };
  }

  context.session.liveDelivery = incoming.message.body.live_delivery === true;
  return { type: STATUS, body: await statusBody(context, undefined) };
}

/**
 * Push freshly stored messages to every live session the owner holds open —
 * the WebSocket half of pickup, called from the forward handler. Messages
 * stay in the inbox until messages-received deletes them, so a push that
 * races a disconnect loses nothing.
 */
export async function pushLiveDelivery(
  ctx: DIDCommContext,
  sessions: LiveSink,
  ownerDid: string,
  messages: StoredMessage[],
  asDid: string = ctx.did
): Promise<void> {
  if (messages.length === 0 || !(await sessions.wantsPush(ownerDid))) {
    return;
  }

  const packed = await ctx.packEncrypted(
    {
      id: randomUUID(),
      typ: "application/didcomm-plain+json",
      type: DELIVERY,
      from: asDid,
      to: [ownerDid],
      created_time: Math.floor(Date.now() / 1000),
      body: {},
      attachments: messages.map(toAttachment),
    },
    ownerDid,
    asDid
  );

  await sessions.push(ownerDid, packed);
}
