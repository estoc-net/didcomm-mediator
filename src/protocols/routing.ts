import { didOf } from "../didcomm/didcomm.js";
import type { Unpacked } from "../didcomm/didcomm.js";
import type { StoredMessage } from "../store/types.js";
import type { HandlerContext, Reply } from "./types.js";
import { pushLiveDelivery } from "./pickup.js";

/**
 * routing/2.0 — https://didcomm.org/routing/2.0
 *
 * The one protocol an anonymous sender may use: the outer envelope of a
 * forward is anoncrypt by design (the whole point is that the mediator cannot
 * see who is writing to its clients), so no account gate and no reply — a
 * forward is fire-and-forget, and an undeliverable one is dropped, not
 * bounced, because a bounce to an anonymous sender is addressed to nobody.
 */

export const FORWARD = "https://didcomm.org/routing/2.0/forward";

/**
 * Where a forward for `next` lands.
 *
 * A local account wins over any keylist binding, unconditionally: an account
 * is created only by proving the DID with its own keys, so if `next` holds
 * one, the account holder is the DID's true controller — and a squatter who
 * bound the DID before the controller registered loses the race the moment
 * registration happens.
 */
function ownerFor(
  next: string,
  { store }: HandlerContext
): string | null {
  if (store.isMediated(next)) {
    return next;
  }
  return store.ownerOf(next);
}

/**
 * The packed form of one forwarded attachment, whichever way it was attached.
 * A links attachment has neither shape and is refused — a mediator that
 * fetches URLs on an anonymous sender's say-so is a proxy.
 */
function packedOf(attachment: { data: Record<string, unknown> }): string | null {
  const { data } = attachment;

  if (data.json !== undefined && data.json !== null) {
    return JSON.stringify(data.json);
  }

  if (typeof data.base64 === "string") {
    try {
      return Buffer.from(data.base64, "base64url").toString("utf8");
    } catch {
      return null;
    }
  }

  return null;
}

export async function forward(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  const next = didOf(
    typeof incoming.message.body.next === "string"
      ? incoming.message.body.next
      : null
  );
  if (next === null) {
    return null;
  }

  const owner = ownerFor(next, context);
  if (owner === null) {
    return null;
  }

  const attachments = incoming.message.attachments ?? [];
  const stored: StoredMessage[] = [];

  for (const attachment of attachments) {
    const packed = packedOf(attachment);
    if (packed === null) {
      continue;
    }

    const id = context.store.storeMessage(owner, packed);
    if (id !== null) {
      stored.push({ id, packed, createdAt: Date.now() });
    }
  }

  await pushLiveDelivery(context.ctx, context.sessions, owner, stored);
  return null;
}
