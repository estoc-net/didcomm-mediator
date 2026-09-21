import canonicalize from "canonicalize";

import { didOf } from "../didcomm/didcomm.js";
import type { Unpacked } from "../didcomm/didcomm.js";
import type { HandlerContext, Reply } from "./types.js";
import { pushLiveDelivery } from "./pickup.js";

/**
 * routing/2.0 — https://didcomm.org/routing/2.0
 *
 * The one protocol an anonymous sender may use: the outer envelope of a
 * forward is anoncrypt by design (the whole point is that the mediator cannot
 * see who is writing to its clients), so no account gate and no DIDComm
 * reply — a bounce to an anonymous sender is addressed to nobody. What a
 * sender does get is the HTTP status of its own call: a forward that was not
 * queued is refused there, so an accepted call always means queued mail.
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
async function ownerFor(
  next: string,
  { store }: HandlerContext
): Promise<string | null> {
  if (await store.isMediated(next)) {
    return next;
  }
  return store.ownerOf(next);
}

export const ENCRYPTED_MEDIA_TYPE = "application/didcomm-encrypted+json";

/**
 * Why a forward was not queued, as the HTTP status its sender sees. Malformed
 * (400) and oversized (413) are judged on the forward alone. Everything that
 * depends on who holds mail here — no such recipient, a full queue, a key
 * already holding other bytes — is one answer (422), so the status says
 * little about any account. The message never quotes the forward.
 */
export class ForwardRefused extends Error {
  constructor(
    readonly status: 400 | 413 | 422,
    message: string
  ) {
    super(message);
  }
}

const malformed = (what: string) => new ForwardRefused(400, `The forward ${what}`);

const JWE_MEMBERS = ["protected", "iv", "ciphertext", "tag"];

/**
 * The one envelope a forward carries, as the bytes that are queued and later
 * handed over: its RFC 8785 form, so a retry that spells the same JSON another
 * way is still the same package. The envelope is looked at, never opened —
 * a links attachment is refused too, since a mediator that fetches URLs on an
 * anonymous sender's say-so is a proxy.
 */
function envelopeOf(incoming: Unpacked): string {
  const attachments = incoming.message.attachments ?? [];
  if (attachments.length !== 1) {
    throw malformed("must carry exactly one attachment");
  }

  // didcomm-rust's own forward wrapper leaves the media type out, so only an
  // attachment that claims to be something else is turned away; what it
  // holds is checked below either way.
  const [attachment] = attachments;
  const mediaType = attachment.media_type ?? ENCRYPTED_MEDIA_TYPE;
  if (mediaType !== ENCRYPTED_MEDIA_TYPE) {
    throw malformed(`attachment must be ${ENCRYPTED_MEDIA_TYPE}`);
  }

  const data = attachment.data as Record<string, unknown>;
  const asJson = data.json !== undefined && data.json !== null;
  const asBase64 = typeof data.base64 === "string";
  if (asJson === asBase64 || data.links !== undefined) {
    throw malformed("attachment must hold its envelope as json or as base64, and only so");
  }

  let envelope: unknown;
  try {
    envelope = asJson
      ? data.json
      : JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            Buffer.from(data.base64 as string, "base64url")
          )
        );
  } catch {
    throw malformed("attachment does not decode to JSON");
  }

  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
    throw malformed("attachment is not an encrypted message");
  }
  const members = envelope as Record<string, unknown>;
  const recipients = members.recipients;
  if (
    !JWE_MEMBERS.every((name) => typeof members[name] === "string" && members[name] !== "") ||
    !Array.isArray(recipients) ||
    recipients.length === 0
  ) {
    throw malformed("attachment is not an encrypted message");
  }

  try {
    return canonicalize(envelope) as string;
  } catch {
    throw malformed("attachment has no canonical form");
  }
}

export async function forward(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  if (incoming.metadata.encrypted !== true) {
    throw malformed("must arrive encrypted");
  }

  const next = didOf(
    typeof incoming.message.body.next === "string"
      ? incoming.message.body.next
      : null
  );
  if (next === null || !next.startsWith("did:")) {
    throw malformed("names no recipient");
  }

  // The wire limit does not settle this: a number written `1e20` is three
  // bytes on the wire and twenty-one in canonical form.
  const packed = envelopeOf(incoming);
  const limit = context.config.maxMessageBytes;
  if (new TextEncoder().encode(packed).byteLength > limit) {
    throw new ForwardRefused(413, `Envelope exceeds ${limit} bytes`);
  }

  const notQueued = () => new ForwardRefused(422, "The forward was not queued");
  const owner = await ownerFor(next, context);
  if (owner === null) {
    throw notQueued();
  }

  const stored = await context.store.storeMessage(
    owner,
    { next, forwardId: incoming.message.id },
    packed
  );
  if (stored.outcome === "repeated") {
    return null;
  }
  if (stored.outcome !== "stored") {
    throw notQueued();
  }

  // The push introduces itself as the DID the forward was addressed to — the
  // routing DID the recipient's grant handed out, so the name they expect.
  await pushLiveDelivery(
    context.ctx,
    context.sessions,
    owner,
    [stored.message],
    context.ctx.asOwnDid(incoming.addressedTo)
  );
  return null;
}
