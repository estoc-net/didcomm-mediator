import { parse, traverse } from "@humanwhocodes/momoa";
import type { AnyNode, MemberNode, StringNode } from "@humanwhocodes/momoa";
import canonicalize from "canonicalize";
import { decodeProtectedHeader } from "jose";

import { DIDCommFailure, didOf } from "../didcomm/didcomm.js";
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
 * already holding other bytes — is one answer (422), which does not tell the
 * three apart; an accepted forward still tells its sender that `next` takes
 * mail here right now. The message never quotes the forward.
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

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** base64url as JOSE writes it (RFC 7515 §2): that alphabet only, no padding. */
const isBase64url = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1;

/**
 * JSON text as a value, refusing a member name that comes twice: JSON.parse
 * would quietly keep the last one, and RFC 8785 has no canonical form for an
 * object that was never unambiguous.
 */
function parseUnambiguous(text: string): unknown {
  traverse(parse(text, { mode: "json" }), {
    enter(node) {
      const { type, members } = node as AnyNode & { members?: MemberNode[] };
      if (type !== "Object" || members === undefined) {
        return;
      }
      const names = new Set(members.map(({ name }) => (name as StringNode).value));
      if (names.size !== members.length) {
        throw new SyntaxError("duplicate member name");
      }
    },
  });
  return JSON.parse(text);
}

/** An attachment's `base64`, decoded; senders differ on padding, so either way. */
function carriedText(base64: string): string {
  const unpadded = base64.length % 4 === 0 ? base64.replace(/={1,2}$/, "") : base64;
  if (!isBase64url(unpadded)) {
    throw new SyntaxError("not base64url");
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(unpadded, "base64url"));
}

const isName = (value: unknown): value is string => typeof value === "string" && value !== "";

/**
 * The JOSE header one recipient ends up with (RFC 7516 §7.2.1): the protected,
 * shared and per-recipient headers may not repeat a name between them, and
 * together they must name how the key was wrapped and the content encrypted
 * (§4.1.1, §4.1.2). Key agreement parameters are held to their JSON type and
 * no further: which algorithms these are is the recipient's business, and one
 * this mediator has never heard of is as welcome as any.
 */
function isJoseHeader(parts: Record<string, unknown>[]): boolean {
  const names = parts.flatMap(Object.keys);
  const header = Object.fromEntries(parts.flatMap(Object.entries));
  return (
    new Set(names).size === names.length &&
    isName(header.alg) &&
    isName(header.enc) &&
    (header.epk === undefined || isObject(header.epk)) &&
    ["apu", "apv", "skid"].every((name) => header[name] === undefined || typeof header[name] === "string")
  );
}

/**
 * The General JWE JSON Serialization (RFC 7516 §7.2.1) as DIDComm uses it,
 * by shape alone: every recipient names a key and carries a wrapped one, the
 * binary members are base64url, and each recipient's headers add up to one
 * JOSE header. `protected` is read, never rewritten: it is authenticated as
 * the string it came as. Members this does not know are left alone.
 */
function isEncryptedMessage(envelope: unknown): envelope is Record<string, unknown> {
  if (!isObject(envelope)) {
    return false;
  }
  const { recipients, aad, unprotected = {} } = envelope;
  if (
    !["protected", "iv", "ciphertext", "tag"].every((name) => isBase64url(envelope[name])) ||
    (aad !== undefined && !isBase64url(aad)) ||
    !isObject(unprotected) ||
    !Array.isArray(recipients) ||
    recipients.length === 0
  ) {
    return false;
  }
  let protectedHeader: Record<string, unknown>;
  try {
    protectedHeader = decodeProtectedHeader({ protected: envelope.protected }) as Record<string, unknown>;
  } catch {
    return false;
  }
  return recipients.every(
    (recipient: unknown) =>
      isObject(recipient) &&
      isBase64url(recipient.encrypted_key) &&
      isObject(recipient.header) &&
      isName(recipient.header.kid) &&
      isJoseHeader([protectedHeader, unprotected, recipient.header])
  );
}

/**
 * The one envelope a forward carries, as the bytes that are queued and later
 * handed over: its RFC 8785 form, so a retry that spells the same JSON another
 * way is still the same package. The envelope is looked at, never opened —
 * a links attachment is refused too, since a mediator that fetches URLs on an
 * anonymous sender's say-so is a proxy.
 */
function envelopeOf(incoming: Unpacked, limit: number): string {
  // Read from the sender's text, not the library's message: there a name that
  // came twice is already one value and a number may have moved, so the same
  // envelope could be queued as different bytes depending on how it was carried.
  let written: unknown;
  try {
    written = parseUnambiguous(incoming.plaintext);
  } catch {
    throw malformed("is not unambiguous JSON");
  }
  const attachments = isObject(written) && Array.isArray(written.attachments) ? written.attachments : [];
  if (attachments.length !== 1) {
    throw malformed("must carry exactly one attachment");
  }

  // didcomm-rust's own forward wrapper leaves the media type out, so only an
  // attachment that claims to be something else is turned away; what it
  // holds is checked below either way.
  const [attachment] = attachments as Record<string, unknown>[];
  if ((attachment.media_type ?? ENCRYPTED_MEDIA_TYPE) !== ENCRYPTED_MEDIA_TYPE) {
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
    envelope = asJson ? data.json : parseUnambiguous(carriedText(data.base64 as string));
  } catch {
    throw malformed("attachment does not decode to JSON");
  }

  let canonical: string | undefined;
  try {
    if (isEncryptedMessage(envelope)) {
      canonical = canonicalize(envelope);
    }
  } catch {
    // Nested past what the stack walks, or a value with no canonical form.
  }
  if (canonical === undefined) {
    throw malformed("attachment is not an encrypted message");
  }

  // The wire limit does not settle this: a number written `1e20` is four
  // bytes on the wire and twenty-one in canonical form.
  if (new TextEncoder().encode(canonical).byteLength > limit) {
    throw new ForwardRefused(413, `Envelope exceeds ${limit} bytes`);
  }
  return canonical;
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

  const packed = envelopeOf(incoming, context.config.maxMessageBytes);

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

  // The mail is queued, and that is what the sender is told whatever becomes
  // of the push: pickup hands it over all the same. The push introduces itself
  // as the DID the forward was addressed to — the routing DID the recipient's
  // grant handed out, so the name they expect.
  try {
    await pushLiveDelivery(
      context.ctx,
      context.sessions,
      owner,
      [stored.message],
      context.ctx.asOwnDid(incoming.addressedTo)
    );
  } catch (err) {
    context.log?.(
      "live delivery push failed; the message stays queued",
      err instanceof DIDCommFailure ? err : undefined
    );
  }
  return null;
}
