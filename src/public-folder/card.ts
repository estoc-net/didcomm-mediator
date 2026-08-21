/**
 * The root card — the one signature in the system. Compact JWS, EdDSA over
 * Ed25519, `kid` naming the owner's verification method.
 *
 * Copied lineage from @estoc/signed-dir, with the spec's takedown-card
 * change already applied: `root` is REQUIRED but nullable, and a null root
 * is the owner's signed statement that this DID currently publishes
 * nothing. Null is the only takedown encoding — a card missing the field
 * is malformed, so a takedown can only be written deliberately.
 *
 * This module proves *who signed what*; whether the card is acceptable —
 * expiry, publish policy — is the caller's decision, deliberately outside.
 */

import {
  base64urlToBytes,
  base64urlToUtf8,
  bytesToBase64url,
  utf8ToBase64url,
} from "@estoc/did-peer";

/** The one signed statement: owner, opaque version label, lifetime, tree. */
export interface RootCard {
  did: string;
  /** Opaque author label — the protocol only ever compares it for equality. */
  id: string;
  /** RFC 3339 instant after which the card is stale (the DNS-TTL analogue). */
  expires: string;
  /** Root directory CID; null on a takedown card. */
  root: string | null;
}

function checkCardShape(value: unknown): RootCard {
  const { did, id, expires, root } = (value ?? {}) as Record<string, unknown>;
  if (
    typeof did !== "string" ||
    typeof id !== "string" ||
    typeof expires !== "string" ||
    (root !== null && typeof root !== "string")
  ) {
    throw new Error("malformed root card");
  }
  return { did, id, expires, root };
}

/** Anything that can produce a raw 64-byte Ed25519 signature. */
export interface CardSigner {
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Sign a root card into a compact JWS (tests and tooling; the relay only verifies). */
export async function createCard(
  card: RootCard,
  signer: CardSigner,
  kid: string
): Promise<string> {
  const header = utf8ToBase64url(JSON.stringify({ alg: "EdDSA", kid }));
  const payload = utf8ToBase64url(JSON.stringify(card));
  const signingInput = new TextEncoder().encode(`${header}.${payload}`);
  const signature = await signer.sign(signingInput);
  if (signature.length !== 64) {
    throw new Error("signer did not return a 64-byte Ed25519 signature");
  }
  return `${header}.${payload}.${bytesToBase64url(signature)}`;
}

/** A verified card plus the kid that named the key which checked out. */
export interface VerifiedCard {
  card: RootCard;
  kid: string;
}

/**
 * Verify a compact JWS root card. `publicKeyFor` maps the protected header's
 * `kid` to a raw Ed25519 public key (32 bytes); returning null rejects the
 * kid. Throws unless the signature verifies and the payload has the RootCard
 * shape. Expiry is NOT checked here — it is acceptance policy.
 */
export async function verifyCard(
  jws: string,
  publicKeyFor: (kid: string) => Promise<Uint8Array | null> | Uint8Array | null
): Promise<VerifiedCard> {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("not a compact JWS");
  }
  const [h, p, s] = parts as [string, string, string];
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = JSON.parse(base64urlToUtf8(h));
  } catch {
    throw new Error("malformed JWS header");
  }
  if (header.alg !== "EdDSA" || typeof header.kid !== "string") {
    throw new Error("expected EdDSA JWS with a kid");
  }
  const publicKey = await publicKeyFor(header.kid);
  if (publicKey === null) {
    throw new Error(`unknown kid ${header.kid}`);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    publicKey as Uint8Array<ArrayBuffer>,
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "Ed25519",
    key,
    base64urlToBytes(s) as Uint8Array<ArrayBuffer>,
    new TextEncoder().encode(`${h}.${p}`)
  );
  if (!ok) {
    throw new Error("root card signature does not verify");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(base64urlToUtf8(p));
  } catch {
    throw new Error("malformed root card payload");
  }
  return { card: checkCardShape(payload), kid: header.kid };
}
