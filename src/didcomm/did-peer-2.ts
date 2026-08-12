import bs58 from "bs58";

import type { PeerDocument } from "./did-peer-4.js";

/**
 * did:peer:2 (numalgo 2) — https://identity.foundation/peer-did-method-spec/
 *
 * The document *is* the identifier: every key and every service is encoded into
 * the DID itself, so resolving is decoding — no network, no store, nothing to
 * be out of date. That is also why there is no create endpoint to match
 * `/did/peer/4`: whoever holds the keys assembles the string, and this side
 * only ever reads one somebody else assembled.
 *
 * Mediators are the reason this exists here. An agent behind a mediator names
 * the mediator's DID as its service endpoint, and that DID is usually a
 * did:peer:2 — so without this, a message addressed to such an agent has
 * nowhere to go, and a message *from* one cannot be opened, since unpacking
 * needs the sender's document.
 */

const PREFIX = "did:peer:2";

/** Purpose codes and the verification relationship each one denotes. */
const PURPOSE_RELATIONSHIPS: Record<string, string> = {
  A: "assertionMethod",
  E: "keyAgreement",
  V: "authentication",
  I: "capabilityInvocation",
  D: "capabilityDelegation",
};

/**
 * A service is JSON with its most common strings abbreviated to one letter.
 * Both halves of a pair are abbreviated, so expansion applies to values as well
 * as keys — which is what turns `"t":"dm"` back into DIDCommMessaging.
 */
const SERVICE_KEYS: Record<string, string> = {
  t: "type",
  s: "serviceEndpoint",
  r: "routingKeys",
  a: "accept",
};
const SERVICE_VALUES: Record<string, string> = { dm: "DIDCommMessaging" };

export class PeerDID2Error extends Error {
  readonly name = "PeerDID2Error";
}

export function isPeerDID2(did: string): boolean {
  return did.startsWith(PREFIX);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Resolve a did:peer:2 into its document.
 *
 * References are left relative (`#key-1`), as they are for did:peer:4 — the
 * spec resolves them that way, and `toDIDCommDIDDoc` absolutizes for the
 * consumers that need it.
 */
export function resolve(did: string): PeerDocument {
  if (!isPeerDID2(did)) {
    throw new PeerDID2Error("Not a did:peer:2");
  }

  // The method-specific id is a run of `.`-prefixed elements, so splitting one
  // always opens with an empty string. Anything else is malformed.
  const elements = did.slice(PREFIX.length).split(".");
  if (elements.shift() !== "" || elements.length === 0) {
    throw new PeerDID2Error("did:peer:2 must be followed by at least one element");
  }

  const verificationMethod: Record<string, unknown>[] = [];
  const relationships: Record<string, string[]> = {};
  const service: Record<string, unknown>[] = [];

  for (const element of elements) {
    const purpose = element.slice(0, 1);
    const value = element.slice(1);

    if (value === "") {
      throw new PeerDID2Error(`Element "${element}" carries no value`);
    }

    if (purpose === "S") {
      service.push(decodeService(value, service.length));
      continue;
    }

    const relationship = PURPOSE_RELATIONSHIPS[purpose];
    if (relationship === undefined) {
      throw new PeerDID2Error(`Unknown purpose code "${purpose}"`);
    }

    // Keys are numbered across every purpose in the order they appear, so the
    // count so far is the number of the one being read.
    const id = `#key-${verificationMethod.length + 1}`;
    verificationMethod.push({
      id,
      controller: did,
      // The spec's own type. didcomm-rust has no Multikey variant, but
      // toDIDCommDIDDoc remaps it by multicodec prefix.
      type: "Multikey",
      publicKeyMultibase: validateKey(value),
    });

    const references = relationships[relationship] ?? [];
    references.push(id);
    relationships[relationship] = references;
  }

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    ...(verificationMethod.length > 0 ? { verificationMethod } : {}),
    ...relationships,
    ...(service.length > 0 ? { service } : {}),
  };
}

/**
 * Keys are multibase base58btc. Checking that here means a malformed element is
 * refused outright rather than resolving into a verification method that no
 * operation can use and nobody can explain.
 */
function validateKey(value: string): string {
  if (!value.startsWith("z")) {
    throw new PeerDID2Error(`Key "${value}" is not base58btc multibase`);
  }

  try {
    bs58.decode(value.slice(1));
  } catch {
    throw new PeerDID2Error(`Key "${value}" is not valid base58btc`);
  }

  return value;
}

function decodeService(value: string, index: number): Record<string, unknown> {
  let decoded: unknown;

  try {
    decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new PeerDID2Error("Service element is not base64url-encoded JSON");
  }

  const expanded = expand(decoded);
  if (!isRecord(expanded)) {
    throw new PeerDID2Error("Service element is not a JSON object");
  }

  // The first service is `#service` and the rest are numbered from one — a
  // block that names itself keeps its own id.
  const id = index === 0 ? "#service" : `#service-${index}`;
  return { id, ...expanded };
}

function expand(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(expand);
  }

  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        SERVICE_KEYS[key] ?? key,
        expand(entry),
      ])
    );
  }

  if (typeof value === "string") {
    return SERVICE_VALUES[value] ?? value;
  }

  return value;
}
