import bs58 from "bs58";

import type { DIDDoc, Service, VerificationMethod } from "./types.js";
import { absolutizeReferences, type PeerDocument } from "./did-peer-4.js";

/**
 * Converts a W3C DID document into the flat DIDDoc shape didcomm-rust expects:
 * absolute DID URLs everywhere, embedded verification methods hoisted into
 * `verificationMethod`, and only DIDCommMessaging services retained.
 */

export class DIDDocConversionError extends Error {
  readonly name = "DIDDocConversionError";
}

/** multicodec prefixes for the key types didcomm-rust can read from multibase */
const ED25519_PUB = Uint8Array.from([0xed, 0x01]);
const X25519_PUB = Uint8Array.from([0xec, 0x01]);

const KNOWN_VERIFICATION_METHOD_TYPES = new Set([
  "JsonWebKey2020",
  "X25519KeyAgreementKey2019",
  "Ed25519VerificationKey2018",
  "EcdsaSecp256k1VerificationKey2019",
  "X25519KeyAgreementKey2020",
  "Ed25519VerificationKey2020",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Read the two-byte multicodec prefix from a base58btc multibase key. */
function multicodecPrefix(publicKeyMultibase: string): Uint8Array | null {
  if (!publicKeyMultibase.startsWith("z")) {
    return null;
  }
  try {
    const decoded = bs58.decode(publicKeyMultibase.slice(1));
    return decoded.length >= 2 ? decoded.slice(0, 2) : null;
  } catch {
    return null;
  }
}

function prefixMatches(prefix: Uint8Array | null, expected: Uint8Array): boolean {
  return (
    prefix !== null && prefix[0] === expected[0] && prefix[1] === expected[1]
  );
}

/**
 * didcomm-rust has no `Multikey` variant, so a Multikey verification method is
 * rewritten to the equivalent 2020 suite based on its multicodec prefix.
 *
 * Anything still unrecognized becomes `Other`. didcomm-rust's
 * VerificationMethodType has no catch-all deserializer, so leaving an unknown
 * type in place fails deserialization of the *entire* DIDDoc — one unusable
 * method in a counterparty's document would otherwise break every operation.
 * An `Other` method survives the round trip but cannot be used for crypto.
 */
function normalizeType(type: string, method: Record<string, unknown>): string {
  if (KNOWN_VERIFICATION_METHOD_TYPES.has(type)) {
    return type;
  }

  if (type === "Multikey") {
    const multibase = method.publicKeyMultibase;
    if (typeof multibase === "string") {
      const prefix = multicodecPrefix(multibase);
      if (prefixMatches(prefix, ED25519_PUB)) {
        return "Ed25519VerificationKey2020";
      }
      if (prefixMatches(prefix, X25519_PUB)) {
        return "X25519KeyAgreementKey2020";
      }
    }
  }

  return "Other";
}

function toVerificationMethod(
  method: Record<string, unknown>,
  documentId: string
): VerificationMethod | null {
  const { id, type } = method;
  if (typeof id !== "string" || typeof type !== "string") {
    return null;
  }

  const controller =
    typeof method.controller === "string" ? method.controller : documentId;

  const normalized: VerificationMethod = {
    id,
    type: normalizeType(type, method),
    controller,
  };

  if (isRecord(method.publicKeyJwk)) {
    normalized.publicKeyJwk = method.publicKeyJwk;
  }
  if (typeof method.publicKeyMultibase === "string") {
    normalized.publicKeyMultibase = method.publicKeyMultibase;
  }
  if (typeof method.publicKeyBase58 === "string") {
    normalized.publicKeyBase58 = method.publicKeyBase58;
  }

  return normalized;
}

/**
 * Reads a verification relationship, returning its DID URL references and any
 * verification methods embedded directly in it.
 */
function collectRelationship(
  entries: unknown,
  documentId: string
): { references: string[]; embedded: VerificationMethod[] } {
  const references: string[] = [];
  const embedded: VerificationMethod[] = [];

  if (!Array.isArray(entries)) {
    return { references, embedded };
  }

  for (const entry of entries) {
    if (typeof entry === "string") {
      references.push(entry);
      continue;
    }
    if (!isRecord(entry)) {
      continue;
    }
    const method = toVerificationMethod(entry, documentId);
    if (method !== null) {
      references.push(method.id);
      embedded.push(method);
    }
  }

  return { references, embedded };
}

function firstEndpoint(serviceEndpoint: unknown): unknown {
  return Array.isArray(serviceEndpoint) ? serviceEndpoint[0] : serviceEndpoint;
}

function toService(service: Record<string, unknown>): Service | null {
  const { id, type } = service;
  if (typeof id !== "string" || type !== "DIDCommMessaging") {
    return null;
  }

  const endpoint = firstEndpoint(service.serviceEndpoint);

  // A bare string endpoint is the DIDComm v1 spelling of `{ uri }`.
  if (typeof endpoint === "string") {
    return { id, type, serviceEndpoint: { uri: endpoint, routingKeys: [] } };
  }

  if (!isRecord(endpoint) || typeof endpoint.uri !== "string") {
    return null;
  }

  const normalized: Service["serviceEndpoint"] = {
    uri: endpoint.uri,
    routingKeys: Array.isArray(endpoint.routingKeys)
      ? endpoint.routingKeys.filter((key): key is string => typeof key === "string")
      : [],
  };

  if (Array.isArray(endpoint.accept)) {
    normalized.accept = endpoint.accept.filter(
      (item): item is string => typeof item === "string"
    );
  }

  return { id, type, serviceEndpoint: normalized };
}

/**
 * Convert a W3C DID document into the didcomm-rust DIDDoc shape.
 *
 * Relative references are absolutized against the document `id` first, since
 * didcomm-rust derives a DID by splitting a `kid` on `#`.
 */
export function toDIDCommDIDDoc(document: PeerDocument): DIDDoc {
  const absolutized = absolutizeReferences(document);

  const id = absolutized.id;
  if (typeof id !== "string") {
    throw new DIDDocConversionError("DID document has no string `id`");
  }

  const authentication = collectRelationship(absolutized.authentication, id);
  const keyAgreement = collectRelationship(absolutized.keyAgreement, id);

  const methods = new Map<string, VerificationMethod>();
  if (Array.isArray(absolutized.verificationMethod)) {
    for (const entry of absolutized.verificationMethod) {
      if (!isRecord(entry)) {
        continue;
      }
      const method = toVerificationMethod(entry, id);
      if (method !== null) {
        methods.set(method.id, method);
      }
    }
  }
  for (const method of [...authentication.embedded, ...keyAgreement.embedded]) {
    if (!methods.has(method.id)) {
      methods.set(method.id, method);
    }
  }

  const service: Service[] = [];
  if (Array.isArray(absolutized.service)) {
    for (const entry of absolutized.service) {
      if (!isRecord(entry)) {
        continue;
      }
      const normalized = toService(entry);
      if (normalized !== null) {
        service.push(normalized);
      }
    }
  }

  return {
    id,
    keyAgreement: keyAgreement.references,
    authentication: authentication.references,
    verificationMethod: [...methods.values()],
    service,
  };
}
