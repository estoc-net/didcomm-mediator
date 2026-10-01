import bs58 from "bs58";
import canonicalize from "canonicalize";
import { compactVerify, decodeProtectedHeader, importJWK } from "jose";
import {
  bytesToBase64url,
  isLongForm,
  isShortForm,
  longToShort,
  resolveDIDCommDoc,
} from "@estoc/did-peer";
import type { DIDDoc, VerificationMethod } from "@estoc/did-peer";

/**
 * The grant a replica-mediation account signs for one replica: a lifetime
 * binding of that replica's ID and DID to the account, its mediation ID and
 * one mediator. The account's signature is what lets the mediator, and later
 * every other replica, take the binding from anyone who relays it.
 */

export const GRANT_TYP = "estoc/replica-grant+jws";

/**
 * A grant holds two did:peer:4 long forms and a signature; a listing page
 * returns several at once, so one grant is kept well under the wire limit.
 */
const MAX_GRANT_CHARS = 16 * 1024;

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const PAYLOAD_FIELDS = [
  "account",
  "mediation_id",
  "mediator",
  "replica_did",
  "replica_id",
  "replica_long_form",
];

export interface ReplicaGrant {
  account: string;
  mediationId: string;
  mediator: string;
  replicaId: string;
  replicaDid: string;
  replicaLongForm: string;
}

/** A did:peer:4 in the spelling bindings are compared and stored under. */
export function canonicalDid(did: string): string {
  return isLongForm(did) ? longToShort(did) : did;
}

const ED25519_MULTICODEC = [0xed, 0x01];

function ed25519Jwk(method: VerificationMethod): Record<string, unknown> | null {
  const { publicKeyJwk, publicKeyMultibase } = method;
  if (publicKeyJwk !== undefined) {
    return publicKeyJwk.kty === "OKP" && publicKeyJwk.crv === "Ed25519"
      ? { kty: "OKP", crv: "Ed25519", x: publicKeyJwk.x }
      : null;
  }
  if (publicKeyMultibase === undefined || !publicKeyMultibase.startsWith("z")) {
    return null;
  }
  let decoded: Uint8Array;
  try {
    decoded = bs58.decode(publicKeyMultibase.slice(1));
  } catch {
    return null;
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== ED25519_MULTICODEC[0] ||
    decoded[1] !== ED25519_MULTICODEC[1]
  ) {
    return null;
  }
  return { kty: "OKP", crv: "Ed25519", x: bytesToBase64url(decoded.slice(2)) };
}

/**
 * The Ed25519 key `kid` names among `doc`'s authentication methods. The DID
 * part of `kid` may be either spelling of the document's DID; the key is
 * always taken from the document, never from anything the JWS carries.
 */
function authenticationKey(doc: DIDDoc, kid: string): Record<string, unknown> | null {
  const [did, fragment, ...rest] = kid.split("#");
  if (fragment === undefined || rest.length > 0 || canonicalDid(did) !== canonicalDid(doc.id)) {
    return null;
  }
  const id = `${doc.id}#${fragment}`;
  const method = doc.verificationMethod.find((candidate) => candidate.id === id);
  return method !== undefined && doc.authentication.includes(id) ? ed25519Jwk(method) : null;
}

/**
 * The payload as its exact fields, or null: a grant is RFC 8785 text, so the
 * bytes that were signed are the only spelling of what they say.
 */
function payloadOf(bytes: Uint8Array): Record<string, string> | null {
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const names = Object.keys(parsed).sort();
  if (
    names.length !== PAYLOAD_FIELDS.length ||
    names.some((name, i) => name !== PAYLOAD_FIELDS[i]) ||
    Object.values(parsed).some((value) => typeof value !== "string") ||
    canonicalize(parsed) !== text
  ) {
    return null;
  }
  return parsed as Record<string, string>;
}

function servedBy(doc: DIDDoc, mediator: string): boolean {
  return doc.service.some(
    ({ serviceEndpoint }) =>
      (typeof serviceEndpoint === "string" ? serviceEndpoint : serviceEndpoint.uri) === mediator
  );
}

/**
 * What `jws` grants, once `accountDoc`'s own authentication key has signed
 * it and everything it names holds together; null otherwise. Whether the
 * account and mediator are the ones the request came from and went to is
 * the caller's to compare.
 */
export async function verifyReplicaGrant(
  jws: unknown,
  accountDoc: DIDDoc
): Promise<ReplicaGrant | null> {
  if (typeof jws !== "string" || jws.length > MAX_GRANT_CHARS) {
    return null;
  }

  let payload: Record<string, string> | null;
  try {
    const header = decodeProtectedHeader(jws);
    const names = Object.keys(header).sort();
    if (
      names.join() !== "alg,kid,typ" ||
      header.alg !== "EdDSA" ||
      header.typ !== GRANT_TYP ||
      typeof header.kid !== "string"
    ) {
      return null;
    }
    const jwk = authenticationKey(accountDoc, header.kid);
    if (jwk === null) {
      return null;
    }
    const verified = await compactVerify(jws, await importJWK(jwk, "EdDSA"), {
      algorithms: ["EdDSA"],
    });
    payload = payloadOf(verified.payload);
  } catch {
    return null;
  }
  if (payload === null) {
    return null;
  }

  const {
    account,
    mediation_id: mediationId,
    mediator,
    replica_id: replicaId,
    replica_did: replicaDid,
    replica_long_form: replicaLongForm,
  } = payload;

  if (
    account !== canonicalDid(accountDoc.id) ||
    !isShortForm(account) ||
    !UUID_V7.test(mediationId) ||
    !UUID_V7.test(replicaId) ||
    !isLongForm(replicaLongForm) ||
    longToShort(replicaLongForm) !== replicaDid ||
    replicaDid === account
  ) {
    return null;
  }

  const replicaDoc = await resolveDIDCommDoc(replicaLongForm);
  if (replicaDoc === null || !servedBy(replicaDoc, mediator)) {
    return null;
  }

  return { account, mediationId, mediator, replicaId, replicaDid, replicaLongForm };
}
