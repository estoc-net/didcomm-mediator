import { resolve as resolvePeer2 } from "./didcomm/did-peer-2.js";
import { toDIDCommDIDDoc } from "./didcomm/did-doc.js";
import type { DIDDoc, Secret } from "./didcomm/types.js";

/**
 * The runtime-independent half of the mediator's identity: the stored shape
 * and its expansion into a usable one. Minting and disk persistence live in
 * identity.ts (Node only — Workers receive a StoredIdentity as a secret and
 * never mint).
 */

export interface MediatorIdentity {
  did: string;
  didDoc: DIDDoc;
  secrets: Secret[];
  publicUrl: string;
}

/** What gets persisted (a file on Node, a secret on Workers). */
export interface StoredIdentity {
  did: string;
  publicUrl: string;
  /** Relative ids (#key-1…), absolutized against the DID on load. */
  secrets: Secret[];
}

export function toIdentity(stored: StoredIdentity): MediatorIdentity {
  return {
    did: stored.did,
    didDoc: toDIDCommDIDDoc(resolvePeer2(stored.did)),
    publicUrl: stored.publicUrl,
    // didcomm-rust matches a secret to a verification method by id, and the
    // converted document's ids are absolute, so these have to be too.
    secrets: stored.secrets.map((secret) => ({
      ...secret,
      id: `${stored.did}${secret.id}`,
    })),
  };
}
