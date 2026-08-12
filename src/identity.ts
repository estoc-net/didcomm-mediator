import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import bs58 from "bs58";

import { resolve as resolvePeer2 } from "./didcomm/did-peer-2.js";
import { toDIDCommDIDDoc } from "./didcomm/did-doc.js";
import type { DIDDoc, Secret } from "./didcomm/types.js";

/**
 * The mediator's own did:peer:2, minted on first boot and reused forever.
 *
 * did:peer:2 encodes the service endpoint into the DID itself, which is why
 * the public URL must be known before the first start and cannot change after:
 * a new URL is a new DID, and every agent that granted mediation against the
 * old one would be pointing at nobody. The identity file on the data volume is
 * what makes restarts keep the DID.
 */

const IDENTITY_FILE = "identity.json";

export interface MediatorIdentity {
  did: string;
  didDoc: DIDDoc;
  secrets: Secret[];
  publicUrl: string;
}

interface StoredIdentity {
  did: string;
  publicUrl: string;
  /** Relative ids (#key-1…), absolutized against the DID on load. */
  secrets: Secret[];
}

function keyPair(curve: "Ed25519" | "X25519"): { x: string; d: string } {
  const { privateKey } =
    curve === "Ed25519"
      ? generateKeyPairSync("ed25519")
      : generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" });

  if (typeof jwk.x !== "string" || typeof jwk.d !== "string") {
    throw new Error(`A ${curve} key did not export as a JWK`);
  }

  return { x: jwk.x, d: jwk.d };
}

const MULTICODEC = {
  Ed25519: [0xed, 0x01],
  X25519: [0xec, 0x01],
} as const;

function multibase(curve: "Ed25519" | "X25519", x: string): string {
  const raw = Buffer.from(x, "base64url");
  return `z${bs58.encode(Buffer.concat([Buffer.from(MULTICODEC[curve]), raw]))}`;
}

/**
 * Assemble a did:peer:2 from one X25519 (keyAgreement) and one Ed25519
 * (authentication) key plus one DIDCommMessaging service.
 *
 * Element order is E then V — the customary order in the wild — and the
 * resolver numbers keys across elements in order of appearance, so #key-1 is
 * the X25519 key and #key-2 the Ed25519. The secrets this module writes use
 * the same numbering; change one and the other breaks silently.
 */
function encodePeer2(keys: { e: string; v: string }, endpoint: string): string {
  const service = {
    t: "dm",
    s: { uri: endpoint, a: ["didcomm/v2"] },
  };
  const encoded = Buffer.from(JSON.stringify(service))
    .toString("base64url")
    .replace(/=+$/, "");

  return `did:peer:2.E${keys.e}.V${keys.v}.S${encoded}`;
}

function createIdentity(publicUrl: string): StoredIdentity {
  const e = keyPair("X25519");
  const v = keyPair("Ed25519");

  const did = encodePeer2(
    { e: multibase("X25519", e.x), v: multibase("Ed25519", v.x) },
    publicUrl
  );

  return {
    did,
    publicUrl,
    secrets: [
      {
        id: "#key-1",
        type: "JsonWebKey2020",
        privateKeyJwk: { kty: "OKP", crv: "X25519", x: e.x, d: e.d },
      },
      {
        id: "#key-2",
        type: "JsonWebKey2020",
        privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: v.x, d: v.d },
      },
    ],
  };
}

function toIdentity(stored: StoredIdentity): MediatorIdentity {
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

/** A fresh identity that touches no disk — the test suite's client factory. */
export function mintIdentity(publicUrl: string): MediatorIdentity {
  return toIdentity(createIdentity(publicUrl));
}

export function loadOrCreateIdentity(
  dataDir: string,
  publicUrl: string,
  log: (msg: string) => void = console.log
): MediatorIdentity {
  mkdirSync(dataDir, { recursive: true });
  const path = join(dataDir, IDENTITY_FILE);

  let stored: StoredIdentity | null = null;
  try {
    stored = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    stored = null;
  }

  if (stored !== null) {
    if (stored.publicUrl !== publicUrl) {
      log(
        `MEDIATOR_PUBLIC_URL is ${publicUrl} but the identity was minted for ` +
          `${stored.publicUrl}; the DID keeps its original endpoint. ` +
          `To move the mediator, delete ${path} and accept a new DID.`
      );
    }
    return toIdentity(stored);
  }

  const created = createIdentity(publicUrl);
  writeFileSync(path, JSON.stringify(created, null, 2), { mode: 0o600 });
  log(`Minted mediator identity ${created.did}`);
  return toIdentity(created);
}
