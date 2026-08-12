import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import bs58 from "bs58";

import {
  toIdentity,
  type MediatorIdentity,
  type StoredIdentity,
} from "./identity-core.js";

export { toIdentity } from "./identity-core.js";
export type { MediatorIdentity, StoredIdentity } from "./identity-core.js";

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
 * (authentication) key plus one DIDCommMessaging service per endpoint.
 *
 * Element order is E then V — the customary order in the wild — and the
 * resolver numbers keys across elements in order of appearance, so #key-1 is
 * the X25519 key and #key-2 the Ed25519. The secrets this module writes use
 * the same numbering; change one and the other breaks silently.
 *
 * One service per endpoint, not one service with an endpoint array: clients
 * pick a transport by scanning services for a URI scheme they speak (the DIF
 * demo does exactly this for ws), and at least one resolver in the wild
 * cannot read an array-valued serviceEndpoint at all.
 */
function encodePeer2(keys: { e: string; v: string }, endpoints: string[]): string {
  const services = endpoints.map((uri) => {
    const service = { t: "dm", s: { uri, a: ["didcomm/v2"] } };
    return Buffer.from(JSON.stringify(service))
      .toString("base64url")
      .replace(/=+$/, "");
  });

  return `did:peer:2.E${keys.e}.V${keys.v}${services
    .map((s) => `.S${s}`)
    .join("")}`;
}

/** ws(s):// twin of the public URL — the WebSocket upgrade lives on the same path. */
function wsUrl(publicUrl: string): string | null {
  return publicUrl.startsWith("http") ? publicUrl.replace(/^http/, "ws") : null;
}

function createIdentity(publicUrl: string): StoredIdentity {
  const e = keyPair("X25519");
  const v = keyPair("Ed25519");

  const ws = wsUrl(publicUrl);
  const did = encodePeer2(
    { e: multibase("X25519", e.x), v: multibase("Ed25519", v.x) },
    // HTTP first: packers take the first v2 service, and POST is the
    // transport every client speaks. The ws twin is for live delivery.
    ws === null ? [publicUrl] : [publicUrl, ws]
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

/** A fresh identity that touches no disk — the test suite's client factory. */
export function mintIdentity(publicUrl: string): MediatorIdentity {
  return toIdentity(createIdentity(publicUrl));
}

/**
 * The stored (persistable) form of a fresh identity — what a Workers deploy
 * pastes into `wrangler secret put MEDIATOR_IDENTITY`.
 */
export function mintStoredIdentity(publicUrl: string): StoredIdentity {
  return createIdentity(publicUrl);
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
