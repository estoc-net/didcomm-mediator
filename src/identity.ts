import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Secret } from "@estoc/did-peer";

import {
  deriveDid,
  methodOf,
  toIdentity,
  type DidMethod,
  type MediatorIdentity,
  type StoredIdentity,
} from "./identity-core.js";

export { toIdentity } from "./identity-core.js";
export type {
  DidMethod,
  MediatorIdentity,
  StoredIdentity,
} from "./identity-core.js";

/**
 * The mediator's own identity: one key set minted on first boot and reused
 * forever, answering to one DID per active method (identity-core has the
 * derivations):
 *
 * - did:peer:2 (default) — self-contained, works anywhere including localhost.
 *   The endpoint is encoded into the DID itself, so the public URL must be
 *   known before the first start; a new URL is a new DID.
 * - did:peer:4 — same trade-offs in a different encoding (the long form
 *   carries the whole document).
 * - did:web — the identity is the domain. Keys and endpoints live in the
 *   did.json the mediator serves, so they can change without changing the
 *   DID; in exchange the URL must be https and resolvers must reach it.
 *
 * The identity file on the data volume is what makes restarts keep the DID.
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

function createIdentity(publicUrl: string, method: DidMethod): StoredIdentity {
  const e = keyPair("X25519");
  const v = keyPair("Ed25519");

  // #key-1 is the X25519 key and #key-2 the Ed25519 across every method, so
  // one set of secrets fits whichever documents the DIDs expand to.
  const secrets: Secret[] = [
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
  ];

  return {
    did: deriveDid(secrets, publicUrl, method),
    publicUrl,
    secrets,
  };
}

function asList(methods: DidMethod | DidMethod[]): DidMethod[] {
  return Array.isArray(methods) ? methods : [methods];
}

/**
 * A fresh identity that touches no disk — the test suite's client factory.
 * The first method is minted (and primary); the rest ride as aliases.
 */
export function mintIdentity(
  publicUrl: string,
  methods: DidMethod | DidMethod[] = "peer2"
): MediatorIdentity {
  const list = asList(methods);
  return toIdentity(createIdentity(publicUrl, list[0]), list);
}

/**
 * The stored (persistable) form of a fresh identity — what a Workers deploy
 * pastes into `wrangler secret put MEDIATOR_IDENTITY`. Aliases are not stored:
 * which methods are active is the deployment's MEDIATOR_DID_METHODS.
 */
export function mintStoredIdentity(
  publicUrl: string,
  method: DidMethod = "peer2"
): StoredIdentity {
  return createIdentity(publicUrl, method);
}

export function loadOrCreateIdentity(
  dataDir: string,
  publicUrl: string,
  /** Empty = unspecified: follow the stored DID's method; mint peer2 fresh. */
  methods: DidMethod | DidMethod[] = [],
  log: (msg: string) => void = console.log
): MediatorIdentity {
  const list = asList(methods);
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
          `${stored.publicUrl}; the identity keeps its original endpoint. ` +
          `To move the mediator, delete ${path} and accept a new DID.`
      );
    }
    const storedMethod = methodOf(stored.did);
    if (list.length > 0 && storedMethod !== null && !list.includes(storedMethod)) {
      log(
        `The identity on disk is ${storedMethod} but MEDIATOR_DID_METHODS is ` +
          `${list.join(",")} — clients bound to ${stored.did} will no longer ` +
          `be served until ${storedMethod} is listed again.`
      );
    }
    return toIdentity(stored, list);
  }

  const created = createIdentity(publicUrl, list[0] ?? "peer2");
  writeFileSync(path, JSON.stringify(created, null, 2), { mode: 0o600 });
  log(`Minted mediator identity ${created.did}`);
  return toIdentity(created, list);
}
