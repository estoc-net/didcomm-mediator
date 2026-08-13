import bs58 from "bs58";
import {
  base64urlToBytes,
  resolveLongForm,
  resolvePeer2,
  toDIDCommDIDDoc,
  utf8ToBase64url,
  validateInputDocument,
  encodeLongForm,
} from "@estoc/did-peer";
import type { DIDDoc, PeerDocument, Secret } from "@estoc/did-peer";

import type { MediationStore } from "./store/types.js";

/**
 * The mediator's identity, whole: what is stored is nothing but two private
 * keys (X25519 + Ed25519, as relative-id Secrets in the store's identity
 * table), and every name is a pure function of those keys, a public URL, and
 * a method — did:peer:2 encodes the public keys and endpoints, did:peer:4
 * hashes the document, did:web is the domain itself.
 *
 * No DID and no URL is ever persisted. Which methods are active is
 * configuration (MEDIATOR_DID_METHODS); which URL the names bind to is the
 * caller's — Node passes its configured public URL, Workers pass each
 * request's own origin, which is what lets one Workers deployment answer as
 * did:web:<host> for every host that routes to it. Keep the store's identity
 * row (and, for the peer methods, the URL), keep the DID.
 */

export const DID_METHODS = ["peer2", "peer4", "web"] as const;
export type DidMethod = (typeof DID_METHODS)[number];

/** One of the mediator's own names: a DID and the document behind it. */
export interface OwnIdentity {
  did: string;
  didDoc: DIDDoc;
}

export interface MediatorIdentity {
  /** The primary DID — what GET / and the OOB invitation advertise. */
  did: string;
  didDoc: DIDDoc;
  /** The other active DIDs, equally answerable, not advertised. */
  aliases: OwnIdentity[];
  /** Every active DID, primary first. */
  dids: string[];
  /** Absolutized for every active DID: one private key, one entry per name. */
  secrets: Secret[];
  publicUrl: string;
  /**
   * The W3C document a did:web identity publishes at did.json — the one
   * external resolvers fetch. Null when "web" is not an active method.
   */
  webDidDoc: Record<string, unknown> | null;
}

async function jwkKeyPair(
  algorithm: "Ed25519" | "X25519"
): Promise<{ x: string; d: string }> {
  const usages: KeyUsage[] =
    algorithm === "Ed25519" ? ["sign", "verify"] : ["deriveBits"];
  const pair = (await crypto.subtle.generateKey(
    algorithm,
    true,
    usages
  )) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);

  if (typeof jwk.x !== "string" || typeof jwk.d !== "string") {
    throw new Error(`A ${algorithm} key did not export as a JWK`);
  }

  return { x: jwk.x, d: jwk.d };
}

/**
 * A fresh key set — WebCrypto, so the same code mints on Node and on workerd.
 * #key-1 is the X25519 key and #key-2 the Ed25519 across every method, so one
 * set of secrets fits whichever documents the DIDs expand to.
 */
export async function mintSecrets(): Promise<Secret[]> {
  const e = await jwkKeyPair("X25519");
  const v = await jwkKeyPair("Ed25519");

  return [
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
}

/**
 * The store's identity row, minting it if this is first contact. Concurrent
 * first contacts race benignly: initIdentity is insert-if-absent and returns
 * the row that won, so every caller ends up holding the same keys.
 */
export async function loadOrCreateSecrets(
  store: MediationStore,
  log: (msg: string) => void = () => {}
): Promise<Secret[]> {
  const existing = await store.loadIdentity();
  if (existing !== null) {
    return JSON.parse(existing) as Secret[];
  }

  const minted = JSON.stringify(await mintSecrets());
  const winner = await store.initIdentity(minted);
  if (winner === minted) {
    log("Minted mediator identity keys");
  }
  return JSON.parse(winner) as Secret[];
}

/** ws(s):// twin of the public URL — the WebSocket upgrade lives on the same path. */
function wsUrl(publicUrl: string): string | null {
  return publicUrl.startsWith("http") ? publicUrl.replace(/^http/, "ws") : null;
}

/**
 * HTTP first: packers take the first v2 service, and POST is the transport
 * every client speaks. The ws twin is for live delivery.
 */
export function endpointsOf(publicUrl: string): string[] {
  const ws = wsUrl(publicUrl);
  return ws === null ? [publicUrl] : [publicUrl, ws];
}

/**
 * The did:web name of the mediator's public URL: host (with an %3A-encoded
 * port), then one colon-joined segment per path element.
 *
 * https is a hard requirement, not a SHOULD — resolvers (web-did-resolver
 * included) only ever fetch `https://…/did.json`, so a did:web minted from an
 * http URL would be unresolvable by everyone else. The one exception is
 * localhost: `wrangler dev` serves plain http, our own resolver knows to
 * fetch such a DID over http, and a loopback name was never resolvable by
 * the outside world anyway.
 */
export function didWebFromUrl(publicUrl: string): string {
  const url = new URL(publicUrl);
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(
      `did:web requires an https public URL (got ${publicUrl}); ` +
        "use peer2 or peer4 for non-loopback http"
    );
  }

  const host =
    url.port === "" ? url.hostname : `${url.hostname}%3A${url.port}`;
  const segments = url.pathname
    .split("/")
    .filter((segment) => segment !== "")
    .map((segment) => encodeURIComponent(decodeURIComponent(segment)));

  return ["did:web", host, ...segments].join(":");
}

function publicJwk(secret: Secret): Record<string, unknown> {
  if (secret.privateKeyJwk === undefined) {
    throw new Error(`Secret ${secret.id} has no privateKeyJwk`);
  }
  const { d: _d, ...pub } = secret.privateKeyJwk;
  return pub;
}

const MULTICODEC = {
  Ed25519: Uint8Array.from([0xed, 0x01]),
  X25519: Uint8Array.from([0xec, 0x01]),
} as const;

function multibase(curve: keyof typeof MULTICODEC, x: string): string {
  const raw = base64urlToBytes(x);
  const prefixed = new Uint8Array(2 + raw.length);
  prefixed.set(MULTICODEC[curve]);
  prefixed.set(raw, 2);
  return `z${bs58.encode(prefixed)}`;
}

/**
 * Assemble the did:peer:2 of these secrets: .E then .V — the customary order
 * in the wild, and the resolver numbers keys across elements in order of
 * appearance, so #key-1 is the X25519 key and #key-2 the Ed25519, matching
 * the secrets' own numbering — plus one .S per endpoint.
 *
 * This encoding is an invariant, not an implementation detail: every DID is
 * re-derived from the stored secrets on every boot, so any change here would
 * silently rename deployed mediators.
 */
function encodePeer2(secrets: Secret[], endpoints: string[]): string {
  const byCurve = (crv: string): string => {
    const secret = secrets.find((s) => s.privateKeyJwk?.crv === crv);
    if (secret === undefined || typeof secret.privateKeyJwk?.x !== "string") {
      throw new Error(`No ${crv} secret to derive a did:peer:2 from`);
    }
    return secret.privateKeyJwk.x;
  };

  const e = multibase("X25519", byCurve("X25519"));
  const v = multibase("Ed25519", byCurve("Ed25519"));
  const services = endpoints.map((uri) => {
    const service = { t: "dm", s: { uri, a: ["didcomm/v2"] } };
    return utf8ToBase64url(JSON.stringify(service)).replace(/=+$/, "");
  });

  return `did:peer:2.E${e}.V${v}${services.map((s) => `.S${s}`).join("")}`;
}

/**
 * The method-independent heart of the mediator's document: each secret's
 * public half as a JsonWebKey2020 verification method (X25519 → keyAgreement,
 * Ed25519 → authentication, so the relationship follows the key rather than a
 * position), and one DIDCommMessaging service per endpoint — clients pick a
 * transport by scanning services for a URI scheme they speak, and at least one
 * resolver in the wild cannot read an array-valued serviceEndpoint at all.
 *
 * All references are relative: did:peer:4 requires that of its input document
 * (the DID is a hash of it), and did:web absolutizes against the derived DID.
 */
export function didDocumentSkeleton(
  secrets: Secret[],
  endpoints: string[]
): PeerDocument {
  const verificationMethod: Record<string, unknown>[] = [];
  const keyAgreement: string[] = [];
  const authentication: string[] = [];

  for (const secret of secrets) {
    const jwk = publicJwk(secret);
    verificationMethod.push({
      id: secret.id,
      type: "JsonWebKey2020",
      publicKeyJwk: jwk,
    });
    (jwk.crv === "X25519" ? keyAgreement : authentication).push(secret.id);
  }

  const service = endpoints.map((uri, index) => ({
    id: `#service-${index + 1}`,
    type: "DIDCommMessaging",
    serviceEndpoint: { uri, accept: ["didcomm/v2"] },
  }));

  return { verificationMethod, keyAgreement, authentication, service };
}

/**
 * The document a did:web identity serves at did.json. References are made
 * absolute here rather than left to the reader: web-did-resolver insists the
 * document's `id` equal the DID it derived, and not every consumer absolutizes
 * relative fragments correctly.
 */
export function webDidDocument(
  secrets: Secret[],
  publicUrl: string
): Record<string, unknown> {
  const did = didWebFromUrl(publicUrl);
  const skeleton = didDocumentSkeleton(secrets, endpointsOf(publicUrl));
  const absolute = (id: unknown) => `${did}${id}`;

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: (skeleton.verificationMethod as Record<string, unknown>[]).map(
      (method) => ({
        ...method,
        id: absolute(method.id),
        controller: did,
      })
    ),
    keyAgreement: (skeleton.keyAgreement as string[]).map(absolute),
    authentication: (skeleton.authentication as string[]).map(absolute),
    service: (skeleton.service as Record<string, unknown>[]).map((entry) => ({
      ...entry,
      id: absolute(entry.id),
    })),
  };
}

/** Derive the DID a method gives this key set and URL. */
export function deriveDid(
  secrets: Secret[],
  publicUrl: string,
  method: DidMethod
): string {
  const endpoints = endpointsOf(publicUrl);
  switch (method) {
    case "peer2":
      return encodePeer2(secrets, endpoints);
    case "peer4": {
      const input = didDocumentSkeleton(secrets, endpoints);
      validateInputDocument(input);
      return encodeLongForm(input);
    }
    case "web":
      return didWebFromUrl(publicUrl);
    default:
      // The type is exhaustive, but a JS caller can still hand in anything.
      throw new Error(`Unknown DID method: ${String(method)}`);
  }
}

/**
 * The W3C-shaped document behind one of the mediator's DIDs. The peer DIDs
 * carry their own; did:web's is rebuilt from the keys and URL, never fetched —
 * the mediator does not dial itself to learn who it is.
 */
function documentOf(
  secrets: Secret[],
  publicUrl: string,
  method: DidMethod,
  did: string
): PeerDocument {
  switch (method) {
    case "peer2":
      return resolvePeer2(did);
    case "peer4":
      return resolveLongForm(did);
    case "web":
      return webDidDocument(secrets, publicUrl);
    default:
      throw new Error(`Unsupported mediator DID method: ${String(method)}`);
  }
}

/**
 * Expand a key set into every active name at one URL. `methods` is ordered —
 * the first entry is the primary (advertised) DID. Deployments choose their
 * own default (Node: peer2, which works on any URL; Workers: web, whose name
 * follows the request host), so an empty list is a caller bug, not a choice.
 */
export function identityFor(
  secrets: Secret[],
  publicUrl: string,
  methods: DidMethod[]
): MediatorIdentity {
  if (methods.length === 0) {
    throw new Error("identityFor needs at least one active DID method");
  }

  const active = [...new Set(methods)];
  const own: OwnIdentity[] = active.map((method) => {
    const did = deriveDid(secrets, publicUrl, method);
    return {
      did,
      didDoc: toDIDCommDIDDoc(documentOf(secrets, publicUrl, method, did)),
    };
  });

  return {
    did: own[0].did,
    didDoc: own[0].didDoc,
    aliases: own.slice(1),
    dids: own.map((identity) => identity.did),
    publicUrl,
    webDidDoc: active.includes("web") ? webDidDocument(secrets, publicUrl) : null,
    // didcomm-rust matches a secret to a verification method by id, and the
    // converted documents' ids are absolute — so each private key appears
    // once per active DID, under that DID's absolute id.
    secrets: own.flatMap(({ did }) =>
      secrets.map((secret) => ({
        ...secret,
        id: `${did}${secret.id}`,
      }))
    ),
  };
}

function asList(methods: DidMethod | DidMethod[]): DidMethod[] {
  return Array.isArray(methods) ? methods : [methods];
}

/** A fresh identity in one call — the test suite's client factory. */
export async function mintIdentity(
  publicUrl: string,
  methods: DidMethod | DidMethod[] = "peer2"
): Promise<MediatorIdentity> {
  return identityFor(await mintSecrets(), publicUrl, asList(methods));
}
