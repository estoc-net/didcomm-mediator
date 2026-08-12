import bs58 from "bs58";
import {
  base64urlToBytes,
  isPeerDID2,
  isPeerDID4,
  resolveLongForm,
  resolvePeer2,
  toDIDCommDIDDoc,
  utf8ToBase64url,
  validateInputDocument,
  encodeLongForm,
} from "@estoc/did-peer";
import type { DIDDoc, PeerDocument, Secret } from "@estoc/did-peer";

/**
 * The runtime-independent half of the mediator's identity: the stored shape
 * and its expansion into a usable one. Minting and disk persistence live in
 * identity.ts (Node only — Workers receive a StoredIdentity as a secret and
 * never mint).
 *
 * One key set, up to three names. Every method's DID is a deterministic
 * function of the stored secrets and public URL — did:peer:2 encodes the
 * public keys and endpoints, did:peer:4 hashes the document, did:web is the
 * domain — so a mediator can answer to several DIDs at once without storing
 * more than one. Which methods are active is configuration
 * (MEDIATOR_DID_METHODS), not storage; the identity file never migrates.
 */

export const DID_METHODS = ["peer2", "peer4", "web"] as const;
export type DidMethod = (typeof DID_METHODS)[number];

/** The method a DID belongs to, or null for anything the mediator cannot be. */
export function methodOf(did: string): DidMethod | null {
  if (isPeerDID2(did)) {
    return "peer2";
  }
  if (isPeerDID4(did)) {
    return "peer4";
  }
  if (did.startsWith("did:web:")) {
    return "web";
  }
  return null;
}

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

/** What gets persisted (a file on Node, a secret on Workers). */
export interface StoredIdentity {
  did: string;
  publicUrl: string;
  /** Relative ids (#key-1…), absolutized against each active DID on load. */
  secrets: Secret[];
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
 * http URL would be unresolvable by everyone else. Local development belongs
 * to the peer methods.
 */
export function didWebFromUrl(publicUrl: string): string {
  const url = new URL(publicUrl);
  if (url.protocol !== "https:") {
    throw new Error(
      `did:web requires an https public URL (got ${publicUrl}); ` +
        "use peer2 or peer4 for local development"
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
 * This encoding is an invariant, not an implementation detail: the DID of an
 * existing identity is re-derived from its secrets whenever peer2 rides as an
 * alias, so any change here would silently rename deployed mediators.
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
export function webDidDocument(stored: StoredIdentity): Record<string, unknown> {
  const did = didWebFromUrl(stored.publicUrl);
  const skeleton = didDocumentSkeleton(
    stored.secrets,
    endpointsOf(stored.publicUrl)
  );
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

/** Derive the DID a method gives this key set and URL — minting and aliasing. */
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
 * The stored DID is the source of truth for its own method — derivation must
 * agree with it, but trusting the stored string means an encoding drift shows
 * up as a loud test failure, not as a renamed production mediator.
 */
function didForMethod(stored: StoredIdentity, method: DidMethod): string {
  return methodOf(stored.did) === method
    ? stored.did
    : deriveDid(stored.secrets, stored.publicUrl, method);
}

/**
 * The W3C-shaped document behind one of the mediator's DIDs. The peer DIDs
 * carry their own; did:web's is rebuilt from the stored keys and URL, never
 * fetched — the mediator does not dial itself to learn who it is.
 */
function documentOf(stored: StoredIdentity, did: string): PeerDocument {
  switch (methodOf(did)) {
    case "peer2":
      return resolvePeer2(did);
    case "peer4":
      // The long form; a short form throws here, and rightly — it carries no
      // document, so an identity stored that way could never sign anything.
      return resolveLongForm(did);
    case "web":
      return webDidDocument(stored);
    default:
      throw new Error(`Unsupported mediator DID method: ${did}`);
  }
}

/**
 * Expand a stored identity into every active name. `methods` is ordered —
 * the first entry is the primary (advertised) DID; when omitted, the stored
 * DID's own method is the only active one, which is what a deployment that
 * never heard of aliases gets.
 */
export function toIdentity(
  stored: StoredIdentity,
  methods: DidMethod[] = []
): MediatorIdentity {
  const storedMethod = methodOf(stored.did);
  if (storedMethod === null) {
    throw new Error(`Unsupported mediator DID method: ${stored.did}`);
  }

  const active = methods.length > 0 ? [...new Set(methods)] : [storedMethod];
  const own: OwnIdentity[] = active.map((method) => {
    const did = didForMethod(stored, method);
    return { did, didDoc: toDIDCommDIDDoc(documentOf(stored, did)) };
  });

  return {
    did: own[0].did,
    didDoc: own[0].didDoc,
    aliases: own.slice(1),
    dids: own.map((identity) => identity.did),
    publicUrl: stored.publicUrl,
    webDidDoc: active.includes("web") ? webDidDocument(stored) : null,
    // didcomm-rust matches a secret to a verification method by id, and the
    // converted documents' ids are absolute — so each private key appears
    // once per active DID, under that DID's absolute id.
    secrets: own.flatMap(({ did }) =>
      stored.secrets.map((secret) => ({
        ...secret,
        id: `${did}${secret.id}`,
      }))
    ),
  };
}
