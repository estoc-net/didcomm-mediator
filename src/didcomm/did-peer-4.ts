import { createHash } from "node:crypto";
import bs58 from "bs58";

/**
 * did:peer:4 (numalgo 4) — https://identity.foundation/peer-did-method-spec/
 *
 * Port of the reference implementation at references/did-peer-4-ts. The upstream
 * package is not published to npm, so the ~170 lines live here instead. The
 * `varint` dependency is dropped: both multicodec prefixes used by the method are
 * constants, so they are inlined below.
 */

/** multicodec `json` (0x0200) as an unsigned varint */
const MULTICODEC_JSON = Uint8Array.from([0x80, 0x04]);
/** multihash `sha2-256` (0x12) with a 32-byte digest length (0x20) */
const MULTIHASH_SHA2_256 = Uint8Array.from([0x12, 0x20]);
const MULTIBASE_BASE58BTC = "z";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const LONG_FORM_RE = new RegExp(`^did:peer:4zQm[${B58}]{44}:z[${B58}]{6,}$`);
export const SHORT_FORM_RE = new RegExp(`^did:peer:4zQm[${B58}]{44}$`);

/** A DID document, or the "input document" a did:peer:4 is derived from. */
export type PeerDocument = Record<string, unknown>;

export class PeerDID4Error extends Error {
  readonly name = "PeerDID4Error";
}

function toMultibaseB58(input: Uint8Array): string {
  return `${MULTIBASE_BASE58BTC}${bs58.encode(input)}`;
}

function fromMultibaseB58(input: string): Uint8Array {
  if (!input.startsWith(MULTIBASE_BASE58BTC)) {
    throw new PeerDID4Error("Multibase value must start with 'z'");
  }
  return bs58.decode(input.slice(1));
}

function concatBytes(prefix: Uint8Array, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix);
  out.set(body, prefix.length);
  return out;
}

function encodeDocument(document: PeerDocument): string {
  const json = new TextEncoder().encode(JSON.stringify(document));
  return toMultibaseB58(concatBytes(MULTICODEC_JSON, json));
}

function decodeDocument(encodedDocument: string): PeerDocument {
  const bytes = fromMultibaseB58(encodedDocument);
  if (bytes[0] !== MULTICODEC_JSON[0] || bytes[1] !== MULTICODEC_JSON[1]) {
    throw new PeerDID4Error("Encoded document is not multicodec-tagged JSON");
  }
  const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes.slice(2)));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new PeerDID4Error("Encoded document is not a JSON object");
  }
  return { ...parsed };
}

function hashDocument(encodedDocument: string): string {
  const digest = createHash("sha256").update(encodedDocument, "utf8").digest();
  return toMultibaseB58(concatBytes(MULTIHASH_SHA2_256, digest));
}

/**
 * Check an input document against the constraints a caller creating a new
 * did:peer:4 can actually be wrong about.
 *
 * Deliberately *not* applied when resolving: did:peer:4 is self-certifying, so
 * a document that violates a SHOULD still yields a sound DID. Rejecting a
 * counterparty's DID over that would trade interoperability for nothing.
 */
export function validateInputDocument(inputDocument: PeerDocument): void {
  if (inputDocument.id !== undefined) {
    throw new PeerDID4Error(
      "Input document must not have a root `id`; the DID is derived from the document"
    );
  }

  const methods = inputDocument.verificationMethod;
  if (Array.isArray(methods)) {
    for (const method of methods) {
      if (isRecord(method)) {
        assertNotAbsolute(method.id, "Verification method id");
      }
    }
  }

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const entries = inputDocument[relationship];
    if (!Array.isArray(entries)) {
      continue;
    }
    for (const entry of entries) {
      // A string entry is a *reference*, and may legitimately point at another
      // DID's key. An embedded object *defines* a key in this document, so its
      // id is a self-reference and must be relative.
      if (isRecord(entry)) {
        assertNotAbsolute(entry.id, `Embedded ${relationship} verification method id`);
      }
    }
  }

  if (Array.isArray(inputDocument.service)) {
    for (const service of inputDocument.service) {
      if (isRecord(service)) {
        assertNotAbsolute(service.id, "Service id");
      }
    }
  }
}

/**
 * Identifiers defined by the input document are self-references, and the DID is
 * a hash of that document — so an absolute one cannot be known ahead of time
 * and is necessarily wrong.
 *
 * Only absoluteness is checked. Relative DID URLs have several legal shapes
 * (`#key-1`, `?version=1#key-1`, `key-1`), and enumerating them here would
 * reject valid documents for no benefit.
 */
function assertNotAbsolute(id: unknown, label: string): void {
  if (typeof id === "string" && id.startsWith("did:")) {
    throw new PeerDID4Error(
      `${label} must be a relative reference like "#key-1", got the absolute "${id}"`
    );
  }
}

/** Derive the long form did:peer:4 from an input document. */
export function encodeLongForm(inputDocument: PeerDocument): string {
  const encodedDocument = encodeDocument(inputDocument);
  return `did:peer:4${hashDocument(encodedDocument)}:${encodedDocument}`;
}

/** Derive the short form did:peer:4 from an input document. */
export function encodeShortForm(inputDocument: PeerDocument): string {
  return `did:peer:4${hashDocument(encodeDocument(inputDocument))}`;
}

export function isPeerDID4(did: string): boolean {
  return did.startsWith("did:peer:4");
}

export function isLongForm(did: string): boolean {
  return LONG_FORM_RE.test(did);
}

export function isShortForm(did: string): boolean {
  return SHORT_FORM_RE.test(did);
}

export function longToShort(did: string): string {
  if (!LONG_FORM_RE.test(did)) {
    throw new PeerDID4Error("DID is not a long form did:peer:4");
  }
  return did.slice(0, did.lastIndexOf(":"));
}

/**
 * Recover the input document from a long form did:peer:4, verifying that the
 * embedded hash matches the encoded document.
 */
export function decode(did: string): PeerDocument {
  if (!isPeerDID4(did)) {
    throw new PeerDID4Error("Not a did:peer:4");
  }
  if (SHORT_FORM_RE.test(did)) {
    throw new PeerDID4Error(
      "Cannot decode a document from a short form did:peer:4"
    );
  }
  if (!LONG_FORM_RE.test(did)) {
    throw new PeerDID4Error("Invalid did:peer:4");
  }

  const [hash, encodedDocument] = did.slice("did:peer:4".length).split(":");
  if (hash !== hashDocument(encodedDocument)) {
    throw new PeerDID4Error(`Hash is invalid for did: ${did}`);
  }

  return decodeDocument(encodedDocument);
}

const VERIFICATION_RELATIONSHIPS = [
  "authentication",
  "assertionMethod",
  "keyAgreement",
  "capabilityDelegation",
  "capabilityInvocation",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function mapVerificationMethods(
  document: PeerDocument,
  callback: (method: Record<string, unknown>) => Record<string, unknown>
): PeerDocument {
  const result: PeerDocument = { ...document };

  const methods = result.verificationMethod;
  if (Array.isArray(methods)) {
    result.verificationMethod = methods.map((method) =>
      isRecord(method) ? callback({ ...method }) : method
    );
  }

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const entries = result[relationship];
    if (Array.isArray(entries)) {
      // Entries are either DID URL references or embedded verification methods.
      result[relationship] = entries.map((entry) =>
        isRecord(entry) ? callback({ ...entry }) : entry
      );
    }
  }

  return result;
}

/**
 * Apply the resolution rules from the spec: set `id`, and default the
 * `controller` of every verification method to the DID.
 *
 * Per the spec, relative references (`#key-1`) are left as-is. Use
 * {@link absolutizeReferences} for consumers that require absolute DID URLs.
 */
function contextualizeDocument(did: string, document: PeerDocument): PeerDocument {
  const contextualized = mapVerificationMethods(
    { ...document, id: did },
    (method) => {
      if (method.controller === undefined) {
        method.controller = did;
      }
      return method;
    }
  );

  return contextualized;
}

/**
 * Resolve a relative DID URL against the DID.
 *
 * Fragment (`#key-1`) and query (`?version=1#key-1`) references are resolved by
 * concatenation, which is what RFC 3986 recomposition reduces to for a base
 * with no authority, path, query or fragment of its own.
 *
 * Path-style references (`/foo`, `key-1`) are left alone. A DID has no
 * authority component, so RFC 3986 would resolve `/foo` against the base to
 * `did:/foo` — dropping the method-specific id, plainly not the intent — and
 * DID Core does not define what should happen instead.
 */
function absolutize(reference: string, did: string): string {
  return reference.startsWith("#") || reference.startsWith("?")
    ? `${did}${reference}`
    : reference;
}

/**
 * Rewrite relative references (`#key-1`) into absolute DID URLs
 * (`did:peer:4zQm...#key-1`).
 *
 * did:peer:4 documents legitimately use relative references, but didcomm-rust
 * derives the sender/recipient DID by splitting a `kid` on `#`, so a relative
 * `kid` resolves to an empty DID and unpacking fails.
 */
export function absolutizeReferences(document: PeerDocument): PeerDocument {
  const did = document.id;
  if (typeof did !== "string") {
    return document;
  }

  const result = mapVerificationMethods(document, (method) => {
    if (typeof method.id === "string") {
      method.id = absolutize(method.id, did);
    }
    return method;
  });

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const entries = result[relationship];
    if (Array.isArray(entries)) {
      result[relationship] = entries.map((entry) =>
        typeof entry === "string" ? absolutize(entry, did) : entry
      );
    }
  }

  if (Array.isArray(result.service)) {
    result.service = result.service.map((service) =>
      isRecord(service) ? absolutizeService(service, did) : service
    );
  }

  return result;
}

/**
 * Routing keys are DID URLs that DIDComm forwarding actually resolves, so a
 * relative one has to be absolutized like any other reference.
 */
function absolutizeEndpoint(endpoint: unknown, did: string): unknown {
  if (!isRecord(endpoint) || !Array.isArray(endpoint.routingKeys)) {
    return endpoint;
  }
  return {
    ...endpoint,
    routingKeys: endpoint.routingKeys.map((key) =>
      typeof key === "string" ? absolutize(key, did) : key
    ),
  };
}

function absolutizeService(
  service: Record<string, unknown>,
  did: string
): Record<string, unknown> {
  const result = { ...service };

  if (typeof result.id === "string") {
    result.id = absolutize(result.id, did);
  }

  const endpoint = result.serviceEndpoint;
  result.serviceEndpoint = Array.isArray(endpoint)
    ? endpoint.map((entry) => absolutizeEndpoint(entry, did))
    : absolutizeEndpoint(endpoint, did);

  return result;
}

function withAlsoKnownAs(document: PeerDocument, alias: string): PeerDocument {
  const existing = document.alsoKnownAs;
  const aliases = Array.isArray(existing) ? [...existing] : [];
  if (!aliases.includes(alias)) {
    aliases.push(alias);
  }
  return { ...document, alsoKnownAs: aliases };
}

/** Resolve a long form did:peer:4 to a document identified by the long form. */
export function resolveLongForm(did: string): PeerDocument {
  const document = contextualizeDocument(did, decode(did));
  return withAlsoKnownAs(document, longToShort(did));
}

/**
 * Resolve the short form of a long form did:peer:4, producing a document
 * identified by the short form.
 */
export function resolveShortForm(longFormDid: string): PeerDocument {
  const shortForm = longToShort(longFormDid);
  const document = contextualizeDocument(shortForm, decode(longFormDid));
  return withAlsoKnownAs(document, longFormDid);
}

/**
 * Resolve a short form did:peer:4 given its input document, verifying that the
 * document actually hashes to the supplied DID.
 */
export function resolveShortFormFromDocument(
  inputDocument: PeerDocument,
  did?: string
): PeerDocument {
  const longForm = encodeLongForm(inputDocument);
  if (did !== undefined && did !== longToShort(longForm)) {
    throw new PeerDID4Error(`DID mismatch: ${did} !== ${longToShort(longForm)}`);
  }
  return resolveShortForm(longForm);
}
