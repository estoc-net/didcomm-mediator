import { Resolver, type DIDDocument } from "did-resolver";
import { getResolver as getWebResolver } from "web-did-resolver";
import {
  isPeerDID2,
  isPeerDID4,
  isShortForm,
  resolveLongForm,
  resolvePeer2,
  toDIDCommDIDDoc,
} from "@estoc/did-peer";
import type { DIDDoc } from "@estoc/did-peer";

let cachedResolver: Resolver | null = null;

function getDidWebResolver(): Resolver {
  if (!cachedResolver) {
    cachedResolver = new Resolver({ ...getWebResolver() });
  }
  return cachedResolver;
}

export interface ResolveResult {
  // did:peer:4 documents are not DIDDocument-shaped (relative references, no
  // required fields), so the union stays open.
  didDocument: DIDDocument | Record<string, unknown> | null;
  didDocumentMetadata: Record<string, unknown>;
  didResolutionMetadata: {
    contentType?: string;
    error?: string;
    message?: string;
  };
}

export async function resolveDID(did: string): Promise<ResolveResult> {
  if (isPeerDID2(did)) {
    return resolveDidPeer2(did);
  }

  if (isPeerDID4(did)) {
    return resolveDidPeer4(did);
  }

  if (did.startsWith("did:web:")) {
    return resolveDidWeb(did);
  }

  return {
    didDocument: null,
    didDocumentMetadata: {},
    didResolutionMetadata: {
      error: "methodNotSupported",
      message: `Unsupported DID method: ${did.split(":")[1] ?? "unknown"}`,
    },
  };
}

/**
 * did:webvh is not resolved here — the didwebvh-ts dependency is heavy and no
 * mediator client has shown up naming one. The didcomm-http sibling has the
 * implementation to lift when one does.
 */

/** How long a fetched document is reused, in seconds. */
const CACHE_TTL = Number(process.env.DID_CACHE_TTL ?? 300) * 1000;

/** Past this many entries the oldest is dropped, so a busy endpoint cannot grow it forever. */
const CACHE_MAX = 512;

const cache = new Map<string, { doc: DIDDoc; expiresAt: number }>();

/**
 * A did:peer carries its own document, so resolving one is decoding a string.
 * Only the methods that cost a request are worth keeping, and keeping only
 * those also means a stranger introducing themselves cannot push out the
 * mediators and correspondents that were.
 */
function isFetched(did: string): boolean {
  return did.startsWith("did:web:");
}

function cached(did: string): DIDDoc | null {
  const entry = cache.get(did);
  if (entry === undefined) {
    return null;
  }

  if (entry.expiresAt <= Date.now()) {
    cache.delete(did);
    return null;
  }

  return entry.doc;
}

function remember(did: string, doc: DIDDoc): void {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next();
    if (!oldest.done) {
      cache.delete(oldest.value);
    }
  }

  cache.set(did, { doc, expiresAt: Date.now() + CACHE_TTL });
}

/** Forgets every fetched document. For tests, and for a key rotation nobody wants to wait out. */
export function clearDIDCache(): void {
  cache.clear();
}

/**
 * Resolve a DID into the flat DIDDoc the pack and unpack operations read,
 * caching whatever had to be fetched.
 *
 * Anything that does not resolve, or resolves to something that cannot be
 * converted, is `null` — the same answer as a DID that does not exist, which is
 * what it amounts to for a message addressed to it.
 */
export async function resolveDIDCommDoc(did: string): Promise<DIDDoc | null> {
  const hit = cached(did);
  if (hit !== null) {
    return hit;
  }

  const { didDocument } = await resolveDID(did);
  if (didDocument === null) {
    return null;
  }

  let doc: DIDDoc;
  try {
    doc = toDIDCommDIDDoc(didDocument);
  } catch {
    return null;
  }

  if (isFetched(did)) {
    remember(did, doc);
  }

  return doc;
}

function resolveDidPeer2(did: string): ResolveResult {
  try {
    return {
      didDocument: resolvePeer2(did),
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: "application/did+ld+json" },
    };
  } catch (err) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "invalidDid",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }
}

function resolveDidPeer4(did: string): ResolveResult {
  // The short form carries no document, so it can only be resolved by a party
  // that already holds the long form.
  if (isShortForm(did)) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "notFound",
        message:
          "Short form did:peer:4 cannot be resolved on its own; supply the long form",
      },
    };
  }

  try {
    return {
      didDocument: resolveLongForm(did),
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: "application/did+ld+json" },
    };
  } catch (err) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "invalidDid",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }
}

/**
 * The did.json URL of a loopback did:web, or null for any other host.
 * web-did-resolver only ever fetches https, which is right for the world at
 * large but leaves `wrangler dev` (plain http on localhost) unresolvable —
 * and a loopback name was never reachable by anyone else anyway.
 */
function loopbackDidWebUrl(did: string): string | null {
  const [host, ...segments] = did
    .slice("did:web:".length)
    .split(":")
    .map((part) => decodeURIComponent(part));

  const hostname = host.split(":")[0];
  if (hostname !== "localhost" && hostname !== "127.0.0.1") {
    return null;
  }

  const path =
    segments.length === 0
      ? "/.well-known/did.json"
      : `/${segments.join("/")}/did.json`;
  return `http://${host}${path}`;
}

async function resolveDidWeb(did: string): Promise<ResolveResult> {
  const loopback = loopbackDidWebUrl(did);
  if (loopback !== null) {
    try {
      const response = await fetch(loopback);
      if (!response.ok) {
        throw new Error(`GET ${loopback} answered ${response.status}`);
      }
      return {
        didDocument: (await response.json()) as Record<string, unknown>,
        didDocumentMetadata: {},
        didResolutionMetadata: { contentType: "application/did+ld+json" },
      };
    } catch (err) {
      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: "notFound",
          message: err instanceof Error ? err.message : String(err),
        },
      };
    }
  }

  const resolver = getDidWebResolver();
  const result = await resolver.resolve(did);
  return {
    didDocument: result.didDocument ?? null,
    didDocumentMetadata: result.didDocumentMetadata ?? {},
    didResolutionMetadata: result.didResolutionMetadata ?? {},
  };
}
