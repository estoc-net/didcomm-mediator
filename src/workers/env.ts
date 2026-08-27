import type { Secret } from "@estoc/did-peer";

import { BlobService } from "../blobs/service.js";
import {
  DEFAULT_MAX_MESSAGE_BYTES,
  blobPolicyFrom,
  parseDidMethods,
  type MediatorPolicy,
} from "../config.js";
import { DIDCommContext } from "../didcomm/didcomm.js";
import {
  identityFor,
  loadOrCreateSecrets,
  type MediatorIdentity,
} from "../identity-core.js";
import { D1Store } from "./d1-store.js";
import { R2BlobStorage } from "./r2-storage.js";

export interface Env {
  DB: D1Database;
  INBOX: DurableObjectNamespace;
  /** blob-store/1.0's bucket; unbound, the mediator keeps no blobs. */
  BLOBS?: R2Bucket;
  /** Ordered, comma-separated: "web,peer2". First = primary; default: web. */
  MEDIATOR_DID_METHODS?: string;
  MEDIATOR_OPEN_REGISTRATION?: string;
  MEDIATOR_CORS_ORIGIN?: string;
  MEDIATOR_MESSAGE_TTL_SECONDS?: string;
  MEDIATOR_MAX_MESSAGES_PER_ACCOUNT?: string;
  MEDIATOR_MAX_MESSAGE_BYTES?: string;
  MEDIATOR_BLOB_RETAIN_SECONDS?: string;
  MEDIATOR_BLOB_MAX_BYTES?: string;
  MEDIATOR_BLOB_QUOTA_BYTES?: string;
  /** Abuse contact for the invitation page's footer; unset = no footer. */
  MEDIATOR_ABUSE_EMAIL?: string;
}

export interface WorkerDeps {
  identity: MediatorIdentity;
  ctx: DIDCommContext;
  store: D1Store;
  policy: MediatorPolicy;
  blobs: BlobService | null;
}

export function policyFromEnv(env: Env): MediatorPolicy {
  return {
    openRegistration: env.MEDIATOR_OPEN_REGISTRATION !== "false",
    corsOrigin: env.MEDIATOR_CORS_ORIGIN ?? "*",
    messageTtlSeconds: Number(env.MEDIATOR_MESSAGE_TTL_SECONDS ?? 7 * 24 * 3600),
    maxMessagesPerAccount: Number(env.MEDIATOR_MAX_MESSAGES_PER_ACCOUNT ?? 1000),
    maxMessageBytes: Number(env.MEDIATOR_MAX_MESSAGE_BYTES ?? DEFAULT_MAX_MESSAGE_BYTES),
    ...blobPolicyFrom((name) => env[name as keyof Env] as string | undefined),
    // `||` on purpose: an empty string means unset, same as Node's env().
    abuseEmail: env.MEDIATOR_ABUSE_EMAIL || null,
  };
}

export function storeFromEnv(env: Env): D1Store {
  const policy = policyFromEnv(env);
  return new D1Store(env.DB, {
    messageTtlSeconds: policy.messageTtlSeconds,
    maxMessagesPerAccount: policy.maxMessagesPerAccount,
  });
}

// The keys are one row in D1, loaded (minted, on very first contact) once per
// isolate. A failed load is not cached — the next request retries.
let cachedSecrets: Promise<Secret[]> | null = null;

function secretsFromStore(store: D1Store): Promise<Secret[]> {
  if (cachedSecrets === null) {
    cachedSecrets = loadOrCreateSecrets(store, (msg) => console.log(msg));
    cachedSecrets.catch(() => {
      cachedSecrets = null;
    });
  }
  return cachedSecrets;
}

/**
 * Everything a request needs, bound to the origin it arrived on. The Workers
 * deployment is URL-agnostic: no public URL is configured anywhere, the
 * mediator answers every host that routes to it as that host's own did:web
 * (workers.dev and a custom domain are then two names for one mediator, both
 * live). did:web is the default method because it is the only one whose name
 * survives moving between those hosts with the same keys.
 */
export async function depsForOrigin(env: Env, origin: string): Promise<WorkerDeps> {
  const store = storeFromEnv(env);
  const secrets = await secretsFromStore(store);
  const methods = parseDidMethods(env.MEDIATOR_DID_METHODS);
  const identity = identityFor(
    secrets,
    origin,
    methods.length > 0 ? methods : ["web"]
  );

  const policy = policyFromEnv(env);
  return {
    identity,
    ctx: new DIDCommContext(identity.did, identity.didDoc, identity.secrets, {
      aliases: identity.aliases,
    }),
    store,
    policy,
    blobs: blobsFor(env, store, policy, identity.publicUrl),
  };
}

/** The blob service for one origin, or null without an R2 binding. */
export function blobsFor(
  env: Env,
  store: D1Store,
  policy: MediatorPolicy,
  publicUrl: string
): BlobService | null {
  return env.BLOBS === undefined
    ? null
    : new BlobService(store, new R2BlobStorage(env.BLOBS), policy, publicUrl);
}
