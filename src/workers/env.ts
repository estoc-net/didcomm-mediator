import type { Secret } from "@estoc/did-peer";

import { parseDidMethods, type MediatorPolicy } from "../config.js";
import { DIDCommContext } from "../didcomm/didcomm.js";
import {
  identityFor,
  loadOrCreateSecrets,
  type MediatorIdentity,
} from "../identity-core.js";
import { D1Store } from "./d1-store.js";

export interface Env {
  DB: D1Database;
  INBOX: DurableObjectNamespace;
  /** Ordered, comma-separated: "web,peer2". First = primary; default: web. */
  MEDIATOR_DID_METHODS?: string;
  MEDIATOR_OPEN_REGISTRATION?: string;
  MEDIATOR_CORS_ORIGIN?: string;
  MEDIATOR_MESSAGE_TTL_SECONDS?: string;
  MEDIATOR_MAX_MESSAGES_PER_ACCOUNT?: string;
}

export interface WorkerDeps {
  identity: MediatorIdentity;
  ctx: DIDCommContext;
  store: D1Store;
  policy: MediatorPolicy;
}

export function policyFromEnv(env: Env): MediatorPolicy {
  return {
    openRegistration: env.MEDIATOR_OPEN_REGISTRATION !== "false",
    corsOrigin: env.MEDIATOR_CORS_ORIGIN ?? "*",
    messageTtlSeconds: Number(env.MEDIATOR_MESSAGE_TTL_SECONDS ?? 7 * 24 * 3600),
    maxMessagesPerAccount: Number(env.MEDIATOR_MAX_MESSAGES_PER_ACCOUNT ?? 1000),
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

  return {
    identity,
    ctx: new DIDCommContext(identity.did, identity.didDoc, identity.secrets, {
      aliases: identity.aliases,
    }),
    store,
    policy: policyFromEnv(env),
  };
}
