import { parseDidMethods, type MediatorPolicy } from "../config.js";
import { DIDCommContext } from "../didcomm/didcomm.js";
import {
  toIdentity,
  type MediatorIdentity,
  type StoredIdentity,
} from "../identity-core.js";
import { D1Store } from "./d1-store.js";

export interface Env {
  DB: D1Database;
  INBOX: DurableObjectNamespace;
  /**
   * The mediator's StoredIdentity as JSON — mint one with
   * `npm run mint-identity -- https://your.public.url` and store it with
   * `wrangler secret put MEDIATOR_IDENTITY` (locally: a line in .dev.vars).
   * Workers never mint: an accidental redeploy that minted a fresh DID would
   * orphan every client.
   */
  MEDIATOR_IDENTITY?: string;
  /** Ordered, comma-separated: "peer2,web". First = primary; default = the stored DID's method. */
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

export function depsFromEnv(env: Env): WorkerDeps {
  if (env.MEDIATOR_IDENTITY === undefined || env.MEDIATOR_IDENTITY === "") {
    throw new Error(
      "MEDIATOR_IDENTITY is not set. Mint one with " +
        "`npm run mint-identity -- <public-url>` and store it with " +
        "`wrangler secret put MEDIATOR_IDENTITY`."
    );
  }

  const stored = JSON.parse(env.MEDIATOR_IDENTITY) as StoredIdentity;
  const identity = toIdentity(
    stored,
    env.MEDIATOR_DID_METHODS === undefined
      ? []
      : parseDidMethods(env.MEDIATOR_DID_METHODS)
  );
  const policy = policyFromEnv(env);

  return {
    identity,
    ctx: new DIDCommContext(identity.did, identity.didDoc, identity.secrets, {
      aliases: identity.aliases,
    }),
    store: new D1Store(env.DB, {
      messageTtlSeconds: policy.messageTtlSeconds,
      maxMessagesPerAccount: policy.maxMessagesPerAccount,
    }),
    policy,
  };
}
