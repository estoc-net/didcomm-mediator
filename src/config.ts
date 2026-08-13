import { DID_METHODS, type DidMethod } from "./identity-core.js";

/**
 * The part of the configuration the protocol layer and shared HTTP surface
 * consume — everything that is true of the mediator regardless of whether it
 * runs on Node or on Workers.
 */
export interface MediatorPolicy {
  /**
   * Whether any DID that asks is granted mediation. Off, mediate-request is
   * denied unless the DID already holds an account (granted out of band).
   */
  openRegistration: boolean;
  corsOrigin: string | boolean;
  messageTtlSeconds: number;
  maxMessagesPerAccount: number;
}

export interface MediatorConfig extends MediatorPolicy {
  /**
   * The URL agents reach this mediator at. Every DID derives from the stored
   * keys and this URL, so changing it renames the mediator (the keys stay).
   */
  publicUrl: string;
  /**
   * The active DID methods, in order — the first is the primary (advertised)
   * DID; the rest are aliases the mediator answers to equally. All derive
   * from the one stored key set. Empty means the default, web — set peer2
   * here for a public URL the world cannot fetch (non-loopback http).
   */
  didMethods: DidMethod[];
  host: string;
  port: number;
  dataDir: string;
}

function env(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

/**
 * A comma-separated, ordered method list — "peer2,web" — shared with Workers.
 * Unset means unspecified (empty list): each target applies its own default.
 */
export function parseDidMethods(value: string | undefined): DidMethod[] {
  if (value === undefined) {
    return [];
  }
  const methods = value.split(",").map((entry) => entry.trim());
  for (const method of methods) {
    if (!(DID_METHODS as readonly string[]).includes(method)) {
      throw new Error(
        `MEDIATOR_DID_METHODS entries must be among ${DID_METHODS.join(", ")}, got ${method}`
      );
    }
  }
  return methods as DidMethod[];
}

export function configFromEnv(): MediatorConfig {
  const publicUrl = env("MEDIATOR_PUBLIC_URL");
  if (publicUrl === undefined) {
    throw new Error(
      "MEDIATOR_PUBLIC_URL must be set — the mediator's DIDs derive from it, " +
        "and changing it later renames the mediator"
    );
  }

  return {
    publicUrl,
    didMethods: parseDidMethods(env("MEDIATOR_DID_METHODS")),
    host: env("MEDIATOR_HOST") ?? "0.0.0.0",
    port: Number(env("MEDIATOR_PORT") ?? 8080),
    dataDir: env("MEDIATOR_DATA_DIR") ?? "./data",
    openRegistration: env("MEDIATOR_OPEN_REGISTRATION") !== "false",
    corsOrigin: env("MEDIATOR_CORS_ORIGIN") ?? "*",
    messageTtlSeconds: Number(env("MEDIATOR_MESSAGE_TTL_SECONDS") ?? 7 * 24 * 3600),
    maxMessagesPerAccount: Number(env("MEDIATOR_MAX_MESSAGES_PER_ACCOUNT") ?? 1000),
  };
}
