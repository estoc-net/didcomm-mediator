export interface MediatorConfig {
  /** The URL agents reach this mediator at; baked into the DID on first boot. */
  publicUrl: string;
  host: string;
  port: number;
  dataDir: string;
  /**
   * Whether any DID that asks is granted mediation. Off, mediate-request is
   * denied unless the DID already holds an account (granted out of band).
   */
  openRegistration: boolean;
  corsOrigin: string | boolean;
  messageTtlSeconds: number;
  maxMessagesPerAccount: number;
}

function env(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

export function configFromEnv(): MediatorConfig {
  const publicUrl = env("MEDIATOR_PUBLIC_URL");
  if (publicUrl === undefined) {
    throw new Error(
      "MEDIATOR_PUBLIC_URL must be set before first start — it is encoded " +
        "into the mediator's DID and cannot change afterwards"
    );
  }

  return {
    publicUrl,
    host: env("MEDIATOR_HOST") ?? "0.0.0.0",
    port: Number(env("MEDIATOR_PORT") ?? 8080),
    dataDir: env("MEDIATOR_DATA_DIR") ?? "./data",
    openRegistration: env("MEDIATOR_OPEN_REGISTRATION") !== "false",
    corsOrigin: env("MEDIATOR_CORS_ORIGIN") ?? "*",
    messageTtlSeconds: Number(env("MEDIATOR_MESSAGE_TTL_SECONDS") ?? 7 * 24 * 3600),
    maxMessagesPerAccount: Number(env("MEDIATOR_MAX_MESSAGES_PER_ACCOUNT") ?? 1000),
  };
}
