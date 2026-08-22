import { randomUUID } from "node:crypto";
import { Message } from "didcomm-node";
import type { IMessage } from "didcomm-node";

import type { MediatorConfig } from "../src/config.js";
import { DIDCommContext } from "../src/didcomm/didcomm.js";
import { resolveDIDCommDoc } from "../src/didcomm/did-resolver.js";
import { mintIdentity, type MediatorIdentity } from "../src/identity-core.js";
import { SqliteStore } from "../src/store/sqlite.js";

export const TEST_CONFIG: MediatorConfig = {
  publicUrl: "https://mediator.test",
  didMethods: ["peer2"],
  host: "127.0.0.1",
  port: 0,
  dataDir: "/nonexistent-tests-never-touch-disk",
  openRegistration: true,
  corsOrigin: "*",
  messageTtlSeconds: 3600,
  maxMessagesPerAccount: 5,
  maxPublicationBytes: 16 * 1024 * 1024,
  publicationRetainSeconds: 365 * 24 * 3600,
  abuseEmail: "abuse@mediator.test",
  publicationServeDefault: "allow",
};

export function memoryStore(): SqliteStore {
  return new SqliteStore(":memory:", {
    messageTtlSeconds: TEST_CONFIG.messageTtlSeconds,
    maxMessagesPerAccount: TEST_CONFIG.maxMessagesPerAccount,
  });
}

/** An agent for tests: a did:peer:2 identity and the context to speak with it. */
export interface TestAgent {
  identity: MediatorIdentity;
  did: string;
  ctx: DIDCommContext;
}

export async function agent(name: string): Promise<TestAgent> {
  const identity = await mintIdentity(`https://${name}.test/didcomm`);
  return {
    identity,
    did: identity.did,
    ctx: new DIDCommContext(identity.did, identity.didDoc, identity.secrets),
  };
}

export function plaintext(
  type: string,
  body: Record<string, unknown>,
  overrides: Partial<IMessage> = {}
): IMessage {
  return {
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    type,
    body,
    created_time: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

/** Anoncrypt to `to` — how a stranger's forward arrives at a mediator. */
export async function packAnonymous(
  message: IMessage,
  to: string
): Promise<string> {
  const msg = new Message(message);
  const [packed] = await msg.pack_encrypted(
    to,
    null,
    null,
    { resolve: resolveDIDCommDoc },
    { get_secret: async () => null, find_secrets: async () => [] },
    { forward: false }
  );
  return packed;
}
