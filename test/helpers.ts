import { randomUUID } from "node:crypto";
import { Message } from "@estoc/didcomm-node";
import { FlattenedEncrypt, importJWK } from "jose";
import type { IMessage } from "@estoc/didcomm-node";

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
  maxMessageBytes: 64 * 1024,
  blobRetainSeconds: 3600,
  blobMaxBytes: 4096,
  blobQuotaBytes: 6000,
  abuseEmail: "abuse@mediator.test",
  blobDir: null,
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

const FORWARD = "https://didcomm.org/routing/2.0/forward";
export const ENCRYPTED = "application/didcomm-encrypted+json";

/** A real envelope nobody here can open, as the JSON a forward carries. */
export async function sealed(to: TestAgent, content: string): Promise<Record<string, unknown>> {
  return JSON.parse(
    await packAnonymous(plaintext("https://example.test/note", { content }), to.did)
  );
}

/** The forward a conforming sender builds around `envelope`, not yet sealed. */
export function forwardOf(
  next: string,
  envelope: unknown,
  overrides: Partial<IMessage> = {}
): IMessage {
  return plaintext(FORWARD, { next }, {
    attachments: [{ media_type: ENCRYPTED, data: { json: envelope } }],
    ...overrides,
  });
}

/**
 * `raw`, whatever it is, in an anonymous envelope to the mediator's
 * key-agreement key: what no library packer would put on a wire.
 */
export async function sealRaw(raw: string, to: MediatorIdentity): Promise<string> {
  const secret = to.secrets.find((s) => s.privateKeyJwk?.crv === "X25519");
  if (secret === undefined) throw new Error("no key-agreement key");
  const { kty, crv, x } = secret.privateKeyJwk as { kty: string; crv: string; x: string };
  const apv = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret.id))
  );
  const jwe = await new FlattenedEncrypt(new TextEncoder().encode(raw))
    .setProtectedHeader({ typ: ENCRYPTED, alg: "ECDH-ES+A256KW", enc: "A256GCM" })
    .setUnprotectedHeader({ kid: secret.id })
    .setKeyManagementParameters({ apv })
    .encrypt(await importJWK({ kty, crv, x }, "ECDH-ES+A256KW"));
  const { header, encrypted_key, ...rest } = jwe;
  return JSON.stringify({ ...rest, recipients: [{ header, encrypted_key }] });
}
