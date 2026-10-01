import { randomUUID } from "node:crypto";
import bs58 from "bs58";
import canonicalize from "canonicalize";
import {
  base64urlToBytes,
  encodeLongForm,
  longToShort,
  resolveLongForm,
  resolveShortForm,
  toDIDCommDIDDoc,
} from "@estoc/did-peer";
import type { Secret } from "@estoc/did-peer";
import { Message } from "@estoc/didcomm-node";
import { CompactSign, FlattenedEncrypt, importJWK, type JWK } from "jose";
import type { IMessage } from "@estoc/didcomm-node";

import type { MediatorConfig } from "../src/config.js";
import { DIDCommContext } from "../src/didcomm/didcomm.js";
import { resolveDIDCommDoc } from "../src/didcomm/did-resolver.js";
import { mintIdentity, mintSecrets, type MediatorIdentity } from "../src/identity-core.js";
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
  replicaMediation: true,
  maxActiveReplicas: 3,
  maxMembershipPage: 2,
  maxSharedRecipients: 4,
  maxRetainedBytes: 256 * 1024,
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

/**
 * A did:peer:4 the way a vault mints one: a Multikey per use, authentication
 * first, and a DIDComm service at `service` when it has one.
 */
export interface Peer4Agent {
  did: string;
  longForm: string;
  /** Speaks as the long form: what a first contact must do. */
  ctx: DIDCommContext;
  /** Speaks as the short form: resolvable only by who kept the long one. */
  shortCtx: DIDCommContext;
  signingKey: JWK;
}

const MULTICODEC = { Ed25519: [0xed, 0x01], X25519: [0xec, 0x01] };

function multikey(jwk: Record<string, unknown>): string {
  const prefix = MULTICODEC[jwk.crv as keyof typeof MULTICODEC];
  return `z${bs58.encode(Uint8Array.from([...prefix, ...base64urlToBytes(jwk.x as string)]))}`;
}

type InputDocument = Parameters<typeof encodeLongForm>[0];

/** `reshape` turns the document into one no vault would mint. */
export async function peer4Agent(
  service: string | null,
  reshape: (document: InputDocument) => InputDocument = (document) => document
): Promise<Peer4Agent> {
  const [agreement, signing] = (await mintSecrets()).map(
    (secret) => secret.privateKeyJwk as Record<string, unknown>
  );
  const longForm = encodeLongForm(reshape({
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    verificationMethod: [
      { id: "#key-1", type: "Multikey", publicKeyMultibase: multikey(signing) },
      { id: "#key-2", type: "Multikey", publicKeyMultibase: multikey(agreement) },
    ],
    authentication: ["#key-1"],
    keyAgreement: ["#key-2"],
    ...(service === null
      ? {}
      : {
          service: [
            {
              id: "#service",
              type: "DIDCommMessaging",
              serviceEndpoint: { uri: service, accept: ["didcomm/v2"] },
            },
          ],
        }),
  }));
  const did = longToShort(longForm);
  const secretsAs = (name: string): Secret[] => [
    { id: `${name}#key-1`, type: "JsonWebKey2020", privateKeyJwk: signing },
    { id: `${name}#key-2`, type: "JsonWebKey2020", privateKeyJwk: agreement },
  ];
  return {
    did,
    longForm,
    ctx: new DIDCommContext(
      longForm,
      toDIDCommDIDDoc(resolveLongForm(longForm)),
      secretsAs(longForm)
    ),
    shortCtx: new DIDCommContext(
      did,
      toDIDCommDIDDoc(resolveShortForm(longForm)),
      secretsAs(did)
    ),
    signingKey: signing as JWK,
  };
}

export const GRANT_TYP = "estoc/replica-grant+jws";

/** A compact JWS over `payload` in its RFC 8785 form, as `signer`'s authentication key. */
export async function signedBy(
  signer: Peer4Agent,
  payload: unknown,
  header: Record<string, unknown> = {}
): Promise<string> {
  return new CompactSign(new TextEncoder().encode(canonicalize(payload)))
    .setProtectedHeader({ alg: "EdDSA", typ: GRANT_TYP, kid: `${signer.did}#key-1`, ...header })
    .sign(await importJWK(signer.signingKey, "EdDSA"));
}
