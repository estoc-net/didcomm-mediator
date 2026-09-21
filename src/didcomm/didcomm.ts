import { Message } from "@estoc/didcomm-node";
import type {
  DIDResolver,
  IMessage,
  SecretsResolver,
  UnpackMetadata,
} from "@estoc/didcomm-node";
import { resolveDIDCommDoc } from "./did-resolver.js";
import type { DIDDoc, Secret } from "@estoc/did-peer";
import type { OwnIdentity } from "../identity-core.js";

/**
 * Pack and unpack with the mediator's own identity.
 *
 * Unlike didcomm-http, where every call carries its own secrets, a mediator has
 * exactly one key set — its own — and every envelope it opens or seals uses it.
 * The key set may answer to several DIDs at once (see identity-core): the
 * context knows them all, opens envelopes addressed to any of them, and seals
 * replies as whichever one was addressed. The resolvers are built once and
 * shared.
 */

/** The mediator's documents first (never fetched), then the world. */
class ChainedResolver implements DIDResolver {
  private pinned: Map<string, DIDDoc>;

  constructor(didDocs: DIDDoc[]) {
    this.pinned = new Map(didDocs.map((doc) => [doc.id, doc]));
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.pinned.get(did) ?? (await resolveDIDCommDoc(did));
  }
}

class InMemorySecretsResolver implements SecretsResolver {
  private secrets: Map<string, Secret>;

  constructor(secrets: Secret[]) {
    this.secrets = new Map(secrets.map((s) => [s.id, s]));
  }

  async get_secret(secretId: string): Promise<Secret | null> {
    return this.secrets.get(secretId) ?? null;
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) => this.secrets.has(id));
  }
}

/** A key ID names a DID and a key within it; everything here wants the DID. */
export function didOf(value: string | null | undefined): string | null {
  return value ? value.split("#")[0] : null;
}

const FAILURE_KINDS = [
  "DIDCommDIDNotResolved",
  "DIDCommDIDUrlNotFound",
  "DIDCommMalformed",
  "DIDCommIoError",
  "DIDCommInvalidState",
  "DIDCommNoCompatibleCrypto",
  "DIDCommUnsupported",
  "DIDCommIllegalArgument",
  "DIDCommSecretNotFound",
] as const;

/**
 * A pack or unpack that failed, by kind alone. The library's own message can
 * quote what it was reading — a header of an envelope it had already
 * decrypted — and errors end up in logs, so neither the message nor the
 * original error travels any further than this.
 */
export class DIDCommFailure extends Error {
  readonly kind: (typeof FAILURE_KINDS)[number] | "unknown";

  constructor(operation: "pack" | "unpack", err: unknown) {
    const name = err instanceof Error ? err.name : null;
    const kind = FAILURE_KINDS.find((known) => known === name) ?? "unknown";
    super(`${operation} failed: ${kind}`);
    this.name = "DIDCommFailure";
    this.kind = kind;
  }
}

export interface Unpacked {
  message: IMessage;
  /**
   * The plaintext as its sender wrote it. `message` is the library's reading
   * of it, in which a member name that came twice has already become its last
   * value and a number may have moved; whoever must answer for the JSON text
   * itself parses this.
   */
  plaintext: string;
  metadata: UnpackMetadata;
  /** The DID the plaintext claims sent it. */
  from: string | null;
  /**
   * The DID proven by the envelope — the authcrypt key or the signature.
   * Opening an envelope proves who held the key that closed it, not the `from`
   * in the plaintext; didcomm-rust never compares them, so anyone can authcrypt
   * with their own key and write somebody else's DID in the header. Handlers
   * that grant anything must key off this, never off `from`.
   */
  verifiedFrom: string | null;
  /**
   * Which of the mediator's own DIDs the envelope was sealed to — the name
   * the sender knows this mediator by, and so the name replies should carry.
   */
  addressedTo: string | null;
}

export interface ContextOptions {
  /** The mediator's other active DIDs, beyond the primary. */
  aliases?: OwnIdentity[];
  /** Extra documents resolved without fetching — a counterparty whose DID
   * (did:web, short-form peer:4) cannot be decoded offline. */
  pinned?: DIDDoc[];
}

export class DIDCommContext {
  /** Every DID this context answers to, primary first. */
  readonly dids: string[];
  private didResolver: DIDResolver;
  private secretsResolver: SecretsResolver;

  constructor(
    readonly did: string,
    didDoc: DIDDoc,
    secrets: Secret[],
    { aliases = [], pinned = [] }: ContextOptions = {}
  ) {
    this.dids = [did, ...aliases.map((alias) => alias.did)];
    this.didResolver = new ChainedResolver([
      didDoc,
      ...aliases.map((alias) => alias.didDoc),
      ...pinned,
    ]);
    this.secretsResolver = new InMemorySecretsResolver(secrets);
  }

  /**
   * `did` if it is one of this context's own names, else the primary — what
   * dispatch replies as when the envelope named nobody (or a name this
   * deployment no longer answers to).
   */
  asOwnDid(did: string | null): string {
    return did !== null && this.dids.includes(did) ? did : this.did;
  }

  async unpack(packed: string): Promise<Unpacked> {
    let msg: Message;
    let metadata: UnpackMetadata;
    let plaintext: string;
    try {
      [msg, metadata, plaintext] = await Message.unpack(
        packed,
        this.didResolver,
        this.secretsResolver,
        {}
      );
    } catch (err) {
      throw new DIDCommFailure("unpack", err);
    }

    const message = msg.as_value();
    return {
      message,
      plaintext,
      metadata,
      from: message.from ?? null,
      verifiedFrom: didOf(metadata.encrypted_from_kid ?? metadata.sign_from),
      addressedTo: didOf(metadata.encrypted_to_kids?.[0]),
    };
  }

  /**
   * Seal a message from the mediator to `to`, as `asDid` (default: the
   * primary DID; must be one of this context's own names).
   *
   * `forward: false` — replies go back on the return route or into the
   * recipient's own inbox here; wrapping them for yet another mediator would
   * assume an infrastructure DID is itself mediated, which this one is not.
   */
  async packEncrypted(
    message: IMessage,
    to: string,
    asDid: string = this.did
  ): Promise<string> {
    try {
      const [packed] = await new Message(message).pack_encrypted(
        to,
        asDid,
        null,
        this.didResolver,
        this.secretsResolver,
        { forward: false }
      );
      return packed;
    } catch (err) {
      throw new DIDCommFailure("pack", err);
    }
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.didResolver.resolve(did);
  }
}
