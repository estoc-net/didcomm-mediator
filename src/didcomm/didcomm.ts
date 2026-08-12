import { Message } from "didcomm-node";
import type {
  DIDResolver,
  IMessage,
  SecretsResolver,
  UnpackMetadata,
} from "didcomm-node";
import { resolveDIDCommDoc } from "./did-resolver.js";
import type { DIDDoc, Secret } from "@estoc/did-peer";

/**
 * Pack and unpack with the mediator's own identity.
 *
 * Unlike didcomm-http, where every call carries its own secrets, a mediator has
 * exactly one set — its own — and every envelope it opens or seals uses them.
 * The resolvers are built once and shared.
 */

/** The mediator's document first (never fetched), then the world. */
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

export interface Unpacked {
  message: IMessage;
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
}

export class DIDCommContext {
  private didResolver: DIDResolver;
  private secretsResolver: SecretsResolver;

  constructor(
    readonly did: string,
    didDoc: DIDDoc,
    secrets: Secret[]
  ) {
    this.didResolver = new ChainedResolver([didDoc]);
    this.secretsResolver = new InMemorySecretsResolver(secrets);
  }

  async unpack(packed: string): Promise<Unpacked> {
    const [msg, metadata] = await Message.unpack(
      packed,
      this.didResolver,
      this.secretsResolver,
      {}
    );

    const message = msg.as_value();
    return {
      message,
      metadata,
      from: message.from ?? null,
      verifiedFrom: didOf(metadata.encrypted_from_kid ?? metadata.sign_from),
    };
  }

  /**
   * Seal a message from the mediator to `to`.
   *
   * `forward: false` — replies go back on the return route or into the
   * recipient's own inbox here; wrapping them for yet another mediator would
   * assume an infrastructure DID is itself mediated, which this one is not.
   */
  async packEncrypted(message: IMessage, to: string): Promise<string> {
    const msg = new Message(message);
    const [packed] = await msg.pack_encrypted(
      to,
      this.did,
      null,
      this.didResolver,
      this.secretsResolver,
      { forward: false }
    );
    return packed;
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.didResolver.resolve(did);
  }
}
