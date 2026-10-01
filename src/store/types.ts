/**
 * What a mediator remembers: who it mediates for, which recipient DIDs route
 * to whom, and the messages waiting to be picked up.
 *
 * An account is a DID that asked for mediation and was granted it — existence
 * of the row is the grant. A keylist entry binds a recipient DID to exactly
 * one owner account; the binding is exclusive, first-come, and the ownership
 * checks live in the protocol layer, not here.
 *
 * Every method is async because the least capable backend sets the contract:
 * Cloudflare D1 has no synchronous API, and the protocol layer is shared.
 */

export type AddRecipientResult = "added" | "already-yours" | "taken";

export interface StoredMessage {
  id: string;
  packed: string;
  createdAt: number;
}

/**
 * What names one forwarded package in an account's queue: the recipient the
 * forward named and the forward's own id. A sender retrying a call repeats
 * both, which is how the retry is told from new mail.
 */
export interface PackageKey {
  next: string;
  forwardId: string;
}

/**
 * `repeated`: the key already holds these exact bytes, and nothing changed.
 * `conflict`: the key holds other bytes, which stay. `full`: the account is
 * at its quota. Nothing is written in any of the three.
 */
export type StoreOutcome =
  | { outcome: "stored"; message: StoredMessage }
  | { outcome: "repeated" | "conflict" | "full" };

/**
 * One replica's enrollment in a replica-mediation account. Both DIDs are
 * did:peer:4 short forms; the long forms are what resolves them later.
 */
export interface ReplicaRegistration {
  accountDid: string;
  accountLongForm: string;
  mediationId: string;
  replicaId: string;
  replicaDid: string;
  replicaLongForm: string;
  grant: string;
  /** Whether an absent account may be created by this registration. */
  createAccount: boolean;
  maxReplicas: number;
}

/**
 * `registered` also answers an exact repeat, with the time of the first.
 * `refused`: the account is absent and may not be created. `conflict`: an ID
 * or DID is already bound otherwise, here or under ordinary mediation.
 * `full`: the account is at its replica limit. Only `registered` wrote
 * anything, and it wrote the account and the replica together or neither.
 */
export type RegisterOutcome =
  | { outcome: "registered"; registeredTime: number }
  | { outcome: "refused" | "conflict" | "full" };

export interface RosterEntry {
  /** The replica's place in the order its account enrolled them, from 1. */
  ordinal: number;
  grant: string;
  registeredTime: number;
}

export interface RosterPage {
  /** How many replicas the account holds now. */
  size: number;
  entries: RosterEntry[];
}

export interface RecipientPage {
  recipients: string[];
  /** Entries remaining after this page. */
  remaining: number;
}

export interface BlobRow {
  /** where the bytes are served: `/b/<id>` — random, unrelated to the hash */
  id: string;
  /** the mediation that put it; the only one that can delete it */
  ownerDid: string;
  hash: string;
  size: number;
  /** When the bytes arrived and were verified; null while still expected. */
  uploadedAt: number | null;
  retainUntil: number;
}

export interface UploadGrant {
  id: string;
  hash: string;
  size: number;
}

export interface MediationStore {
  /**
   * The mediator's stored identity secrets as JSON, or null before first
   * mint. The identity lives in the same database as everything else on
   * purpose: one file (or one D1 database) is the whole mediator.
   */
  loadIdentity(): Promise<string | null>;
  /**
   * Store the secrets unless a row already exists, and return the row that
   * won — insert-if-absent, so concurrent first contacts all end up holding
   * the same keys no matter whose mint got there first.
   */
  initIdentity(secretsJson: string): Promise<string>;

  /**
   * Grants `did` an ordinary account unless it is a replica-mediation
   * account or replica; whether it holds an ordinary account afterwards.
   */
  grantMediation(did: string): Promise<boolean>;
  revokeMediation(did: string): Promise<void>;
  isMediated(did: string): Promise<boolean>;

  addRecipient(ownerDid: string, recipientDid: string): Promise<AddRecipientResult>;
  removeRecipient(ownerDid: string, recipientDid: string): Promise<boolean>;
  listRecipients(
    ownerDid: string,
    offset: number,
    limit: number
  ): Promise<RecipientPage>;
  /** The account a recipient DID routes to, if any. */
  ownerOf(recipientDid: string): Promise<string | null>;

  /*
   * replica-mediation/1.0. An account and its replicas are append-only, and
   * their DIDs are kept apart from ordinary accounts and recipients in both
   * directions: neither kind of binding can be made over the other.
   */
  registerReplica(registration: ReplicaRegistration): Promise<RegisterOutcome>;
  /** Whether `did` is a replica-mediation account. */
  isReplicaAccount(did: string): Promise<boolean>;
  /**
   * The account's replicas with an ordinal after `after` and up to `through`
   * (its current size when null), oldest first; null without such an account.
   */
  replicaRoster(
    accountDid: string,
    after: number,
    through: number | null,
    limit: number
  ): Promise<RosterPage | null>;
  /** The long form of a replica-mediation account or replica DID, if `did` is one. */
  resolutionMaterial(did: string): Promise<string | null>;

  /** Queues `packed` under its key, once: the first bytes a key is given are the ones it keeps. */
  storeMessage(ownerDid: string, key: PackageKey, packed: string): Promise<StoreOutcome>;
  messageCount(ownerDid: string): Promise<number>;
  messagesFor(ownerDid: string, limit: number): Promise<StoredMessage[]>;
  /** Deletes the named messages; returns the ids that existed and are gone. */
  deleteMessages(ownerDid: string, ids: string[]): Promise<string[]>;

  purgeExpired(): Promise<number>;

  /*
   * blob-store/1.0. A blob row is one mediation's bytes: (owner, hash) is
   * unique, and nothing is shared between mediations — the same hash put by
   * two of them is two rows, two ids, two uploads. Bytes are kept by a
   * BlobStorage under the id; the store only knows what should exist.
   */
  blobOf(ownerDid: string, hash: string): Promise<BlobRow | null>;
  blobById(id: string): Promise<BlobRow | null>;
  /** Bytes of this mediation's live blobs, uploaded or not. */
  blobUsage(ownerDid: string): Promise<number>;
  /** Creates the row if absent (under `id`), else extends its retention; never shortens it. */
  keepBlob(
    id: string,
    ownerDid: string,
    hash: string,
    size: number,
    retainUntil: number
  ): Promise<void>;
  /** Removes the mediation's blob for the hash; returns its id (bytes to delete) or null if there was none. */
  dropBlob(ownerDid: string, hash: string): Promise<string | null>;
  /** A one-time upload token for the blob, good until `expiresAt`. */
  grantUpload(id: string, expiresAt: number): Promise<string>;
  /** The blob a live token names, consumed on read; null if unknown or expired. */
  claimUpload(token: string): Promise<UploadGrant | null>;
  markUploaded(id: string): Promise<void>;
  /**
   * Drops every blob past its retention or whose mediation has ended, and
   * expired tokens; returns the ids whose bytes should now be deleted.
   */
  purgeBlobs(): Promise<string[]>;

  close(): void;
}
