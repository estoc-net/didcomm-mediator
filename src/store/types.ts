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

export interface RecipientPage {
  recipients: string[];
  /** Entries remaining after this page. */
  remaining: number;
}

export interface BlobInfo {
  hash: string;
  size: number;
  /** When the bytes arrived and were verified; null while still expected. */
  uploadedAt: number | null;
  /** The latest retention any mediation holds on it; 0 when nobody does. */
  retainUntil: number;
}

export interface UploadGrant {
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

  grantMediation(did: string): Promise<void>;
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

  /** Returns the stored message id, or null if the account is over quota. */
  storeMessage(ownerDid: string, packed: string): Promise<string | null>;
  messageCount(ownerDid: string): Promise<number>;
  messagesFor(ownerDid: string, limit: number): Promise<StoredMessage[]>;
  /** Deletes the named messages; returns the ids that existed and are gone. */
  deleteMessages(ownerDid: string, ids: string[]): Promise<string[]>;

  purgeExpired(): Promise<number>;

  /*
   * blob-store/1.0. A blob row is one set of bytes named by hash; a hold is
   * one mediation's claim on it until a time. Bytes and names are kept by a
   * BlobStorage; the store only knows what should exist.
   */
  blobInfo(hash: string): Promise<BlobInfo | null>;
  /** Bytes held by this mediation's live holds, uploaded or not. */
  blobUsage(ownerDid: string): Promise<number>;
  /** Creates the blob row if absent and sets (or extends) the owner's hold. */
  holdBlob(
    ownerDid: string,
    hash: string,
    size: number,
    retainUntil: number
  ): Promise<void>;
  /** Whether this mediation holds the blob right now (a live hold). */
  blobHeld(ownerDid: string, hash: string): Promise<boolean>;
  releaseBlob(ownerDid: string, hash: string): Promise<void>;
  /** A one-time upload token for the named blob, good until `expiresAt`. */
  grantUpload(hash: string, expiresAt: number): Promise<string>;
  /** The blob a live token names, consumed on read; null if unknown or expired. */
  claimUpload(token: string): Promise<UploadGrant | null>;
  markUploaded(hash: string): Promise<void>;
  /**
   * Drops expired holds and every blob nobody holds any more; returns the
   * hashes whose bytes should now be deleted from storage.
   */
  purgeBlobs(): Promise<string[]>;

  close(): void;
}
