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
