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

export interface MediationStore {
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
  close(): void;
}
