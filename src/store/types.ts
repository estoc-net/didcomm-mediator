/**
 * What a mediator remembers: who it mediates for, which recipient DIDs route
 * to whom, and the messages waiting to be picked up.
 *
 * An account is a DID that asked for mediation and was granted it — existence
 * of the row is the grant. A keylist entry binds a recipient DID to exactly
 * one owner account; the binding is exclusive, first-come, and the ownership
 * checks live in the protocol layer, not here.
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
  grantMediation(did: string): void;
  revokeMediation(did: string): void;
  isMediated(did: string): boolean;

  addRecipient(ownerDid: string, recipientDid: string): AddRecipientResult;
  removeRecipient(ownerDid: string, recipientDid: string): boolean;
  listRecipients(ownerDid: string, offset: number, limit: number): RecipientPage;
  /** The account a recipient DID routes to, if any. */
  ownerOf(recipientDid: string): string | null;

  /** Returns the stored message id, or null if the account is over quota. */
  storeMessage(ownerDid: string, packed: string): string | null;
  messageCount(ownerDid: string): number;
  messagesFor(ownerDid: string, limit: number): StoredMessage[];
  /** Deletes the named messages; returns the ids that existed and are gone. */
  deleteMessages(ownerDid: string, ids: string[]): string[];

  purgeExpired(): number;
  close(): void;
}
