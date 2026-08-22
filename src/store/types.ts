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

/** Keeps every statement under SQLite's and D1's bound-parameter ceilings. */
export const SQL_CHUNK = 50;

export function chunked<T>(items: T[], size: number = SQL_CHUNK): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

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

/** An owner's current public-folder card. */
export interface StoredCard {
  /** The compact JWS, exactly as published. */
  card: string;
  /** The tree's root CID, or null for a takedown card. */
  root: string | null;
}

/*
 * Operator policy — the compliance layer's storage. A rule names one subject
 * (a DID or a CID) and what the relay does about it. Rules are operator
 * decisions, distinct in every way from an owner's takedown card: no protocol
 * event occurs, readers see the same responses absence produces.
 */

export type PolicyKind = "did" | "cid";

/**
 * `block` — refuse to serve (and, for a DID, to accept publishes), answering
 * exactly as if the subject did not exist; `legal` — the same refusal, but
 * HTTP reads may say so (451); `allow` — list the subject into a deployment
 * whose serve default is deny.
 */
export type PolicyMode = "allow" | "block" | "legal";

export interface PolicyRule {
  kind: PolicyKind;
  subject: string;
  mode: PolicyMode;
  /**
   * Epoch ms; while in the future, a `cid` rule's object survives the purge
   * even when nothing references it — quarantined evidence under a legal
   * preservation duty is frozen, never collected. Null = no hold.
   */
  holdUntil: number | null;
  /** Operator's own annotation (ticket number, report reference). */
  note: string | null;
  createdAt: number;
}

/** One line of the operator-action audit trail — the only compliance log. */
export interface PolicyAuditEntry {
  at: number;
  action: "set" | "clear";
  kind: PolicyKind;
  subject: string;
  mode: PolicyMode | null;
  holdUntil: number | null;
  note: string | null;
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

  /*
   * public-folder relay state: one current card per owner, a shared
   * content-addressed object pool, and reference rows tying each owner's
   * current publication closure to the objects it needs. Objects live
   * exactly as long as some closure references them (plus a staging grace
   * period for publishes still in flight) — refcounting, not policy.
   */

  /** The owner's current card, or null when this relay holds none. */
  getCard(ownerDid: string): Promise<StoredCard | null>;
  /**
   * Make this card the served version, atomically replacing the owner's
   * closure references with `closure` (every CID reachable from `root`;
   * empty for a takedown card, whose root is null).
   */
  putCard(
    ownerDid: string,
    cardJws: string,
    root: string | null,
    closure: string[]
  ): Promise<void>;
  /** Store an object under its CID; the caller has verified bytes hash to it. */
  putObject(cid: string, bytes: Uint8Array): Promise<void>;
  getObject(cid: string): Promise<Uint8Array | null>;
  /** Which of these CIDs are present, and their byte lengths. */
  objectsPresent(cids: string[]): Promise<Map<string, number>>;

  /**
   * Also drops unreferenced objects past the staging grace period — except
   * objects a `cid` policy rule holds (`hold_until` in the future).
   */
  purgeExpired(): Promise<number>;

  /*
   * Operator policy rules and their audit trail. Writes append to the audit
   * trail themselves, so no caller can change policy without leaving a line.
   */

  /** Upsert a rule (kind + subject is the identity). */
  setPolicyRule(rule: Omit<PolicyRule, "createdAt">): Promise<void>;
  /** Remove a rule; returns whether one existed. */
  clearPolicyRule(kind: PolicyKind, subject: string): Promise<boolean>;
  /** The rules covering these subjects, keyed by subject. */
  policyRules(kind: PolicyKind, subjects: string[]): Promise<Map<string, PolicyRule>>;
  listPolicyRules(): Promise<PolicyRule[]>;
  /** Most recent first. */
  policyAudit(limit: number): Promise<PolicyAuditEntry[]>;
  /** Owners whose current publication closure references this CID. */
  referencingOwners(cid: string): Promise<string[]>;
  /** Every CID the owner's current publication closure references. */
  closureOf(ownerDid: string): Promise<string[]>;

  close(): void;
}
