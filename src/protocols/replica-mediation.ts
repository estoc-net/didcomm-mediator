import { isPeerDID4 } from "@estoc/did-peer";

import type { MediatorPolicy } from "../config.js";
import type { Unpacked } from "../didcomm/didcomm.js";
import type { HandlerContext, Reply } from "./types.js";
import { isMediatorOwnDid } from "./coordinate-mediation.js";
import { DELIVERY_PAGE_LIMIT } from "./pickup.js";
import { REPLICA_MEDIATION_PROTOCOL } from "./discover-features.js";
import { PROBLEM_REPORT } from "./problem-report.js";
import { canonicalDid, verifyReplicaGrant } from "./replica-grant.js";

/**
 * replica-mediation/1.0 — https://estoc.dev/replica-mediation/1.0
 *
 * An account here is a vault's standalone mediation arrangement: the account
 * DID manages it and never picks up mail, and each replica it enrolls is a
 * DID of its own that will. Enrollment is append-only. These accounts share
 * nothing with coordinate-mediation's: a DID is one kind or the other, and
 * neither protocol's controls reach the other's state.
 */

export const REGISTER = `${REPLICA_MEDIATION_PROTOCOL}/register`;
export const REGISTERED = `${REPLICA_MEDIATION_PROTOCOL}/registered`;
export const LIST = `${REPLICA_MEDIATION_PROTOCOL}/list`;
export const REPLICAS = `${REPLICA_MEDIATION_PROTOCOL}/replicas`;

type Problem =
  | "invalid-message"
  | "invalid-grant"
  | "account-refused"
  | "unknown-account"
  | "identity-conflict"
  | "replica-required"
  | "quota";

export function replicaProblem(problem: Problem): Reply {
  return {
    type: PROBLEM_REPORT,
    body: { code: `e.estoc.replica-mediation.${problem}` },
  };
}

export function replicaLimits(policy: MediatorPolicy): Record<string, number> {
  return {
    message_retention_seconds: policy.messageTtlSeconds,
    max_message_bytes: policy.maxMessageBytes,
    max_active_replicas: policy.maxActiveReplicas,
    max_membership_page: policy.maxMembershipPage,
    max_shared_recipients: policy.maxSharedRecipients,
    max_retained_bytes: policy.maxRetainedBytes,
    max_retained_messages: policy.maxMessagesPerAccount,
    max_deliveries_per_request: DELIVERY_PAGE_LIMIT,
  };
}

interface Control {
  /** The authenticated account DID, in its short form when it is a did:peer:4. */
  account: string;
  /** The one mediator DID the request named and was sealed to, as it spelled it. */
  addressed: string;
  /** That DID in its short form when it is a did:peer:4. */
  mediator: string;
  body: Record<string, unknown>;
}

/**
 * A control request as what it proved: authcrypted by the DID its plaintext
 * names, to exactly one of this mediator's DIDs, with a body of exactly
 * `fields`. Null when it is not that.
 */
function controlOf(
  incoming: Unpacked,
  { ctx, sender }: HandlerContext,
  fields: string[]
): Control | null {
  const { message, metadata, addressedTo } = incoming;
  if (
    sender === null ||
    metadata.encrypted !== true ||
    metadata.authenticated !== true ||
    !metadata.encrypted_from_kid ||
    typeof message.from !== "string" ||
    canonicalDid(message.from) !== canonicalDid(sender) ||
    addressedTo === null ||
    !ctx.dids.includes(addressedTo) ||
    message.to?.length !== 1 ||
    message.to[0] !== addressedTo
  ) {
    return null;
  }

  const names = Object.keys(message.body).sort();
  if (names.join() !== [...fields].sort().join()) {
    return null;
  }
  return {
    account: canonicalDid(sender),
    addressed: addressedTo,
    mediator: canonicalDid(addressedTo),
    body: message.body,
  };
}

export async function register(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  const { ctx, store, config, sender } = context;
  if (sender === null) {
    return null;
  }
  const control = controlOf(incoming, context, ["grant"]);
  if (control === null) {
    return replicaProblem("invalid-message");
  }

  // The account's document is the one that opened the envelope: its long
  // form on first contact, or the one kept from that contact afterwards.
  const accountDoc = isPeerDID4(sender) ? await ctx.resolve(sender) : null;
  const grant = accountDoc === null ? null : await verifyReplicaGrant(control.body.grant, accountDoc);
  if (
    accountDoc === null ||
    grant === null ||
    grant.account !== control.account ||
    grant.mediator !== control.mediator ||
    isMediatorOwnDid(grant.account, ctx.dids) ||
    isMediatorOwnDid(grant.replicaDid, ctx.dids)
  ) {
    return replicaProblem("invalid-grant");
  }

  const accountLongForm =
    sender === control.account ? await store.resolutionMaterial(sender) : sender;
  if (accountLongForm === null) {
    return replicaProblem("invalid-grant");
  }

  const registration = await store.registerReplica({
    accountDid: grant.account,
    accountLongForm,
    mediationId: grant.mediationId,
    mediator: grant.mediator,
    replicaId: grant.replicaId,
    replicaDid: grant.replicaDid,
    replicaLongForm: grant.replicaLongForm,
    grant: control.body.grant as string,
    createAccount: config.openRegistration,
    maxReplicas: config.maxActiveReplicas,
  });

  switch (registration.outcome) {
    case "refused":
      return replicaProblem("account-refused");
    case "conflict":
      return replicaProblem("identity-conflict");
    case "full":
      return replicaProblem("quota");
    case "registered":
      return {
        type: REGISTERED,
        body: {
          account: grant.account,
          mediation_id: grant.mediationId,
          routing_did: control.addressed,
          replica_id: grant.replicaId,
          replica_did: grant.replicaDid,
          state: "active",
          registered_time: registration.registeredTime,
          limits: replicaLimits(config),
        },
      };
  }
}

/**
 * Where a listing stands: the account it is of, how many replicas the roster
 * held when the listing began, and the last one already returned. Enrollment
 * only appends, so the first `through` replicas are the same roster for as
 * long as the account lives and a listing never expires.
 */
interface Cursor {
  account: string;
  through: number;
  after: number;
}

function writeCursor(cursor: Cursor): string {
  return Buffer.from(JSON.stringify([cursor.account, cursor.through, cursor.after])).toString(
    "base64url"
  );
}

function readCursor(text: string): Cursor | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(text, "base64url").toString());
  } catch {
    return null;
  }
  if (!Array.isArray(parsed) || parsed.length !== 3) {
    return null;
  }
  const [account, through, after] = parsed as unknown[];
  if (
    typeof account !== "string" ||
    !Number.isSafeInteger(through) ||
    !Number.isSafeInteger(after) ||
    (after as number) < 1 ||
    (after as number) >= (through as number)
  ) {
    return null;
  }
  return { account, through: through as number, after: after as number };
}

export async function list(incoming: Unpacked, context: HandlerContext): Promise<Reply | null> {
  const { store, config, sender } = context;
  if (sender === null) {
    return null;
  }
  const control = controlOf(incoming, context, ["cursor", "limit"]);
  if (control === null) {
    return replicaProblem("invalid-message");
  }

  const { cursor: written, limit } = control.body;
  const cursor = typeof written === "string" ? readCursor(written) : null;
  if (
    (written !== null && (cursor === null || cursor.account !== control.account)) ||
    !Number.isSafeInteger(limit) ||
    (limit as number) < 1 ||
    (limit as number) > config.maxMembershipPage
  ) {
    return replicaProblem("invalid-message");
  }

  const roster = await store.replicaRoster(
    control.account,
    control.mediator,
    cursor?.after ?? 0,
    cursor?.through ?? null,
    limit as number
  );
  if (roster === null) {
    return replicaProblem("unknown-account");
  }
  const through = cursor?.through ?? roster.size;
  if (through > roster.size) {
    return replicaProblem("invalid-message");
  }

  const last = roster.entries.at(-1)?.ordinal ?? through;
  return {
    type: REPLICAS,
    body: {
      entries: roster.entries.map((entry) => ({
        grant: entry.grant,
        state: "active",
        registered_time: entry.registeredTime,
      })),
      next_cursor:
        last < through ? writeCursor({ account: control.account, through, after: last }) : null,
    },
  };
}
