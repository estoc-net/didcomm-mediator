import { isLongForm, longToShort } from "@estoc/did-peer";

import type { Unpacked } from "../didcomm/didcomm.js";
import type { HandlerContext, Reply } from "./types.js";

/**
 * coordinate-mediation/3.0 — https://didcomm.org/coordinate-mediation/3.0
 *
 * The account model is the DID itself: whoever proves a DID (authcrypt) and is
 * granted mediation *is* the account, and every recipient DID they bind routes
 * to it. Bindings are exclusive and first-come; the squat-resistance rules
 * below are lifted from the Affinidi fork, where they were earned one incident
 * at a time.
 */

export const MEDIATE_REQUEST =
  "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
export const MEDIATE_GRANT =
  "https://didcomm.org/coordinate-mediation/3.0/mediate-grant";
export const MEDIATE_DENY =
  "https://didcomm.org/coordinate-mediation/3.0/mediate-deny";
export const RECIPIENT_UPDATE =
  "https://didcomm.org/coordinate-mediation/3.0/recipient-update";
export const RECIPIENT_UPDATE_RESPONSE =
  "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response";
export const RECIPIENT_QUERY =
  "https://didcomm.org/coordinate-mediation/3.0/recipient-query";
export const RECIPIENT =
  "https://didcomm.org/coordinate-mediation/3.0/recipient";

const MAX_RECIPIENT_DID_LENGTH = 2048;
const QUERY_PAGE_LIMIT = 100;

/**
 * Whether `did` is one of the mediator's own names in any spelling — every
 * active DID, plus the short form of a long-form did:peer:4, which hashes to
 * the same document and must be just as unbindable.
 */
function isMediatorOwnDid(did: string, mediatorDids: string[]): boolean {
  return mediatorDids.some(
    (own) => own === did || (isLongForm(own) && longToShort(own) === did)
  );
}

export async function mediateRequest(
  incoming: Unpacked,
  { ctx, store, config, sender }: HandlerContext
): Promise<Reply> {
  if (sender === null) {
    return { type: MEDIATE_DENY, body: {} };
  }

  if (!config.openRegistration && !(await store.isMediated(sender))) {
    return { type: MEDIATE_DENY, body: {} };
  }

  await store.grantMediation(sender);
  // The spec's routing_did is an array — 3.0 renamed and pluralized it.
  // Grant the DID the client addressed: that is the one its resolver speaks.
  return {
    type: MEDIATE_GRANT,
    body: { routing_did: [ctx.asOwnDid(incoming.addressedTo)] },
  };
}

interface Update {
  recipient_did: string;
  action: string;
}

function updates(body: Record<string, unknown>): Update[] {
  if (!Array.isArray(body.updates)) {
    return [];
  }
  return body.updates.filter(
    (entry): entry is Update =>
      entry !== null &&
      typeof entry === "object" &&
      typeof entry.recipient_did === "string" &&
      typeof entry.action === "string"
  );
}

/**
 * Why an add would be refused, or null if it is allowed.
 *
 * A recipient DID is a claim on someone else's inbound mail, so adding one is
 * gated harder than reading anything: it must look like a DID at all, must not
 * be the mediator (whose DID routes to nobody's inbox), and must not be a DID
 * that holds its own account here — the true controller proved that DID with
 * its private key, and a squatter must not be able to divert their mail.
 * Registering *after* the squat is covered on the forward path, which prefers
 * a local account over any binding unconditionally.
 */
async function addDenialReason(
  recipientDid: string,
  sender: string,
  context: HandlerContext
): Promise<string | null> {
  if (!recipientDid.startsWith("did:")) {
    return "not a DID";
  }
  if (recipientDid.length > MAX_RECIPIENT_DID_LENGTH) {
    return "DID too long";
  }
  if (isMediatorOwnDid(recipientDid, context.ctx.dids)) {
    return "cannot bind the mediator's own DID";
  }
  if (recipientDid !== sender && (await context.store.isMediated(recipientDid))) {
    return "DID holds its own account here";
  }
  return null;
}

export async function recipientUpdate(
  incoming: Unpacked,
  context: HandlerContext
): Promise<Reply | null> {
  const { store, sender } = context;
  if (sender === null || !(await store.isMediated(sender))) {
    return null;
  }

  const updated = [];
  for (const { recipient_did, action } of updates(incoming.message.body)) {
    if (action === "add") {
      if ((await addDenialReason(recipient_did, sender, context)) !== null) {
        updated.push({ recipient_did, action, result: "client_error" });
        continue;
      }
      const result = await store.addRecipient(sender, recipient_did);
      updated.push({
        recipient_did,
        action,
        result:
          result === "added"
            ? "success"
            : result === "already-yours"
              ? "no_change"
              : "client_error",
      });
      continue;
    }

    if (action === "remove") {
      updated.push({
        recipient_did,
        action,
        result: (await store.removeRecipient(sender, recipient_did))
          ? "success"
          : "no_change",
      });
      continue;
    }

    updated.push({ recipient_did, action, result: "client_error" });
  }

  return { type: RECIPIENT_UPDATE_RESPONSE, body: { updated } };
}

export async function recipientQuery(
  incoming: Unpacked,
  { store, sender }: HandlerContext
): Promise<Reply | null> {
  if (sender === null || !(await store.isMediated(sender))) {
    return null;
  }

  const paginate =
    incoming.message.body.paginate !== null &&
    typeof incoming.message.body.paginate === "object"
      ? (incoming.message.body.paginate as Record<string, unknown>)
      : {};
  const offset =
    typeof paginate.offset === "number" && paginate.offset > 0
      ? Math.floor(paginate.offset)
      : 0;
  const limit =
    typeof paginate.limit === "number" && paginate.limit > 0
      ? Math.min(Math.floor(paginate.limit), QUERY_PAGE_LIMIT)
      : QUERY_PAGE_LIMIT;

  const page = await store.listRecipients(sender, offset, limit);

  return {
    type: RECIPIENT,
    body: {
      dids: page.recipients.map((did) => ({ recipient_did: did })),
      pagination: {
        count: page.recipients.length,
        offset,
        remaining: page.remaining,
      },
    },
  };
}
