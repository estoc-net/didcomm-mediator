import { createHash } from "node:crypto";

/**
 * out-of-band/2.0 — the invitation, as specified in the DIDComm v2 core spec
 * (https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages).
 *
 * The mediator only ever *issues* invitations; nothing here handles one
 * inbound, because an invitation travels as a URL, not as an envelope. The
 * invitation is a plaintext JWM, base64url-encoded into the `_oob` query
 * parameter of the public URL — the string a wallet scans from a QR code and
 * answers with a mediate-request (using the invitation `id` as pthid).
 */

export const OOB_INVITATION = "https://didcomm.org/out-of-band/2.0/invitation";

export interface Invitation {
  type: typeof OOB_INVITATION;
  id: string;
  typ: string;
  from: string;
  body: {
    goal_code: string;
    goal: string;
    accept: string[];
  };
}

export function buildInvitation(did: string): Invitation {
  return {
    type: OOB_INVITATION,
    // Derived from the DID so the invitation — and any QR code printed from
    // it — is the same on every boot of either runtime.
    id: createHash("sha256").update(did).digest("hex").slice(0, 32),
    typ: "application/didcomm-plain+json",
    from: did,
    body: {
      goal_code: "request-mediate",
      goal: "Request mediation from this DIDComm v2 mediator",
      accept: ["didcomm/v2"],
    },
  };
}

/** `<publicUrl>?_oob=<base64url plaintext>` — base64url needs no escaping. */
export function invitationUrl(publicUrl: string, invitation: Invitation): string {
  const url = new URL(publicUrl);
  url.searchParams.set(
    "_oob",
    Buffer.from(JSON.stringify(invitation)).toString("base64url")
  );
  return url.toString();
}
