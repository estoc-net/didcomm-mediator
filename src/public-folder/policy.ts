import type { MediatorPolicy } from "../config.js";
import type { MediationStore } from "../store/types.js";

/**
 * Operator serve policy — the compliance layer's one enforcement primitive
 * (spec §4.1: a relay MAY refuse to store or serve anything; §7 sketches the
 * intended uses). Rules name a DID or a CID. `block` hides the subject behind
 * exactly the responses absence produces — an operator removal is not a
 * protocol event, and no reader can tell it from nothing-there (no tipping
 * off). `legal` is the same refusal where HTTP reads may say so (451).
 * `allow` lists a subject into a deployment whose serve default is deny —
 * blocklist and allowlist are one mechanism with the default inverted
 * (`serveDefault`).
 *
 * DIDComm and HTTP reads funnel through the same two decisions here; the
 * browse-domain gateway is a pure forwarder of the HTTP reads and needs no
 * code of its own.
 */

export type ServeDecision = "ok" | "hidden" | "legal";

/**
 * May these DIDs' cards and trees be served (or their publishes accepted)?
 * `hidden` dominates `legal`: when any subject must be indistinguishable
 * from absent, saying less is always safe.
 */
export async function didDecision(
  store: MediationStore,
  config: MediatorPolicy,
  dids: string[]
): Promise<ServeDecision> {
  const rules = await store.policyRules("did", dids);
  let decision: ServeDecision = "ok";
  for (const did of dids) {
    const mode = rules.get(did)?.mode;
    if (mode === "block") {
      return "hidden";
    }
    if (mode === "legal") {
      decision = "legal";
    }
    if (mode === undefined && config.publicationServeDefault === "deny") {
      return "hidden";
    }
  }
  return decision;
}

export interface CidDecision {
  decision: ServeDecision;
  /** The first CID the decision hinges on, when it is not "ok". */
  cid: string | null;
}

/**
 * May these objects be served? `ownerCleared` marks CIDs reached through a
 * DID that already passed `didDecision` (the query path), which under a
 * deny default spares the reference walk; a bare CID read (HTTP) instead
 * needs some referencing owner to be servable.
 */
export async function cidDecision(
  store: MediationStore,
  config: MediatorPolicy,
  cids: string[],
  options: { ownerCleared?: boolean } = {}
): Promise<CidDecision> {
  const rules = await store.policyRules("cid", cids);
  let legal: string | null = null;
  for (const cid of cids) {
    const mode = rules.get(cid)?.mode;
    if (mode === "block") {
      return { decision: "hidden", cid };
    }
    if (mode === "legal") {
      legal = legal ?? cid;
      continue;
    }
    if (
      mode === undefined &&
      config.publicationServeDefault === "deny" &&
      options.ownerCleared !== true
    ) {
      const owners = await store.referencingOwners(cid);
      let served = false;
      for (const owner of owners) {
        if ((await didDecision(store, config, [owner])) === "ok") {
          served = true;
          break;
        }
      }
      if (!served) {
        return { decision: "hidden", cid };
      }
    }
  }
  return legal === null
    ? { decision: "ok", cid: null }
    : { decision: "legal", cid: legal };
}

/**
 * Is publishing barred for any of these DIDs? Distinct from serving: a
 * deny-default relay still accepts publishes from its mediation clients
 * (serving is what the default gates), but a blocked DID's publish is
 * refused so the content never lands.
 */
export async function publishBarred(
  store: MediationStore,
  dids: string[]
): Promise<boolean> {
  const rules = await store.policyRules("did", dids);
  for (const rule of rules.values()) {
    if (rule.mode === "block" || rule.mode === "legal") {
      return true;
    }
  }
  return false;
}
