import type { Session, SessionRegistry } from "../protocols/types.js";

/**
 * The WebSocket connections currently open, indexed by the DID each one has
 * proven. A session joins the index on its first authenticated message and
 * leaves when the socket closes; live delivery consults the index, so a
 * closed socket stops receiving pushes by ceasing to exist.
 */
export class Sessions implements SessionRegistry {
  private byDid = new Map<string, Set<Session>>();

  bind(did: string, session: Session): void {
    const set = this.byDid.get(did) ?? new Set();
    set.add(session);
    this.byDid.set(did, set);
  }

  drop(did: string | null, session: Session): void {
    if (did === null) {
      return;
    }
    const set = this.byDid.get(did);
    if (set !== undefined) {
      set.delete(session);
      if (set.size === 0) {
        this.byDid.delete(did);
      }
    }
  }

  liveSessionsFor(did: string): Session[] {
    return [...(this.byDid.get(did) ?? [])].filter(
      (session) => session.liveDelivery
    );
  }
}
