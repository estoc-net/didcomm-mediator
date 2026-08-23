import type { Unpacked } from "../didcomm/didcomm.js";
import type { HandlerContext, Reply } from "./types.js";

/** discover-features/2.0 — https://didcomm.org/discover-features/2.0 */

export const QUERIES = "https://didcomm.org/discover-features/2.0/queries";
export const DISCLOSE = "https://didcomm.org/discover-features/2.0/disclose";

export const SUPPORTED_PROTOCOLS = [
  "https://didcomm.org/coordinate-mediation/3.0",
  "https://didcomm.org/messagepickup/3.0",
  "https://didcomm.org/routing/2.0",
  "https://didcomm.org/discover-features/2.0",
  "https://didcomm.org/trust-ping/2.0",
];

/**
 * The spec calls `match` a regex, but every match in the wild is a literal or
 * a prefix ending in `*` or `.*` — so those are what is honored, and an
 * actual regex is treated as the literal string it is. Running a
 * counterparty's regex would hand anonymous senders a ReDoS.
 */
function matches(pattern: string, id: string): boolean {
  const star = pattern.endsWith(".*")
    ? pattern.slice(0, -2)
    : pattern.endsWith("*")
      ? pattern.slice(0, -1)
      : null;

  return star !== null ? id.startsWith(star) : id === pattern;
}

export function queries(
  incoming: Unpacked,
  _context: HandlerContext
): Reply {
  const asked: unknown[] = Array.isArray(incoming.message.body.queries)
    ? incoming.message.body.queries
    : [];

  const protocolQueries = asked
    .filter(
      (query): query is Record<string, unknown> =>
        query !== null && typeof query === "object"
    )
    .filter(
      (query): query is { match: string } =>
        query["feature-type"] === "protocol" && typeof query.match === "string"
    );

  const disclosures = SUPPORTED_PROTOCOLS.filter((id) =>
    protocolQueries.some((query) => matches(query.match, id))
  ).map((id) => ({ "feature-type": "protocol", id }));

  return { type: DISCLOSE, body: { disclosures } };
}
