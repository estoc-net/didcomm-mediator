import type { Unpacked } from "../didcomm/didcomm.js";
import type { HandlerContext, Reply } from "./types.js";

/** trust-ping/2.0 — https://didcomm.org/trust-ping/2.0 */

export const PING = "https://didcomm.org/trust-ping/2.0/ping";
export const PING_RESPONSE = "https://didcomm.org/trust-ping/2.0/ping-response";

export function ping(
  incoming: Unpacked,
  { sender }: HandlerContext
): Reply | null {
  if (sender === null || incoming.message.body.response_requested === false) {
    return null;
  }
  return { type: PING_RESPONSE, body: {} };
}
