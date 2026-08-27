import type { Unpacked } from "../didcomm/didcomm.js";
import { PROBLEM_REPORT } from "./problem-report.js";
import type { HandlerContext, Reply } from "./types.js";

/**
 * blob-store/1.0 — estoc `docs/blob-store.md`: an agent asks its own
 * mediator to keep (`put`) or delete (`delete`) a blob named by hash. The
 * bytes go over HTTP (`/b/<id>`, `src/blobs/service.ts`); these messages
 * only say what should exist. Both need a proven sender holding a mediation
 * here — this is a mediation service, not a public one.
 */

export const BLOB_PUT = "https://estoc.dev/blob-store/1.0/put";
export const BLOB_PUT_RESULT = "https://estoc.dev/blob-store/1.0/put-result";
export const BLOB_DELETE = "https://estoc.dev/blob-store/1.0/delete";
export const BLOB_DELETE_RESULT = "https://estoc.dev/blob-store/1.0/delete-result";

function refused(comment: string): Reply {
  return { type: PROBLEM_REPORT, body: { code: "e.p.blob.refused", comment } };
}

export async function blobPut(
  incoming: Unpacked,
  { store, blobs, sender }: HandlerContext
): Promise<Reply | null> {
  if (sender === null) {
    return null;
  }
  if (!(await store.isMediated(sender))) {
    return refused("no mediation");
  }
  if (blobs === null) {
    return refused("this mediator does not store blobs");
  }
  const outcome = await blobs.put(sender, incoming.message.body.hash, incoming.message.body.size);
  if (!outcome.ok) {
    return {
      type: PROBLEM_REPORT,
      body: { code: `e.p.blob.${outcome.code}`, comment: outcome.comment },
    };
  }
  return {
    type: BLOB_PUT_RESULT,
    body: {
      hash: outcome.hash,
      url: outcome.url,
      retain_until: new Date(outcome.retainUntil).toISOString(),
      ...(outcome.upload === null
        ? {}
        : {
            upload: {
              url: outcome.upload.url,
              expires: new Date(outcome.upload.expires).toISOString(),
            },
          }),
    },
  };
}

export async function blobDelete(
  incoming: Unpacked,
  { store, blobs, sender }: HandlerContext
): Promise<Reply | null> {
  if (sender === null) {
    return null;
  }
  if (!(await store.isMediated(sender))) {
    return refused("no mediation");
  }
  if (blobs === null) {
    return refused("this mediator does not store blobs");
  }
  const hash = await blobs.remove(sender, incoming.message.body.hash);
  if (hash === null) {
    return refused("hash is not a blob name");
  }
  return { type: BLOB_DELETE_RESULT, body: { hash } };
}
