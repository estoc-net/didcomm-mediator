import type { MediatorPolicy } from "../config.js";
import type { MediationStore } from "../store/types.js";
import { BLOB_NAME_PATTERN, mintBlobId } from "./hash.js";
import type { BlobStorage } from "./storage.js";

/** How long an upload grant stays good: one hour is plenty for one PUT. */
const UPLOAD_GRANT_MS = 60 * 60 * 1000;

export type PutOutcome =
  | {
      ok: true;
      hash: string;
      url: string;
      retainUntil: number;
      upload: { url: string; expires: number } | null;
    }
  | { ok: false; code: "too-large" | "quota" | "refused"; comment: string };

/**
 * blob-store/1.0, the store side (`docs/blob-store.md` in estoc): rows and
 * quotas in the database, bytes in a BlobStorage under a random id, URLs
 * under this mediator's public URL. A blob is one mediation's: put by it,
 * served at its own `/b/<id>`, gone when it deletes it or the retention
 * runs out — nothing is shared or deduplicated between mediations. The
 * protocol handlers and the HTTP routes both come here; nothing else
 * touches blobs.
 */
export class BlobService {
  constructor(
    private store: MediationStore,
    private storage: BlobStorage,
    private policy: Pick<
      MediatorPolicy,
      "blobRetainSeconds" | "blobMaxBytes" | "blobQuotaBytes"
    >,
    private publicUrl: string
  ) {}

  url(id: string): string {
    return `${this.publicUrl.replace(/\/$/, "")}/b/${id}`;
  }

  /** The limits, for GET / and for a client that would rather know first. */
  limits() {
    return {
      retainSeconds: this.policy.blobRetainSeconds,
      maxBytes: this.policy.blobMaxBytes,
      quotaBytes: this.policy.blobQuotaBytes,
    };
  }

  async put(ownerDid: string, hash: unknown, size: unknown): Promise<PutOutcome> {
    if (typeof hash !== "string" || !BLOB_NAME_PATTERN.test(hash)) {
      return { ok: false, code: "refused", comment: "hash is not a blob name" };
    }
    if (typeof size !== "number" || !Number.isInteger(size) || size < 0) {
      return { ok: false, code: "refused", comment: "size must be a byte count" };
    }
    if (size > this.policy.blobMaxBytes) {
      return {
        ok: false,
        code: "too-large",
        comment: `blobs are at most ${this.policy.blobMaxBytes} bytes`,
      };
    }
    const existing = await this.store.blobOf(ownerDid, hash);
    if (existing !== null && existing.size !== size) {
      return { ok: false, code: "refused", comment: "size differs from the stored blob" };
    }
    // A renewal adds nothing to the mediation's usage; a new blob adds its
    // whole size, uploaded or not.
    if (existing === null) {
      const usage = await this.store.blobUsage(ownerDid);
      if (usage + size > this.policy.blobQuotaBytes) {
        return {
          ok: false,
          code: "quota",
          comment: `this mediation may hold ${this.policy.blobQuotaBytes} bytes; ${usage} held`,
        };
      }
    }

    const now = Date.now();
    const retainUntil = now + this.policy.blobRetainSeconds * 1000;
    const id = existing?.id ?? mintBlobId();
    await this.store.keepBlob(id, ownerDid, hash, size, retainUntil);

    let upload: { url: string; expires: number } | null = null;
    if (existing === null || existing.uploadedAt === null) {
      const expires = now + UPLOAD_GRANT_MS;
      const token = await this.store.grantUpload(id, expires);
      upload = { url: `${this.url(id)}?token=${token}`, expires };
    }
    return { ok: true, hash, url: this.url(id), retainUntil, upload };
  }

  /** Deletes the mediation's blob for the hash, bytes and all; null if the hash is not a blob name. */
  async remove(ownerDid: string, hash: unknown): Promise<string | null> {
    if (typeof hash !== "string" || !BLOB_NAME_PATTERN.test(hash)) {
      return null;
    }
    const id = await this.store.dropBlob(ownerDid, hash);
    if (id !== null) {
      await this.storage.delete(id);
    }
    return hash;
  }

  /**
   * The upload: one PUT of exactly the declared bytes under a live token.
   * 404 for an unknown or spent token, 400 for a body that is not the blob.
   */
  async upload(id: string, token: string, request: Request): Promise<Response> {
    const grant = await this.store.claimUpload(token);
    if (grant === null || grant.id !== id) {
      return new Response("no such upload", { status: 404 });
    }
    const declared = Number(request.headers.get("content-length"));
    if (!Number.isInteger(declared) || declared !== grant.size) {
      return new Response(`expected ${grant.size} bytes`, { status: 400 });
    }
    const body = request.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() });
    const outcome = await this.storage.put(id, grant.hash, grant.size, body);
    if (outcome !== "stored") {
      return new Response("bytes do not match the name", { status: 400 });
    }
    await this.store.markUploaded(id);
    return new Response(null, { status: 204 });
  }

  /** GET / HEAD of a blob that is uploaded and still retained. */
  async serve(id: string, range: string | null, head: boolean): Promise<Response> {
    const info = await this.store.blobById(id);
    if (info === null || info.uploadedAt === null || info.retainUntil <= Date.now()) {
      return new Response("no such blob", { status: 404 });
    }
    return (await this.storage.get(id, range, head)) ?? new Response("no such blob", { status: 404 });
  }

  /** Drops what has expired or lost its mediation; returns how many blobs went. */
  async purge(): Promise<number> {
    const gone = await this.store.purgeBlobs();
    for (const id of gone) {
      await this.storage.delete(id);
    }
    return gone.length;
  }
}
