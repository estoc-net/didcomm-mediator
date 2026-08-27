import { BLOB_ID_PATTERN, blobDigest, hex } from "../blobs/hash.js";
import {
  blobHeaders,
  parseRange,
  unsatisfiable,
  type BlobStorage,
} from "../blobs/storage.js";

/**
 * The Workers target's blob storage: an R2 bucket, one object per blob under
 * its id. R2 checks the sha-256 itself on put (`sha256` option) and
 * refuses a mismatch, so the Worker streams the body through without
 * buffering; the declared size travels as a fixed-length stream so R2
 * knows the length up front.
 */
export class R2BlobStorage implements BlobStorage {
  constructor(private bucket: R2Bucket) {}

  async put(
    id: string,
    hash: string,
    size: number,
    body: ReadableStream<Uint8Array>
  ): Promise<"stored" | "mismatch"> {
    const expected = blobDigest(hash);
    if (expected === null || !BLOB_ID_PATTERN.test(id)) {
      return "mismatch";
    }
    const fixed = new FixedLengthStream(size);
    const piping = body.pipeTo(fixed.writable).catch(() => {});
    try {
      await this.bucket.put(id, fixed.readable, { sha256: hex(expected) });
    } catch {
      await piping;
      return "mismatch";
    }
    await piping;
    return "stored";
  }

  async get(id: string, range: string | null, head: boolean): Promise<Response | null> {
    if (!BLOB_ID_PATTERN.test(id)) {
      return null;
    }
    const meta = await this.bucket.head(id);
    if (meta === null) {
      return null;
    }
    const size = meta.size;
    const wanted = parseRange(range, size);
    if (wanted === "unsatisfiable") {
      return unsatisfiable(size);
    }
    if (wanted === null) {
      if (head) {
        return new Response(null, { status: 200, headers: blobHeaders(size) });
      }
      const object = await this.bucket.get(id);
      return object === null
        ? null
        : new Response(object.body, { status: 200, headers: blobHeaders(size) });
    }
    const length = wanted.end - wanted.start + 1;
    const headers = {
      ...blobHeaders(length),
      "content-range": `bytes ${wanted.start}-${wanted.end}/${size}`,
    };
    if (head) {
      return new Response(null, { status: 206, headers });
    }
    const object = await this.bucket.get(id, {
      range: { offset: wanted.start, length },
    });
    return object === null ? null : new Response(object.body, { status: 206, headers });
  }

  async delete(id: string): Promise<void> {
    if (!BLOB_ID_PATTERN.test(id)) {
      return;
    }
    await this.bucket.delete(id);
  }
}
