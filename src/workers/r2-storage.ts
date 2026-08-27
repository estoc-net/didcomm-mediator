import { blobDigest, hex } from "../blobs/hash.js";
import {
  blobHeaders,
  parseRange,
  unsatisfiable,
  type BlobStorage,
} from "../blobs/storage.js";

/**
 * The Workers target's blob storage: an R2 bucket, one object per blob under
 * its name. R2 checks the sha-256 itself on put (`sha256` option) and
 * refuses a mismatch, so the Worker streams the body through without
 * buffering; the declared size travels as a fixed-length stream so R2
 * knows the length up front.
 */
export class R2BlobStorage implements BlobStorage {
  constructor(private bucket: R2Bucket) {}

  async put(
    hash: string,
    size: number,
    body: ReadableStream<Uint8Array>
  ): Promise<"stored" | "mismatch"> {
    const expected = blobDigest(hash);
    if (expected === null) {
      return "mismatch";
    }
    const fixed = new FixedLengthStream(size);
    const piping = body.pipeTo(fixed.writable).catch(() => {});
    try {
      await this.bucket.put(hash, fixed.readable, { sha256: hex(expected) });
    } catch {
      await piping;
      return "mismatch";
    }
    await piping;
    return "stored";
  }

  async get(hash: string, range: string | null, head: boolean): Promise<Response | null> {
    if (blobDigest(hash) === null) {
      return null;
    }
    const meta = await this.bucket.head(hash);
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
      const object = await this.bucket.get(hash);
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
    const object = await this.bucket.get(hash, {
      range: { offset: wanted.start, length },
    });
    return object === null ? null : new Response(object.body, { status: 206, headers });
  }

  async delete(hash: string): Promise<void> {
    await this.bucket.delete(hash);
  }
}
