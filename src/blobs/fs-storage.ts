import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import { BLOB_ID_PATTERN, blobDigest, bytesEqual } from "./hash.js";
import {
  blobHeaders,
  parseRange,
  unsatisfiable,
  type BlobStorage,
} from "./storage.js";

/**
 * The Node target's blob storage: one file per blob under a directory,
 * named by id, hashed while written to a temporary name and renamed into
 * place only if the bytes match. A blob file is never partially visible.
 */
export class FsBlobStorage implements BlobStorage {
  constructor(private dir: string) {}

  private path(id: string): string {
    return join(this.dir, id);
  }

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
    await mkdir(this.dir, { recursive: true });
    const temp = `${this.path(id)}.${crypto.randomUUID()}.part`;
    const digest = createHash("sha256");
    let seen = 0;
    let overflow = false;
    const counting = new Transform({
      transform(chunk: Buffer, _enc, done) {
        seen += chunk.length;
        if (seen > size) {
          overflow = true;
          done(new Error("more bytes than declared"));
          return;
        }
        digest.update(chunk);
        done(null, chunk);
      },
    });
    try {
      await pipeline(Readable.fromWeb(body as never), counting, createWriteStream(temp));
    } catch {
      await unlink(temp).catch(() => {});
      return "mismatch";
    }
    if (overflow || seen !== size || !bytesEqual(digest.digest(), expected)) {
      await unlink(temp).catch(() => {});
      return "mismatch";
    }
    await rename(temp, this.path(id));
    return "stored";
  }

  async get(id: string, range: string | null, head: boolean): Promise<Response | null> {
    if (!BLOB_ID_PATTERN.test(id)) {
      return null;
    }
    const path = this.path(id);
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch {
      return null;
    }
    const wanted = parseRange(range, size);
    if (wanted === "unsatisfiable") {
      return unsatisfiable(size);
    }
    if (wanted === null) {
      return new Response(
        head ? null : (Readable.toWeb(createReadStream(path)) as ReadableStream),
        { status: 200, headers: blobHeaders(size) }
      );
    }
    const length = wanted.end - wanted.start + 1;
    return new Response(
      head
        ? null
        : (Readable.toWeb(
            createReadStream(path, { start: wanted.start, end: wanted.end })
          ) as ReadableStream),
      {
        status: 206,
        headers: {
          ...blobHeaders(length),
          "content-range": `bytes ${wanted.start}-${wanted.end}/${size}`,
        },
      }
    );
  }

  async delete(id: string): Promise<void> {
    if (!BLOB_ID_PATTERN.test(id)) {
      return;
    }
    await unlink(this.path(id)).catch(() => {});
  }
}
