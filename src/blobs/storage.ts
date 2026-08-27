/**
 * Where blob bytes live. The store's database knows the names, sizes, holds
 * and retentions; this is only the bytes under a name. Two backends: a
 * directory on Node, an R2 bucket on Workers.
 *
 * `put` is the one place bytes are checked against their name: it consumes
 * the whole body, and stores it only if it is exactly `size` bytes hashing
 * to `hash`. Anything else leaves nothing behind.
 */
export interface BlobStorage {
  put(
    hash: string,
    size: number,
    body: ReadableStream<Uint8Array>
  ): Promise<"stored" | "mismatch">;
  /**
   * The bytes as an HTTP response — 200 or, given a Range header, 206 /
   * 416 — or null when the name is not stored. `head` asks for headers only.
   */
  get(hash: string, range: string | null, head: boolean): Promise<Response | null>;
  delete(hash: string): Promise<void>;
}

/** One satisfiable `bytes=` range (inclusive end), or null for the whole thing. */
export function parseRange(
  header: string | null,
  size: number
): { start: number; end: number } | null | "unsatisfiable" {
  if (header === null) {
    return null;
  }
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (match === null || (match[1] === "" && match[2] === "")) {
    // Malformed or multi-range: serve the whole blob, as HTTP allows.
    return null;
  }
  if (match[1] === "") {
    const suffix = Number(match[2]);
    if (suffix === 0 || size === 0) {
      return "unsatisfiable";
    }
    return { start: Math.max(0, size - suffix), end: size - 1 };
  }
  const start = Number(match[1]);
  const end = match[2] === "" ? size - 1 : Math.min(Number(match[2]), size - 1);
  if (start >= size || start > end) {
    return "unsatisfiable";
  }
  return { start, end };
}

export function blobHeaders(size: number): Record<string, string> {
  return {
    "content-type": "application/octet-stream",
    "accept-ranges": "bytes",
    "cache-control": "private, max-age=3600",
    "content-length": String(size),
  };
}

export function unsatisfiable(size: number): Response {
  return new Response(null, {
    status: 416,
    headers: { "content-range": `bytes */${size}`, "accept-ranges": "bytes" },
  });
}
