/**
 * Compression detection for layer blobs.
 *
 * Decompression itself is streamed to a temp file by `stream.ts`; this module
 * only inspects magic bytes and provides an in-memory fallback for small blobs
 * (tests, fixtures, and OCI layers).
 */
import { gunzipSync } from 'node:zlib';
import zlib from 'node:zlib';

export type Compression = 'none' | 'gzip' | 'zstd' | 'xz' | 'bzip2' | 'unknown';

export function detectCompression(buf: Buffer): Compression {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return 'gzip';
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0xfd2fb528) return 'zstd';
  if (
    buf.length >= 6 &&
    buf[0] === 0xfd &&
    buf[1] === 0x37 &&
    buf[2] === 0x7a &&
    buf[3] === 0x58 &&
    buf[4] === 0x5a &&
    buf[5] === 0x00
  ) {
    return 'xz';
  }
  if (buf.length >= 3 && buf[0] === 0x42 && buf[1] === 0x5a && buf[2] === 0x68) return 'bzip2';
  if (looksLikeTar(buf)) return 'none';
  return 'unknown';
}

export function looksLikeTar(buf: Buffer): boolean {
  if (buf.length < 512) return false;
  // ustar magic at 257, or an all-zero first block (empty tar).
  if (buf.toString('latin1', 257, 262) === 'ustar') return true;
  return buf.subarray(0, 512).every((b) => b === 0);
}

export function zstdAvailable(): boolean {
  const z = zlib as unknown as Record<string, unknown>;
  return typeof z['zstdDecompressSync'] === 'function';
}

/**
 * In-memory decompression for blobs small enough to hold. Returns null when
 * the format is recognised but unsupported in this environment.
 */
export function decompressInMemory(buf: Buffer): Buffer | null {
  const kind = detectCompression(buf);
  if (kind === 'none') return buf;
  if (kind === 'gzip') return gunzipSync(buf);
  if (kind === 'zstd') {
    if (!zstdAvailable()) return null;
    const fn = (
      zlib as unknown as {
        zstdDecompressSync: (b: Buffer) => Buffer;
      }
    ).zstdDecompressSync;
    return fn(buf);
  }
  return null;
}
