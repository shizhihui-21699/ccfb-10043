import {
  createReadStream,
  createWriteStream,
  mkdtempSync,
  rmSync,
  statSync,
  readSync,
  openSync,
  closeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import zlib from 'node:zlib';
import type { Readable, Writable } from 'node:stream';
import { detectCompression, zstdAvailable } from './compress.ts';
import { FileIO } from './io.ts';
import type { BlobIO } from './io.ts';

/**
 * Layer blobs inside a `docker save` tar are compressed streams referenced by
 * offset and length. Decompressing a multi-gigabyte layer in memory would be
 * wasteful, so we stream it to a temporary file and index that with random
 * access instead.
 */

export type LayerCompression = 'gzip' | 'zstd' | 'none' | 'unknown';

export interface MaterializedLayer {
  io: BlobIO;
  /** Delete the backing temp file when done with the whole image. */
  cleanup: () => void;
  uncompressedSize: number;
  chain: string[];
}

export interface MaterializeFailure {
  ok: false;
  compression: LayerCompression;
  message: string;
}

export type MaterializeResult = ({ ok: true } & MaterializedLayer) | MaterializeFailure;

function readSlice(path: string, offset: number, length: number): Readable {
  return createReadStream(path, {
    start: offset,
    end: offset + length - 1,
    highWaterMark: 1 << 20,
  });
}

function zstdDecompressor(): Writable & Readable {
  const z = zlib as unknown as Record<string, unknown>;
  const factory = z['createZstdDecompress'];
  if (typeof factory !== 'function') {
    throw new Error('this Node build has no zstd support; cannot read zstd-compressed layers');
  }
  return (factory as () => Writable & Readable)();
}

export function probeCompression(path: string, offset: number, length: number): LayerCompression {
  const n = Math.min(Math.max(length, 0), 512);
  const head = Buffer.alloc(n);
  const fd = openSync(path, 'r');
  try {
    readSync(fd, head, 0, n, offset);
  } finally {
    closeSync(fd);
  }
  const kind = detectCompression(head);
  if (kind === 'gzip' || kind === 'zstd' || kind === 'none') return kind;
  return 'unknown';
}

/**
 * Decompress a byte range into a temp file.
 *
 * Unsupported formats (xz, bzip2, or unknown magic) come back as a failure
 * result rather than a throw, so one odd layer does not abort a whole scan.
 */
export async function materializeLayer(
  sourcePath: string,
  offset: number,
  length: number,
  workDir: string,
  compression?: LayerCompression,
): Promise<MaterializeResult> {
  const kind = compression ?? probeCompression(sourcePath, offset, length);

  // Validate before creating any stream: a throw after createWriteStream()
  // leaves an orphaned stream that errors asynchronously.
  if (kind === 'unknown') {
    return {
      ok: false,
      compression: kind,
      message: `unsupported or unrecognised compression at offset ${offset}`,
    };
  }
  if (kind === 'zstd' && !zstdAvailable()) {
    return {
      ok: false,
      compression: kind,
      message: 'zstd layer but this Node build lacks zstd support',
    };
  }

  const outPath = join(workDir, `layer-${offset}-${length}.tar`);
  const cleanup = (): void => {
    try {
      rmSync(outPath, { force: true });
    } catch {
      /* best effort */
    }
  };

  try {
    const src = readSlice(sourcePath, offset, length);
    const out = createWriteStream(outPath);
    if (kind === 'gzip') {
      await pipeline(src, zlib.createGunzip(), out);
    } else if (kind === 'zstd') {
      await pipeline(src, zstdDecompressor(), out);
    } else {
      await pipeline(src, out);
    }
    return {
      ok: true,
      io: new FileIO(outPath),
      cleanup,
      uncompressedSize: statSync(outPath).size,
      chain: kind === 'none' ? [] : [kind],
    };
  } catch (err) {
    cleanup();
    return {
      ok: false,
      compression: kind,
      message: `failed to decompress layer at offset ${offset}: ${(err as Error).message}`,
    };
  }
}

export function makeWorkDir(prefix = 'layer-audit-'): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return {
    dir,
    cleanup: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}
