import type { BlobIO } from './io.ts';
import type { TarEntry, TarEntryType } from './tar.ts';
import { parsePax } from './tar.ts';

/**
 * Walk a tar archive held behind a BlobIO without holding its bodies in memory.
 *
 * Only headers (512 bytes) and PAX/GNU extension records are read, so a 20 GiB
 * `docker save` archive costs a few megabytes of RAM to index.
 */

const BLOCK = 512;

export class TarIndexError extends Error {}

function readCString(buf: Buffer, off: number, len: number): string {
  let end = off + len;
  for (let i = off; i < off + len; i++) {
    if (buf[i] === 0) {
      end = i;
      break;
    }
  }
  return buf.toString('utf8', off, end);
}

function readNumeric(buf: Buffer, off: number, len: number): number {
  if (buf[off]! & 0x80) {
    const negative = (buf[off]! & 0x40) !== 0;
    let value = buf[off]! & 0x3f;
    for (let i = off + 1; i < off + len; i++) {
      value = value * 256 + buf[i]!;
      if (value > Number.MAX_SAFE_INTEGER) throw new TarIndexError('numeric field overflow');
    }
    return negative ? -value : value;
  }
  const raw = readCString(buf, off, len).trim();
  if (raw === '') return 0;
  const n = parseInt(raw, 8);
  return Number.isFinite(n) ? n : 0;
}

export function headerChecksumOk(header: Buffer): boolean {
  const stored = readNumeric(header, 148, 8);
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < BLOCK; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : header[i]!;
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }
  return stored === unsigned || stored === signed;
}

function mapType(flag: string): TarEntryType {
  switch (flag) {
    case '0':
    case '\0':
    case '7':
      return 'file';
    case '1':
      return 'hardlink';
    case '2':
      return 'symlink';
    case '3':
      return 'char';
    case '4':
      return 'block';
    case '5':
      return 'dir';
    case '6':
      return 'fifo';
    default:
      return 'other';
  }
}

export interface TarIndexResult {
  entries: TarEntry[];
  /** True when the archive ended with a proper zero-block terminator. */
  terminated: boolean;
  /** Bytes not consumed by any entry, usually zero padding. */
  trailingBytes: number;
}

export interface TarIndexOptions {
  maxEntries?: number;
  /** Called per entry; return false to stop indexing. */
  onEntry?: (entry: TarEntry) => boolean | void;
}

export function indexTar(io: BlobIO, options: TarIndexOptions = {}): TarIndexResult {
  const maxEntries = options.maxEntries ?? 2_000_000;
  const entries: TarEntry[] = [];
  let off = 0;
  let zeroBlocks = 0;
  let terminated = false;
  let pendingName: string | undefined;
  let pendingLink: string | undefined;
  let pendingPax: Record<string, string> = {};
  let globalPax: Record<string, string> = {};

  while (off + BLOCK <= io.size) {
    const header = io.read(off, BLOCK);
    if (header.length < BLOCK) break;
    if (header.every((b) => b === 0)) {
      zeroBlocks++;
      off += BLOCK;
      if (zeroBlocks >= 2) {
        terminated = true;
        break;
      }
      continue;
    }
    zeroBlocks = 0;
    if (!headerChecksumOk(header)) {
      throw new TarIndexError(`bad tar header checksum at offset ${off}`);
    }

    let name = readCString(header, 0, 100);
    const mode = readNumeric(header, 100, 8);
    const uid = readNumeric(header, 108, 8);
    const gid = readNumeric(header, 116, 8);
    const declaredSize = readNumeric(header, 124, 12);
    const mtime = readNumeric(header, 136, 12);
    const typeflag = String.fromCharCode(header[156]!);
    let linkname = readCString(header, 157, 100);
    const magic = readCString(header, 257, 6);
    const uname = readCString(header, 265, 32);
    const gname = readCString(header, 297, 32);

    if (magic.startsWith('ustar')) {
      const prefix = readCString(header, 345, 155);
      if (prefix) name = `${prefix}/${name}`;
    }

    const bodyOff = off + BLOCK;
    const padded = Math.ceil(declaredSize / BLOCK) * BLOCK;
    const bodyLen = Math.max(0, Math.min(declaredSize, io.size - bodyOff));
    const truncated = bodyLen < declaredSize;

    const readBody = (): Buffer => io.read(bodyOff, bodyLen);

    if (typeflag === 'x' || typeflag === 'X') {
      pendingPax = { ...pendingPax, ...parsePax(readBody()) };
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'g') {
      globalPax = { ...globalPax, ...parsePax(readBody()) };
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'L') {
      pendingName = readBody().toString('utf8').replace(/\0.*$/s, '');
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'K') {
      pendingLink = readBody().toString('utf8').replace(/\0.*$/s, '');
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'V' || typeflag === 'M' || typeflag === 'N') {
      off = bodyOff + padded;
      continue;
    }

    const pax: Record<string, string> = { ...globalPax, ...pendingPax };
    if (pendingName !== undefined) {
      name = pendingName;
      pendingName = undefined;
    } else if (pax.path !== undefined) {
      name = pax.path;
    }
    if (pendingLink !== undefined) {
      linkname = pendingLink;
      pendingLink = undefined;
    } else if (pax.linkpath !== undefined) {
      linkname = pax.linkpath;
    }
    pendingPax = {};

    let size = declaredSize;
    let dataLength = bodyLen;
    if (pax.size !== undefined) {
      const n = parseInt(pax.size, 10);
      if (Number.isFinite(n) && n >= 0) {
        size = n;
        dataLength = Math.max(0, Math.min(n, io.size - bodyOff));
      }
    }

    if (typeflag !== 'S' && typeflag !== 'V') {
      const entry: TarEntry = {
        path: name,
        linkname,
        type: mapType(typeflag),
        size,
        mode,
        uid,
        gid,
        uname,
        gname,
        mtime,
        dataOffset: bodyOff,
        dataLength,
        typeflag,
        pax,
      };
      entries.push(entry);
      if (options.onEntry && options.onEntry(entry) === false) break;
      if (entries.length >= maxEntries) break;
    }

    off = bodyOff + padded;
    if (truncated) break;
  }

  return { entries, terminated, trailingBytes: Math.max(0, io.size - off) };
}

/** Read an entry body from the archive. */
export function readIndexedEntry(io: BlobIO, entry: TarEntry, limit?: number): Buffer {
  const n = limit === undefined ? entry.dataLength : Math.min(limit, entry.dataLength);
  if (n <= 0) return Buffer.alloc(0);
  return io.read(entry.dataOffset, n);
}
