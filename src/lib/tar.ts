/**
 * Minimal but careful tar reader.
 *
 * Supports the formats Docker actually produces: POSIX ustar, GNU
 * long-name/long-link entries, and PAX extended headers. Also handles base-256
 * encoded size fields, which GNU tar uses for files over 8 GiB.
 */

export type TarEntryType =
  | 'file'
  | 'dir'
  | 'symlink'
  | 'hardlink'
  | 'char'
  | 'block'
  | 'fifo'
  | 'other';

export interface TarEntry {
  /** Path exactly as stored in the archive (may include leader entries). */
  path: string;
  /** Link target for symlinks and hardlinks. */
  linkname: string;
  type: TarEntryType;
  size: number;
  mode: number;
  uid: number;
  gid: number;
  uname: string;
  gname: string;
  mtime: number;
  /** Offset of the file body inside the supplied archive buffer. */
  dataOffset: number;
  /** Byte length of the file body actually present in the buffer. */
  dataLength: number;
  /** Raw header typeflag, useful in diagnostics. */
  typeflag: string;
  /** PAX/RECORD metadata associated with the entry. */
  pax: Record<string, string>;
}

export interface TarParseOptions {
  /** Stop after this many entries (safety valve for huge layers). */
  maxEntries?: number;
  /** Called for each parsed entry. Return false to stop parsing early. */
  onEntry?: (entry: TarEntry) => boolean | void;
}

const BLOCK = 512;

export class TarFormatError extends Error {}

function readString(buf: Buffer, off: number, len: number): string {
  let end = off + len;
  for (let i = off; i < off + len; i++) {
    if (buf[i] === 0) {
      end = i;
      break;
    }
  }
  return buf.toString('utf8', off, end);
}

function readOctal(buf: Buffer, off: number, len: number): number {
  // Base-256 (binary) encoding: high bit of the first byte is set.
  if (buf[off]! & 0x80) {
    const negative = (buf[off]! & 0x40) !== 0;
    let value = buf[off]! & 0x3f;
    for (let i = off + 1; i < off + len; i++) {
      value = value * 256 + buf[i]!;
      if (value > Number.MAX_SAFE_INTEGER) {
        throw new TarFormatError('tar numeric field overflows JS number');
      }
    }
    return negative ? -value : value;
  }
  const raw = readString(buf, off, len).trim();
  if (raw === '') return 0;
  const parsed = parseInt(raw, 8);
  return Number.isFinite(parsed) ? parsed : 0;
}

function checksumMatches(buf: Buffer, off: number): boolean {
  const stored = readOctal(buf, off + 148, 8);
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < BLOCK; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : buf[off + i]!;
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }
  return stored === unsigned || stored === signed;
}

export function parsePax(data: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) break;
    const lengthStr = data.toString('utf8', pos, sp);
    const length = parseInt(lengthStr, 10);
    if (!Number.isFinite(length) || length <= 0 || pos + length > data.length) break;
    // Record body is `key=value`, terminated by a newline inside the length.
    const record = data.toString('utf8', sp + 1, pos + length - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    pos += length;
  }
  return out;
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

/**
 * Parse every entry in a tar archive held in memory.
 *
 * The archive is not copied; entry bodies are referenced by offset into `buf`.
 */
export function parseTar(buf: Buffer, options: TarParseOptions = {}): TarEntry[] {
  const entries: TarEntry[] = [];
  const maxEntries = options.maxEntries ?? 2_000_000;
  let off = 0;
  let pendingName: string | undefined;
  let pendingLink: string | undefined;
  let pendingPax: Record<string, string> = {};
  let globalPax: Record<string, string> = {};
  let zeroBlocks = 0;

  while (off + BLOCK <= buf.length) {
    const headerOff = off;
    const header = buf.subarray(headerOff, headerOff + BLOCK);
    if (header.every((b) => b === 0)) {
      // Two consecutive zero blocks ends the archive. One is tolerated as padding.
      zeroBlocks++;
      if (zeroBlocks >= 2) break;
      off += BLOCK;
      continue;
    }
    zeroBlocks = 0;

    if (!checksumMatches(buf, headerOff)) {
      throw new TarFormatError(`bad tar header checksum at offset ${headerOff}`);
    }

    let name = readString(buf, headerOff, 100);
    const mode = readOctal(buf, headerOff + 100, 8);
    const uid = readOctal(buf, headerOff + 108, 8);
    const gid = readOctal(buf, headerOff + 116, 8);
    const declaredSize = readOctal(buf, headerOff + 124, 12);
    const mtime = readOctal(buf, headerOff + 136, 12);
    const typeflag = String.fromCharCode(header[156]!);
    let linkname = readString(buf, headerOff + 157, 100);
    const magic = readString(buf, headerOff + 257, 6);
    const uname = readString(buf, headerOff + 265, 32);
    const gname = readString(buf, headerOff + 297, 32);

    // ustar prefix field extends the name.
    if (magic.startsWith('ustar')) {
      const prefix = readString(buf, headerOff + 345, 155);
      if (prefix) name = `${prefix}/${name}`;
    }

    const bodyOff = headerOff + BLOCK;
    const padded = Math.ceil(declaredSize / BLOCK) * BLOCK;
    // Truncated archives are common in interrupted saves: keep what exists.
    const bodyLen = Math.max(0, Math.min(declaredSize, buf.length - bodyOff));
    const body = buf.subarray(bodyOff, bodyOff + bodyLen);

    if (typeflag === 'x' || typeflag === 'X') {
      pendingPax = { ...pendingPax, ...parsePax(body) };
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'g') {
      globalPax = { ...globalPax, ...parsePax(body) };
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'L') {
      pendingName = body.toString('utf8').replace(/\0.*$/s, '');
      off = bodyOff + padded;
      continue;
    }
    if (typeflag === 'K') {
      pendingLink = body.toString('utf8').replace(/\0.*$/s, '');
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
        dataLength = Math.max(0, Math.min(n, buf.length - bodyOff));
      }
    }

    // GNU sparse files keep their real payload in an extension header; skip
    // them rather than reporting bogus contents.
    if (typeflag !== 'S') {
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
  }

  return entries;
}

/** Read up to `limit` bytes of an entry body. */
export function readEntryData(buf: Buffer, entry: TarEntry, limit?: number): Buffer {
  let end = entry.dataOffset + entry.dataLength;
  if (limit !== undefined) end = Math.min(end, entry.dataOffset + limit);
  return buf.subarray(entry.dataOffset, Math.min(end, buf.length));
}
