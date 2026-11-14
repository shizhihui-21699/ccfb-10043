/**
 * Small tar writer used to build test images and to re-emit recovered files.
 * Deliberately simple: ustar with PAX fallback for long names.
 */

const BLOCK = 512;

export interface WriteEntry {
  path: string;
  type?: 'file' | 'dir' | 'symlink' | 'hardlink';
  data?: Buffer | string;
  linkname?: string;
  mode?: number;
  uid?: number;
  gid?: number;
  mtime?: number;
  uname?: string;
  gname?: string;
}

function octal(value: number, len: number): string {
  const s = Math.max(0, Math.floor(value)).toString(8);
  return s.padStart(len - 1, '0').slice(-(len - 1)) + '\0';
}

function writeString(buf: Buffer, off: number, len: number, value: string): void {
  buf.write(value, off, Math.min(len, Buffer.byteLength(value)), 'utf8');
}

function header(
  name: string,
  entry: WriteEntry,
  size: number,
  typeflag: string,
): Buffer {
  const buf = Buffer.alloc(BLOCK, 0);
  writeString(buf, 0, 100, name);
  writeString(buf, 100, 8, octal(entry.mode ?? (entry.type === 'dir' ? 0o755 : 0o644), 8));
  writeString(buf, 108, 8, octal(entry.uid ?? 0, 8));
  writeString(buf, 116, 8, octal(entry.gid ?? 0, 8));
  writeString(buf, 124, 12, octal(size, 12));
  writeString(buf, 136, 12, octal(entry.mtime ?? 0, 12));
  buf.write(typeflag, 156, 1, 'latin1');
  writeString(buf, 157, 100, entry.linkname ?? '');
  buf.write('ustar\0', 257, 'latin1');
  buf.write('00', 263, 'latin1');
  writeString(buf, 265, 32, entry.uname ?? 'root');
  writeString(buf, 297, 32, entry.gname ?? 'root');
  writeString(buf, 329, 8, octal(0, 8));
  writeString(buf, 337, 8, octal(0, 8));

  // Checksum: spaces while computing, then 6 octal digits + NUL + space.
  buf.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of buf) sum += b;
  writeString(buf, 148, 7, octal(sum, 7));
  buf[155] = 0x20;
  return buf;
}

function padTo(data: Buffer): Buffer {
  const rem = data.length % BLOCK;
  if (rem === 0) return data;
  return Buffer.concat([data, Buffer.alloc(BLOCK - rem, 0)]);
}

function paxRecord(key: string, value: string): Buffer {
  // Length prefix includes itself, so iterate until stable.
  let len = Buffer.byteLength(` ${key}=${value}\n`) + 1;
  while (Buffer.byteLength(`${len} ${key}=${value}\n`) !== len) {
    len = Buffer.byteLength(`${len} ${key}=${value}\n`);
  }
  return Buffer.from(`${len} ${key}=${value}\n`, 'utf8');
}

export function createTar(entries: WriteEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const type = entry.type ?? 'file';
    const data =
      type === 'file'
        ? Buffer.isBuffer(entry.data)
          ? entry.data
          : Buffer.from(entry.data ?? '', 'utf8')
        : Buffer.alloc(0);
    const typeflag =
      type === 'dir' ? '5' : type === 'symlink' ? '2' : type === 'hardlink' ? '1' : '0';

    let name = entry.path;
    // Long names need a PAX header; ustar alone caps at 100 bytes.
    if (Buffer.byteLength(name) > 100) {
      const paxBody = paxRecord('path', name);
      parts.push(header('././@PaxHeader', { path: '././@PaxHeader', mode: 0o644 }, paxBody.length, 'x'));
      parts.push(padTo(paxBody));
      name = name.slice(0, 100); // placeholder; the reader prefers the PAX path
    }
    parts.push(header(name, { ...entry, type }, data.length, typeflag));
    if (data.length > 0) parts.push(padTo(data));
  }
  // Two zero blocks terminate an archive.
  parts.push(Buffer.alloc(BLOCK * 2, 0));
  return Buffer.concat(parts);
}

export function isTar(buf: Buffer): boolean {
  return buf.length >= 512 && (buf.toString('latin1', 257, 262) === 'ustar' || buf.every((b) => b === 0));
}
