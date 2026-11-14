import { createHash } from 'node:crypto';

export function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function shortHash(hash: string | undefined, len = 12): string {
  if (!hash) return 'unknown';
  const bare = hash.replace(/^sha256:/, '');
  return bare.slice(0, len);
}

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Mask a secret for display. Enough of the value is kept to let an operator
 * recognise which credential leaked, but not enough to use it.
 */
export function maskSecret(value: string): string {
  const clean = value.replace(/\s+/g, '');
  if (clean.length === 0) return '';
  if (clean.length <= 8) return '•'.repeat(clean.length);
  if (clean.length <= 16) return `${clean.slice(0, 2)}${'•'.repeat(6)}${clean.slice(-2)}`;
  return `${clean.slice(0, 4)}${'•'.repeat(Math.min(12, clean.length - 8))}${clean.slice(-4)}`;
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '?';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** JSON that is safe to inline inside a <script> element. */
export function safeJsonInline(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Normalise a path taken from an image layer.
 *
 * Returns null for paths that try to escape the root (e.g. `../../etc/shadow`)
 * so callers can record a warning instead of following them.
 */
export function normalizeArchivePath(raw: string): string | null {
  let p = raw;
  if (p.includes('\0')) return null;
  p = p.replace(/\\/g, '/');
  while (p.startsWith('./')) p = p.slice(2);
  p = p.replace(/^\/+/, '');
  while (p.endsWith('/') && p.length > 0) p = p.slice(0, -1);
  if (p === '' || p === '.') return '';
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length === 0) return null;
      out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.join('/');
}

export function dirname(path: string): string {
  const i = path.lastIndexOf('/');
  return i <= 0 ? '' : path.slice(0, i);
}

export function basename(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? path : path.slice(i + 1);
}

export function isUnder(path: string, dir: string): boolean {
  if (dir === '') return path !== '';
  return path === dir || path.startsWith(dir + '/');
}

/** Decode bytes as text if they look textual; returns null for binary. */
export function decodeText(buf: Buffer): string | null {
  const sample = buf.subarray(0, Math.min(buf.length, 8192));
  if (sample.length === 0) return '';
  if (sample.includes(0)) return null;
  let suspicious = 0;
  for (const b of sample) {
    if (b < 7 || (b > 13 && b < 32 && b !== 27)) suspicious++;
  }
  if (suspicious / sample.length > 0.1) return null;
  return buf.toString('utf8');
}

export function sortBySeverity<T extends { severity: string }>(items: T[]): T[] {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...items].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max) + '…';
}

export function unique<T>(items: Iterable<T>): T[] {
  return [...new Set(items)];
}
