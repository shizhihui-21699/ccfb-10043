import { closeSync, openSync, readSync, statSync } from 'node:fs';

/** Random-access view over a blob, either in memory or on disk. */
export interface BlobIO {
  readonly size: number;
  read(offset: number, length: number): Buffer;
  close?(): void;
}

export class MemoryIO implements BlobIO {
  readonly size: number;
  private readonly data: Buffer;
  constructor(data: Buffer) {
    this.data = data;
    this.size = data.length;
  }
  read(offset: number, length: number): Buffer {
    const start = Math.max(0, Math.min(offset, this.size));
    const end = Math.max(start, Math.min(offset + length, this.size));
    return this.data.subarray(start, end);
  }
}

export class FileIO implements BlobIO {
  readonly size: number;
  private readonly fd: number;
  constructor(path: string) {
    this.fd = openSync(path, 'r');
    this.size = statSync(path).size;
  }
  read(offset: number, length: number): Buffer {
    const start = Math.max(0, Math.min(offset, this.size));
    const end = Math.max(start, Math.min(offset + length, this.size));
    if (end === start) return Buffer.alloc(0);
    const out = Buffer.alloc(end - start);
    let got = 0;
    while (got < out.length) {
      const n = readSync(this.fd, out, got, out.length - got, start + got);
      if (n <= 0) break;
      got += n;
    }
    return got === out.length ? out : out.subarray(0, got);
  }
  close(): void {
    closeSync(this.fd);
  }
}
