import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTar } from '../src/lib/tarwrite.ts';
import { parseTar, readEntryData } from '../src/lib/tar.ts';
import { MemoryIO } from '../src/lib/io.ts';
import { indexTar, readIndexedEntry } from '../src/lib/tarindex.ts';

test('parses a simple tar with files and directories', () => {
  const tar = createTar([
    { path: 'etc/', type: 'dir' },
    { path: 'etc/passwd', data: 'root:x:0:0::/root:/bin/sh\n' },
    { path: 'bin/sh', data: '#!/bin/sh\n', mode: 0o755 },
  ]);
  const entries = parseTar(tar);
  assert.deepEqual(
    entries.map((e) => [e.path, e.type, e.dataLength]),
    [
      ['etc/', 'dir', 0],
      ['etc/passwd', 'file', 26],
      ['bin/sh', 'file', 10],
    ],
  );
  assert.equal(readEntryData(tar, entries[1]!).toString(), 'root:x:0:0::/root:/bin/sh\n');
  assert.equal(entries[2]!.mode, 0o755);
});

test('handles PAX long paths', () => {
  const longPath = `${'a'.repeat(60)}/${'b'.repeat(60)}/file.txt`;
  const tar = createTar([{ path: longPath, data: 'hello' }]);
  const entries = parseTar(tar);
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.path, longPath);
  assert.equal(readEntryData(tar, entries[0]!).toString(), 'hello');
});

test('handles symlinks and hardlinks', () => {
  const tar = createTar([
    { path: 'target.txt', data: 'content' },
    { path: 'link', type: 'symlink', linkname: 'target.txt' },
    { path: 'hard', type: 'hardlink', linkname: 'target.txt' },
  ]);
  const entries = parseTar(tar);
  assert.equal(entries[1]!.type, 'symlink');
  assert.equal(entries[1]!.linkname, 'target.txt');
  assert.equal(entries[2]!.type, 'hardlink');
  assert.equal(entries[2]!.linkname, 'target.txt');
});

test('random-access indexer matches in-memory parser', () => {
  const tar = createTar([
    { path: 'a/b/c.txt', data: 'x'.repeat(1500) },
    { path: 'whiteout/.wh.c.txt', data: '' },
  ]);
  const io = new MemoryIO(tar);
  const indexed = indexTar(io);
  const parsed = parseTar(tar);
  assert.equal(indexed.entries.length, parsed.length);
  assert.ok(indexed.terminated);
  for (let i = 0; i < parsed.length; i++) {
    assert.equal(indexed.entries[i]!.path, parsed[i]!.path);
    assert.equal(indexed.entries[i]!.dataLength, parsed[i]!.dataLength);
    assert.deepEqual(
      readIndexedEntry(io, indexed.entries[i]!),
      readEntryData(tar, parsed[i]!),
    );
  }
});

test('rejects a corrupt header checksum', () => {
  const tar = createTar([{ path: 'x.txt', data: 'hi' }]);
  tar[0] = 0x41; // corrupt the name field after the checksum was computed
  assert.throws(() => parseTar(tar), /checksum/);
  assert.throws(() => indexTar(new MemoryIO(tar)), /checksum/);
});

test('base-256 numeric fields decode', () => {
  const tar = createTar([{ path: 'big.bin', data: Buffer.alloc(0) }]);
  // Rewrite the size field as base-256 for 1024 bytes.
  const header = tar.subarray(0, 512);
  header.fill(0, 124, 136);
  header[124] = 0x80; // base-256 marker
  header[134] = 0x04; // 1024 = 0x400 in the last two bytes
  header.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of header) sum += b;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
  const entries = parseTar(tar);
  assert.equal(entries[0]!.size, 1024);
});

test('truncated archives are tolerated', () => {
  const tar = createTar([{ path: 'a.txt', data: 'abcdefghij' }]);
  const truncated = tar.subarray(0, 512 + 4); // header + 4 bytes of body
  const entries = parseTar(truncated);
  assert.equal(entries.length, 1);
  assert.equal(readEntryData(truncated, entries[0]!).toString(), 'abcd');
});
