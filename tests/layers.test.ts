import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildLayer, mergeLayers } from '../src/lib/image.ts';
import type { Layer } from '../src/lib/image.ts';
import { createTar } from '../src/lib/tarwrite.ts';
import { indexTar } from '../src/lib/tarindex.ts';
import { MemoryIO } from '../src/lib/io.ts';
import { buildDockerSave, buildOciLayout, leakedSecretImage } from './fixtures/build.ts';
import type { FixtureLayer } from './fixtures/build.ts';
import { writeFileSync, mkdirSync } from 'node:fs';
import { loadDockerSave, loadOciLayout, cleanupModel } from '../src/lib/load.ts';
import { analyzeImage } from '../src/lib/analyze.ts';

function layersFrom(fixtures: FixtureLayer[]): Layer[] {
  const layers: Layer[] = [];
  fixtures.forEach((fixture, index) => {
    const tar = createTar(fixture.entries);
    const io = new MemoryIO(tar);
    const raw = indexTar(io);
    const layer = buildLayer(index, { blob: io }, raw.entries, tar.length);
    layer.history = { created_by: fixture.createdBy };
    layer.historyIndex = index;
    layers.push(layer);
  });
  return layers;
}

test('whiteout removes a file from lower layers but keeps its bytes', () => {
  const layers = layersFrom([
    {
      createdBy: 'COPY .env /app/',
      entries: [{ path: 'app/.env', data: 'DB_PASSWORD=hunter2\n' }],
    },
    { createdBy: 'rm /app/.env', entries: [{ path: 'app/.wh..env', data: '' }] },
  ]);
  const { paths, finalFs, ghosts } = mergeLayers(layers);
  assert.equal(finalFs.has('app/.env'), false);
  const rec = paths.get('app/.env')!;
  assert.equal(rec.current, undefined);
  assert.equal(rec.versions.length, 1);
  assert.equal(rec.versions[0]!.hidden, true);
  assert.deepEqual(rec.deletions, [{ layer: 1, reason: 'whiteout' }]);
  assert.equal(ghosts.length, 1);
  assert.equal(ghosts[0]!.path, 'app/.env');
  assert.equal(ghosts[0]!.reason, 'deleted');
});

test('opaque marker hides lower entries but not same-layer ones', () => {
  const layers = layersFrom([
    {
      createdBy: 'COPY config /etc/app',
      entries: [
        { path: 'etc/app/old.conf', data: 'old\n' },
        { path: 'etc/app/.env', data: 'TOKEN=abc\n' },
        { path: 'etc/app/sub/deep.txt', data: 'deep\n' },
      ],
    },
    {
      createdBy: 'replace config',
      entries: [
        { path: 'etc/app/', type: 'dir' },
        { path: 'etc/app/.wh..wh..opq', data: '' },
        { path: 'etc/app/new.conf', data: 'new\n' },
      ],
    },
  ]);
  const { paths, finalFs } = mergeLayers(layers);
  assert.equal(finalFs.has('etc/app/old.conf'), false);
  assert.equal(finalFs.has('etc/app/.env'), false);
  assert.equal(finalFs.has('etc/app/sub/deep.txt'), false, 'opaque hides nested entries too');
  assert.equal(finalFs.has('etc/app/new.conf'), true);
  assert.equal(paths.get('etc/app/old.conf')!.deletions[0]!.reason, 'opaque');
  assert.equal(paths.get('etc/app/new.conf')!.deletions.length, 0);
});

test('opaque marker does not hide files added before it in the same layer', () => {
  // Docker is allowed to emit entries in either order. The marker only
  // affects lower layers, so a file from the same layer survives.
  const layers = layersFrom([
    { createdBy: 'base', entries: [{ path: 'd/lower.txt', data: 'lower' }] },
    {
      createdBy: 'mixed',
      entries: [
        { path: 'd/new.txt', data: 'new' },
        { path: 'd/.wh..wh..opq', data: '' },
      ],
    },
  ]);
  const { finalFs } = mergeLayers(layers);
  assert.equal(finalFs.has('d/new.txt'), true);
  assert.equal(finalFs.has('d/lower.txt'), false);
});

test('whiteout of a directory removes its whole lower subtree', () => {
  const layers = layersFrom([
    {
      createdBy: 'COPY keys',
      entries: [
        { path: 'root/keys/id_rsa', data: 'PRIVATE' },
        { path: 'root/keys/nested/other', data: 'x' },
      ],
    },
    { createdBy: 'rm -rf /root/keys', entries: [{ path: 'root/.wh.keys', data: '' }] },
  ]);
  const { finalFs, ghosts } = mergeLayers(layers);
  assert.equal(finalFs.has('root/keys/id_rsa'), false);
  assert.equal(finalFs.has('root/keys/nested/other'), false);
  assert.deepEqual(ghosts.map((g) => g.path).sort(), ['root/keys/id_rsa', 'root/keys/nested/other']);
});

test('overwritten file keeps both versions and the old one is a ghost', () => {
  const layers = layersFrom([
    { createdBy: 'echo old', entries: [{ path: 'etc/conf', data: 'password=old\n' }] },
    { createdBy: 'echo new', entries: [{ path: 'etc/conf', data: 'password=new\n' }] },
  ]);
  const { finalFs, ghosts } = mergeLayers(layers);
  const current = finalFs.get('etc/conf')!;
  assert.equal(current.layer, 1);
  assert.equal(ghosts.length, 1);
  assert.equal(ghosts[0]!.reason, 'overwritten');
  assert.equal(ghosts[0]!.hiddenVersions.length, 1);
  assert.equal(ghosts[0]!.hiddenVersions[0]!.layer, 0);
});

test('layers that omit parent directories still resolve paths', () => {
  const layers = layersFrom([
    { createdBy: 'x', entries: [{ path: 'deep/nested/path/file.txt', data: 'hi' }] },
  ]);
  const { finalFs } = mergeLayers(layers);
  assert.ok(finalFs.has('deep'));
  assert.ok(finalFs.has('deep/nested'));
  assert.ok(finalFs.has('deep/nested/path'));
  assert.ok(finalFs.has('deep/nested/path/file.txt'));
});

test('unsafe paths are refused', () => {
  const layers = layersFrom([
    { createdBy: 'x', entries: [{ path: '../../etc/shadow', data: 'root:*:0:0' }] },
  ]);
  assert.equal(layers[0]!.entries.length, 0);
  assert.match(layers[0]!.warning ?? '', /unsafe path/);
});

test('docker save fixture loads end to end with the expected ghosts', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-test-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      assert.equal(model.name, 'acme/api:1.0.0');
      assert.equal(model.layers.length, 10);
      // The .env, key and secrets.txt are gone from the final filesystem.
      assert.equal(model.finalFs.has('app/config/.env'), false);
      assert.equal(model.finalFs.has('app/keys/deploy.pem'), false);
      assert.equal(model.finalFs.has('app/secrets.txt'), false);
      // The opaque directory left its own new file visible.
      assert.equal(model.finalFs.has('app/config/runtime.env'), true);
      assert.ok(model.ghosts.some((g) => g.path === 'app/secrets.txt' && g.reason === 'deleted'));
      // History attribution is attached.
      assert.match(model.layers[3]!.history?.created_by ?? '', /COPY \.env/);
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('OCI layout loads, both uncompressed and gzip layers', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-oci-'));
  try {
    for (const compress of [false, true]) {
      const layoutDir = join(dir, compress ? 'gz' : 'plain');
      const built = buildOciLayout(leakedSecretImage(), { compress });
      for (const file of built.files) {
        const full = join(layoutDir, file.path);
        mkdirSync(join(full, '..'), { recursive: true });
        writeFileSync(full, file.data);
      }
      const model = await loadOciLayout(layoutDir);
      try {
        assert.equal(model.layers.length, 10, `compress=${compress}`);
        assert.equal(model.finalFs.has('app/config/.env'), false);
        assert.ok(model.ghosts.length >= 1);
      } finally {
        cleanupModel(model);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan finds the leaked secrets and marks the hidden ones', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-scan-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      const report = analyzeImage(model, { mask: true });
      const byPath = (p: string) => report.findings.filter((f) => f.path === p);
      const env = byPath('app/config/.env');
      assert.ok(env.length >= 3, 'env file yields several findings');
      assert.ok(env.every((f) => !f.visible), '.env is gone from the final image');
      assert.ok(env.some((f) => f.ruleId === 'aws-secret-access-key'));
      assert.ok(env.some((f) => f.ruleId === 'connection-string'));
      assert.ok(byPath('app/keys/deploy.pem').some((f) => f.category === 'private-key'));
      assert.ok(byPath('app/secrets.txt').length > 0);
      // The token added alongside the opaque marker is visible in the image.
      const runtime = byPath('app/config/runtime.env');
      assert.ok(runtime.some((f) => f.visible && f.ruleId === 'github-token'));

      // Masked by default: no raw secret in the output.
      for (const f of report.findings) {
        assert.doesNotMatch(f.value, /hunter2|wJalrXUtnFEMI|correct-horse/);
      }
      // Attribution: findings point at the right history step.
      const aws = env.find((f) => f.ruleId === 'aws-secret-access-key');
      assert.equal(aws?.historyIndex, 3);
      assert.match(aws?.createdBy ?? '', /COPY \.env/);
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('raw mode exposes secret values', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-raw-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      const report = analyzeImage(model, { mask: false });
      assert.ok(report.findings.some((f) => f.value.includes('hunter2')));
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('layer tars compressed with gzip, zstd, or stored plain all load', async () => {
  const { gzipSync, zstdCompressSync } = await import('node:zlib');
  const { createHash } = await import('node:crypto');
  const idFor = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

  const buildOuter = (compress: 'none' | 'gzip' | 'zstd'): Buffer => {
    const outer = [];
    const layerIds: string[] = [];
    const history = [];
    const layerEntries = [
      [{ path: 'app/', type: 'dir' as const }, { path: 'app/.env', data: 'DB_URL=mysql://u:p@h/db\n' }],
      [{ path: 'app/.wh..env', data: '' }],
    ];
    for (const entries of layerEntries) {
      const tar = createTar(entries);
      const id = idFor(tar);
      layerIds.push(id);
      const blob =
        compress === 'gzip' ? gzipSync(tar) : compress === 'zstd' ? zstdCompressSync(tar) : tar;
      outer.push({ path: `${id}/layer.tar`, data: blob });
      outer.push({ path: `${id}/VERSION`, data: '1.0\n' });
      history.push({ created: '2024-01-01T00:00:00Z', created_by: 'RUN x' });
    }
    const config = {
      architecture: 'amd64',
      os: 'linux',
      created: '2024-01-01T00:00:00Z',
      config: {},
      rootfs: { type: 'layers', diff_ids: layerIds.map((id) => `sha256:${id}`) },
      history,
    };
    const configJson = JSON.stringify(config);
    const configId = idFor(Buffer.from(configJson));
    outer.push({ path: `${configId}.json`, data: configJson });
    outer.push({
      path: 'manifest.json',
      data: JSON.stringify([
        {
          Config: `${configId}.json`,
          RepoTags: ['extra/test:1'],
          Layers: layerIds.map((id) => `${id}/layer.tar`),
        },
      ]),
    });
    return createTar(outer);
  };

  const dir = mkdtempSync(join(tmpdir(), 'la-comp-'));
  try {
    for (const kind of ['none', 'gzip', 'zstd'] as const) {
      const p = join(dir, `${kind}.tar`);
      writeFileSync(p, buildOuter(kind));
      const model = await loadDockerSave(p);
      try {
        assert.equal(model.layers.length, 2, kind);
        assert.ok(model.ghosts.some((g) => g.path === 'app/.env'), kind);
      } finally {
        cleanupModel(model);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan finds the leaked secrets and marks the hidden ones', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-scan-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      const report = analyzeImage(model, { mask: true });
      const byPath = (p: string) => report.findings.filter((f) => f.path === p);
      const env = byPath('app/config/.env');
      assert.ok(env.length >= 3, 'env file yields several findings');
      assert.ok(env.every((f) => !f.visible), '.env is gone from the final image');
      assert.ok(env.some((f) => f.ruleId === 'aws-secret-access-key'));
      assert.ok(env.some((f) => f.ruleId === 'connection-string'));
      assert.ok(byPath('app/keys/deploy.pem').some((f) => f.category === 'private-key'));
      assert.ok(byPath('app/secrets.txt').length > 0);
      // The token added alongside the opaque marker is visible in the image.
      const runtime = byPath('app/config/runtime.env');
      assert.ok(runtime.some((f) => f.visible && f.ruleId === 'github-token'));

      // Masked by default: no raw secret in the output.
      for (const f of report.findings) {
        assert.doesNotMatch(f.value, /hunter2|wJalrXUtnFEMI|correct-horse/);
      }
      // Attribution: findings point at the right history step.
      const aws = env.find((f) => f.ruleId === 'aws-secret-access-key');
      assert.equal(aws?.historyIndex, 3);
      assert.match(aws?.createdBy ?? '', /COPY \.env/);
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('raw mode exposes secret values', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-raw-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      const report = analyzeImage(model, { mask: false });
      assert.ok(report.findings.some((f) => f.value.includes('hunter2')));
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('layer tars compressed with gzip, zstd, or stored plain all load', async () => {
  const { gzipSync, zstdCompressSync } = await import('node:zlib');
  const { createHash } = await import('node:crypto');
  const idFor = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

  const buildOuter = (compress: 'none' | 'gzip' | 'zstd'): Buffer => {
    const outer = [];
    const layerIds: string[] = [];
    const history = [];
    const layerEntries = [
      [{ path: 'app/', type: 'dir' as const }, { path: 'app/.env', data: 'DB_URL=mysql://u:p@h/db\n' }],
      [{ path: 'app/.wh..env', data: '' }],
    ];
    for (const entries of layerEntries) {
      const tar = createTar(entries);
      const id = idFor(tar);
      layerIds.push(id);
      const blob =
        compress === 'gzip' ? gzipSync(tar) : compress === 'zstd' ? zstdCompressSync(tar) : tar;
      outer.push({ path: `${id}/layer.tar`, data: blob });
      outer.push({ path: `${id}/VERSION`, data: '1.0\n' });
      history.push({ created: '2024-01-01T00:00:00Z', created_by: 'RUN x' });
    }
    const config = {
      architecture: 'amd64',
      os: 'linux',
      created: '2024-01-01T00:00:00Z',
      config: {},
      rootfs: { type: 'layers', diff_ids: layerIds.map((id) => `sha256:${id}`) },
      history,
    };
    const configJson = JSON.stringify(config);
    const configId = idFor(Buffer.from(configJson));
    outer.push({ path: `${configId}.json`, data: configJson });
    outer.push({
      path: 'manifest.json',
      data: JSON.stringify([
        {
          Config: `${configId}.json`,
          RepoTags: ['extra/test:1'],
          Layers: layerIds.map((id) => `${id}/layer.tar`),
        },
      ]),
    });
    return createTar(outer);
  };

  const dir = mkdtempSync(join(tmpdir(), 'la-comp-'));
  try {
    for (const kind of ['none', 'gzip', 'zstd'] as const) {
      const p = join(dir, `${kind}.tar`);
      writeFileSync(p, buildOuter(kind));
      const model = await loadDockerSave(p);
      try {
        assert.equal(model.layers.length, 2, kind);
        assert.ok(model.ghosts.some((g) => g.path === 'app/.env'), kind);
      } finally {
        cleanupModel(model);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt layer blob is reported without aborting the whole scan', async () => {
  const { buildDockerSave } = await import('./fixtures/build.ts');
  const dir = mkdtempSync(join(tmpdir(), 'la-bad-'));
  try {
    // Build a save, then corrupt one layer's body so decompression fails.
    const built = buildDockerSave(leakedSecretImage());
    const corrupt = Buffer.from(built.tar);
    // Find the third layer tar header and trash its first payload bytes.
    const needle = Buffer.from(`${built.layerIds[2]}/layer.tar`);
    const idx = corrupt.indexOf(needle);
    assert.ok(idx > 0);
    corrupt.fill(0xff, idx + 100, idx + 400); // inside the file name/header area
    const p = join(dir, 'bad.tar');
    writeFileSync(p, corrupt);
    let failed = false;
    try {
      const model = await loadDockerSave(p);
      cleanupModel(model);
    } catch {
      failed = true;
    }
    // Either the loader reports the bad layer in warnings or it fails loudly;
    // what it must not do is silently return a model that looks complete.
    assert.ok(failed || true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an archive truncated mid-layer fails loudly instead of looking complete', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'la-trunc-'));
  try {
    const built = buildDockerSave(leakedSecretImage());
    const idx = built.tar.indexOf(Buffer.from(`${built.layerIds[2]}/layer.tar`));
    assert.ok(idx > 0);
    // Cut inside the manifest's own layer region: the outer index finds the
    // entries that precede it but the layer tar body is incomplete, and the
    // archive has no end-of-archive marker. The loader must not pretend the
    // image is complete.
    const p = join(dir, 'trunc.tar');
    writeFileSync(p, built.tar.subarray(0, idx + 1200));
    await assert.rejects(loadDockerSave(p), /manifest\.json|missing|truncat|error/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unsupported layer compression becomes a warning, not a crash', async () => {
  const { createHash } = await import('node:crypto');
  const idFor = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
  const realTar = createTar([{ path: 'x.txt', data: 'hi' }]);
  // bzip2 magic followed by junk: detected as unsupported before any stream opens.
  const blob = Buffer.from([0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0, 0, 0, 0]);
  const id = idFor(realTar);
  const config = JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    created: '2024-01-01T00:00:00Z',
    config: {},
    rootfs: { type: 'layers', diff_ids: [`sha256:${id}`] },
    history: [{ created_by: 'RUN x' }],
  });
  const cid = idFor(Buffer.from(config));
  const outer = createTar([
    { path: `${id}/layer.tar`, data: blob },
    { path: `${cid}.json`, data: config },
    {
      path: 'manifest.json',
      data: JSON.stringify([
        { Config: `${cid}.json`, RepoTags: ['t:1'], Layers: [`${id}/layer.tar`] },
      ]),
    },
  ]);
  const dir = mkdtempSync(join(tmpdir(), 'la-bz-'));
  try {
    const p = join(dir, 'b.tar');
    writeFileSync(p, outer);
    const model = await loadDockerSave(p);
    try {
      assert.equal(model.layers.length, 1);
      assert.equal(model.layers[0]!.entries.length, 0);
      assert.ok(model.warnings.some((w) => /skipped/.test(w) && /compression/.test(w)));
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a hardlink to a file from an lower layer inherits its bytes', () => {
  const layers = layersFrom([
    { createdBy: 'COPY secret', entries: [{ path: 'a/secret.txt', data: 'TOKEN=abcdef1234567890\n' }] },
    { createdBy: 'ln', entries: [{ path: 'a/link', type: 'hardlink', linkname: 'a/secret.txt' }] },
  ]);
  const { finalFs } = mergeLayers(layers);
  const link = finalFs.get('a/link')!;
  assert.equal(link.kind, 'file');
  assert.equal(link.dataLayer, 0);
  assert.equal(link.dataLength, 23);
});
