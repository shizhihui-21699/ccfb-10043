#!/usr/bin/env node
/**
 * Write the test fixtures to disk. Used by `npm run fixtures` and by the test
 * suite, which needs real files for the loaders to read.
 */
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { buildDockerSave, buildOciLayout, leakedSecretImage } from './build.ts';

const outRoot = process.argv[2] ?? join(import.meta.dirname, 'out');

export function writeFixtures(root = outRoot): { saveTar: string; ociDir: string; ociGzDir: string } {
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });

  const image = leakedSecretImage();

  const saveTar = join(root, 'leaky-image.tar');
  writeFileSync(saveTar, buildDockerSave(image).tar);

  const ociDir = join(root, 'oci-layout');
  const built = buildOciLayout(image);
  for (const file of built.files) {
    const full = join(ociDir, file.path);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, file.data);
  }

  const ociGzDir = join(root, 'oci-layout-gzip');
  const builtGz = buildOciLayout(image, { compress: true });
  for (const file of builtGz.files) {
    const full = join(ociGzDir, file.path);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, file.data);
  }

  return { saveTar, ociDir, ociGzDir };
}

if (import.meta.filename === process.argv[1]) {
  const written = writeFixtures();
  console.log(`fixtures written under ${outRoot}`);
  for (const [k, v] of Object.entries(written)) console.log(`  ${k}: ${v}`);
}
