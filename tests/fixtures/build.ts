/**
 * Fixture builder: assembles a `docker save` archive and an OCI layout
 * entirely in-process. No Docker daemon, no external tar binary.
 *
 * The generated archive mirrors what Docker produces:
 *
 *   manifest.json          [{ Config, RepoTags, Layers }]
 *   <config-id>.json       image config (with history)
 *   <layer-id>/layer.tar   uncompressed per-layer tars
 *   <layer-id>/VERSION     "1.0"
 *   <layer-id>/json        legacy layer metadata
 *
 * Layers here are uncompressed. `docker save` normally writes uncompressed
 * layer.tar too; compressed variants are exercised separately by wrapping
 * blobs in gzip for the OCI layout.
 */

import { createHash } from 'node:crypto';
import { createTar } from '../../src/lib/tarwrite.ts';
import type { WriteEntry } from '../../src/lib/tarwrite.ts';
import { gzipSync } from 'node:zlib';

export interface FixtureLayer {
  /** Entries in the layer tar. Whiteouts are ordinary files named `.wh.*`. */
  entries: WriteEntry[];
  /** History step that produced this layer. */
  createdBy: string;
  created?: string;
  /** Mark this history step as metadata-only (no layer tar). */
  empty?: boolean;
}

export interface FixtureImage {
  repoTag: string;
  /** Layers in build order, base first. */
  layers: FixtureLayer[];
  env?: string[];
  created?: string;
}

export interface BuiltSave {
  tar: Buffer;
  /** Layer ids, base first. */
  layerIds: string[];
  configId: string;
}

const EPOCH = '2024-01-01T00:00:00Z';

function idFor(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function buildDockerSave(image: FixtureImage): BuiltSave {
  const outer: WriteEntry[] = [];
  const layerIds: string[] = [];
  const diffIds: string[] = [];
  const history: Array<Record<string, unknown>> = [];

  for (const layer of image.layers) {
    if (layer.empty) {
      history.push({
        created: layer.created ?? EPOCH,
        created_by: layer.createdBy,
        empty_layer: true,
      });
      continue;
    }
    const tar = createTar(layer.entries);
    const id = idFor(tar);
    layerIds.push(id);
    diffIds.push(`sha256:${idFor(tar)}`);
    outer.push({ path: `${id}/layer.tar`, data: tar });
    outer.push({ path: `${id}/VERSION`, data: '1.0\n' });
    outer.push({ path: `${id}/json`, data: JSON.stringify({ id }) });
    history.push({ created: layer.created ?? EPOCH, created_by: layer.createdBy });
  }

  const config = {
    architecture: 'amd64',
    os: 'linux',
    created: image.created ?? EPOCH,
    config: { Env: image.env ?? ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'] },
    rootfs: { type: 'layers', diff_ids: diffIds },
    history,
  };
  const configJson = JSON.stringify(config, null, 2);
  const configId = idFor(configJson);
  outer.push({ path: `${configId}.json`, data: configJson });

  const manifest = [
    {
      Config: `${configId}.json`,
      RepoTags: [image.repoTag],
      Layers: layerIds.map((id) => `${id}/layer.tar`),
    },
  ];
  outer.push({ path: 'manifest.json', data: JSON.stringify(manifest, null, 2) });

  return { tar: createTar(outer), layerIds, configId };
}

/** Build an OCI layout directory, with layers optionally gzip-compressed. */
export interface OciBlob {
  path: string;
  data: Buffer;
}

export interface BuiltOci {
  files: OciBlob[];
  configDigest: string;
  layerDigests: string[];
}

export function buildOciLayout(
  image: FixtureImage,
  options: { compress?: boolean } = {},
): BuiltOci {
  const files: OciBlob[] = [];
  const layerDescriptors: Array<Record<string, unknown>> = [];
  const diffIds: string[] = [];
  const history: Array<Record<string, unknown>> = [];
  const layerDigests: string[] = [];
  const compress = options.compress ?? false;

  for (const layer of image.layers) {
    if (layer.empty) {
      history.push({ created: layer.created ?? EPOCH, created_by: layer.createdBy, empty_layer: true });
      continue;
    }
    const tar = createTar(layer.entries);
    diffIds.push(`sha256:${idFor(tar)}`);
    const blob = compress ? gzipSync(tar) : tar;
    const digest = idFor(blob);
    layerDigests.push(digest);
    files.push({ path: `blobs/sha256/${digest}`, data: blob });
    layerDescriptors.push({
      mediaType: compress
        ? 'application/vnd.oci.image.layer.v1.tar+gzip'
        : 'application/vnd.oci.image.layer.v1.tar',
      digest: `sha256:${digest}`,
      size: blob.length,
    });
    history.push({ created: layer.created ?? EPOCH, created_by: layer.createdBy });
  }

  const config = {
    architecture: 'amd64',
    os: 'linux',
    created: image.created ?? EPOCH,
    config: { Env: image.env ?? [] },
    rootfs: { type: 'layers', diff_ids: diffIds },
    history,
  };
  const configBytes = Buffer.from(JSON.stringify(config), 'utf8');
  const configDigest = idFor(configBytes);
  files.push({ path: `blobs/sha256/${configDigest}`, data: configBytes });

  const manifest = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: `sha256:${configDigest}`,
      size: configBytes.length,
    },
    layers: layerDescriptors,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest), 'utf8');
  const manifestDigest = idFor(manifestBytes);
  files.push({ path: `blobs/sha256/${manifestDigest}`, data: manifestBytes });

  files.push({
    path: 'oci-layout',
    data: Buffer.from(JSON.stringify({ imageLayoutVersion: '1.0.0' }), 'utf8'),
  });
  const index = {
    schemaVersion: 2,
    manifests: [
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: `sha256:${manifestDigest}`,
        size: manifestBytes.length,
        annotations: { 'org.opencontainers.image.ref.name': image.repoTag },
      },
    ],
  };
  files.push({
    path: 'index.json',
    data: Buffer.from(JSON.stringify(index, null, 2), 'utf8'),
  });

  return { files, configDigest, layerDigests };
}

/** Write built OCI files to a directory. */
export function writeOciLayout(built: BuiltOci, writeFile: (path: string, data: Buffer) => void): void {
  for (const f of built.files) writeFile(f.path, f.data);
}

/** Convenience: a realistic image with a secret that a later layer removes. */
export function leakedSecretImage(): FixtureImage {
  const privateKeyBody = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEAx3Vw1s0Kq2m9vJ7pQe5rT8yU1iO2pA3sD4fG5hJ6kL7zX8cV9bN',
    '0mQ1wE2rT3yU4iO5pA6sD7fG8hJ9kL0zX1cV2bN3mQ4wE5rT6yU7iO8pA9sD0fG1hJ',
    '2kL3zX4cV5bN6mQ7wE8rT9yU0iO1pA2sD3fG4hJ5kL6zX7cV8bN9mQ0wE1rT2yU3i',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');

  return {
    repoTag: 'acme/api:1.0.0',
    layers: [
      {
        createdBy: '/bin/sh -c #(nop)  CMD ["/bin/sh"]',
        entries: [
          { path: 'bin/', type: 'dir', mode: 0o755 },
          { path: 'etc/', type: 'dir', mode: 0o755 },
          { path: 'app/', type: 'dir', mode: 0o755 },
        ],
      },
      {
        createdBy: '/bin/sh -c adduser -D appuser',
        entries: [
          { path: 'home/', type: 'dir', mode: 0o755 },
          { path: 'home/appuser/', type: 'dir', mode: 0o700 },
          { path: 'etc/passwd', data: 'root:x:0:0:root:/root:/bin/sh\nappuser:x:1000:1000::/home/appuser:/bin/sh\n' },
        ],
      },
      {
        createdBy: '/bin/sh -c apk add --no-cache curl postgresql-client',
        entries: [
          { path: 'usr/', type: 'dir', mode: 0o755 },
          { path: 'usr/bin/', type: 'dir', mode: 0o755 },
          { path: 'usr/bin/curl', data: '#!/bin/sh\necho curl\n', mode: 0o755 },
        ],
      },
      {
        // The leak: build tools copy a private key and a .env into the image.
        createdBy: '/bin/sh -c COPY .env /app/config/',
        entries: [
          { path: 'app/config/', type: 'dir', mode: 0o755 },
          {
            path: 'app/config/.env',
            data: [
              'NODE_ENV=production',
              'DATABASE_URL=postgres://appuser:s3cr3t-P4ssw0rd@db.internal:5432/appdb',
              'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
              'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
              'STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc',
              'REDIS_URL=redis://:hunter2@cache.internal:6379/0',
              '',
            ].join('\n'),
            mode: 0o644,
          },
          { path: 'app/keys/', type: 'dir', mode: 0o755 },
          { path: 'app/keys/deploy.pem', data: privateKeyBody + '\n', mode: 0o600 },
        ],
      },
      {
        createdBy: '/bin/sh -c npm install --production',
        entries: [
          { path: 'app/node_modules/', type: 'dir', mode: 0o755 },
          { path: 'app/node_modules/.package-lock.json', data: '{"lockfileVersion":3}\n' },
        ],
      },
      {
        // "Cleanup" layer that only looks like it removes the secret.
        createdBy: '/bin/sh -c rm -rf /app/config/.env /app/keys',
        entries: [
          { path: 'app/config/', type: 'dir', mode: 0o755 },
          { path: 'app/config/.wh..env', data: '' },
          { path: 'app/.wh.keys', data: '' },
        ],
      },
      {
        // Opaque directory: hides everything below /app/config from lower layers.
        createdBy: '/bin/sh -c mv /app/config.prod /app/config',
        entries: [
          { path: 'app/config/', type: 'dir', mode: 0o755 },
          { path: 'app/config/.wh..wh..opq', data: '' },
          { path: 'app/config/app.yaml', data: 'server:\n  port: 8080\n' },
          // A secret added in the same layer as the opaque marker stays visible.
          { path: 'app/config/runtime.env', data: 'GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' },
        ],
      },
      {
        // Overwrite a file in place: the old bytes remain in the lower layer.
        createdBy: '/bin/sh -c echo "path=/srv" > /etc/app.conf',
        entries: [
          { path: 'etc/app.conf', data: 'path=/srv\n', mode: 0o644 },
        ],
      },
      {
        // The key ends up in the layer *and* in the history record.
        createdBy: '/bin/sh -c export STRIPE_KEY=sk_live_51H8XyzABCDEFghijklmnop && echo "password=correct-horse-battery" > /app/secrets.txt',
        entries: [{ path: 'app/secrets.txt', data: 'password=correct-horse-battery\n', mode: 0o600 }],
      },
      {
        createdBy: '/bin/sh -c rm /app/secrets.txt',
        entries: [{ path: 'app/.wh.secrets.txt', data: '' }],
      },
    ],
    env: [
      'PATH=/usr/local/bin:/usr/bin:/bin',
      'NODE_ENV=production',
      // A classic metadata leak: the secret ships in the image config and is
      // visible via `docker inspect`, regardless of later layer deletions.
      'SENDGRID_API_KEY=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',
      'FEATURE_FLAGS=beta,metrics',
    ],
  };
}

/**
 * NOTE: the credentials in this builder are published documentation examples
 * (AWS "EXAMPLE" keys, Stripe's public test key format, and hand-made values).
 * They are not live credentials. The scanner's own tests scan this file's
 * *output*, so the literals here are fixtures, not leaks.
 */
