import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { FileIO, MemoryIO } from './io.ts';
import type { BlobIO } from './io.ts';
import { indexTar, readIndexedEntry } from './tarindex.ts';
import type { TarEntry } from './tar.ts';
import type { ImageConfig, LayerBlob, Layer, ImageModel } from './image.ts';
import { buildLayer, mergeLayers } from './image.ts';
import { materializeLayer, makeWorkDir } from './stream.ts';
import { basename } from './util.ts';

export interface LoadOptions {
  /** Keep temp files after loading (debugging). */
  keepTemp?: boolean;
  /** Skip layer bodies larger than this (bytes). Default 8 GiB. */
  maxLayerBytes?: number;
  log?: (msg: string) => void;
}

export class ImageLoadError extends Error {}

export type CleanableModel = ImageModel & { __cleanup?: () => void };

export function cleanupModel(model: ImageModel): void {
  const fn = (model as CleanableModel).__cleanup;
  if (fn) fn();
}

const DEFAULT_MAX_LAYER = 8 * 1024 ** 3;

// ---------------------------------------------------------------------------
// docker save layout
// ---------------------------------------------------------------------------

interface DockerSaveManifestEntry {
  Config: string;
  RepoTags?: string[] | null;
  Layers: string[];
  Parent?: string;
}

function normalizeTarName(name: string): string {
  return name.replace(/^\.\//, '');
}

function readTarFile(io: BlobIO, entries: Map<string, TarEntry>, name: string): Buffer | null {
  const entry = entries.get(name);
  return entry ? readIndexedEntry(io, entry) : null;
}

/**
 * Load an image from a tar produced by `docker save` (or
 * `podman save --format docker-archive`).
 *
 * The outer tar is indexed with random access, so the archive never has to fit
 * in memory. Each layer region is streamed through its decompressor into a temp
 * file, which is then indexed and discarded with the model.
 */
export async function loadDockerSave(path: string, options: LoadOptions = {}): Promise<ImageModel> {
  const log = options.log ?? (() => {});
  const outerSize = statSync(path).size;
  const outer = new FileIO(path);
  const warnings: string[] = [];

  try {
    log(`indexing ${basename(path)} (${outerSize} bytes)`);
    const { entries: tarEntries, terminated } = indexTar(outer);
    if (!terminated && tarEntries.length > 0) {
      warnings.push('outer archive is missing its end-of-archive marker (truncated save?)');
    }
    const byName = new Map<string, TarEntry>();
    for (const e of tarEntries) byName.set(normalizeTarName(e.path), e);

    const manifestRaw = readDockerManifest(byName, outer);
    if (!manifestRaw) {
      throw new ImageLoadError(
        'this archive has no manifest.json; it does not look like a `docker save` output',
      );
    }
    const manifests = JSON.parse(manifestRaw.toString('utf8')) as DockerSaveManifestEntry[];
    if (!Array.isArray(manifests) || manifests.length === 0) {
      throw new ImageLoadError('manifest.json is empty');
    }
    const manifest = pickManifest(manifests);

    const configEntry = byName.get(normalizeTarName(manifest.Config));
    if (!configEntry) throw new ImageLoadError(`config blob ${manifest.Config} is missing`);
    const config = JSON.parse(readIndexedEntry(outer, configEntry).toString('utf8')) as ImageConfig;

    return await assembleLayersFromSave(path, outer, byName, manifest, config, warnings, options);
  } finally {
    outer.close?.();
  }
}

async function assembleLayersFromSave(
  path: string,
  _outer: BlobIO,
  byName: Map<string, TarEntry>,
  manifest: DockerSaveManifestEntry,
  config: ImageConfig,
  warnings: string[],
  options: LoadOptions,
): Promise<ImageModel> {
  const log = options.log ?? (() => {});
  const workDirRef = makeWorkDir();
  const cleanups: Array<() => void> = [];
  const keepTemp = options.keepTemp ?? false;
  const finalCleanup = (): void => {
    for (const c of cleanups) c();
    if (keepTemp) log(`temp files kept in ${workDirRef.dir}`);
    else workDirRef.cleanup();
  };

  try {
    const layers: Layer[] = [];
    const maxLayer = options.maxLayerBytes ?? DEFAULT_MAX_LAYER;
    for (let i = 0; i < manifest.Layers.length; i++) {
      const layerName = normalizeTarName(manifest.Layers[i]!);
      const entry = byName.get(layerName);
      if (!entry) {
        warnings.push(`layer ${i} (${layerName}) is missing from the archive`);
        layers.push(emptyLayer(i, { sourceLabel: layerName }));
        continue;
      }
      if (entry.size > maxLayer) {
        warnings.push(
          `layer ${i} (${layerName}) is ${entry.size} bytes; skipped because it exceeds --max-layer-bytes`,
        );
        layers.push(emptyLayer(i, { sourceLabel: layerName, size: entry.size }));
        continue;
      }
      log(`layer ${i}: ${layerName} (${entry.size} bytes)`);
      const materialized = await materializeLayer(
        path,
        entry.dataOffset,
        entry.dataLength,
        workDirRef.dir,
      );
      if (!materialized.ok) {
        // One unreadable layer must not sink the scan: report it and carry on.
        warnings.push(`layer ${i} (${layerName}) skipped: ${materialized.message}`);
        layers.push(emptyLayer(i, { sourceLabel: layerName, size: entry.size }));
        continue;
      }
      cleanups.push(materialized.cleanup);
      const raw = indexTar(materialized.io);
      const blob: LayerBlob = {
        diffId: config.rootfs?.diff_ids?.[i],
        size: entry.size,
        blob: materialized.io,
        sourceLabel: layerName,
      };
      layers.push(
        buildLayer(i, blob, raw.entries, materialized.uncompressedSize, {
          truncated: !raw.terminated,
        }),
      );
    }
    return finalizeModel(imageName(manifest), config, layers, warnings, finalCleanup);
  } catch (err) {
    finalCleanup();
    throw err;
  }
}

function finalizeModel(
  name: string,
  config: ImageConfig,
  layers: Layer[],
  warnings: string[],
  cleanup: () => void,
): ImageModel {
  attachHistory(layers, config);
  const merged = mergeLayers(layers, warnings);
  for (const layer of layers) if (layer.warning) warnings.push(layer.warning);
  const model: ImageModel = {
    name,
    config,
    layers,
    paths: merged.paths,
    finalFs: merged.finalFs,
    ghosts: merged.ghosts,
    warnings,
  };
  Object.defineProperty(model, '__cleanup', { value: cleanup, enumerable: false });
  return model;
}

function emptyLayer(index: number, blob: Partial<LayerBlob>): Layer {
  return {
    index,
    blob: { ...blob, blob: new MemoryIO(Buffer.alloc(0)) },
    entries: [],
    whiteouts: [],
    whiteoutEntries: [],
    uncompressedSize: 0,
  };
}

function readDockerManifest(byName: Map<string, TarEntry>, io: BlobIO): Buffer | null {
  const direct = readTarFile(io, byName, 'manifest.json');
  if (direct) return direct;

  // Older `docker save` outputs only carry a `repositories` file.
  const repos = readTarFile(io, byName, 'repositories');
  if (repos) {
    const synthesized = synthesizeFromRepositories(repos, io, byName);
    if (synthesized.length > 0) return Buffer.from(JSON.stringify(synthesized), 'utf8');
  }
  return null;
}

function synthesizeFromRepositories(
  reposRaw: Buffer,
  io: BlobIO,
  byName: Map<string, TarEntry>,
): DockerSaveManifestEntry[] {
  const parsed = JSON.parse(reposRaw.toString('utf8')) as Record<string, Record<string, string>>;
  const out: DockerSaveManifestEntry[] = [];
  for (const [repo, tags] of Object.entries(parsed)) {
    for (const [tag, topLayer] of Object.entries(tags)) {
      // Each layer directory has a `json` file naming its parent.
      const layers: string[] = [];
      let current: string | undefined = topLayer;
      const seen = new Set<string>();
      while (current && !seen.has(current)) {
        seen.add(current);
        layers.unshift(`${current}/layer.tar`);
        const meta = readTarFile(io, byName, `${current}/json`);
        if (!meta) break;
        try {
          const parsedMeta = JSON.parse(meta.toString('utf8')) as { parent?: string };
          current = parsedMeta.parent;
        } catch {
          current = undefined;
        }
      }
      out.push({
        Config: `${topLayer}/json`,
        RepoTags: [`${repo}:${tag}`],
        Layers: layers,
      });
    }
  }
  return out;
}

function pickManifest(manifests: DockerSaveManifestEntry[]): DockerSaveManifestEntry {
  return manifests.find((m) => m.RepoTags && m.RepoTags.length > 0) ?? manifests[0]!;
}

function imageName(manifest: DockerSaveManifestEntry): string {
  const tag = manifest.RepoTags?.[0];
  if (tag && tag !== '<none>:<none>') return tag;
  return manifest.Config.replace(/\/json$/, '') || 'image';
}

export function attachHistory(layers: Layer[], config: ImageConfig): void {
  const history = config.history ?? [];
  let layerIdx = 0;
  for (let i = 0; i < history.length; i++) {
    const h = history[i]!;
    if (h.empty_layer) continue;
    const layer = layers[layerIdx];
    if (!layer) break;
    layer.history = h;
    layer.historyIndex = i;
    h.layerIndex = layerIdx;
    layerIdx++;
  }
}

// ---------------------------------------------------------------------------
// OCI image layout directory
// ---------------------------------------------------------------------------

interface OciDescriptor {
  mediaType?: string;
  digest: string;
  size?: number;
  platform?: { architecture?: string; os?: string; variant?: string };
  annotations?: Record<string, string>;
}

interface OciIndex {
  mediaTypes?: string[];
  manifests?: OciDescriptor[];
}

interface OciManifest {
  mediaType?: string;
  config: OciDescriptor;
  layers: OciDescriptor[];
}

export function isOciLayout(path: string): boolean {
  return (
    existsSync(join(path, 'oci-layout')) &&
    existsSync(join(path, 'index.json')) &&
    existsSync(join(path, 'blobs', 'sha256'))
  );
}

function digestToPath(dir: string, digest: string): string {
  const [algo = 'sha256', bare = ''] = digest.split(':');
  return join(dir, 'blobs', algo, bare);
}

export interface ResolvedOci {
  manifest: OciManifest;
  config: ImageConfig;
  name: string;
  layers: Array<{ descriptor: OciDescriptor; path: string }>;
}

export function resolveOciLayout(dir: string): ResolvedOci {
  const indexPath = join(dir, 'index.json');
  const index = JSON.parse(readFileSync(indexPath, 'utf8')) as OciIndex;
  const first = index.manifests?.[0];
  if (!first) throw new ImageLoadError(`no manifests in ${indexPath}`);

  const loadJson = <T>(digest: string): T =>
    JSON.parse(readFileSync(digestToPath(dir, digest), 'utf8')) as T;

  let descriptor: OciDescriptor = first;
  let manifest: OciManifest | undefined;
  for (let depth = 0; depth < 4; depth++) {
    if (
      descriptor.mediaType?.includes('image.index') ||
      descriptor.mediaType?.includes('manifest.list')
    ) {
      const nested = loadJson<OciIndex>(descriptor.digest);
      const pick =
        nested.manifests?.find(
          (m) => m.platform?.os === 'linux' && m.platform?.architecture === process.arch,
        ) ??
        nested.manifests?.find((m) => m.platform?.os === 'linux') ??
        nested.manifests?.[0];
      if (!pick) throw new ImageLoadError('nested index has no manifests');
      descriptor = pick;
      continue;
    }
    manifest = loadJson<OciManifest>(descriptor.digest);
    break;
  }
  if (!manifest) throw new ImageLoadError('could not resolve an image manifest');

  const config = loadJson<ImageConfig>(manifest.config.digest);
  const layers = manifest.layers.map((layer) => {
    const p = digestToPath(dir, layer.digest);
    if (!existsSync(p)) throw new ImageLoadError(`missing layer blob ${layer.digest}`);
    return { descriptor: layer, path: p };
  });
  const name =
    descriptor.annotations?.['org.opencontainers.image.ref.name'] ??
    descriptor.annotations?.['io.containerd.image.name'] ??
    `${basename(dir)}@${manifest.config.digest.replace(/^sha256:/, '').slice(0, 12)}`;

  return { manifest, config, name, layers };
}

export async function loadOciLayout(dir: string, options: LoadOptions = {}): Promise<ImageModel> {
  const log = options.log ?? (() => {});
  const warnings: string[] = [];
  const resolved = resolveOciLayout(dir);

  const workDirRef = makeWorkDir();
  const cleanups: Array<() => void> = [];
  const keepTemp = options.keepTemp ?? false;
  const finalCleanup = (): void => {
    for (const c of cleanups) c();
    if (keepTemp) log(`temp files kept in ${workDirRef.dir}`);
    else workDirRef.cleanup();
  };

  try {
    const layers: Layer[] = [];
    const maxLayer = options.maxLayerBytes ?? DEFAULT_MAX_LAYER;
    for (let i = 0; i < resolved.layers.length; i++) {
      const { descriptor, path: blobPath } = resolved.layers[i]!;
      const size = statSync(blobPath).size;
      if (size > maxLayer) {
        warnings.push(`layer ${i} is ${size} bytes; skipped because it exceeds --max-layer-bytes`);
        layers.push(emptyLayer(i, { sourceLabel: basename(blobPath), size }));
        continue;
      }
      log(`layer ${i}: ${descriptor.digest} (${size} bytes)`);
      const materialized = await materializeLayer(blobPath, 0, size, workDirRef.dir);
      if (!materialized.ok) {
        warnings.push(`layer ${i} (${descriptor.digest}) skipped: ${materialized.message}`);
        layers.push(emptyLayer(i, { sourceLabel: basename(blobPath), size }));
        continue;
      }
      cleanups.push(materialized.cleanup);
      const raw = indexTar(materialized.io);
      const blob: LayerBlob = {
        digest: descriptor.digest,
        diffId: resolved.config.rootfs?.diff_ids?.[i],
        size,
        blob: materialized.io,
        mediaType: descriptor.mediaType,
        sourceLabel: basename(blobPath),
      };
      layers.push(
        buildLayer(i, blob, raw.entries, materialized.uncompressedSize, {
          truncated: !raw.terminated,
        }),
      );
    }
    return finalizeModel(resolved.name, resolved.config, layers, warnings, finalCleanup);
  } catch (err) {
    finalCleanup();
    throw err;
  }
}
