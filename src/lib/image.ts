import { basename, dirname, isUnder, normalizeArchivePath } from './util.ts';
import type { TarEntry } from './tar.ts';
import type { BlobIO } from './io.ts';

export type FileKind = 'file' | 'dir' | 'symlink' | 'hardlink' | 'device' | 'other';

export interface ImageHistoryEntry {
  created?: string;
  created_by?: string;
  comment?: string;
  author?: string;
  empty_layer?: boolean;
  /** Index into `layers` for non-empty history entries; set during load. */
  layerIndex?: number;
}

export interface ImageConfig {
  architecture?: string;
  os?: string;
  variant?: string;
  created?: string;
  author?: string;
  config?: {
    Env?: string[];
    Cmd?: string[];
    Entrypoint?: string[];
    WorkingDir?: string;
    User?: string;
    Labels?: Record<string, string>;
    ExposedPorts?: Record<string, unknown>;
    [key: string]: unknown;
  };
  rootfs?: { type?: string; diff_ids?: string[] };
  history?: ImageHistoryEntry[];
  [key: string]: unknown;
}

export interface LayerBlob {
  /** Digest as recorded by the image (sha256:...). */
  digest?: string;
  /** Uncompressed diff id (sha256:...) when known. */
  diffId?: string;
  size?: number;
  /** Compressed blob reader. */
  blob: BlobIO;
  mediaType?: string;
  /** Human-readable label, e.g. the file name the blob came from. */
  sourceLabel?: string;
}

export interface LayerEntry {
  /** Index into the image's layer list. */
  layer: number;
  entry: TarEntry;
  /** Normalised path (leading slash removed). */
  path: string;
  kind: FileKind;
  tarIndex: number;
}

export type WhiteoutKind = 'file' | 'opaque';

export interface Whiteout {
  kind: WhiteoutKind;
  /** Directory holding the whiteout marker. */
  dir: string;
  /** Target path being hidden; for opaque, the directory itself. */
  path: string;
  entryPath: string;
}

export interface Layer {
  index: number;
  blob: LayerBlob;
  /** All non-whiteout entries. */
  entries: LayerEntry[];
  whiteouts: Whiteout[];
  /** Whiteout marker entries, retained for provenance display. */
  whiteoutEntries: LayerEntry[];
  /** Decompressed archive size in bytes. */
  uncompressedSize: number;
  truncated?: boolean;
  warning?: string;
  /** Compose history step that produced this layer. */
  history?: ImageHistoryEntry;
  historyIndex?: number;
}

export type FinalState = 'present' | 'deleted';

export interface Deletion {
  layer: number;
  reason: 'whiteout' | 'opaque' | 'replaced-by-dir' | 'replaced-by-other-type';
}

export interface FileVersion {
  layer: number;
  /** Tar entry index within the layer; -1 for an implicit parent directory. */
  tarIndex: number;
  path: string;
  kind: FileKind;
  mode: number;
  size: number;
  mtime: number;
  linkname?: string;
  /**
   * Layer whose blob holds the bytes. Usually the same as `layer`, but a
   * hardlink can point at a file from a lower layer.
   */
  dataLayer?: number;
  /** Byte offset and length inside the uncompressed layer blob. */
  dataOffset: number;
  dataLength: number;
  /** True for versions that are not the one visible in the final filesystem. */
  hidden: boolean;
  /** True for parent directories synthesised because a layer omitted them. */
  implicit?: boolean;
}

export interface PathRecord {
  path: string;
  versions: FileVersion[];
  deletions: Deletion[];
  /** The version visible in the merged filesystem, if any. */
  current?: FileVersion;
  finalState: FinalState;
}

export type GhostReason = 'deleted' | 'overwritten';

export interface GhostPath {
  path: string;
  reason: GhostReason;
  /** Every hidden version, newest first. */
  hiddenVersions: FileVersion[];
  deletion?: Deletion;
}

export interface ImageModel {
  name: string;
  config: ImageConfig;
  layers: Layer[];
  paths: Map<string, PathRecord>;
  finalFs: Map<string, FileVersion>;
  ghosts: GhostPath[];
  warnings: string[];
}

const WHITEOUT_PREFIX = '.wh.';
const OPAQUE_MARKER = '.wh..wh..opq';
const BOOKKEEPING = new Set(['.wh..wh.plnk', '.wh..wh.orph', '.wh..wh.aufs', '.wh..wh.utsch']);

export function classifyEntry(entry: TarEntry): FileKind {
  switch (entry.type) {
    case 'file':
      return 'file';
    case 'dir':
      return 'dir';
    case 'symlink':
      return 'symlink';
    case 'hardlink':
      return 'hardlink';
    case 'char':
    case 'block':
    case 'fifo':
      return 'device';
    default:
      return 'other';
  }
}

export function isWhiteoutEntry(path: string): boolean {
  return basename(path).startsWith(WHITEOUT_PREFIX);
}

export function whiteoutFromEntry(path: string): Whiteout | null {
  const name = basename(path);
  const dir = dirname(path);
  if (name === OPAQUE_MARKER) return { kind: 'opaque', dir, path: dir, entryPath: path };
  if (BOOKKEEPING.has(name) || !name.startsWith(WHITEOUT_PREFIX)) return null;
  const target = name.slice(WHITEOUT_PREFIX.length);
  if (target === '') return null;
  const targetPath = normalizeArchivePath(dir === '' ? target : `${dir}/${target}`);
  if (targetPath === null || targetPath === '') return null;
  return { kind: 'file', dir, path: targetPath, entryPath: path };
}

export function buildLayer(
  index: number,
  blob: LayerBlob,
  raw: TarEntry[],
  uncompressedSize: number,
  options: { truncated?: boolean } = {},
): Layer {
  const entries: LayerEntry[] = [];
  const whiteouts: Whiteout[] = [];
  const whiteoutEntries: LayerEntry[] = [];
  let warning: string | undefined;

  for (let tarIndex = 0; tarIndex < raw.length; tarIndex++) {
    const entry = raw[tarIndex]!;
    const path = normalizeArchivePath(entry.path);
    if (path === null) {
      warning = `layer ${index}: skipped unsafe path ${JSON.stringify(entry.path)}`;
      continue;
    }
    if (path === '') continue; // the root directory entry carries no file
    const le: LayerEntry = { layer: index, entry, path, kind: classifyEntry(entry), tarIndex };

    if (isWhiteoutEntry(path)) {
      whiteoutEntries.push(le);
      const wo = whiteoutFromEntry(path);
      if (wo) whiteouts.push(wo);
      else {
        // Bookkeeping markers still count as additions in the archive but are
        // not files in the merged filesystem.
        entries.push(le);
      }
      continue;
    }
    entries.push(le);
  }

  if (options.truncated) warning = `layer ${index}: archive appears truncated`;
  const layer: Layer = {
    index,
    blob,
    entries,
    whiteouts,
    whiteoutEntries,
    uncompressedSize,
  };
  if (options.truncated) layer.truncated = true;
  if (warning) layer.warning = warning;
  return layer;
}

/** Resolve the on-disk identity of an entry, following hardlinks in-layer. */
export function resolveVersion(layer: Layer, le: LayerEntry): FileVersion {
  let kind = le.kind;
  let dataOffset = le.entry.dataOffset;
  let dataLength = le.entry.dataLength;
  let linkname: string | undefined;

  if (kind === 'symlink') {
    linkname = le.entry.linkname;
    dataLength = 0;
  } else if (kind === 'hardlink') {
    linkname = le.entry.linkname;
    const targetPath = normalizeArchivePath(le.entry.linkname);
    const target =
      targetPath === null ? undefined : findEntryInLayer(layer, targetPath, le.tarIndex);
    if (target && target.kind === 'file') {
      dataOffset = target.entry.dataOffset;
      dataLength = target.entry.dataLength;
    } else {
      kind = 'other';
      dataLength = 0;
    }
  } else if (kind !== 'file') {
    dataLength = 0;
  }

  return {
    layer: layer.index,
    tarIndex: le.tarIndex,
    path: le.path,
    kind,
    mode: le.entry.mode,
    size: le.entry.size,
    mtime: le.entry.mtime,
    dataOffset,
    dataLength,
    hidden: false,
    ...(linkname !== undefined ? { linkname } : {}),
  };
}

export function findEntryInLayer(
  layer: Layer,
  path: string,
  beforeTarIndex = Number.POSITIVE_INFINITY,
): LayerEntry | undefined {
  let found: LayerEntry | undefined;
  for (const le of layer.entries) {
    if (le.path !== path || le.tarIndex >= beforeTarIndex) continue;
    found = le; // a layer can repeat a path; the last one wins
  }
  return found;
}

/**
 * Merge layers into a final filesystem and record what got hidden.
 *
 * OCI semantics: `.wh.<name>` hides a path (and its subtree) from lower
 * layers; `.wh..wh..opq` inside a directory hides every lower-layer entry
 * beneath that directory. Whiteouts apply only to lower layers, so entries
 * added in the same layer stay visible.
 */
export function mergeLayers(layers: Layer[], warnings: string[] = []): {
  paths: Map<string, PathRecord>;
  finalFs: Map<string, FileVersion>;
  ghosts: GhostPath[];
} {
  const paths = new Map<string, PathRecord>();
  const finalFs = new Map<string, FileVersion>();

  const recordFor = (path: string): PathRecord => {
    let rec = paths.get(path);
    if (!rec) {
      rec = { path, versions: [], deletions: [], finalState: 'deleted' };
      paths.set(path, rec);
    }
    return rec;
  };

  const deletePath = (path: string, layerIndex: number, reason: Deletion['reason']): void => {
    const rec = paths.get(path);
    if (!rec || rec.versions.length === 0) return;
    const live = finalFs.get(path);
    if (!live) return;
    live.hidden = true;
    finalFs.delete(path);
    rec.current = undefined;
    rec.finalState = 'deleted';
    rec.deletions.push({ layer: layerIndex, reason });
  };

  const under = (path: string, dir: string): boolean => isUnder(path, dir);

  for (const layer of layers) {
    // Whiteouts are applied first: they only affect lower layers.
    for (const wo of layer.whiteouts) {
      if (wo.kind === 'file') {
        deletePath(wo.path, layer.index, 'whiteout');
        for (const rec of paths.values()) {
          if (rec.path === wo.path || !under(rec.path, wo.path)) continue;
          deletePath(rec.path, layer.index, 'whiteout');
        }
      } else {
        for (const rec of paths.values()) {
          if (rec.path === wo.dir || !under(rec.path, wo.dir)) continue;
          if (!rec.versions.some((v) => v.layer < layer.index)) continue;
          deletePath(rec.path, layer.index, 'opaque');
        }
      }
    }

    for (const le of layer.entries) {
      if (isWhiteoutEntry(le.path)) continue; // bookkeeping marker
      const version = resolveVersion(layer, le);
      // A hardlink whose target lives in a lower layer: inherit that file's
      // bytes so the content is still scanned and attributed correctly.
      if (version.kind === 'other' && le.kind === 'hardlink' && version.linkname) {
        const targetPath = normalizeArchivePath(version.linkname);
        const targetVersion = targetPath === null ? undefined : finalFs.get(targetPath);
        if (targetVersion) {
          version.kind = 'file';
          version.dataLayer = targetVersion.dataLayer ?? targetVersion.layer;
          version.dataOffset = targetVersion.dataOffset;
          version.dataLength = targetVersion.dataLength;
          version.size = targetVersion.size;
        }
      }
      const rec = recordFor(le.path);
      const prev = finalFs.get(le.path);

      if (version.kind === 'dir' && prev && prev.kind !== 'dir') {
        deletePath(le.path, layer.index, 'replaced-by-dir');
      }
      if (version.kind !== 'dir' && prev && prev.kind === 'dir') {
        for (const child of paths.values()) {
          if (child.path !== le.path && under(child.path, le.path)) {
            deletePath(child.path, layer.index, 'replaced-by-other-type');
          }
        }
      }

      // Directories carry no content, and layers routinely re-list them, so
      // only real file versions are tracked as hidden.
      if (prev && prev.kind !== 'dir') prev.hidden = prev.layer <= layer.index;
      if (prev && prev.kind === 'dir') prev.hidden = false;

      rec.versions.push(version);
      finalFs.set(le.path, version);
      rec.current = version;
      rec.finalState = 'present';

      let parent = dirname(le.path);
      while (parent !== '') {
        if (!finalFs.has(parent)) {
          const parentRec = recordFor(parent);
          const implicit = implicitDirVersion(parent, layer.index);
          parentRec.versions.push(implicit);
          parentRec.current = implicit;
          parentRec.finalState = 'present';
          finalFs.set(parent, implicit);
        }
        parent = dirname(parent);
      }
    }
  }

  const ghosts: GhostPath[] = [];
  for (const rec of paths.values()) {
    if (rec.versions.length === 0) continue;
    // Only files leave bytes behind; a re-listed directory has nothing to leak.
    const hiddenVersions = rec.versions.filter((v) => v.hidden && v.kind !== 'dir').reverse();
    if (hiddenVersions.length === 0) continue;
    const deletion = rec.deletions[rec.deletions.length - 1];
    const reason: GhostReason = rec.current ? 'overwritten' : 'deleted';
    ghosts.push({
      path: rec.path,
      reason,
      hiddenVersions,
      ...(deletion ? { deletion } : {}),
    });
  }
  ghosts.sort((a, b) => a.path.localeCompare(b.path));

  if (paths.size > 2_000_000) warnings.push('model has more than 2M paths; analysis may be slow');
  return { paths, finalFs, ghosts };
}

function implicitDirVersion(path: string, layerIndex: number): FileVersion {
  return {
    layer: layerIndex,
    tarIndex: -1,
    path,
    kind: 'dir',
    mode: 0o755,
    size: 0,
    mtime: 0,
    dataOffset: 0,
    dataLength: 0,
    hidden: false,
    implicit: true,
  };
}

/** Read the bytes for a version from its layer blob. */
export function readVersionBytes(layers: Layer[], version: FileVersion, limit?: number): Buffer {
  // `hardlink` versions are resolved to `file` during merge; keep the guard
  // for callers that build versions directly.
  if (version.kind !== 'file' && version.kind !== 'hardlink') return Buffer.alloc(0);
  const layer = layers[version.dataLayer ?? version.layer];
  if (!layer) return Buffer.alloc(0);
  const n = limit === undefined ? version.dataLength : Math.min(limit, version.dataLength);
  if (n <= 0) return Buffer.alloc(0);
  return layer.blob.blob.read(version.dataOffset, n);
}

