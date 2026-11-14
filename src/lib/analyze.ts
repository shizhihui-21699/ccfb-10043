import type { Layer, ImageModel, FileVersion, GhostPath } from './image.ts';
import { readVersionBytes } from './image.ts';
import type { SecretCategory, Severity } from './rules.ts';
import { scanText, pathFindings, pathHeuristicHit, redactCommand } from './rules.ts';
import { decodeText, truncate } from './util.ts';

export interface Finding {
  /** Stable id: fingerprint + location, for the report and UI. */
  id: string;
  path: string;
  /** Layer whose bytes contain the secret. */
  layer: number;
  tarIndex: number;
  /** Whether the file is reachable from the final filesystem. */
  visible: boolean;
  reason: 'visible' | 'deleted' | 'overwritten';
  /** Whiteout/opaque layer that removed it, for deleted files. */
  deletedInLayer?: number;
  deletionReason?: string;
  ruleId: string;
  ruleName: string;
  category: SecretCategory;
  severity: Severity;
  value: string;
  line?: number;
  context?: string;
  fingerprint: string;
  fileSize: number;
  fileMode: number;
  /** History step (Dockerfile instruction) that introduced the layer. */
  historyIndex?: number;
  createdBy?: string;
  created?: string;
  /**
   * Where the secret was found. `file` for layer contents, `config-env` /
   * `config-label` / `history` for image metadata that ships with the image
   * but lives outside any layer.
   */
  source?: FindingSource;
}

export type FindingSource = 'file' | 'config-env' | 'config-label' | 'history';

export interface ScanStats {
  scannedFiles: number;
  scannedBytes: number;
  skippedBinary: number;
  skippedLarge: number;
  layers: number;
  durationMs: number;
}

export interface ScanReport {
  image: string;
  generatedAt: string;
  imageCreated?: string;
  architecture?: string;
  os?: string;
  findings: Finding[];
  stats: ScanStats;
  warnings: string[];
  /** Per-layer summary used by the viewer. */
  layerSummaries: LayerSummary[];
  ghosts: GhostSummary[];
  history: HistorySummary[];
  /** Metadata findings (ENV, labels, history) grouped for the viewer. */
  configFindings: ConfigFinding[];
}

export interface ConfigFinding {
  /** `env`, `label`, or `history`. */
  kind: 'env' | 'label' | 'history';
  /** Variable name, label key, or history index. */
  key: string;
  /** Always masked: the report may be shared without leaking the value. */
  maskedValue: string;
  /** The full metadata value the secret was found in, masked. */
  maskedSource: string;
  ruleId: string;
  ruleName: string;
  category: SecretCategory;
  severity: Severity;
  fingerprint: string;
}

export interface LayerSummary {
  index: number;
  digest?: string;
  diffId?: string;
  size?: number;
  uncompressedSize: number;
  entryCount: number;
  whiteoutCount: number;
  deletedFileCount: number;
  createdAt?: string;
  createdBy?: string;
  historyIndex?: number;
  emptyLayer: boolean;
  /** Entries added by this layer, capped for report size. */
  files: LayerFileSummary[];
  /** Number of entries omitted from `files` by the cap. */
  filesOmitted: number;
}

export interface LayerFileSummary {
  path: string;
  kind: 'file' | 'dir' | 'symlink' | 'hardlink' | 'device' | 'other';
  size: number;
  mode: number;
  linkname?: string;
  /** Currently reachable in the merged filesystem. */
  visible: boolean;
  /** Removed by a later layer (whiteout, opaque dir, or overwrite). */
  hidden?: boolean;
  hasSecrets: boolean;
}

/** Upper bound on file rows embedded per layer in the HTML report. */
const MAX_FILES_PER_LAYER = 2000;

export interface GhostSummary {
  path: string;
  reason: 'deleted' | 'overwritten';
  /** Newest hidden version's layer. */
  layer: number;
  versions: number;
  bytes: number;
  deletionLayer?: number;
  deletionReason?: string;
  hasSecrets: boolean;
}

export interface HistorySummary {
  index: number;
  createdAt?: string;
  createdBy?: string;
  empty: boolean;
  layerIndex?: number;
}

export interface AnalyzeOptions {
  /** Only scan ghosts (files unreachable in the final image). Default false. */
  ghostsOnly?: boolean;
  /** Minimum severity to keep. */
  minSeverity?: Severity;
  /** Skip files larger than this. Default 4 MiB. */
  maxFileBytes?: number;
  /** Mask values in the output. Default true. */
  mask?: boolean;
  /** Treat path-only heuristics as findings too. */
  pathRules?: boolean;
  log?: (msg: string) => void;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024;

export function analyzeImage(model: ImageModel, options: AnalyzeOptions = {}): ScanReport {
  const started = performance.now();
  const log = options.log ?? (() => {});
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const mask = options.mask ?? true;
  const minSeverity = options.minSeverity ?? 'info';

  const findings: Finding[] = [];
  let scannedFiles = 0;
  let scannedBytes = 0;
  let skippedBinary = 0;
  let skippedLarge = 0;

  const decisionFor = (version: FileVersion): { visible: boolean; reason: Finding['reason'] } => {
    const rec = model.paths.get(version.path);
    if (!rec) return { visible: true, reason: 'visible' };
    const current = rec.current;
    if (current && current.layer === version.layer && current.tarIndex === version.tarIndex) {
      return { visible: true, reason: 'visible' };
    }
    return { visible: false, reason: current ? 'overwritten' : 'deleted' };
  };

  // Group every recorded version by layer so each layer's own bytes get
  // scanned. A secret can live in a layer even when a higher layer replaced
  // the file; `ghostsOnly` only limits what is reported.
  const versionsByLayer = new Map<number, FileVersion[]>();
  for (const rec of model.paths.values()) {
    for (const version of rec.versions) {
      if (version.kind !== 'file' && version.kind !== 'hardlink') continue;
      if (version.implicit) continue;
      let list = versionsByLayer.get(version.layer);
      if (!list) {
        list = [];
        versionsByLayer.set(version.layer, list);
      }
      list.push(version);
    }
  }

  for (const layer of model.layers) {
    const versions = versionsByLayer.get(layer.index) ?? [];
    for (const version of versions) {
      const decision = decisionFor(version);
      if (options.ghostsOnly && decision.visible) continue;

      if (version.dataLength === 0) {
        // Empty files can still be sensitive by name (.env, .npmrc, keys).
        if (options.pathRules !== false && pathHeuristicHit(version.path)) {
          for (const pf of pathFindings({ path: version.path, mode: version.mode }, false)) {
            findings.push(
              makeFinding(model, layer, version, {
                ruleId: pf.ruleId,
                ruleName: pf.ruleName,
                category: pf.category,
                severity: pf.severity,
                value: '',
                fingerprint: `${pf.ruleId}:${version.path}`,
                visible: decision.visible,
                reason: decision.reason,
                mask,
              }),
            );
          }
        }
        scannedFiles++;
        continue;
      }
      if (version.dataLength > maxFileBytes) {
        skippedLarge++;
        continue;
      }

      const bytes = readVersionBytes(model.layers, version);
      scannedBytes += bytes.length;
      const text = decodeText(bytes);
      if (text === null) {
        skippedBinary++;
        continue;
      }
      scannedFiles++;

      const { matches } = scanText(
        text,
        { path: version.path, mode: version.mode },
        { includeRaw: !mask },
      );
      for (const m of matches) {
        findings.push(
          makeFinding(model, layer, version, {
            ...m,
            visible: decision.visible,
            reason: decision.reason,
            mask,
          }),
        );
      }

      if (options.pathRules !== false && pathHeuristicHit(version.path)) {
        const already = new Set(matches.map((m) => m.category));
        for (const pf of pathFindings({ path: version.path, mode: version.mode }, false)) {
          if (already.has(pf.category)) continue;
          findings.push(
            makeFinding(model, layer, version, {
              ruleId: pf.ruleId,
              ruleName: pf.ruleName,
              category: pf.category,
              severity: pf.severity,
              value: '',
              fingerprint: `${pf.ruleId}:${version.path}`,
              visible: decision.visible,
              reason: decision.reason,
              mask,
            }),
          );
        }
      }
    }
    log(`scanned layer ${layer.index}: ${layer.entries.length} entries`);
  }

  // ---- image metadata: ENV, labels, and history commands ----
  // These ship with every container run, so a secret here is visible even
  // after the file that carried it has been deleted from the layers.
  const configFindings: ConfigFinding[] = [];
  const scanConfigValue = (
    kind: ConfigFinding['kind'],
    key: string,
    value: string,
    extraPath: string,
  ): void => {
    // Always scan masked: these values are echoed into reports and the web UI.
    const { matches } = scanText(value, { path: extraPath }, { includeRaw: false });
    if (matches.length === 0) return;
    // The whole metadata value goes through command-level redaction, because a
    // context window can contain a second secret the content rules missed.
    const maskedSource = redactCommand(value);
    for (const m of matches) {
      configFindings.push({
        kind,
        key,
        ruleId: m.ruleId,
        ruleName: m.ruleName,
        category: m.category,
        severity: m.severity,
        maskedValue: m.value,
        maskedSource,
        fingerprint: m.fingerprint,
      });
    }
  };

  for (const env of model.config.config?.Env ?? []) {
    const eq = env.indexOf('=');
    if (eq <= 0) continue;
    scanConfigValue('env', env.slice(0, eq), env.slice(eq + 1), `ENV ${env.slice(0, eq)}`);
  }
  for (const [key, value] of Object.entries(model.config.config?.Labels ?? {})) {
    if (typeof value !== 'string') continue;
    scanConfigValue('label', key, value, `LABEL ${key}`);
  }
  for (let i = 0; i < (model.config.history?.length ?? 0); i++) {
    const h = model.config.history![i]!;
    if (!h.created_by || h.empty_layer) continue;
    scanConfigValue('history', String(i), h.created_by, `history[${i}]`);
  }

  const filtered = dedupe(findings)
    .filter((f) => SEVERITY_RANK[f.severity] <= SEVERITY_RANK[minSeverity])
    .sort(compareFindings);

  const layerSummaries = summarizeLayers(model, dedupe(findings));
  const ghosts = summarizeGhosts(model, filtered);
  const history = summarizeHistory(model);

  const durationMs = Math.round(performance.now() - started);
  return {
    image: model.name,
    generatedAt: new Date().toISOString(),
    ...(model.config.created ? { imageCreated: model.config.created } : {}),
    ...(model.config.architecture ? { architecture: model.config.architecture } : {}),
    ...(model.config.os ? { os: model.config.os } : {}),
    findings: filtered,
    stats: {
      scannedFiles,
      scannedBytes,
      skippedBinary,
      skippedLarge,
      layers: model.layers.length,
      durationMs,
    },
    warnings: model.warnings,
    layerSummaries,
    ghosts,
    history,
    configFindings: configFindings.filter(
      (c) => SEVERITY_RANK[c.severity] <= SEVERITY_RANK[minSeverity],
    ),
  };
}

interface MakeFindingInput {
  ruleId: string;
  ruleName: string;
  category: SecretCategory;
  severity: Severity;
  value: string;
  fingerprint: string;
  line?: number;
  context?: string;
  visible: boolean;
  reason: Finding['reason'];
  mask: boolean;
}

function makeFinding(
  model: ImageModel,
  layer: Layer,
  version: FileVersion,
  input: MakeFindingInput,
): Finding {
  const del = model.paths.get(version.path)?.deletions;
  const lastDeletion = del && del.length > 0 ? del[del.length - 1] : undefined;
  const history = layer.history;
  return {
    id: `${input.fingerprint}:${version.path}:${version.layer}:${version.tarIndex}`,
    path: version.path,
    layer: version.layer,
    tarIndex: version.tarIndex,
    visible: input.visible,
    reason: input.reason,
    ...(lastDeletion ? { deletedInLayer: lastDeletion.layer, deletionReason: lastDeletion.reason } : {}),
    ruleId: input.ruleId,
    ruleName: input.ruleName,
    category: input.category,
    severity: input.severity,
    value: input.value,
    ...(input.line !== undefined ? { line: input.line } : {}),
    ...(input.context !== undefined ? { context: truncate(input.context, 220) } : {}),
    fingerprint: input.fingerprint,
    fileSize: version.size,
    fileMode: version.mode,
    ...(layer.historyIndex !== undefined ? { historyIndex: layer.historyIndex } : {}),
    ...(history?.created_by ? { createdBy: redactCommand(history.created_by) } : {}),
    ...(history?.created ? { created: history.created } : {}),
  };
}

function dedupe(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.path}:${f.layer}:${f.ruleId}:${f.fingerprint}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, f);
      continue;
    }
    // Prefer the copy that is still visible: a file whose content survived is
    // a louder problem than one that a later layer deleted.
    if (!prev.visible && f.visible) byKey.set(key, f);
  }
  return [...byKey.values()];
}

function compareFindings(a: Finding, b: Finding): number {
  const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sev !== 0) return sev;
  if (a.visible !== b.visible) return a.visible ? -1 : 1;
  if (a.layer !== b.layer) return a.layer - b.layer;
  return a.path.localeCompare(b.path);
}

function summarizeLayers(model: ImageModel, findings: Finding[]): LayerSummary[] {
  const secretPaths = new Set(findings.map((f) => `${f.layer}:${f.path}`));
  return model.layers.map((layer) => {
    // Only entries that are real files (not whiteout markers) are listed.
    const listed = layer.entries.filter((e) => !isWhiteoutPath(e.path));
    const files = listed.slice(0, MAX_FILES_PER_LAYER).map((e) => {
      const rec = model.paths.get(e.path);
      const current = rec?.current;
      const isCurrent =
        current !== undefined && current.layer === layer.index && current.tarIndex === e.tarIndex;
      const file: LayerFileSummary = {
        path: e.path,
        kind: e.kind,
        size: e.entry.size,
        mode: e.entry.mode,
        visible: isCurrent,
        hasSecrets: secretPaths.has(`${layer.index}:${e.path}`),
      };
      if (!isCurrent) file.hidden = true;
      if (e.entry.linkname) file.linkname = e.entry.linkname;
      return file;
    });
    return {
      index: layer.index,
      ...(layer.blob.digest ? { digest: layer.blob.digest } : {}),
      ...(layer.blob.diffId ? { diffId: layer.blob.diffId } : {}),
      ...(layer.blob.size !== undefined ? { size: layer.blob.size } : {}),
      uncompressedSize: layer.uncompressedSize,
      entryCount: layer.entries.length,
      whiteoutCount: layer.whiteouts.length,
      deletedFileCount: model.ghosts.filter((g) => g.deletion?.layer === layer.index).length,
      ...(layer.history?.created ? { createdAt: layer.history.created } : {}),
      ...(layer.history?.created_by
        ? { createdBy: redactCommand(layer.history.created_by) }
        : {}),
      ...(layer.historyIndex !== undefined ? { historyIndex: layer.historyIndex } : {}),
      emptyLayer: !layer.history || layer.entries.length === 0,
      files,
      filesOmitted: Math.max(0, listed.length - files.length),
    };
  });
}

function isWhiteoutPath(path: string): boolean {
  const base = path.slice(path.lastIndexOf('/') + 1);
  return base.startsWith('.wh.');
}

function summarizeGhosts(model: ImageModel, findings: Finding[]): GhostSummary[] {
  const withSecrets = new Set(findings.filter((f) => !f.visible).map((f) => f.path));
  return model.ghosts.map((g: GhostPath) => {
    const newest = g.hiddenVersions[0]!;
    return {
      path: g.path,
      reason: g.reason,
      layer: newest.layer,
      versions: g.hiddenVersions.length,
      bytes: newest.dataLength,
      ...(g.deletion ? { deletionLayer: g.deletion.layer, deletionReason: g.deletion.reason } : {}),
      hasSecrets: withSecrets.has(g.path),
    };
  });
}

function summarizeHistory(model: ImageModel): HistorySummary[] {
  const history = model.config.history ?? [];
  return history.map((h, index) => {
    const layer = model.layers.find((l) => l.historyIndex === index);
    return {
      index,
      ...(h.created ? { createdAt: h.created } : {}),
      ...(h.created_by ? { createdBy: redactCommand(h.created_by) } : {}),
      empty: h.empty_layer === true,
      ...(layer ? { layerIndex: layer.index } : {}),
    };
  });
}
