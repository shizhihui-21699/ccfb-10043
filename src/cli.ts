import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { loadDockerSave, loadOciLayout, isOciLayout, cleanupModel } from './lib/load.ts';
import type { ImageModel } from './lib/image.ts';
import { analyzeImage } from './lib/analyze.ts';
import type { AnalyzeOptions } from './lib/analyze.ts';
import { renderHtmlReport, renderTextReport } from './report/html.ts';
import { createTar } from './lib/tarwrite.ts';
import { readVersionBytes } from './lib/image.ts';
import type { Severity } from './lib/rules.ts';
import { formatBytes } from './lib/util.ts';
import { writeFileSync as write } from 'node:fs';

const VERSION = '1.0.0';

const USAGE = `image-layer-audit ${VERSION} — find secrets hiding in container image layers

Usage:
  image-layer-audit scan <image> [options]
  image-layer-audit list <image> [options]
  image-layer-audit recover <image> [options]

  <image> is either a tar produced by \`docker save\` / \`podman save\`, or a
  directory containing an OCI image layout (oci-layout + index.json + blobs/).
  Docker is not required.

scan options:
  --html <file>         write a browsable HTML report
  --json <file>         write the full report as JSON (- for stdout)
  --text                print the text report (default when no output file)
  --ghosts-only         report only files that are not in the final filesystem
  --min-severity <s>    critical|high|medium|low|info (default: info)
  --raw                 do not mask secret values in the output
  --no-path-rules       ignore filename-only heuristics
  --max-file-bytes <n>  skip files larger than n bytes (default 4 MiB)
  --max-layer-bytes <n> skip layers larger than n bytes (default 8 GiB)
  --image <ref>         override the image name in the report
  --keep-temp           keep decompressed layer temp files
  -q, --quiet           suppress progress logging

list options:
  --layer <n>           list entries of one layer
  --deleted             list only whiteout-removed paths
  --json                machine-readable output

recover options:
  --out <dir>           destination directory (required)
  --layer <n>           recover only paths hidden in this layer
  --path <glob>         recover paths matching a substring/glob
  --dry-run             show what would be written

Global:
  -h, --help            show this help
  -V, --version         print version
`;

interface ParsedArgs {
  command: string;
  image?: string;
  flags: Map<string, string | boolean>;
  errors: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];
  const errors: string[] = [];
  const valueFlags = new Set([
    'html',
    'json',
    'min-severity',
    'max-file-bytes',
    'max-layer-bytes',
    'image',
    'layer',
    'out',
    'path',
  ]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '-h' || arg === '--help') {
      flags.set('help', true);
      continue;
    }
    if (arg === '-V' || arg === '--version') {
      flags.set('version', true);
      continue;
    }
    if (arg === '-q' || arg === '--quiet') {
      flags.set('quiet', true);
      continue;
    }
    if (arg.startsWith('--')) {
      const body = arg.slice(2);
      const eq = body.indexOf('=');
      if (eq >= 0) {
        const name = body.slice(0, eq);
        flags.set(name, body.slice(eq + 1));
        continue;
      }
      if (valueFlags.has(body)) {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith('--')) {
          errors.push(`--${body} requires a value`);
          continue;
        }
        flags.set(body, next);
        i++;
        continue;
      }
      flags.set(body, true);
      continue;
    }
    positional.push(arg);
  }
  return { command: positional[0] ?? '', image: positional[1], flags, errors };
}

function num(flags: Map<string, string | boolean>, name: string, fallback: number): number {
  const raw = flags.get(name);
  if (raw === undefined || raw === true) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

async function openImage(
  path: string,
  flags: Map<string, string | boolean>,
): Promise<ImageModel> {
  if (!existsSync(path)) throw new Error(`no such file or directory: ${path}`);
  const stat = statSync(path);
  const log = flags.get('quiet') ? undefined : (msg: string): void => console.error(`  ${msg}`);
  const options = {
    keepTemp: flags.get('keep-temp') === true,
    maxLayerBytes: num(flags, 'max-layer-bytes', 8 * 1024 ** 3),
    ...(log ? { log } : {}),
  };
  if (stat.isDirectory()) {
    if (!isOciLayout(path)) {
      throw new Error(`${path} is a directory but not an OCI image layout (needs oci-layout, index.json, blobs/)`);
    }
    console.error(`Loading OCI layout ${path}`);
    return loadOciLayout(path, options);
  }
  console.error(`Loading docker-save archive ${path}`);
  return loadDockerSave(path, options);
}

async function cmdScan(args: ParsedArgs): Promise<number> {
  if (!args.image) {
    console.error('scan: missing <image>');
    return 2;
  }
  const model = await openImage(resolve(args.image), args.flags);
  try {
    const override = args.flags.get('image');
    if (typeof override === 'string') model.name = override;

    const minSeverity = String(args.flags.get('min-severity') ?? 'info') as Severity;
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(minSeverity)) {
      console.error(`invalid --min-severity: ${minSeverity}`);
      return 2;
    }

    const analyzeOptions: AnalyzeOptions = {
      ghostsOnly: args.flags.get('ghosts-only') === true,
      minSeverity,
      mask: args.flags.get('raw') !== true,
      pathRules: args.flags.get('no-path-rules') !== true,
      maxFileBytes: num(args.flags, 'max-file-bytes', 4 * 1024 * 1024),
      ...(args.flags.get('quiet') ? {} : { log: (m: string): void => console.error(`  ${m}`) }),
    };
    const report = analyzeImage(model, analyzeOptions);

    let wrote = false;
    const htmlOut = args.flags.get('html');
    if (typeof htmlOut === 'string') {
      const file = resolve(htmlOut);
      mkdirSync(join(file, '..'), { recursive: true });
      writeFileSync(file, renderHtmlReport(report), 'utf8');
      console.error(`HTML report: ${file}`);
      wrote = true;
    }
    const jsonOut = args.flags.get('json');
    if (typeof jsonOut === 'string') {
      if (jsonOut === '-') process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      else {
        const file = resolve(jsonOut);
        mkdirSync(join(file, '..'), { recursive: true });
        writeFileSync(file, JSON.stringify(report, null, 2) + '\n', 'utf8');
        console.error(`JSON report: ${file}`);
      }
      wrote = true;
    }
    if (!wrote || args.flags.get('text') === true) {
      process.stdout.write(renderTextReport(report, process.stdout.isTTY === true) + '\n');
    }

    const critical = report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    return critical > 0 ? 1 : 0;
  } finally {
    cleanupModel(model);
  }
}

async function cmdList(args: ParsedArgs): Promise<number> {
  if (!args.image) {
    console.error('list: missing <image>');
    return 2;
  }
  const model = await openImage(resolve(args.image), args.flags);
  try {
    const json = args.flags.get('json') === true;
    const layerFilter = args.flags.has('layer') ? num(args.flags, 'layer', -1) : undefined;
    const deletedOnly = args.flags.get('deleted') === true;

    if (deletedOnly) {
      if (json) {
        process.stdout.write(
          JSON.stringify(
            model.ghosts.map((g) => ({
              path: g.path,
              reason: g.reason,
              hiddenLayer: g.hiddenVersions[0]?.layer,
              deletion: g.deletion,
            })),
            null,
            2,
          ) + '\n',
        );
        return 0;
      }
      console.log(`Deleted/hidden paths: ${model.ghosts.length}`);
      for (const g of model.ghosts) {
        const del = g.deletion ? `layer ${g.deletion.layer} (${g.deletion.reason})` : 'unknown';
        console.log(`  ${g.path}  [${g.reason}, hidden in ${del}]`);
      }
      return 0;
    }

    if (layerFilter !== undefined) {
      const layer = model.layers[layerFilter];
      if (!layer) {
        console.error(`no layer ${layerFilter}; image has ${model.layers.length} layers`);
        return 2;
      }
      const entries = layer.entries.map((e) => ({
        path: e.path,
        type: e.kind,
        size: e.entry.size,
        mode: e.entry.mode.toString(8),
        ...(e.entry.linkname ? { link: e.entry.linkname } : {}),
      }));
      if (json) {
        process.stdout.write(
          JSON.stringify(
            {
              layer: layer.index,
              digest: layer.blob.digest,
              createdBy: layer.history?.created_by,
              whiteouts: layer.whiteouts,
              entries,
            },
            null,
            2,
          ) + '\n',
        );
        return 0;
      }
      console.log(
        `Layer ${layer.index}: ${entries.length} entries, ${layer.whiteouts.length} whiteouts, ${formatBytes(
          layer.uncompressedSize,
        )}`,
      );
      if (layer.history?.created_by) console.log(`  created by: ${layer.history.created_by}`);
      for (const e of entries) {
        const suffix = e.link ? ` -> ${e.link}` : '';
        console.log(`  ${e.type.padEnd(8)} ${String(e.size).padStart(9)} ${e.mode.padStart(4)}  ${e.path}${suffix}`);
      }
      for (const w of layer.whiteouts) {
        console.log(`  ${w.kind === 'opaque' ? 'opaque  ' : 'whiteout'} ${' '.repeat(9)}       ${w.entryPath}  (hides ${w.path || '/'})`);
      }
      return 0;
    }

    // Default: image overview.
    if (json) {
      process.stdout.write(
        JSON.stringify(
          {
            image: model.name,
            layers: model.layers.map((l) => ({
              index: l.index,
              digest: l.blob.digest,
              size: l.blob.size,
              uncompressedSize: l.uncompressedSize,
              entries: l.entries.length,
              whiteouts: l.whiteouts.length,
              createdBy: l.history?.created_by,
            })),
            paths: model.paths.size,
            finalFiles: model.finalFs.size,
            ghosts: model.ghosts.length,
            warnings: model.warnings,
          },
          null,
          2,
        ) + '\n',
      );
      return 0;
    }
    console.log(`Image: ${model.name}`);
    console.log(`  os/arch: ${model.config.os ?? '?'}/${model.config.architecture ?? '?'}`);
    console.log(`  created: ${model.config.created ?? '?'}`);
    console.log(`  layers: ${model.layers.length}`);
    console.log(`  paths seen: ${model.paths.size}, in final fs: ${model.finalFs.size}, hidden: ${model.ghosts.length}`);
    for (const l of model.layers) {
      const cmd = (l.history?.created_by ?? '').replace(/\s+/g, ' ').slice(0, 80);
      console.log(
        `  [${String(l.index).padStart(2)}] ${formatBytes(l.uncompressedSize).padStart(9)} ${String(
          l.entries.length,
        ).padStart(6)} files ${String(l.whiteouts.length).padStart(3)} wh  ${cmd}`,
      );
    }
    for (const w of model.warnings) console.log(`  ! ${w}`);
    return 0;
  } finally {
    cleanupModel(model);
  }
}

async function cmdRecover(args: ParsedArgs): Promise<number> {
  if (!args.image) {
    console.error('recover: missing <image>');
    return 2;
  }
  const outFlag = args.flags.get('out');
  if (typeof outFlag !== 'string') {
    console.error('recover: --out <dir> is required');
    return 2;
  }
  const outDir = resolve(outFlag);
  const dryRun = args.flags.get('dry-run') === true;
  const layerFilter = args.flags.has('layer') ? num(args.flags, 'layer', -1) : undefined;
  const pathFilter = typeof args.flags.get('path') === 'string' ? String(args.flags.get('path')) : undefined;

  const model = await openImage(resolve(args.image), args.flags);
  try {
    const wanted = model.ghosts.filter((g) => {
      if (layerFilter !== undefined && g.hiddenVersions[0]?.layer !== layerFilter) return false;
      if (pathFilter && !g.path.includes(pathFilter)) return false;
      return true;
    });
    if (wanted.length === 0) {
      console.error('Nothing to recover.');
      return 0;
    }

    console.error(`Recovering ${wanted.length} path(s)${dryRun ? ' (dry run)' : ''}`);
    const entries: Array<{ path: string; type: 'file'; data: Buffer; mode: number; mtime: number }> = [];
    let total = 0;
    for (const ghost of wanted) {
      for (const version of ghost.hiddenVersions) {
        if (version.kind !== 'file' && version.kind !== 'hardlink') continue;
        const bytes = readVersionBytes(model.layers, version);
        // Keep the path the file had inside the layer, prefixed by its layer so
        // different historical versions do not collide.
        const safePath = version.path.replace(/^\/+/, '');
        const archivePath = `layer-${String(version.layer).padStart(3, '0')}/${safePath}`;
        entries.push({
          path: archivePath,
          type: 'file',
          data: bytes,
          mode: version.mode & 0o7777,
          mtime: version.mtime,
        });
        total += bytes.length;
        if (dryRun) console.error(`  would recover ${version.path} (${formatBytes(bytes.length)}) from layer ${version.layer}`);
      }
    }
    if (dryRun) return 0;

    mkdirSync(outDir, { recursive: true });
    const tarPath = join(outDir, 'recovered.tar');
    write(tarPath, createTar(entries));
    console.error(`Wrote ${tarPath} (${entries.length} files, ${formatBytes(total)} raw)`);
    return 0;
  } finally {
    cleanupModel(model);
  }
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.flags.get('help') === true || (!args.command && !args.flags.get('version'))) {
    process.stdout.write(USAGE);
    return args.flags.get('help') === true ? 0 : 2;
  }
  if (args.flags.get('version') === true) {
    console.log(VERSION);
    return 0;
  }
  if (args.errors.length > 0) {
    for (const e of args.errors) console.error(e);
    return 2;
  }
  try {
    switch (args.command) {
      case 'scan':
        return await cmdScan(args);
      case 'list':
        return await cmdList(args);
      case 'recover':
        return await cmdRecover(args);
      default:
        console.error(`unknown command: ${args.command}\n`);
        process.stdout.write(USAGE);
        return 2;
    }
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    if (process.env['DEBUG']) console.error((err as Error).stack);
    return 2;
  }
}
