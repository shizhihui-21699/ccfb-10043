# image-layer-audit

Find secrets that survive in container image layers even after a later layer
deletes them.

A security scan that reports "no keys in the image" only looks at the merged
filesystem. The bytes are still there: `docker save`, `docker history`, and any
registry pull hand you every layer, including files that a later `rm` hid with a
whiteout. This tool reads the image directly, reconstructs the layer stack with
correct whiteout and opaque-directory semantics, and scans **each layer's own
bytes** rather than the flattened result.

It is a single TypeScript program with no native dependencies. Docker is not
required, and neither is an external `tar` or `gzip` binary.

```
                               ┌──────────────┐
   docker save tar ──┐         │  layer index  │        ┌───────────────┐
   OCI layout dir ───┼────────▶│  + whiteouts  │───────▶│ secret scan   │──▶ text / JSON
                     │         │  per layer     │        │ each layer    │
   gzip/zstd layers ─┘         └──────┬───────┘        └───────┬───────┘
                                      │                        │
                              final fs + ghosts          attribution
                              (deleted/overwritten)      (history step)
                                      │                        │
                                      └────────▶ HTML report ◀─┘
                                                 (browse by layer)
```

## Install and run

```sh
npm install
npm test

# Scan a `docker save` archive
node src/main.ts scan image.tar --html report.html --json report.json

# Scan an OCI layout pulled with `skopeo copy docker://repo:tag oci:./dir`
node src/main.ts scan ./oci-layout --html report.html

# Browse without writing files
node src/main.ts list image.tar
node src/main.ts list image.tar --layer 7
node src/main.ts list image.tar --deleted

# Recover the hidden files as a tar, for incident response
node src/main.ts recover image.tar --out ./recovered
```

`npm link` exposes the `image-layer-audit` binary.

## What it looks for

Each finding is tagged with a category and a severity:

| Category            | Examples                                                                 |
| ------------------- | ------------------------------------------------------------------------ |
| `private-key`       | PEM/RSA/EC/OpenSSH/PGP blocks, `.pem`/`.key`/`.p12` files, `~/.ssh`       |
| `cloud-credential`  | AWS key ids and secret keys, GCP service-account JSON, Azure keys, DO tokens |
| `connection-string` | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`, JDBC  |
| `api-token`         | GitHub, GitLab, Slack, Stripe, SendGrid, npm, PyPI, OpenAI, Anthropic, HF, JWTs, Vault |
| `password`          | `password=`/`passwd=`/`PWD=` assignments, `.pgpass`, `shadow` files       |
| `auth-file`         | `.aws/credentials`, `.docker/config.json`, `.npmrc`, `.netrc`, `.env`, `.kube/config` |

Image **metadata** is scanned too: `ENV`, labels, and the `history` commands.
A key exported in a `RUN` step stays readable through `docker inspect` no matter
what a later layer deletes, and the history text itself routinely contains the
literal secret (`ENV API_KEY=...`, `RUN export TOKEN=... && ...`).

Detection combines regex rules with an entropy floor and a placeholder filter,
so `password=changeme`, `your-api-key`, and `${DB_PASSWORD}` do not produce noise.

### Masking

Values are masked by default (`sk_l••••••••••••••••p7dc`). Metadata findings are
always masked. Pass `--raw` to emit unmasked values in the text and JSON output;
the HTML report still masks.

## What makes this different from grep on the merged filesystem

**Layer-level scanning.** A file deleted in layer 9 is still scanned in layer 8.
Findings carry a `visible` flag and a `reason` (`visible`, `deleted`,
`overwritten`), and the report groups "only in hidden layers" separately.

**Correct whiteout semantics.**

- `.wh.<name>` hides that path *and its subtree* from lower layers.
- `.wh..wh..opq` hides every lower-layer entry below that directory, while
  entries added in the *same* layer stay visible.
- AUFS bookkeeping markers (`.wh..wh.plnk`, `.wh..wh.orph`, …) are not treated
  as file deletions.
- A file replaced by a directory, or a directory replaced by a file, is handled.

**Ghost inventory.** Every path that exists in some layer but not in the final
filesystem is listed with the layer that hid it and the mechanism used.

**Attribution.** Each finding points at the layer whose bytes contain it and,
where the image has history, at the `RUN`/`COPY` step that created that layer.
`image.tar --layer 3` shows exactly what that step shipped.

**Bounded memory.** The outer archive and each layer's tar are indexed with
random access. Compressed layer streams are decompressed to temp files, so a
10 GiB `docker save` does not need 10 GiB of RAM. Files over `--max-file-bytes`
(default 4 MiB) are skipped and counted; binary files are skipped and counted.

## Input formats

- **`docker save` / `podman save --format docker-archive`** — `manifest.json`,
  config blob, and per-layer `layer.tar` entries. Also handles the older
  `repositories`-only layout.
- **OCI image layout directory** — `oci-layout`, `index.json`, `blobs/sha256/*`,
  including a nested index for multi-platform images (the `linux` manifest is
  resolved, preferring the host architecture).

Layer tars may be stored plain, gzip-compressed, or zstd-compressed; all three
are detected from magic bytes. (zstd requires a Node build with zstd support,
which Node 22+ provides.)

## Output

- `--html <file>` — self-contained page with tabs for findings, a per-layer
  browser (pick a layer, see the Dockerfile step that made it and every file it
  added, marked `in image` or `removed later`), deleted/hidden files, image
  metadata findings, and build history. No network access at runtime.
- `--json <file>` — the full report including per-layer summaries and file lists.
  `--json -` writes to stdout.
- `--text` — coloured terminal report (default when no output file is given).

Exit status: `0` clean, `1` critical or high findings, `2` usage or load error.
Useful in CI (`image-layer-audit scan image.tar --min-severity high`).

## Tests

```sh
npm test          # node:test, no Docker, no network
npm run typecheck
npm run fixtures  # write sample images under tests/fixtures/out/
```

The suite builds test images in-process with its own tar writer
(`src/lib/tarwrite.ts`), so it covers:

- tar parsing: ustar, PAX long names, GNU long names, base-256 sizes, symlinks,
  hardlinks, truncated archives, bad checksums;
- whiteout, opaque-directory, subtree deletion, overwrite, and directory/file
  replacement semantics, including same-layer ordering;
- `docker save` and OCI layout loading, plain/gzip/zstd layer tars;
- scanner rules, entropy and placeholder filtering, masking, line numbers;
- HTML escaping of hostile paths and image names.

## Layout

```
src/
  lib/
    tar.ts        tar reader (in-memory, full format coverage)
    tarindex.ts   random-access tar indexer over a BlobIO
    tarwrite.ts   tar writer (fixtures and recovery output)
    io.ts         memory and file backed random access
    stream.ts     stream-decompress a blob region to a temp file
    image.ts      layer model, whiteout/opaque merge, ghost computation
    load.ts       docker-save and OCI layout loaders
    rules.ts      detection rules, path heuristics, masking
    analyze.ts    scan orchestration, attribution, report model
    util.ts       paths, entropy, masking, HTML helpers
  report/
    html.ts       self-contained HTML viewer and text report
  cli.ts          argument parsing and commands
  main.ts         entry point
tests/
  fixtures/       in-process image builder
  *.test.ts
```

## Limitations

- Encrypted or binary key material is reported by path heuristics, not decoded.
- Archives split across multiple tar files (`docker save` of a >10 GiB image on
  old Docker) are not reassembled.
- `xz` and `bzip2` layer compression is detected but not decompressed; the layer
  is reported as skipped rather than silently ignored.
- Secret detection is regex plus entropy. It will miss deliberately obfuscated
  secrets and can be fooled by high-entropy non-secrets; treat it as a strong
  first pass, not a proof of absence.
