import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, pathHeuristicHit } from '../src/lib/rules.ts';
import { maskSecret, entropy, normalizeArchivePath, decodeText, formatBytes } from '../src/lib/util.ts';
import { renderHtmlReport } from '../src/report/html.ts';
import type { ScanReport } from '../src/lib/analyze.ts';

function ids(text: string, path = 'file.txt'): string[] {
  return scanText(text, { path }, { includeRaw: true }).matches.map((m) => m.ruleId);
}

test('detects AWS key pair', () => {
  const text = [
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  ].join('\n');
  const found = ids(text);
  assert.ok(found.includes('aws-access-key-id'));
  assert.ok(found.includes('aws-secret-access-key'));
});

test('detects connection strings with embedded credentials', () => {
  const found = ids('DATABASE_URL=postgres://user:p4ss@db:5432/app');
  assert.ok(found.includes('connection-string'));
  const matches = scanText('DATABASE_URL=postgres://user:p4ss@db:5432/app', { path: 'x' }, { includeRaw: false }).matches;
  const conn = matches.find((m) => m.ruleId === 'connection-string')!;
  // Masked output must not leak the password.
  assert.doesNotMatch(conn.value, /p4ss/);
});

test('detects private key blocks without dumping the whole key', () => {
  const key = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA'.repeat(6),
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');
  const { matches } = scanText(key, { path: 'id_rsa' }, { includeRaw: false });
  const pem = matches.find((m) => m.ruleId === 'private-key')!;
  assert.ok(pem);
  assert.match(pem.value, /chars/);
  assert.doesNotMatch(pem.value, /MIIEowIBAAK/);
});

test('ignores placeholders and documentation values', () => {
  assert.deepEqual(ids('password=changeme'), []);
  assert.deepEqual(ids('api_key="your-api-key-here"'), []);
  assert.deepEqual(ids('password=<password>'), []);
  assert.deepEqual(ids('AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX'), ['aws-access-key-id'], 'the key shape itself is a finding');
});

test('detects tokens added in later years', () => {
  assert.ok(ids('GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a').includes('github-token'));
  assert.ok(ids('token=glpat-abcdefghij1234567890').includes('gitlab-token'));
  assert.ok(ids('SLACK=xoxb-1234567890-abcdefghijkl').includes('slack-token'));
  assert.ok(ids('key=sk-ant-api03-abcdefghijklmnopqrstuv').includes('anthropic-key'));
  assert.ok(ids('key=hf_abcdefghijklmnopqrstuvwxyz0123456789').includes('huggingface-token'));
  assert.ok(ids('key=AIzaSyA1234567890abcdefghijklmnopqrstuv').includes('gcp-api-key'));
});

test('finds a private key escaped inside JSON', () => {
  const json = JSON.stringify({
    type: 'service_account',
    private_key: '-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\n-----END PRIVATE KEY-----\\n',
  });
  const text = json.replace(/\n/g, '\\n');
  const found = ids(text, 'sa.json');
  assert.ok(found.includes('gcp-service-account'));
});

test('reports line numbers', () => {
  const text = 'line one\nline two\npassword=sup3rs3cret\nline four\n';
  const { matches } = scanText(text, { path: 'x' }, { includeRaw: true });
  const pw = matches.find((m) => m.ruleId === 'generic-password-bare')!;
  assert.equal(pw.line, 3);
});

test('context is redacted around the secret', () => {
  const text = 'DATABASE_URL=postgres://admin:supersecret@db:5432/app';
  const { matches } = scanText(text, { path: 'x' }, { includeRaw: false });
  for (const m of matches) {
    assert.doesNotMatch(m.context ?? '', /supersecret/);
  }
});

test('path heuristics flag credential files', () => {
  assert.ok(pathHeuristicHit('/root/.ssh/id_rsa'));
  assert.ok(pathHeuristicHit('app/.npmrc'));
  assert.ok(pathHeuristicHit('home/user/.netrc'));
  assert.ok(!pathHeuristicHit('usr/bin/curl'));
});

test('maskSecret keeps enough to recognise a value', () => {
  assert.equal(maskSecret('abc'), '•••');
  const masked = maskSecret('sk_live_4eC39HqLyjWDarjtT1zdp7dc');
  assert.ok(masked.startsWith('sk_l'));
  assert.ok(masked.endsWith('p7dc'));
  assert.ok(!masked.includes('4eC39Hq'));
});

test('normalizeArchivePath refuses traversal', () => {
  assert.equal(normalizeArchivePath('/etc/passwd'), 'etc/passwd');
  assert.equal(normalizeArchivePath('./app/./x'), 'app/x');
  assert.equal(normalizeArchivePath('a/../b'), 'b');
  assert.equal(normalizeArchivePath('../etc/shadow'), null);
  assert.equal(normalizeArchivePath(''), '');
});

test('decodeText rejects binary and accepts text', () => {
  assert.equal(decodeText(Buffer.from('hello world')), 'hello world');
  assert.equal(decodeText(Buffer.from([0, 1, 2, 3, 0])), null);
  assert.equal(decodeText(Buffer.from([0xff, 0xfe, 0x00])), null);
});

test('entropy and byte formatting behave', () => {
  assert.ok(entropy('aaaa') < 0.1);
  assert.ok(entropy('abcdefghijklmnop') > 3.5);
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(2048), '2.0 KiB');
});

test('html report escapes image-controlled strings', () => {
  const report: ScanReport = {
    image: '<img src=x onerror=alert(1)>',
    generatedAt: '2024-01-01T00:00:00Z',
    findings: [
      {
        id: 'f1',
        path: '</script><script>alert(2)</script>',
        layer: 0,
        tarIndex: 0,
        visible: false,
        reason: 'deleted',
        ruleId: 'x',
        ruleName: '<b>rule</b>',
        category: 'password',
        severity: 'high',
        value: 'secret',
        context: '</script>',
        fingerprint: 'fp',
        fileSize: 10,
        fileMode: 0o644,
        createdBy: 'RUN echo "<script>"',
      },
    ],
    stats: {
      scannedFiles: 1,
      scannedBytes: 10,
      skippedBinary: 0,
      skippedLarge: 0,
      layers: 1,
      durationMs: 1,
    },
    warnings: ['</script>'],
    layerSummaries: [],
    ghosts: [],
    history: [],
    configFindings: [],
  };
  const html = renderHtmlReport(report);
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /<\/script><script>alert\(2\)/);
  // The embedded JSON must not break out of its script tag.
  assert.doesNotMatch(html, /<\/script><script>alert/);
  assert.match(html, /&lt;img src=x/);
});

test('config findings cover ENV, labels and history', async () => {
  const { leakedSecretImage, buildDockerSave } = await import('./fixtures/build.ts');
  const { loadDockerSave, cleanupModel } = await import('../src/lib/load.ts');
  const { analyzeImage } = await import('../src/lib/analyze.ts');
  const { writeFileSync, mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  const dir = mkdtempSync(join(tmpdir(), 'la-cfg-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    try {
      model.config.config!.Labels = { 'org.example.deploy.token': 'ghp_16C7e42F292c6912E7710c838347Ae178B4a' };
      const report = analyzeImage(model, { mask: true });
      const kinds = new Set(report.configFindings.map((c) => c.kind));
      assert.ok(kinds.has('env'), 'ENV secret detected');
      assert.ok(kinds.has('history'), 'history command secret detected');
      assert.ok(kinds.has('label'), 'label secret detected');
      // Metadata values are always masked, even with --raw.
      const raw = analyzeImage(model, { mask: false });
      for (const c of raw.configFindings) {
        assert.doesNotMatch(c.maskedValue, /SG\.ngeVf|ghp_16C7|sk_live_51H8/);
      }
    } finally {
      cleanupModel(model);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('reports never contain raw secret material', async () => {
  const { leakedSecretImage, buildDockerSave } = await import('./fixtures/build.ts');
  const { loadDockerSave, cleanupModel } = await import('../src/lib/load.ts');
  const { analyzeImage } = await import('../src/lib/analyze.ts');
  const { renderHtmlReport, renderTextReport } = await import('../src/report/html.ts');
  const { writeFileSync, mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  const rawSecrets = [
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    's3cr3t-P4ssw0rd',
    'hunter2',
    'correct-horse-battery',
    'AKIAIOSFODNN7EXAMPLE',
    'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
    'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
    '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',
    'MIIEowIBAAKCAQEAx3Vw1s0Kq2m9vJ7pQe5rT8yU1iO2pA3sD4fG5hJ6kL7zX8cV9bN',
    'sk_live_51H8XyzABCDEFghijklmnop',
  ];

  const dir = mkdtempSync(join(tmpdir(), 'la-leak-'));
  try {
    const tarPath = join(dir, 'image.tar');
    writeFileSync(tarPath, buildDockerSave(leakedSecretImage()).tar);
    const model = await loadDockerSave(tarPath);
    let json: string;
    let html: string;
    let text: string;
    try {
      // Mashed mode is the default and what reports ship.
      const report = analyzeImage(model, { mask: true });
      json = JSON.stringify(report);
      html = renderHtmlReport(report);
      text = renderTextReport(report);
    } finally {
      cleanupModel(model);
    }
    for (const secret of rawSecrets) {
      assert.ok(!json.includes(secret), `JSON leaked ${secret}`);
      assert.ok(!html.includes(secret), `HTML leaked ${secret}`);
      assert.ok(!text.includes(secret), `text report leaked ${secret}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('context windows do not expose neighbouring secrets', () => {
  const text = [
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc',
  ].join('\n');
  const { matches } = scanText(text, { path: '.env' }, { includeRaw: false });
  assert.ok(matches.length >= 3);
  for (const m of matches) {
    assert.doesNotMatch(m.context ?? '', /wJalrXUtnFEMI|AKIAIOSFODNN7EXAMPLE|sk_live_4eC39Hq/);
  }
});

test('history commands are redacted before they reach a report', async () => {
  const { redactCommand } = await import('../src/lib/rules.ts');
  const redacted = redactCommand(
    '/bin/sh -c export STRIPE_KEY=sk_live_51H8XyzABCDEFghijklmnop && echo "password=correct-horse-battery" > /app/x',
  );
  assert.doesNotMatch(redacted, /sk_live_51H8Xyz/);
  assert.doesNotMatch(redacted, /correct-horse/);
  assert.match(redacted, /STRIPE_KEY=sk_l/);
});
