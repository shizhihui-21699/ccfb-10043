import { basename, entropy } from './util.ts';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecretMatch {
  /** Rule identifier, e.g. `aws-access-key-id`. */
  ruleId: string;
  ruleName: string;
  category: SecretCategory;
  severity: Severity;
  /** The matched secret, already masked unless `raw` was requested. */
  value: string;
  /** 1-based line number inside the decoded text, when known. */
  line?: number;
  /** Short context window around the match, masked. */
  context?: string;
  /** Stable fingerprint so findings can be compared across images. */
  fingerprint: string;
}

export type SecretCategory =
  | 'private-key'
  | 'cloud-credential'
  | 'connection-string'
  | 'api-token'
  | 'password'
  | 'certificate'
  | 'auth-file';

export interface Rule {
  id: string;
  name: string;
  category: SecretCategory;
  severity: Severity;
  /** Regex; must have a named `secret` group when `maskGroup` is set. */
  pattern: RegExp;
  /** Which capture group holds the secret value. Default 0. */
  group?: number;
  /** Extra validation beyond the regex. */
  validate?: (value: string) => boolean;
  /** Minimum entropy for the captured value (filters placeholder junk). */
  minEntropy?: number;
  /** Ignore matches whose value looks like documentation/placeholder text. */
  ignorePlaceholders?: boolean;
}

const PLACEHOLDER =
  /^(?:x{3,}|\*{3,}|<[^>]*>|\[.*\]|\{.*\}|changeme|change-me|placeholder|example|dummy|test|null|none|undefined|false|true|0|abc123|\$\{?[A-Z_]+\}?|%[A-Z_]+%)$/i;

/**
 * Values that read as documentation rather than credentials: `your-api-key`,
 * `insert-token-here`, `REPLACE_ME`, and friends. These are all lowercase or
 * all uppercase words with separators, never high-entropy.
 */
const PLACEHOLDER_LIKE =
  /^(?:(?:your|my|our|insert|replace|enter|put|add|use)[-_ ]|(?:replace|insert|enter)[-_]?me|todo|fixme)/i;

export interface ScanContext {
  /** File path, used by path-based heuristics. */
  path: string;
  /** File mode; private-key files are expected to be 0600. */
  mode?: number;
}

export interface ScanOptions {
  /** Include unmasked values in results (only for local debugging). */
  includeRaw?: boolean;
  /** Extra rules appended to the built-in set. */
  extraRules?: Rule[];
  /** Minimum entropy for generic secret assignment rules. */
  minEntropy?: number;
  maxBytes?: number;
}

/** AWS key ids and secret access keys. */
const AWS_ACCESS_KEY = /(?:^|[^A-Z0-9])((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)/;
const AWS_SECRET = /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*(?:'|"|`)?([A-Za-z0-9/+=]{40})(?:'|"|`)?/;
const AWS_SECRET_BARE = /(?:^|[^A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)/;

const GCP_SERVICE_ACCOUNT = /"type"\s*:\s*"service_account"/;
const GCP_PRIVATE_KEY = /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/;
const GCP_API_KEY = /AIza[0-9A-Za-z_-]{35}/;
const AZURE_CONN = /(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/=]{40,90})/;

const GITHUB_TOKEN = /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}/;
const GITLAB_TOKEN = /glpat-[A-Za-z0-9_-]{20,}/;
const SLACK_TOKEN = /xox[abposr]-[A-Za-z0-9-]{10,}/;
const SLACK_WEBHOOK = /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/;
const STRIPE_KEY = /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/;
const STRIPE_WEBHOOK = /whsec_[A-Za-z0-9]{32,}/;
const SENDGRID_KEY = /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/;
const NPM_TOKEN = /npm_[A-Za-z0-9]{36}/;
const NPM_AUTH = /(?:^|\n)\/\/[^:\n]+:(?:_authToken=|email=)[A-Za-z0-9._-]*(?:\n|$)/;
const PYPI_TOKEN = /pypi-[A-Za-z0-9_-]{50,}/;
const OPENAI_KEY = /sk-(?:proj-|svcacct-|live-)?[A-Za-z0-9]{32,}/;
const ANTHROPIC_KEY = /sk-ant-[A-Za-z0-9_-]{20,}/;
const HUGGINGFACE = /hf_[A-Za-z0-9]{34,}/;
const TWILIO_KEY = /(?:SK|AP)[a-f0-9]{32}/;
const DIGITALOCEAN = /(?:^|[^A-Za-z0-9])(dop_v1_[a-f0-9]{64}|do_[or]_v1_[a-f0-9]{64})/;
const JWT = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;

const PRIVATE_KEY_BLOCK =
  /-----BEGIN\s*(RSA|DSA|EC|OpenSSH|PGP|ENCRYPTED|PRIVATE|OPENSSH)\s*PRIVATE KEY( BLOCK)?-----/;
const PRIVATE_KEY_CONTENT = /-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{64,}-----END/;
const CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]{64,}-----END CERTIFICATE-----/;
const SSH_PRIVATE_KEY_FILE = /-----BEGIN OPENSSH PRIVATE KEY-----/;

const CONNECTION_STRING =
  /(?:\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver|oracle|cockroachdb|clickhouse|kafka|nats|smtp|ldap[s]?|ftp|ftps|sftp|elasticsearch|opensearch):\/\/[^\s'"`<>]+)/i;
const JDBC_CONNECTION = /jdbc:[a-z]+:\/\/[^\s'"`<>]+/i;
const MEMCACHED = /memcached:\/\/[^\s'"`<>]+/i;

const PEM_IN_JSON = /\\n-----BEGIN [A-Z ]*PRIVATE KEY-----/;

const GENERIC_PASSWORD = /(?:password|passwd|pwd|secret|passphrase)\s*[:=]\s*['"`]([^'"`\n]{6,})['"`]/i;
const GENERIC_PASSWORD_BARE = /(?:^|\n)\s*(?:password|passwd|pwd)\s*[:=]\s*([^\s'"`#]{6,})\s*(?:\n|$)/i;
const GENERIC_SECRET_ASSIGN =
  /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)\s*[:=]\s*['"`]([A-Za-z0-9_\-./+=]{12,})['"`]/i;

const AWS_CREDENTIALS_INI = /\[(?:default|profile [^\]]+)\][^\n]*\n(?:[^\n]*\n)*?(?:aws_access_key_id|aws_secret_access_key)\s*=/;
const DOCKER_AUTH_B64 = /"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"/;
const NETRC_ENTRY = /(?:^|\n)\s*machine\s+[^\s]+\s*\n\s*login\s+[^\s]+\s*\n\s*password\s+([^\s]+)/;
const PGP_PRIVATE = /-----BEGIN PGP PRIVATE KEY BLOCK-----/;
const KUBECONFIG_TOKEN = /(?:^|\n)\s*token:\s*([A-Za-z0-9._-]{20,})\s*(?:\n|$)/;
const VAULT_TOKEN = /(?:^|\n)(hvs?\.)[A-Za-z0-9_-]{24,}/;
const TFE_TOKEN = /(?:^|\n)[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}/;
const GOOGLE_OAUTH = /ya29\.[A-Za-z0-9_-]{20,}/;

function looksLikePlaceholder(value: string): boolean {
  const v = value.trim();
  return PLACEHOLDER.test(v) || PLACEHOLDER_LIKE.test(v);
}

const RULES: Rule[] = [
  {
    id: 'private-key',
    name: 'PEM private key',
    category: 'private-key',
    severity: 'critical',
    pattern: PRIVATE_KEY_CONTENT,
    ignorePlaceholders: false,
  },
  {
    id: 'private-key-header',
    name: 'Private key header',
    category: 'private-key',
    severity: 'critical',
    pattern: PRIVATE_KEY_BLOCK,
  },
  {
    id: 'ssh-private-key',
    name: 'OpenSSH private key',
    category: 'private-key',
    severity: 'critical',
    pattern: SSH_PRIVATE_KEY_FILE,
  },
  {
    id: 'pgp-private-key',
    name: 'PGP private key block',
    category: 'private-key',
    severity: 'critical',
    pattern: PGP_PRIVATE,
  },
  {
    id: 'private-key-json-escaped',
    name: 'Private key embedded in JSON (escaped newlines)',
    category: 'private-key',
    severity: 'critical',
    pattern: PEM_IN_JSON,
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    category: 'cloud-credential',
    severity: 'high',
    pattern: AWS_ACCESS_KEY,
    group: 1,
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS secret access key',
    category: 'cloud-credential',
    severity: 'critical',
    pattern: AWS_SECRET,
    group: 1,
    minEntropy: 3.5,
  },
  {
    id: 'gcp-service-account',
    name: 'GCP service account key file',
    category: 'cloud-credential',
    severity: 'critical',
    pattern: GCP_SERVICE_ACCOUNT,
  },
  {
    id: 'gcp-private-key',
    name: 'GCP service account private key',
    category: 'cloud-credential',
    severity: 'critical',
    pattern: GCP_PRIVATE_KEY,
  },
  {
    id: 'gcp-api-key',
    name: 'Google API key',
    category: 'cloud-credential',
    severity: 'high',
    pattern: GCP_API_KEY,
    minEntropy: 3.5,
  },
  {
    id: 'azure-key',
    name: 'Azure storage/SAS key',
    category: 'cloud-credential',
    severity: 'critical',
    pattern: AZURE_CONN,
    group: 1,
    minEntropy: 3.5,
  },
  {
    id: 'digitalocean-token',
    name: 'DigitalOcean token',
    category: 'cloud-credential',
    severity: 'high',
    pattern: DIGITALOCEAN,
    group: 1,
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    category: 'api-token',
    severity: 'critical',
    pattern: GITHUB_TOKEN,
    minEntropy: 3,
  },
  {
    id: 'gitlab-token',
    name: 'GitLab token',
    category: 'api-token',
    severity: 'critical',
    pattern: GITLAB_TOKEN,
    minEntropy: 3,
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    category: 'api-token',
    severity: 'critical',
    pattern: SLACK_TOKEN,
  },
  {
    id: 'slack-webhook',
    name: 'Slack webhook URL',
    category: 'api-token',
    severity: 'high',
    pattern: SLACK_WEBHOOK,
  },
  {
    id: 'stripe-key',
    name: 'Stripe secret key',
    category: 'api-token',
    severity: 'critical',
    pattern: STRIPE_KEY,
  },
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe webhook signing secret',
    category: 'api-token',
    severity: 'high',
    pattern: STRIPE_WEBHOOK,
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API key',
    category: 'api-token',
    severity: 'high',
    pattern: SENDGRID_KEY,
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    category: 'api-token',
    severity: 'high',
    pattern: NPM_TOKEN,
  },
  {
    id: 'npmrc-auth',
    name: 'npm registry auth token',
    category: 'auth-file',
    severity: 'high',
    pattern: NPM_AUTH,
  },
  {
    id: 'pypi-token',
    name: 'PyPI upload token',
    category: 'api-token',
    severity: 'high',
    pattern: PYPI_TOKEN,
  },
  {
    id: 'openai-key',
    name: 'OpenAI API key',
    category: 'api-token',
    severity: 'high',
    pattern: OPENAI_KEY,
    minEntropy: 3.5,
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API key',
    category: 'api-token',
    severity: 'high',
    pattern: ANTHROPIC_KEY,
    minEntropy: 3.5,
  },
  {
    id: 'huggingface-token',
    name: 'Hugging Face token',
    category: 'api-token',
    severity: 'high',
    pattern: HUGGINGFACE,
  },
  {
    id: 'twilio-key',
    name: 'Twilio API key or auth token',
    category: 'api-token',
    severity: 'high',
    pattern: TWILIO_KEY,
    minEntropy: 3.5,
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    category: 'api-token',
    severity: 'high',
    pattern: JWT,
    minEntropy: 3,
  },
  {
    id: 'vault-token',
    name: 'HashiCorp Vault token',
    category: 'api-token',
    severity: 'critical',
    pattern: VAULT_TOKEN,
    group: 1,
  },
  {
    id: 'terraform-cloud-token',
    name: 'Terraform Cloud token',
    category: 'api-token',
    severity: 'high',
    pattern: TFE_TOKEN,
  },
  {
    id: 'connection-string',
    name: 'Database/cache/message-broker connection string',
    category: 'connection-string',
    severity: 'high',
    pattern: CONNECTION_STRING,
  },
  {
    id: 'jdbc-connection',
    name: 'JDBC connection string',
    category: 'connection-string',
    severity: 'high',
    pattern: JDBC_CONNECTION,
  },
  {
    id: 'memcached-uri',
    name: 'Memcached URI',
    category: 'connection-string',
    severity: 'medium',
    pattern: MEMCACHED,
  },
  {
    id: 'generic-password',
    name: 'Password assignment',
    category: 'password',
    severity: 'high',
    pattern: GENERIC_PASSWORD,
    group: 1,
    ignorePlaceholders: true,
    minEntropy: 2.5,
  },
  {
    id: 'generic-password-bare',
    name: 'Password assignment (bare)',
    category: 'password',
    severity: 'high',
    pattern: GENERIC_PASSWORD_BARE,
    group: 1,
    ignorePlaceholders: true,
    minEntropy: 2.5,
  },
  {
    id: 'generic-secret-assignment',
    name: 'Credential assignment',
    category: 'api-token',
    severity: 'medium',
    pattern: GENERIC_SECRET_ASSIGN,
    group: 1,
    ignorePlaceholders: true,
    minEntropy: 3.2,
  },
  {
    id: 'aws-credentials-file',
    name: 'AWS credentials file',
    category: 'auth-file',
    severity: 'high',
    pattern: AWS_CREDENTIALS_INI,
  },
  {
    id: 'docker-config-auth',
    name: 'Docker registry credentials',
    category: 'auth-file',
    severity: 'high',
    pattern: DOCKER_AUTH_B64,
    group: 1,
  },
  {
    id: 'netrc-password',
    name: 'Password in netrc file',
    category: 'auth-file',
    severity: 'high',
    pattern: NETRC_ENTRY,
    group: 1,
  },
  {
    id: 'kubeconfig-token',
    name: 'Kubernetes bearer token',
    category: 'auth-file',
    severity: 'high',
    pattern: KUBECONFIG_TOKEN,
    group: 1,
    minEntropy: 3,
  },
  {
    id: 'google-oauth-token',
    name: 'Google OAuth access token',
    category: 'cloud-credential',
    severity: 'high',
    pattern: GOOGLE_OAUTH,
  },
  {
    id: 'certificate',
    name: 'X.509 certificate',
    category: 'certificate',
    severity: 'low',
    pattern: CERTIFICATE,
  },
];

/** Path heuristics that raise severity independent of content. */
const SENSITIVE_PATHS: Array<{ pattern: RegExp; category: SecretCategory; severity: Severity; name: string }> = [
  { pattern: /(?:^|\/)\.(?:ssh|gnupg)\/?/, category: 'private-key', severity: 'critical', name: 'SSH/GnuPG material' },
  { pattern: /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/, category: 'private-key', severity: 'critical', name: 'SSH private key file' },
  { pattern: /\.(?:pem|key|p12|pfx|jks|keystore)$/i, category: 'private-key', severity: 'high', name: 'Key or keystore file' },
  { pattern: /(?:^|\/)\.(?:aws|docker)\/config(?:\.json)?$/, category: 'auth-file', severity: 'high', name: 'Cloud CLI config' },
  { pattern: /(?:^|\/)\.docker\/config\.json$/, category: 'auth-file', severity: 'high', name: 'Docker registry config' },
  { pattern: /(?:^|\/)\.netrc$/, category: 'auth-file', severity: 'high', name: 'netrc credentials' },
  { pattern: /(?:^|\/)\.npmrc$/, category: 'auth-file', severity: 'high', name: 'npm registry config' },
  { pattern: /(?:^|\/)\.pypirc$/, category: 'auth-file', severity: 'high', name: 'PyPI upload config' },
  { pattern: /(?:^|\/)(?:\.env|\.env\.[^.]+|.*\.env)$/, category: 'auth-file', severity: 'high', name: 'Environment file' },
  { pattern: /(?:^|\/)(?:credentials|secrets)[^/]*\.(?:json|yml|yaml|txt|env)$/i, category: 'auth-file', severity: 'high', name: 'Credentials file' },
  { pattern: /(?:^|\/)\.kube\/config$/, category: 'auth-file', severity: 'high', name: 'Kubernetes config' },
  { pattern: /(?:^|\/)\.git-credentials$/, category: 'auth-file', severity: 'high', name: 'Git credentials store' },
  { pattern: /(?:^|\/)\.htpasswd$/, category: 'password', severity: 'medium', name: 'Apache htpasswd' },
  { pattern: /(?:^|\/)shadow(?:-|$)/, category: 'password', severity: 'critical', name: 'Shadow password file' },
  { pattern: /(?:^|\/)pgpass$/, category: 'password', severity: 'high', name: 'PostgreSQL password file' },
  { pattern: /(?:^|\/)\.pgpass$/, category: 'password', severity: 'high', name: 'PostgreSQL password file' },
  { pattern: /(?:^|\/)\.mypy_cache$/, category: 'auth-file', severity: 'low', name: 'Python cache' },
];

export function pathHeuristicHit(path: string): boolean {
  return SENSITIVE_PATHS.some((h) => h.pattern.test(path));
}

export function ruleSet(extra: Rule[] = []): Rule[] {
  return [...RULES, ...extra];
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function contextWindow(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + length + 40);
  const window = text.slice(start, end).replace(/\n/g, '⏎');
  // If redaction consumed nearly everything, the window adds no signal.
  const visible = window.replace(/[•⏎\s]/g, '').length;
  if (visible < 6) return '';
  return window;
}

export interface ContentScanResult {
  matches: SecretMatch[];
  /** Non-fatal note, e.g. a rule that produced a suspiciously long match. */
  notes: string[];
}

/** Scan a decoded text buffer for secrets. */
export function scanText(
  text: string,
  ctx: ScanContext,
  options: ScanOptions = {},
): ContentScanResult {
  const notes: string[] = [];
  const rules = ruleSet(options.extraRules);

  interface RawHit {
    rule: Rule;
    /** Offset of the captured secret itself. */
    start: number;
    /** Offset and length of the whole regex match (for the context window). */
    matchStart: number;
    matchLength: number;
    raw: string;
  }
  const hits: RawHit[] = [];

  const consider = (
    rule: Rule,
    start: number,
    matchStart: number,
    matchLength: number,
    rawGroup: string,
    minEntropyOverride?: number,
  ): void => {
    const value = rawGroup;
    if (options.includeRaw !== true && value.length > 4000) {
      notes.push(`${rule.id}: skipped oversized match in ${ctx.path}`);
      return;
    }
    if (rule.ignorePlaceholders && looksLikePlaceholder(value)) return;
    const minE = minEntropyOverride ?? rule.minEntropy;
    if (minE !== undefined && entropy(value) < minE) return;
    hits.push({ rule, start, matchStart, matchLength, raw: value });
  };

  for (const rule of rules) {
    const flags = rule.pattern.flags.replace(/[gy]/g, '');
    // `d` gives capture-group offsets, so `line` points at the captured
    // secret rather than at the start of a multi-line match.
    const pattern = new RegExp(rule.pattern.source, `${flags}gd`);
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = pattern.exec(text)) !== null) {
      if (guard++ > 2000) {
        notes.push(`${rule.id}: stopped after 2000 matches in ${ctx.path}`);
        break;
      }
      if (m[0].length === 0) {
        pattern.lastIndex++;
        continue;
      }
      const group = rule.group ?? 0;
      const raw = m[group];
      if (raw === undefined) continue;
      const groupStart = m.indices?.[group]?.[0] ?? m.index;
      consider(rule, groupStart, m.index, m[0].length, raw);
    }
  }

  // AWS secret keys without an explicit assignment are 40 chars of base64.
  // Matching all of those is noisy, so only try inside AWS-looking files.
  if (/aws|credential/.test(ctx.path)) {
    const pattern = new RegExp(AWS_SECRET_BARE.source, 'gd');
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = pattern.exec(text)) !== null && guard++ < 500) {
      const raw = m[1];
      if (!raw) continue;
      if (entropy(raw) < 4.0) continue;
      consider(
        {
          id: 'aws-secret-access-key-bare',
          name: 'AWS secret access key (unlabelled)',
          category: 'cloud-credential',
          severity: 'high',
          pattern: AWS_SECRET_BARE,
          group: 1,
        },
        m.indices?.[1]?.[0] ?? m.index,
        m.index,
        m[0].length,
        raw,
        4.0,
      );
      if (m[0].length === 0) pattern.lastIndex++;
    }
  }

  // Build contexts from one global redaction pass. Masking only the matched
  // value leaks neighbouring secrets and key bodies that fall inside the
  // window, which defeats the point of masking.
  const redacted = redactForDisplay(
    text,
    hits.map((h) => h.raw),
  );

  const matches: SecretMatch[] = hits
    .sort((a, b) => a.start - b.start)
    .map((hit) => ({
      ruleId: hit.rule.id,
      ruleName: hit.rule.name,
      category: hit.rule.category,
      severity: hit.rule.severity,
      value: options.includeRaw ? hit.raw : maskGeneric(hit.raw),
      line: lineAt(text, hit.start),
      context: contextWindow(redacted, hit.matchStart, hit.matchLength),
      fingerprint: `${hit.rule.id}:${hashish(hit.raw)}`,
    }));

  return { matches, notes };
}

/**
 * Mask every sensitive-looking run in a block of text.
 *
 * Used to build safe context windows and to sanitise history commands that are
 * echoed next to findings. `explicitSecrets` must be the values the rules
 * actually captured, so passwords and other shapes the heuristics miss are
 * covered too.
 */
export function redactForDisplay(text: string, explicitSecrets: string[] = []): string {
  let out = text;
  if (PEM_HEADER.test(out)) out = out.replace(PEM_BLOCK, (block) => maskPemBlock(block));
  out = out.replace(SECRET_RUN, (run) => (run.length >= 16 ? maskGeneric(run) : run));
  out = out.replace(
    /([a-z][a-z0-9+.-]*:\/\/)([^@\s/]+)@/gi,
    (_all, scheme: string) => `${scheme}***:***@`,
  );
  out = out.replace(/(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}/g,
    (key) => maskGeneric(key));
  out = out.replace(
    /(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|xox[abposr]|sk_live|sk_test|sk-ant|SG\.|npm_|pypi-|hf_)[A-Za-z0-9_-]{8,}/g,
    (token) => maskGeneric(token),
  );
  out = out.replace(/jdbc:[a-z]+:\/\/[^\s'"`<>]*:[^@\s'"`<>]*@/gi, (_m) => 'jdbc:***:***@');
  // Finally, redact every value the rules actually captured. This covers
  // shapes the heuristics above do not recognise (passwords, usernames).
  for (const secret of explicitSecrets) {
    if (secret.length < 4) continue;
    out = out.split(secret).join(maskGeneric(secret));
  }
  return out;
}

/**
 * Redact credentials inside a history command (`ENV TOKEN=...`,
 * `RUN export KEY=...`). The command itself is useful attribution context, so
 * only the secret part is masked.
 */
export function redactCommand(command: string): string {
  // History commands are shell syntax, not env files: the bare password rule
  // also fires here, and scanning the command unmasked lets us learn the
  // literal secret spans before masking them.
  const { matches } = scanText(command, { path: 'history' }, { includeRaw: true });
  const secrets = matches.map((m) => m.value);
  // `PASSWORD_WORD` catches shell-quoted values after a password-ish key that
  // the content rules may leave alone.
  const quoted = [...command.matchAll(PASSWORD_WORD)];
  for (const q of quoted) if (q[1]) secrets.push(q[1]);
  return redactForDisplay(command, secrets);
}

/**
 * A password-ish key followed by a value. The value stops at whitespace, a
 * quote, or a newline, which matches both `password=hunter2` and
 * `echo "password=correct-horse-battery"`.
 */
const PASSWORD_WORD =
  /(?:password|passwd|pwd|secret|passphrase)\s*[=:]\s*["']?([^\s"'`]{6,})/gi;

function maskPemBlock(block: string): string {
  const begin = /-----BEGIN [^-]+-----/.exec(block)?.[0];
  const end = /-----END [^-]+-----/.exec(block)?.[0];
  const lines = block.split('\n').length;
  return `${begin ?? '-----BEGIN KEY-----'}\n… ${lines} lines masked …\n${end ?? '-----END KEY-----'}`;
}

const PEM_HEADER = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const PEM_BLOCK =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,100000}?-----END [A-Z ]*PRIVATE KEY-----/g;
/**
 * Opaque credential-shaped runs. Restricted to character sets that read as a
 * token rather than a word: the run must mix upper-, lower-case and have a
 * digit or base64 symbol, which filters out ordinary prose and env names.
 */
const SECRET_RUN =
  /(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]{16,}(?![A-Za-z0-9+/_-]))(?=[A-Za-z0-9+/_-]*[A-Z])(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[0-9+/])[A-Za-z0-9+/_-]{16,}(?![A-Za-z0-9+/_-])/g;

function hashish(value: string): string {
  // Cheap, non-cryptographic fingerprint is fine: it only dedupes findings.
  let h1 = 0x811c9dc5;
  let h2 = 0x1000193;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 + c, 0x5bd1e995) >>> 0;
  }
  return `${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

function maskGeneric(value: string): string {
  if (value.length <= 6) return '•'.repeat(value.length);
  // Long multi-line matches (PEM blocks) are summarised rather than masked in
  // full: the operator needs to recognise the material, not read it.
  if (value.length > 80) {
    const lines = value.split('\n').length;
    return `${value.slice(0, 8)}… ${value.length} chars${lines > 1 ? `, ${lines} lines` : ''} …${value.slice(-4)}`;
  }
  const keep = value.length > 20 ? 4 : 2;
  const dots = Math.min(28, Math.max(4, value.length - keep * 2));
  return `${value.slice(0, keep)}${'•'.repeat(dots)}${value.slice(-keep)}`;
}

/** Path-based findings that do not depend on file contents. */
export function pathFindings(
  ctx: ScanContext,
  includeRaw: boolean,
): Array<{ ruleId: string; ruleName: string; category: SecretCategory; severity: Severity }> {
  void includeRaw;
  const out: Array<{ ruleId: string; ruleName: string; category: SecretCategory; severity: Severity }> = [];
  for (const h of SENSITIVE_PATHS) {
    if (h.pattern.test(ctx.path)) {
      out.push({
        ruleId: `path:${h.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        ruleName: h.name,
        category: h.category,
        severity: h.severity,
      });
    }
  }
  return out;
}

export function fileLooksLikeKeyMaterial(name: string, mode: number | undefined): boolean {
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/i.test(name)) return true;
  // A private key in a world-readable file is worth flagging even if the
  // content scan found nothing (e.g. an encrypted key we cannot parse).
  if (mode !== undefined && (mode & 0o077) !== 0 && /(?:key|pem)$/i.test(basename(name))) return true;
  return false;
}
