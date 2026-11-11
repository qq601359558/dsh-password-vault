/**
 * Password Vault core.
 *
 * The vault file contains only ciphertext plus a protected copy of the vault
 * key. Passwords never leave this module except for an explicit local UI
 * reveal; model-facing tools receive a short-lived lease and sanitized output.
 */
import { spawn } from 'node:child_process';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { chmod, copyFile, mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const VAULT_VERSION = 1;
export const ENTRY_VERSION = 1;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_ENTRY_BYTES = 32 * 1024;
const MAX_OUTPUT_BYTES = 128 * 1024;
const MAX_HTTP_BODY_BYTES = 256 * 1024;
const DEFAULT_LEASE_MINUTES = 10;
const DEFAULT_AUTO_LOCK_MINUTES = 30;

const AUTH_TYPES = new Set(['none', 'basic', 'bearer', 'header', 'query']);

/** A user-visible vault failure with a stable code and HTTP status. */
export class VaultError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
    this.status = status;
  }
}

/** Resolve the default vault directory, respecting the active DSH home. */
export function defaultVaultDir() {
  const home = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh');
  return join(home, 'password-vault');
}

/** Resolve the active vault file path. */
export function defaultVaultFile() {
  return join(defaultVaultDir(), 'vault.json');
}

/** Whether a hostname names this machine's loopback interface. */
export function isLoopbackHost(hostname) {
  const host = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost');
}

/** Mask an account name for model-facing metadata. */
export function maskAccount(value) {
  const text = String(value ?? '').trim();
  if (text === '') return '';
  const at = text.indexOf('@');
  if (at > 0) {
    const local = text.slice(0, at);
    const domain = text.slice(at);
    if (local.length <= 1) return `*${domain}`;
    return `${local[0]}${'*'.repeat(Math.min(Math.max(local.length - 1, 2), 8))}${domain}`;
  }
  if (text.length <= 2) return '*'.repeat(text.length || 1);
  if (/^\+?\d[\d -]{5,}$/.test(text)) return `***${text.replace(/\D/g, '').slice(-4)}`;
  return `${text[0]}${'*'.repeat(Math.min(Math.max(text.length - 2, 2), 8))}${text[text.length - 1]}`;
}

/** Normalize one allowed-host entry; returns '' when it is not a host. */
export function normalizeAllowedHost(value) {
  let text = String(value ?? '').trim().toLowerCase();
  if (text === '') return '';
  text = text.replace(/^[a-z]+:\/\//, '');
  text = text.split('/')[0].split('?')[0].split('#')[0];
  if (text.startsWith('*.')) {
    const rest = text.slice(2).replace(/:\d+$/, '');
    return rest === '' ? '' : `*.${rest}`;
  }
  text = text.replace(/:\d+$/, '');
  if (text === '' || /\s/.test(text)) return '';
  return text;
}

/** Parse a comma/newline separated host allow-list. */
export function parseAllowedHosts(value) {
  const source = Array.isArray(value) ? value : String(value ?? '').split(/[\s,;]+/);
  return [...new Set(source.map(normalizeAllowedHost).filter(Boolean))];
}

/** Whether a target hostname is admitted by an entry's allow-list. */
export function hostAllowed(hostname, allowedHosts) {
  const host = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  for (const pattern of allowedHosts ?? []) {
    if (pattern === host) return true;
    if (pattern.startsWith('*.') && host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1) {
      return true;
    }
  }
  return false;
}

/** Encode bytes as base64url without padding. */
function b64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

/** AES-256-GCM encrypt one UTF-8 string with associated data. */
function encryptString(key, plaintext, aad) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
  };
}

/** AES-256-GCM decrypt one UTF-8 string with associated data. */
function decryptString(key, box, aad) {
  let iv;
  let tag;
  let data;
  try {
    iv = Buffer.from(box.iv, 'base64');
    tag = Buffer.from(box.tag, 'base64');
    data = Buffer.from(box.data, 'base64');
  } catch {
    throw new VaultError('VAULT_CORRUPT', 'The vault contains an unreadable encrypted record.', 500);
  }
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new VaultError('VAULT_CORRUPT', 'The vault contains a malformed encrypted record.', 500);
  }
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    throw new VaultError('VAULT_CORRUPT', 'The vault could not be decrypted. It may have been modified.', 500);
  }
}

/** Derive a key-encryption key from a master password. */
function deriveKek(password, salt) {
  return scryptSync(String(password), salt, KEY_BYTES, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 128 * 1024 * 1024,
  });
}

/** Wrap the vault key with a master-password-derived key. */
function wrapKeyWithPassword(key, password, salt) {
  const kek = deriveKek(password, salt);
  try {
    return encryptString(kek, key.toString('base64'), `vault-key:password:v${VAULT_VERSION}`);
  } finally {
    kek.fill(0);
  }
}

/** Unwrap the vault key with a master password. */
function unwrapKeyWithPassword(box, password, salt) {
  const kek = deriveKek(password, salt);
  try {
    const encoded = decryptString(kek, box, `vault-key:password:v${VAULT_VERSION}`);
    const key = Buffer.from(encoded, 'base64');
    if (key.length !== KEY_BYTES) throw new VaultError('VAULT_CORRUPT', 'The vault key is malformed.', 500);
    return key;
  } finally {
    kek.fill(0);
  }
}

const DPAPI_PROTECT = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName System.Security',
  '$raw = [Console]::In.ReadToEnd()',
  "if ([string]::IsNullOrWhiteSpace($raw)) { throw 'empty input' }",
  '$bytes = [Convert]::FromBase64String($raw)',
  '$protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
  '[Convert]::ToBase64String($protected)',
].join('; ');

const DPAPI_UNPROTECT = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName System.Security',
  '$raw = [Console]::In.ReadToEnd()',
  "if ([string]::IsNullOrWhiteSpace($raw)) { throw 'empty input' }",
  '$bytes = [Convert]::FromBase64String($raw)',
  '$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
  '[Convert]::ToBase64String($plain)',
].join('; ');

/** Run a small Windows PowerShell helper with bounded input and output. */
function runPowerShell(script, input, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    if (process.platform !== 'win32') {
      reject(new VaultError('DPAPI_UNAVAILABLE', 'Automatic unlock is only available on Windows. Use a master password.', 500));
      return;
    }
    let child;
    try {
      child = spawn('powershell.exe', [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        script,
      ], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (error) {
      reject(new VaultError('DPAPI_UNAVAILABLE', `Windows account protection is unavailable: ${error.message}`, 500));
      return;
    }
    let out = '';
    let err = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new VaultError('DPAPI_TIMEOUT', 'Windows account protection timed out.', 500));
    }, timeoutMs);
    timer.unref?.();
    child.stdin.on('error', () => {
      // The child may close its input before the write completes.
    });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new VaultError('DPAPI_UNAVAILABLE', `Windows account protection is unavailable: ${error.message}`, 500));
    });
    child.stdout.on('data', (chunk) => {
      out += chunk.toString('utf8');
      if (out.length > 64 * 1024) out = out.slice(0, 64 * 1024);
    });
    child.stderr.on('data', (chunk) => {
      err += chunk.toString('utf8');
      if (err.length > 64 * 1024) err = err.slice(0, 64 * 1024);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        const detail = err.trim().split(/\r?\n/).slice(-2).join(' ').slice(0, 300);
        reject(new VaultError('DPAPI_FAILED', `Windows account protection failed${detail ? `: ${detail}` : '.'}`, 500));
        return;
      }
      resolve(out.trim());
    });
    child.stdin.end(input);
  });
}

/** Protect the vault key with the signed-in Windows account. */
async function protectWithDpapi(key) {
  const encoded = await runPowerShell(DPAPI_PROTECT, key.toString('base64'));
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length < 64) throw new VaultError('DPAPI_FAILED', 'Windows account protection returned an invalid key.', 500);
  return encoded;
}

/** Recover the vault key from a Windows-account-protected blob. */
async function unprotectWithDpapi(encoded) {
  const raw = await runPowerShell(DPAPI_UNPROTECT, String(encoded ?? ''));
  const key = Buffer.from(raw, 'base64');
  if (key.length !== KEY_BYTES) {
    throw new VaultError('DPAPI_FAILED', 'Windows account protection returned a malformed vault key.', 500);
  }
  return key;
}

/** Base32 decode a TOTP secret. */
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const text = String(input).toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (text === '') return Buffer.alloc(0);
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of text) {
    const index = alphabet.indexOf(char);
    if (index === -1) throw new VaultError('INVALID_TOTP', 'The one-time-password secret is not valid base32.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Accept either a raw base32 secret or an otpauth:// URI. */
export function normalizeTotpSecret(value) {
  const text = String(value ?? '').trim();
  if (text === '') return '';
  if (/^otpauth:\/\//i.test(text)) {
    let url;
    try {
      url = new URL(text);
    } catch {
      throw new VaultError('INVALID_TOTP', 'The otpauth URI is malformed.');
    }
    const secret = url.searchParams.get('secret');
    if (secret === null) throw new VaultError('INVALID_TOTP', 'The otpauth URI has no secret parameter.');
    return normalizeTotpSecret(secret);
  }
  const compact = text.toUpperCase().replace(/[\s-]/g, '');
  if (!/^[A-Z2-7]+$/.test(compact) || compact.length < 8) {
    throw new VaultError('INVALID_TOTP', 'The one-time-password secret must be base32 (at least 8 characters).');
  }
  return compact;
}

/** RFC 6238 TOTP at a specific millisecond timestamp. */
export function totpAt(secret, timestamp = Date.now(), periodSeconds = 30, digits = 6) {
  const key = base32Decode(secret);
  if (key.length === 0) return '';
  const counter = Math.floor(timestamp / 1000 / periodSeconds);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Current TOTP plus the seconds left in its window. */
export function currentTotp(secret, timestamp = Date.now(), periodSeconds = 30) {
  if (!secret) return null;
  const code = totpAt(secret, timestamp, periodSeconds);
  const remaining = periodSeconds - (Math.floor(timestamp / 1000) % periodSeconds);
  return { code, secondsRemaining: remaining, period: periodSeconds };
}

/** Secret encodings that may appear in command or HTTP output. */
function secretVariants(secret) {
  const text = String(secret ?? '');
  if (text.length < 3) return [];
  const variants = new Set([text, encodeURIComponent(text), JSON.stringify(text).slice(1, -1)]);
  try {
    variants.add(Buffer.from(text).toString('base64'));
    variants.add(Buffer.from(text).toString('base64url'));
  } catch {
    // Text that cannot be encoded still has its raw form in the set.
  }
  return [...variants].filter((item) => item.length >= 3).sort((a, b) => b.length - a.length);
}

/** Replace known secret encodings in a string. */
export function scrubSecrets(text, secrets) {
  let value = String(text ?? '');
  let redacted = false;
  const variants = [...new Set((secrets ?? []).flatMap(secretVariants))].sort((a, b) => b.length - a.length);
  for (const variant of variants) {
    if (variant === '' || !value.includes(variant)) continue;
    value = value.split(variant).join('[REDACTED]');
    redacted = true;
  }
  return { text: value, redacted };
}

/** Build the environment passed to a leased command. */
function buildCredentialEnv(entry) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith('VAULT_')) delete env[key];
  }
  const totp = currentTotp(entry.totpSecret)?.code ?? '';
  Object.assign(env, {
    VAULT_ENTRY_ID: entry.id,
    VAULT_LABEL: entry.label,
    VAULT_USERNAME: entry.username,
    VAULT_PASSWORD: entry.password,
    VAULT_SECRET: entry.password,
    VAULT_TOKEN: entry.password,
    VAULT_TOTP: totp,
    VAULT_URL: entry.url,
    VAULT_NOTES: entry.notes,
    VAULT_AUTH_TYPE: entry.authType,
    VAULT_AUTH_KEY: entry.authKey,
    VAULT_ALLOWED_HOSTS: (entry.allowedHosts ?? []).join(','),
  });
  return env;
}

/** Run a command with bounded output. */
function runCommand(file, args, options) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(file, args, {
        cwd: options.cwd,
        env: options.env,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(new VaultError('EXEC_FAILED', `Could not start the command: ${error.message}`, 500));
      return;
    }
    let stdout = '';
    let stderr = '';
    let truncated = false;
    let timedOut = false;
    let settled = false;
    const started = Date.now();
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener?.('abort', onAbort);
      resolve(result);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, options.timeoutMs);
    timer.unref?.();
    const onAbort = () => child.kill();
    if (options.signal) {
      if (options.signal.aborted) onAbort();
      else options.signal.addEventListener('abort', onAbort, { once: true });
    }
    const collect = (chunk, current) => {
      if (current.length >= MAX_OUTPUT_BYTES) {
        truncated = true;
        return current;
      }
      const remaining = MAX_OUTPUT_BYTES - current.length;
      if (chunk.length > remaining) truncated = true;
      return current + chunk.subarray(0, remaining).toString('utf8');
    };
    child.stdout.on('data', (chunk) => {
      stdout = collect(chunk, stdout);
    });
    child.stderr.on('data', (chunk) => {
      stderr = collect(chunk, stderr);
    });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener?.('abort', onAbort);
      reject(new VaultError('EXEC_FAILED', `Could not run the command: ${error.message}`, 500));
    });
    child.on('close', (code, signal) => {
      finish({
        exitCode: typeof code === 'number' ? code : null,
        signal: signal ?? null,
        stdout,
        stderr,
        truncated,
        timedOut,
        durationMs: Date.now() - started,
      });
    });
  });
}

/** Read a fetch response body up to a byte limit. */
async function readLimitedBody(response, maxBytes = MAX_HTTP_BODY_BYTES) {
  if (response.body === null) return { text: '', truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (total >= maxBytes) {
      truncated = true;
      break;
    }
    const take = Math.min(value.byteLength, maxBytes - total);
    chunks.push(value.subarray(0, take));
    total += take;
    if (take < value.byteLength) {
      truncated = true;
      break;
    }
  }
  try {
    await reader.cancel();
  } catch {
    // The body may already be closed.
  }
  return { text: Buffer.concat(chunks).toString('utf8'), truncated };
}

/** Redact secret values from a URL's userinfo and query values. */
function redactUrl(url, secrets) {
  const copy = new URL(url.toString());
  copy.username = '';
  copy.password = '';
  const values = new Set((secrets ?? []).map(String));
  for (const key of [...copy.searchParams.keys()]) {
    const value = copy.searchParams.get(key) ?? '';
    if (values.has(value) || secretVariants(value).some((variant) => values.has(variant))) {
      copy.searchParams.set(key, '[REDACTED]');
    }
  }
  return copy.toString();
}

/** Substitute documented placeholders in a string. */
function fillPlaceholders(value, context, mode) {
  return String(value).replace(/\{\{\s*(username|password|secret|totp|label|url|auth_key)\s*\}\}/gi, (_match, name) => {
    const key = name.toLowerCase();
    const raw = key === 'username'
      ? context.username
      : key === 'label'
        ? context.label
        : key === 'url'
          ? context.url
          : key === 'auth_key'
            ? context.authKey
            : key === 'totp'
              ? context.totp
              : context.password;
    return mode === 'url' ? encodeURIComponent(raw ?? '') : String(raw ?? '');
  });
}

/** Convert a database row to the UI-safe summary. */
function toUiSummary(entry) {
  return {
    id: entry.id,
    label: entry.label,
    username: entry.username,
    accountHint: maskAccount(entry.username),
    url: entry.url,
    tags: [...entry.tags],
    authType: entry.authType,
    authKey: entry.authKey,
    notes: entry.notes,
    aiEnabled: entry.aiEnabled,
    allowInsecure: entry.allowInsecure,
    allowedHosts: [...entry.allowedHosts],
    hasPassword: entry.password !== '',
    hasTotp: entry.totpSecret !== '',
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  };
}

/** Convert a database row to model-facing metadata with no secrets. */
function toAiSummary(entry) {
  return {
    id: entry.id,
    label: entry.label,
    accountHint: maskAccount(entry.username),
    url: entry.url,
    tags: [...entry.tags],
    authType: entry.authType,
    hasPassword: entry.password !== '',
    hasTotp: entry.totpSecret !== '',
    updatedAt: entry.updatedAt,
  };
}

/** Convert a database row to editor data without secrets. */
function toUiDetail(entry) {
  return {
    ...toUiSummary(entry),
    notes: entry.notes,
  };
}

/** Validate a non-negative number with a fallback. */
function numberOption(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : fallback;
}

/**
 * Encrypted local credential store.
 *
 * All mutations are serialized through a promise chain; reads use the
 * in-memory decrypted map only while the vault is unlocked.
 */
export class VaultStore {
  constructor(options = {}) {
    this.dir = options.dir ?? defaultVaultDir();
    this.file = options.file ?? join(this.dir, 'vault.json');
    this.settingsFile = join(this.dir, 'settings.json');
    this.auditFile = join(this.dir, 'audit.jsonl');
    this.allowExec = false;
    this.leaseMinutes = Math.max(1, numberOption(options.leaseMinutes, DEFAULT_LEASE_MINUTES));
    this.autoLockMinutes = numberOption(options.autoLockMinutes, DEFAULT_AUTO_LOCK_MINUTES);
    this.now = options.now ?? (() => Date.now());
    this.vault = null;
    this.broken = false;
    this.key = null;
    this.entries = new Map();
    this.leases = new Map();
    this.unlocked = false;
    this.loadError = null;
    this.lastActivity = 0;
    this.queue = Promise.resolve();
    this.timer = null;
  }

  /** Load metadata and auto-unlock when Windows DPAPI protects the key. */
  async init() {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    try {
      await chmod(this.dir, 0o700);
    } catch {
      // Windows does not expose POSIX directory modes.
    }
    await this.loadSettings();
    try {
      const text = await readFile(this.file, 'utf8');
      const parsed = JSON.parse(text);
      this.validateVaultDocument(parsed);
      this.vault = parsed;
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.loadError = error instanceof Error ? error.message : String(error);
        this.vault = null;
        this.broken = true;
      }
    }
    if (this.vault !== null && this.vault.protection.mode === 'dpapi') {
      try {
        this.key = await unprotectWithDpapi(this.vault.protection.dpapi);
        this.decryptEntries();
        this.unlocked = true;
        this.lastActivity = this.now();
      } catch (error) {
        this.loadError = error instanceof Error ? error.message : String(error);
        this.key?.fill?.(0);
        this.key = null;
        this.entries.clear();
        this.unlocked = false;
      }
    }
    this.startAutoLock();
    return this.status();
  }

  /** Validate the outer shape of a vault document. */
  validateVaultDocument(document) {
    if (document === null || typeof document !== 'object') {
      throw new VaultError('VAULT_CORRUPT', 'The vault file is not valid JSON.', 500);
    }
    if (document.version !== VAULT_VERSION) {
      throw new VaultError('VAULT_VERSION', `Unsupported vault version ${String(document.version)}.`, 500);
    }
    const protection = document.protection;
    if (protection === null || typeof protection !== 'object') {
      throw new VaultError('VAULT_CORRUPT', 'The vault has no key protection.', 500);
    }
    if (protection.mode !== 'dpapi' && protection.mode !== 'password') {
      throw new VaultError('VAULT_CORRUPT', 'The vault key protection mode is unknown.', 500);
    }
    if (!Array.isArray(document.entries)) {
      throw new VaultError('VAULT_CORRUPT', 'The vault entries are malformed.', 500);
    }
  }

  /** Start the idle-lock timer for master-password vaults. */
  startAutoLock() {
    if (this.timer !== null) clearInterval(this.timer);
    if (this.autoLockMinutes <= 0) {
      this.timer = null;
      return;
    }
    this.timer = setInterval(() => {
      if (!this.unlocked || this.vault?.protection.mode !== 'password') return;
      const idleMs = this.now() - this.lastActivity;
      if (idleMs >= this.autoLockMinutes * 60_000) this.lock();
    }, 60_000);
    this.timer.unref?.();
  }

  /** Refresh the idle deadline after an authenticated operation. */
  touch() {
    this.lastActivity = this.now();
  }

  /** Load non-secret plugin switches; a missing file keeps secure defaults. */
  async loadSettings() {
    try {
      const parsed = JSON.parse(await readFile(this.settingsFile, 'utf8'));
      this.allowExec = parsed?.allowExec === true;
    } catch {
      this.allowExec = false;
    }
  }

  /** Persist non-secret plugin switches without touching the encrypted vault. */
  async writeSettings() {
    const temporary = `${this.settingsFile}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    const text = `${JSON.stringify({ version: 1, allowExec: this.allowExec }, null, 2)}\n`;
    try {
      await writeFile(temporary, text, { mode: 0o600 });
      try {
        await rename(temporary, this.settingsFile);
      } catch (error) {
        if (error?.code !== 'EEXIST' && error?.code !== 'EPERM') throw error;
        await unlink(this.settingsFile).catch(() => {});
        await rename(temporary, this.settingsFile);
      }
      try {
        await chmod(this.settingsFile, 0o600);
      } catch {
        // Windows does not expose POSIX file modes.
      }
    } finally {
      await unlink(temporary).catch(() => {});
    }
  }

  /** Enable or disable the command bridge. Disabled is the secure default. */
  async setAllowExec(enabled) {
    return this.withLock(async () => {
      this.requireUnlocked();
      this.allowExec = enabled === true;
      await this.writeSettings();
      await this.audit('settings.exec', {
        actor: 'ui',
        detail: this.allowExec ? 'on' : 'off',
      });
      return { allowExec: this.allowExec };
    });
  }

  /** Refuse the command bridge unless the user explicitly enabled it. */
  requireExecEnabled() {
    if (!this.allowExec) {
      throw new VaultError(
        'EXEC_DISABLED',
        'vault_exec is disabled by default. Ask the user to enable it in Settings > Password vault > Advanced.',
        403,
      );
    }
  }

  /** Serialize a mutation against other mutations. */
  withLock(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Public status that never includes key material. */
  status() {
    const configured = this.vault !== null || this.broken;
    const mode = this.vault?.protection.mode ?? null;
    const entryCount = this.vault !== null && this.unlocked ? this.entries.size : 0;
    const aiEntryCount = this.vault !== null && this.unlocked
      ? [...this.entries.values()].filter((entry) => entry.aiEnabled).length
      : 0;
    return {
      configured,
      unlocked: this.unlocked,
      locked: configured && !this.unlocked,
      broken: this.broken,
      autoUnlock: mode === 'dpapi',
      protection: mode,
      entryCount,
      aiEntryCount,
      vaultPath: this.file,
      vaultDir: this.dir,
      version: VAULT_VERSION,
      leaseMinutes: this.leaseMinutes,
      autoLockMinutes: this.autoLockMinutes,
      allowExec: this.allowExec,
      error: this.loadError,
    };
  }

  /** Create a new vault. An empty master password uses Windows DPAPI. */
  async setup({ masterPassword = '' } = {}) {
    return this.withLock(async () => {
      if (this.vault !== null || this.broken) {
        throw new VaultError('VAULT_EXISTS', 'A vault file already exists. Repair or remove it before creating a new one.', 409);
      }
      const password = String(masterPassword ?? '');
      const key = randomBytes(KEY_BYTES);
      let protection;
      if (password !== '') {
        if (password.length < 6) {
          throw new VaultError('WEAK_PASSWORD', 'Use a master password of at least 6 characters.');
        }
        const salt = randomBytes(16);
        protection = {
          mode: 'password',
          salt: salt.toString('base64'),
          wrappedKey: wrapKeyWithPassword(key, password, salt),
        };
      } else {
        protection = { mode: 'dpapi', dpapi: await protectWithDpapi(key) };
      }
      this.vault = {
        version: VAULT_VERSION,
        createdAt: new Date(this.now()).toISOString(),
        updatedAt: new Date(this.now()).toISOString(),
        protection,
        entries: [],
      };
      this.key = key;
      this.entries.clear();
      this.unlocked = true;
      this.loadError = null;
      this.touch();
      await this.persist();
      await this.audit('vault.create', { actor: 'ui', detail: protection.mode });
      return this.status();
    });
  }

  /** Unlock a master-password vault; DPAPI vaults unlock without a prompt. */
  async unlock({ masterPassword = '' } = {}) {
    return this.withLock(async () => {
      if (this.vault === null) {
        throw new VaultError(
          this.broken ? 'VAULT_CORRUPT' : 'VAULT_NOT_CONFIGURED',
          this.broken ? 'The vault file is unreadable. Restore a backup before unlocking.' : 'Create the vault first.',
          this.broken ? 500 : 404,
        );
      }
      if (this.unlocked) return this.status();
      let key;
      if (this.vault.protection.mode === 'dpapi') {
        key = await unprotectWithDpapi(this.vault.protection.dpapi);
      } else {
        const password = String(masterPassword ?? '');
        if (password === '') throw new VaultError('VAULT_LOCKED', 'Enter the master password to unlock.', 423);
        key = unwrapKeyWithPassword(
          this.vault.protection.wrappedKey,
          password,
          Buffer.from(this.vault.protection.salt, 'base64'),
        );
      }
      const previousKey = this.key;
      this.key = key;
      try {
        this.decryptEntries();
      } catch (error) {
        this.key = previousKey;
        this.entries.clear();
        this.unlocked = false;
        throw error;
      }
      previousKey?.fill?.(0);
      this.unlocked = true;
      this.loadError = null;
      this.touch();
      await this.audit('vault.unlock', { actor: 'ui' });
      return this.status();
    });
  }

  /** Drop decrypted state and keys from memory. */
  lock({ audit = true } = {}) {
    if (this.key !== null) this.key.fill(0);
    this.key = null;
    this.entries.clear();
    this.leases.clear();
    this.unlocked = false;
    if (audit && this.vault !== null) this.audit('vault.lock', { actor: 'ui' }).catch(() => {});
  }

  /** Decrypt every entry into the in-memory map. */
  decryptEntries() {
    if (this.key === null) throw new VaultError('VAULT_LOCKED', 'The vault is locked.', 423);
    const next = new Map();
    for (const record of this.vault.entries) {
      const id = String(record.id ?? '');
      if (!/^[a-f0-9-]{36}$/i.test(id)) {
        throw new VaultError('VAULT_CORRUPT', 'The vault contains an invalid entry id.', 500);
      }
      const plaintext = decryptString(
        this.key,
        record.data,
        `entry:${id}:v${ENTRY_VERSION}`,
      );
      if (Buffer.byteLength(plaintext, 'utf8') > MAX_ENTRY_BYTES) {
        throw new VaultError('VAULT_CORRUPT', 'The vault contains an oversized entry.', 500);
      }
      let parsed;
      try {
        parsed = JSON.parse(plaintext);
      } catch {
        throw new VaultError('VAULT_CORRUPT', 'The vault contains an unreadable entry.', 500);
      }
      const entry = this.normalizeStoredEntry(parsed, record, id);
      next.set(id, entry);
    }
    this.entries = next;
  }

  /** Validate one decrypted entry and fill defaults from its outer record. */
  normalizeStoredEntry(parsed, record, id) {
    if (parsed === null || typeof parsed !== 'object') {
      throw new VaultError('VAULT_CORRUPT', 'The vault contains an invalid entry.', 500);
    }
    return {
      id,
      aiEnabled: record.aiEnabled !== false,
      createdAt: String(record.createdAt ?? parsed.createdAt ?? new Date(this.now()).toISOString()),
      updatedAt: String(record.updatedAt ?? parsed.updatedAt ?? new Date(this.now()).toISOString()),
      label: String(parsed.label ?? ''),
      username: String(parsed.username ?? ''),
      password: String(parsed.password ?? ''),
      url: String(parsed.url ?? ''),
      notes: String(parsed.notes ?? ''),
      tags: Array.isArray(parsed.tags) ? parsed.tags.map(String) : [],
      totpSecret: String(parsed.totpSecret ?? ''),
      authType: AUTH_TYPES.has(parsed.authType) ? parsed.authType : 'none',
      authKey: String(parsed.authKey ?? ''),
      allowedHosts: Array.isArray(parsed.allowedHosts) ? parsed.allowedHosts.map(String) : [],
      allowInsecure: parsed.allowInsecure === true,
    };
  }

  /** Persist all entries as ciphertext. */
  async persist() {
    if (this.vault === null || this.key === null) {
      throw new VaultError('VAULT_LOCKED', 'The vault is locked.', 423);
    }
    const records = [];
    for (const entry of this.entries.values()) {
      const payload = {
        version: ENTRY_VERSION,
        label: entry.label,
        username: entry.username,
        password: entry.password,
        url: entry.url,
        notes: entry.notes,
        tags: entry.tags,
        totpSecret: entry.totpSecret,
        authType: entry.authType,
        authKey: entry.authKey,
        allowedHosts: entry.allowedHosts,
        allowInsecure: entry.allowInsecure,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      };
      const plaintext = JSON.stringify(payload);
      if (Buffer.byteLength(plaintext, 'utf8') > MAX_ENTRY_BYTES) {
        throw new VaultError('ENTRY_TOO_LARGE', 'This entry is too large to store.');
      }
      records.push({
        id: entry.id,
        aiEnabled: entry.aiEnabled,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
        data: encryptString(this.key, plaintext, `entry:${entry.id}:v${ENTRY_VERSION}`),
      });
    }
    const document = {
      ...this.vault,
      updatedAt: new Date(this.now()).toISOString(),
      entries: records,
    };
    const text = `${JSON.stringify(document, null, 2)}\n`;
    await this.writeAtomic(text);
    this.vault = document;
  }

  /** Write the vault file atomically and keep one ciphertext backup. */
  async writeAtomic(text) {
    const temporary = `${this.file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      await copyFile(this.file, `${this.file}.bak`).catch(() => {});
      const handle = await open(temporary, 'w', 0o600);
      try {
        await handle.writeFile(text, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        await rename(temporary, this.file);
      } catch (error) {
        if (error?.code !== 'EEXIST' && error?.code !== 'EPERM') throw error;
        await unlink(this.file).catch(() => {});
        await rename(temporary, this.file);
      }
      try {
        await chmod(this.file, 0o600);
      } catch {
        // Windows does not expose POSIX file modes.
      }
    } finally {
      await unlink(temporary).catch(() => {});
    }
  }

  /** Require an unlocked vault. */
  requireUnlocked() {
    if (this.vault === null) {
      throw new VaultError(
        this.broken ? 'VAULT_CORRUPT' : 'VAULT_NOT_CONFIGURED',
        this.broken
          ? 'The vault file is unreadable. Restore a backup before using it.'
          : 'Create the vault in Settings > Password vault first.',
        this.broken ? 500 : 404,
      );
    }
    if (!this.unlocked || this.key === null) {
      throw new VaultError('VAULT_LOCKED', 'The password vault is locked. Unlock it in Settings > Password vault.', 423);
    }
    this.touch();
  }

  /** Find an entry or throw. */
  requireEntry(id) {
    this.requireUnlocked();
    const entry = this.entries.get(String(id ?? ''));
    if (entry === undefined) throw new VaultError('ENTRY_NOT_FOUND', 'No matching credential entry was found.', 404);
    return entry;
  }

  /** List entries for the local UI or for the model. */
  list({ audience = 'ui' } = {}) {
    this.requireUnlocked();
    const rows = [...this.entries.values()]
      .filter((entry) => audience !== 'ai' || entry.aiEnabled)
      .sort((a, b) => a.label.localeCompare(b.label, 'zh-CN'));
    return {
      count: rows.length,
      entries: rows.map((entry) => audience === 'ai' ? toAiSummary(entry) : toUiSummary(entry)),
    };
  }

  /** Read one entry; `reveal` is reserved for the local UI. */
  get(id, { reveal = false } = {}) {
    const entry = this.requireEntry(id);
    if (!reveal) return toUiDetail(entry);
    return {
      ...toUiDetail(entry),
      password: entry.password,
      totpSecret: entry.totpSecret,
      totp: currentTotp(entry.totpSecret),
    };
  }

  /** Create or update an entry. A blank password keeps the existing one. */
  async save(input = {}) {
    return this.withLock(async () => {
      this.requireUnlocked();
      const now = new Date(this.now()).toISOString();
      const existing = input.id === undefined ? undefined : this.entries.get(String(input.id));
      if (input.id !== undefined && existing === undefined) {
        throw new VaultError('ENTRY_NOT_FOUND', 'No matching credential entry was found.', 404);
      }
      const entry = existing === undefined
        ? {
            id: randomUUID(),
            aiEnabled: true,
            createdAt: now,
            updatedAt: now,
            label: '',
            username: '',
            password: '',
            url: '',
            notes: '',
            tags: [],
            totpSecret: '',
            authType: 'none',
            authKey: '',
            allowedHosts: [],
            allowInsecure: false,
          }
        : { ...existing, tags: [...existing.tags], allowedHosts: [...existing.allowedHosts] };

      if (input.label !== undefined) {
        const label = String(input.label).trim();
        if (label === '' || label.length > 200) {
          throw new VaultError('INVALID_LABEL', 'The name must be between 1 and 200 characters.');
        }
        entry.label = label;
      } else if (existing === undefined) {
        throw new VaultError('INVALID_LABEL', 'The name is required.');
      }

      if (input.username !== undefined) entry.username = String(input.username).slice(0, 500);
      if (input.password !== undefined && input.password !== null && input.password !== '') {
        entry.password = String(input.password).slice(0, 4096);
      }
      if (input.clearPassword === true) entry.password = '';
      if (input.notes !== undefined) entry.notes = String(input.notes).slice(0, 8000);
      if (input.tags !== undefined) {
        const tags = (Array.isArray(input.tags) ? input.tags : String(input.tags).split(','))
          .map((tag) => String(tag).trim())
          .filter(Boolean)
          .slice(0, 30)
          .map((tag) => tag.slice(0, 40));
        entry.tags = [...new Set(tags)];
      }

      if (input.url !== undefined) {
        const url = String(input.url).trim();
        if (url !== '') {
          let parsed;
          try {
            parsed = new URL(url);
          } catch {
            throw new VaultError('INVALID_URL', 'The sign-in URL is not a valid URL.');
          }
          if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            throw new VaultError('INVALID_URL', 'The sign-in URL must use http or https.');
          }
        }
        entry.url = url.slice(0, 2000);
      }

      if (input.authType !== undefined) {
        const authType = String(input.authType);
        if (!AUTH_TYPES.has(authType)) throw new VaultError('INVALID_AUTH_TYPE', 'Unknown authentication type.');
        entry.authType = authType;
      }
      if (input.authKey !== undefined) entry.authKey = String(input.authKey).trim().slice(0, 120);
      if (input.allowInsecure !== undefined) entry.allowInsecure = input.allowInsecure === true;

      if (input.totpSecret !== undefined) {
        const raw = String(input.totpSecret).trim();
        entry.totpSecret = raw === '' ? '' : normalizeTotpSecret(raw);
      }

      if (input.allowedHosts !== undefined) {
        entry.allowedHosts = parseAllowedHosts(input.allowedHosts);
      } else if (existing === undefined || input.url !== undefined) {
        entry.allowedHosts = entry.url === '' ? [] : parseAllowedHosts([new URL(entry.url).hostname]);
      }
      if (entry.url !== '' && entry.allowedHosts.length === 0) {
        entry.allowedHosts = parseAllowedHosts([new URL(entry.url).hostname]);
      }
      if (entry.authType === 'header' && entry.authKey === '') entry.authKey = 'X-API-Key';
      if (entry.authType === 'query' && entry.authKey === '') entry.authKey = 'api_key';
      if (['basic', 'bearer'].includes(entry.authType)) entry.authKey = '';

      if (input.aiEnabled !== undefined) entry.aiEnabled = input.aiEnabled !== false;
      entry.updatedAt = now;
      this.entries.set(entry.id, entry);
      await this.persist();
      await this.audit(existing === undefined ? 'entry.create' : 'entry.update', {
        actor: 'ui',
        entryId: entry.id,
        entryLabel: entry.label,
        detail: `${entry.authType}; ai=${entry.aiEnabled ? 'on' : 'off'}`,
      });
      return toUiDetail(entry);
    });
  }

  /** Delete an entry and its leases. */
  async delete(id) {
    return this.withLock(async () => {
      const entry = this.requireEntry(id);
      this.entries.delete(entry.id);
      for (const [token, lease] of this.leases) {
        if (lease.entryId === entry.id) this.leases.delete(token);
      }
      await this.persist();
      await this.audit('entry.delete', {
        actor: 'ui',
        entryId: entry.id,
        entryLabel: entry.label,
      });
      return { deleted: entry.id };
    });
  }

  /** Toggle model access for one entry. */
  async setAiEnabled(id, enabled) {
    return this.withLock(async () => {
      const entry = this.requireEntry(id);
      entry.aiEnabled = enabled !== false;
      entry.updatedAt = new Date(this.now()).toISOString();
      await this.persist();
      await this.audit('entry.ai', {
        actor: 'ui',
        entryId: entry.id,
        entryLabel: entry.label,
        detail: entry.aiEnabled ? 'on' : 'off',
      });
      return toUiSummary(entry);
    });
  }

  /** Current TOTP for the local UI. */
  totp(id) {
    const entry = this.requireEntry(id);
    return currentTotp(entry.totpSecret);
  }

  /** Change key protection; an empty password switches back to DPAPI. */
  async changeProtection({ masterPassword = '' } = {}) {
    return this.withLock(async () => {
      this.requireUnlocked();
      const password = String(masterPassword ?? '');
      if (password !== '' && password.length < 6) {
        throw new VaultError('WEAK_PASSWORD', 'Use a master password of at least 6 characters.');
      }
      let protection;
      if (password !== '') {
        const salt = randomBytes(16);
        protection = {
          mode: 'password',
          salt: salt.toString('base64'),
          wrappedKey: wrapKeyWithPassword(this.key, password, salt),
        };
      } else {
        protection = { mode: 'dpapi', dpapi: await protectWithDpapi(this.key) };
      }
      this.vault = { ...this.vault, protection };
      await this.persist();
      this.startAutoLock();
      await this.audit('vault.protection', { actor: 'ui', detail: protection.mode });
      return this.status();
    });
  }

  /** Create a short-lived model lease for one entry. */
  createLease(id, { purpose = '', sessionId = null } = {}) {
    this.requireUnlocked();
    const entry = this.requireEntry(id);
    if (!entry.aiEnabled) {
      throw new VaultError('AI_DISABLED', 'AI access is disabled for this entry.', 403);
    }
    this.pruneLeases();
    const token = b64url(randomBytes(24));
    const expiresAt = this.now() + this.leaseMinutes * 60_000;
    this.leases.set(token, {
      entryId: entry.id,
      expiresAt,
      purpose: String(purpose ?? '').slice(0, 500),
    });
    this.audit('ai.use', {
      actor: 'ai',
      entryId: entry.id,
      entryLabel: entry.label,
      sessionId,
      detail: purpose ? String(purpose).slice(0, 200) : '',
    }).catch(() => {});
    return {
      lease: token,
      expiresAt: new Date(expiresAt).toISOString(),
      expiresInSeconds: this.leaseMinutes * 60,
      entry: toAiSummary(entry),
      message: 'Use this lease with vault_exec or vault_http. It expires automatically.',
    };
  }

  /** Resolve and refresh a lease. */
  resolveLease(token) {
    this.requireUnlocked();
    this.pruneLeases();
    const lease = this.leases.get(String(token ?? ''));
    if (lease === undefined) {
      throw new VaultError('LEASE_INVALID', 'The lease is invalid or has expired. Call vault_use again.', 403);
    }
    if (lease.expiresAt <= this.now()) {
      this.leases.delete(String(token));
      throw new VaultError('LEASE_EXPIRED', 'The lease has expired. Call vault_use again.', 403);
    }
    const entry = this.entries.get(lease.entryId);
    if (entry === undefined) {
      this.leases.delete(String(token));
      throw new VaultError('LEASE_INVALID', 'The leased entry no longer exists.', 403);
    }
    if (!entry.aiEnabled) {
      this.leases.delete(String(token));
      throw new VaultError('AI_DISABLED', 'AI access is disabled for this entry.', 403);
    }
    this.touch();
    return { lease, entry, expiresAt: new Date(lease.expiresAt).toISOString() };
  }

  /** Drop expired leases. */
  pruneLeases() {
    const now = this.now();
    for (const [token, lease] of this.leases) {
      if (lease.expiresAt <= now) this.leases.delete(token);
    }
  }

  /** Run a command with credentials in its environment, never in its arguments. */
  async execWithLease({ lease, command, timeoutSeconds = 60, cwd, signal, sessionId = null } = {}) {
    this.requireUnlocked();
    this.requireExecEnabled();
    const { entry, expiresAt } = this.resolveLease(lease);
    if (typeof command !== 'string' || command.trim() === '') {
      throw new VaultError('INVALID_COMMAND', 'The command is empty.');
    }
    if (command.length > 16_000) {
      throw new VaultError('INVALID_COMMAND', 'The command is too long.');
    }
    const timeoutMs = Math.min(Math.max(Number(timeoutSeconds) || 60, 1), 300) * 1000;
    const env = buildCredentialEnv(entry);
    const secrets = [entry.password];
    const totp = currentTotp(entry.totpSecret)?.code;
    if (totp) secrets.push(totp);
    const started = Date.now();
    const isWindows = process.platform === 'win32';
    const result = await runCommand(
      isWindows ? 'powershell.exe' : '/bin/bash',
      isWindows
        ? ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command]
        : ['-lc', command],
      {
        env,
        cwd: typeof cwd === 'string' && cwd.trim() !== '' ? cwd : process.cwd(),
        timeoutMs,
        signal,
      },
    );
    const cleanOut = scrubSecrets(result.stdout, secrets);
    const cleanErr = scrubSecrets(result.stderr, secrets);
    await this.audit('ai.exec', {
      actor: 'ai',
      entryId: entry.id,
      entryLabel: entry.label,
      sessionId,
      detail: `exit=${String(result.exitCode)}${result.timedOut ? ' timeout' : ''}`,
    });
    return {
      entryId: entry.id,
      label: entry.label,
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: cleanOut.text,
      stderr: cleanErr.text,
      truncated: result.truncated,
      timedOut: result.timedOut,
      redacted: cleanOut.redacted || cleanErr.redacted,
      durationMs: result.durationMs || (Date.now() - started),
      leaseExpiresAt: expiresAt,
    };
  }

  /** Perform an HTTP request with credentials injected host-side. */
  async httpWithLease({
    lease,
    url,
    method = 'GET',
    headers = {},
    body,
    timeoutSeconds = 60,
    signal,
    sessionId = null,
  } = {}) {
    const { entry, expiresAt } = this.resolveLease(lease);
    const targetText = String(url ?? '').trim() || entry.url;
    if (targetText === '') {
      throw new VaultError('INVALID_URL', 'No URL was supplied and the entry has no default URL.');
    }
    let target;
    try {
      target = new URL(targetText);
    } catch {
      throw new VaultError('INVALID_URL', 'The request URL is not valid.');
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      throw new VaultError('INVALID_URL', 'Only http and https requests are supported.');
    }
    const allowedHosts = entry.allowedHosts.length > 0
      ? entry.allowedHosts
      : entry.url !== ''
        ? [new URL(entry.url).hostname]
        : [];
    if (!hostAllowed(target.hostname, allowedHosts)) {
      throw new VaultError(
        'HOST_NOT_ALLOWED',
        `The host ${target.hostname} is not allowed for this entry. Edit the entry's allowed hosts to permit it.`,
        403,
      );
    }
    if (target.protocol === 'http:' && !isLoopbackHost(target.hostname) && !entry.allowInsecure) {
      throw new VaultError(
        'INSECURE_HTTP',
        'This entry only permits HTTP for loopback addresses. Use HTTPS, or enable insecure HTTP for this entry.',
        403,
      );
    }
    const verb = String(method).toUpperCase();
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(verb)) {
      throw new VaultError('INVALID_METHOD', 'Unsupported HTTP method.');
    }
    const totp = currentTotp(entry.totpSecret)?.code ?? '';
    const context = {
      username: entry.username,
      password: entry.password,
      label: entry.label,
      url: entry.url,
      authKey: entry.authKey,
      totp,
    };
    const filledUrl = fillPlaceholders(target.toString(), context, 'url');
    try {
      target = new URL(filledUrl);
    } catch {
      throw new VaultError('INVALID_URL', 'The request URL became invalid after credential substitution.');
    }
    if (!hostAllowed(target.hostname, allowedHosts)) {
      throw new VaultError('HOST_NOT_ALLOWED', 'Credential substitution changed the request host.', 403);
    }

    const requestHeaders = new Headers();
    for (const [key, value] of Object.entries(headers ?? {})) {
      const name = String(key).trim();
      if (name === '' || /^(host|content-length|connection|transfer-encoding)$/i.test(name)) continue;
      requestHeaders.set(name, fillPlaceholders(value, context, 'header'));
    }
    let requestBody;
    if (body !== undefined && body !== null) {
      if (verb === 'GET' || verb === 'HEAD') {
        throw new VaultError('INVALID_BODY', 'GET and HEAD requests cannot carry a body.');
      }
      if (typeof body === 'string') {
        requestBody = fillPlaceholders(body, context, 'body');
      } else {
        requestBody = fillPlaceholders(JSON.stringify(body), context, 'body');
        if (!requestHeaders.has('content-type')) requestHeaders.set('content-type', 'application/json');
      }
    }

    if (entry.authType === 'basic') {
      if (entry.username === '' && entry.password === '') {
        throw new VaultError('MISSING_CREDENTIALS', 'This entry has no username or password for Basic auth.');
      }
      requestHeaders.set(
        'authorization',
        `Basic ${Buffer.from(`${entry.username}:${entry.password}`, 'utf8').toString('base64')}`,
      );
    } else if (entry.authType === 'bearer') {
      if (entry.password === '') throw new VaultError('MISSING_CREDENTIALS', 'This entry has no token for Bearer auth.');
      requestHeaders.set('authorization', `Bearer ${entry.password}`);
    } else if (entry.authType === 'header') {
      requestHeaders.set(entry.authKey || 'X-API-Key', entry.password);
    } else if (entry.authType === 'query') {
      target.searchParams.set(entry.authKey || 'api_key', entry.password);
    }

    const secrets = [entry.password];
    if (totp) secrets.push(totp);
    const authorization = requestHeaders.get('authorization');
    if (authorization) secrets.push(authorization.replace(/^(?:Basic|Bearer)\s+/i, ''));
    const started = Date.now();
    let response;
    try {
      response = await fetch(target, {
        method: verb,
        headers: requestHeaders,
        body: requestBody,
        redirect: 'manual',
        signal: signal ?? AbortSignal.timeout(Math.min(Math.max(Number(timeoutSeconds) || 60, 1), 300) * 1000),
      });
    } catch (error) {
      await this.audit('ai.http', {
        actor: 'ai',
        entryId: entry.id,
        entryLabel: entry.label,
        sessionId,
        detail: `error=${error?.name ?? 'Error'}`,
      });
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        throw new VaultError('HTTP_TIMEOUT', 'The HTTP request timed out.', 504);
      }
      throw new VaultError('HTTP_FAILED', `The HTTP request failed: ${error?.message ?? 'unknown error'}`, 502);
    }
    const payload = await readLimitedBody(response);
    const responseHeaders = {};
    for (const [key, value] of response.headers) {
      if (/^(set-cookie|cookie|authorization|proxy-authenticate)$/i.test(key)) continue;
      responseHeaders[key] = scrubSecrets(value, secrets).text;
    }
    const cleanBody = scrubSecrets(payload.text, secrets);
    const redactedHeader = Object.values(responseHeaders).some((value) => value.includes('[REDACTED]'));
    await this.audit('ai.http', {
      actor: 'ai',
      entryId: entry.id,
      entryLabel: entry.label,
      sessionId,
      detail: `${verb} ${response.status}`,
    });
    return {
      entryId: entry.id,
      label: entry.label,
      status: response.status,
      statusText: response.statusText,
      url: redactUrl(target, secrets),
      headers: responseHeaders,
      body: cleanBody.text,
      truncated: payload.truncated,
      redacted: cleanBody.redacted || redactedHeader,
      redirected: response.status >= 300 && response.status < 400,
      location: response.headers.get('location') === null
        ? null
        : scrubSecrets(response.headers.get('location'), secrets).text,
      durationMs: Date.now() - started,
      leaseExpiresAt: expiresAt,
    };
  }

  /** Append one audit line, rotating the log at a bounded size. */
  async audit(action, { actor = 'ui', entryId = null, entryLabel = null, sessionId = null, detail = '' } = {}) {
    try {
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      try {
        const info = await stat(this.auditFile);
        if (info.size > 512 * 1024) await rename(this.auditFile, `${this.auditFile}.1`).catch(() => {});
      } catch {
        // No existing log.
      }
      const line = JSON.stringify({
        at: new Date(this.now()).toISOString(),
        action,
        actor,
        entryId,
        entryLabel,
        sessionId,
        detail: String(detail ?? '').slice(0, 300),
      });
      const handle = await open(this.auditFile, 'a', 0o600);
      try {
        await handle.writeFile(`${line}\n`, 'utf8');
      } finally {
        await handle.close();
      }
    } catch {
      // Auditing must never make a credential operation fail.
    }
  }

  /** Read the most recent audit entries. */
  async readAudit(limit = 30) {
    this.requireUnlocked();
    let text = '';
    try {
      text = await readFile(this.auditFile, 'utf8');
    } catch {
      return { entries: [] };
    }
    const count = Math.min(Math.max(Number(limit) || 30, 1), 200);
    const rows = [];
    for (const line of text.trim().split(/\r?\n/).slice(-count)) {
      try {
        const parsed = JSON.parse(line);
        rows.push({
          at: String(parsed.at ?? ''),
          action: String(parsed.action ?? ''),
          actor: String(parsed.actor ?? ''),
          entryId: parsed.entryId ?? null,
          entryLabel: parsed.entryLabel ?? null,
          detail: String(parsed.detail ?? ''),
        });
      } catch {
        // Skip a truncated line.
      }
    }
    return { entries: rows.reverse() };
  }

  /** Release keys, timers, and leases. */
  dispose() {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.lock({ audit: false });
  }
}

/** Constant-time comparison helper for future integrity checks. */
export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

/** SHA-256 fingerprint shown in diagnostics without revealing content. */
export function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}
