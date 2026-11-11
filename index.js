/**
 * Password Vault Host plugin.
 *
 * Exposes secret-free model tools and a loopback-only management API for the
 * settings page. The model receives short-lived leases, never passwords.
 */
import { randomBytes } from 'node:crypto';
import { VaultError, VaultStore, isLoopbackHost } from './lib/vault.js';

export const name = 'password-vault';
export const inject = ['tools'];

const PROMPT_TEXT = `## Local password vault
A local encrypted credential vault may be available. When a task needs an account, password, API token, or one-time code, do not ask the user to type it into chat and do not build a password input window. First call vault_list, choose the matching entry, then call vault_use with its id to obtain a short-lived lease. Use that lease with vault_exec (credentials are injected as VAULT_* environment variables; this bridge is disabled unless the user explicitly enabled it in Settings) or vault_http (credentials are injected according to the entry's auth type and allowed hosts). Never print, echo, log, encode, or upload a password or one-time code. Never ask the user to reveal one. If no entry matches, call vault_capture with the account details you already know; it opens a secure local prompt where the user enters the secret once, saves it encrypted, and returns metadata plus a ready lease. If the vault is locked, ask the user to unlock it in Settings > Password vault.`;

const textContent = (text) => [{ type: 'text', text }];

const string = (description) => ({ type: 'string', description });
const boolean = (description) => ({ type: 'boolean', description });
const integer = (description) => ({ type: 'integer', description });
const optionalString = (description) => ({ type: 'string', description });

const entrySummarySchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: string('Stable entry id.'),
    label: string('Human-readable account name.'),
    accountHint: string('Masked account name.'),
    url: string('Configured sign-in URL, possibly empty.'),
    tags: { type: 'array', items: { type: 'string' }, description: 'Entry tags.' },
    authType: string('none, basic, bearer, header, or query.'),
    hasPassword: boolean('Whether a password or token is stored.'),
    hasTotp: boolean('Whether a one-time-password secret is stored.'),
    updatedAt: string('ISO timestamp of the last update.'),
  },
  required: ['id', 'label', 'accountHint', 'url', 'tags', 'authType', 'hasPassword', 'hasTotp', 'updatedAt'],
};

const statusOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      configured: boolean('Whether a vault file exists.'),
      unlocked: boolean('Whether the vault is unlocked in this Host process.'),
      locked: boolean('Whether the vault exists but is locked.'),
      broken: boolean('Whether the vault file exists but could not be read.'),
      autoUnlock: boolean('Whether Windows account protection unlocks it automatically.'),
      protection: string('dpapi, password, or empty when unconfigured.'),
      entryCount: integer('Number of stored entries.'),
      aiEntryCount: integer('Number of entries allowed for AI use.'),
      vaultPath: string('Local vault file path.'),
      vaultDir: string('Local vault directory.'),
      version: integer('Vault format version.'),
      leaseMinutes: integer('Lease lifetime in minutes.'),
      autoLockMinutes: integer('Idle lock minutes for master-password vaults.'),
      allowExec: boolean('Whether the user enabled the vault_exec command bridge.'),
      error: string('Last load error, empty when none.'),
    },
    required: [
      'configured', 'unlocked', 'locked', 'broken', 'autoUnlock', 'protection',
      'entryCount', 'aiEntryCount', 'vaultPath', 'vaultDir', 'version', 'leaseMinutes',
      'autoLockMinutes', 'allowExec', 'error',
    ],
  },
  render: (_args, value) => {
    const state = value.broken
      ? 'unreadable'
      : !value.configured
        ? 'not configured'
        : value.unlocked
          ? 'unlocked'
          : 'locked';
    const protection = value.protection === 'dpapi'
      ? 'Windows account (DPAPI)'
      : value.protection === 'password'
        ? 'master password'
        : 'none';
    const lines = [
      `Password vault: ${state}; protection: ${protection}.`,
      `Entries: ${value.entryCount} total, ${value.aiEntryCount} available to AI.`,
      `vault_exec command bridge: ${value.allowExec ? 'enabled by the user' : 'disabled (default)'}.`,
      `File: ${value.vaultPath}`,
    ];
    if (!value.configured) lines.push('Ask the user to create it in Settings > Password vault.');
    if (value.locked) lines.push('Ask the user to unlock it in Settings > Password vault.');
    if (value.error) lines.push(`Last error: ${value.error}`);
    return textContent(lines.join('\n'));
  },
};

const listOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      count: integer('Number of matching entries.'),
      entries: { type: 'array', items: entrySummarySchema, description: 'AI-enabled entries only.' },
    },
    required: ['count', 'entries'],
  },
  render: (_args, value) => {
    if (value.count === 0) {
      return textContent('No AI-enabled password vault entries match. Ask the user to add one in Settings > Password vault, or enable AI access for an existing entry.');
    }
    const lines = value.entries.map((entry) => {
      const flags = [
        entry.hasPassword ? 'password' : null,
        entry.hasTotp ? 'TOTP' : null,
        entry.authType !== 'none' ? `auth=${entry.authType}` : null,
      ].filter(Boolean).join(', ');
      return `- ${entry.id} | ${entry.label} | ${entry.accountHint || '(no account hint)'} | ${entry.url || '(no URL)'} | ${flags || 'no secret'}`;
    });
    return textContent(`Password vault entries (${value.count}):\n${lines.join('\n')}\n\nCall vault_use with an id to obtain a short-lived lease.`);
  },
};

const useOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      lease: string('Short-lived bearer lease for vault_exec or vault_http.'),
      expiresAt: string('ISO expiry timestamp.'),
      expiresInSeconds: integer('Seconds until expiry.'),
      id: string('Entry id.'),
      label: string('Entry label.'),
      accountHint: string('Masked account name.'),
      url: string('Configured URL.'),
      tags: { type: 'array', items: { type: 'string' } },
      authType: string('Authentication type for vault_http.'),
      hasPassword: boolean('Whether a password or token exists.'),
      hasTotp: boolean('Whether TOTP is available.'),
      message: string('Usage guidance.'),
    },
    required: ['lease', 'expiresAt', 'expiresInSeconds', 'id', 'label', 'accountHint', 'url', 'tags', 'authType', 'hasPassword', 'hasTotp', 'message'],
  },
  render: (_args, value) => textContent([
    `Lease ready for "${value.label}" (${value.id}).`,
    `Expires: ${value.expiresAt} (${value.expiresInSeconds}s).`,
    `Account hint: ${value.accountHint || '(none)'}; auth type: ${value.authType}; password: ${value.hasPassword ? 'stored' : 'none'}; TOTP: ${value.hasTotp ? 'available' : 'none'}.`,
    `Lease: ${value.lease}`,
    'Use vault_exec for commands (VAULT_USERNAME, VAULT_PASSWORD, VAULT_TOTP, VAULT_URL, VAULT_NOTES) or vault_http for HTTP requests. Do not print or upload the secret.',
  ].join('\n')),
};

const execOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      entryId: string('Entry id used for the command.'),
      label: string('Entry label.'),
      exitCode: { oneOf: [{ type: 'integer' }, { type: 'null' }], description: 'Process exit code, or null when terminated.' },
      signal: { oneOf: [{ type: 'string' }, { type: 'null' }], description: 'Termination signal, or null.' },
      stdout: string('Sanitized standard output.'),
      stderr: string('Sanitized standard error.'),
      truncated: boolean('Whether output was truncated.'),
      timedOut: boolean('Whether the command hit its timeout.'),
      redacted: boolean('Whether a secret was found in the output and redacted.'),
      durationMs: integer('Command duration in milliseconds.'),
      leaseExpiresAt: string('Lease expiry timestamp.'),
    },
    required: ['entryId', 'label', 'exitCode', 'signal', 'stdout', 'stderr', 'truncated', 'timedOut', 'redacted', 'durationMs', 'leaseExpiresAt'],
  },
  render: (_args, value) => {
    const lines = [
      `Command finished with exit code ${value.exitCode === null ? 'null' : value.exitCode} in ${value.durationMs} ms.`,
    ];
    if (value.redacted) lines.push('A secret appeared in the command output and was redacted.');
    if (value.timedOut) lines.push('The command timed out.');
    if (value.truncated) lines.push('Output was truncated.');
    if (value.stdout) lines.push(`stdout:\n${value.stdout}`);
    if (value.stderr) lines.push(`stderr:\n${value.stderr}`);
    return textContent(lines.join('\n'));
  },
};

const httpOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      entryId: string('Entry id used for the request.'),
      label: string('Entry label.'),
      status: integer('HTTP status code.'),
      statusText: string('HTTP status text.'),
      url: string('Sanitized final request URL.'),
      headers: { type: 'object', additionalProperties: true, description: 'Response headers except cookies.' },
      body: string('Sanitized response body.'),
      truncated: boolean('Whether the body was truncated.'),
      redacted: boolean('Whether a secret was found in the response and redacted.'),
      redirected: boolean('Whether the server returned a redirect. Redirects are not followed.'),
      location: { oneOf: [{ type: 'string' }, { type: 'null' }], description: 'Redirect location, if any.' },
      durationMs: integer('Request duration in milliseconds.'),
      leaseExpiresAt: string('Lease expiry timestamp.'),
    },
    required: ['entryId', 'label', 'status', 'statusText', 'url', 'headers', 'body', 'truncated', 'redacted', 'redirected', 'location', 'durationMs', 'leaseExpiresAt'],
  },
  render: (_args, value) => {
    const lines = [
      `HTTP ${value.status} ${value.statusText} in ${value.durationMs} ms.`,
      `URL: ${value.url}`,
    ];
    if (value.redirected) lines.push(`Redirect not followed${value.location ? `: ${value.location}` : '.'}`);
    if (value.redacted) lines.push('A secret appeared in the response and was redacted.');
    if (value.truncated) lines.push('The response body was truncated.');
    if (value.body) lines.push(`Body:\n${value.body}`);
    return textContent(lines.join('\n'));
  },
};

const captureOutput = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      captured: boolean('Whether the user saved a credential.'),
      id: string('New entry id.'),
      label: string('Entry label.'),
      accountHint: string('Masked account name.'),
      url: string('Configured URL.'),
      authType: string('Authentication type.'),
      hasPassword: boolean('Whether a password or token was saved.'),
      hasTotp: boolean('Whether a TOTP secret was saved.'),
      aiEnabled: boolean('Whether AI access is enabled for the new entry.'),
      lease: { oneOf: [{ type: 'string' }, { type: 'null' }], description: 'Immediate lease, or null when AI access is off.' },
      expiresAt: { oneOf: [{ type: 'string' }, { type: 'null' }], description: 'Lease expiry, or null.' },
      message: string('Usage guidance.'),
    },
    required: ['captured', 'id', 'label', 'accountHint', 'url', 'authType', 'hasPassword', 'hasTotp', 'aiEnabled', 'lease', 'expiresAt', 'message'],
  },
  render: (_args, value) => {
    const lines = [
      `Saved "${value.label}" (${value.id}) to the password vault.`,
      `Account hint: ${value.accountHint || '(none)'}; auth type: ${value.authType}; password: ${value.hasPassword ? 'saved' : 'none'}; TOTP: ${value.hasTotp ? 'saved' : 'none'}.`,
    ];
    if (value.lease) {
      lines.push(`Lease ready until ${value.expiresAt}.`);
      lines.push(`Lease: ${value.lease}`);
      lines.push('Use vault_exec or vault_http with this lease. Do not print the lease or any secret.');
    } else {
      lines.push('AI access is disabled for this entry; the user chose not to let the agent use it.');
    }
    return textContent(lines.join('\n'));
  },
};

const CAPTURE_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * One pending "enter once" request. The user types the secret into the local
 * overlay; the model only receives the saved metadata and a lease.
 */
class CaptureManager {
  constructor(store) {
    this.store = store;
    this.active = null;
  }

  /** The pending request, stripped of its promise and timer. */
  pending() {
    const active = this.active;
    if (active === null) return null;
    return {
      token: active.token,
      createdAt: active.createdAt,
      expiresAt: active.expiresAt,
      label: active.label,
      username: active.username,
      url: active.url,
      notes: active.notes,
      authType: active.authType,
      authKey: active.authKey,
      allowedHosts: active.allowedHosts,
      purpose: active.purpose,
    };
  }

  /** Open one capture request and return its token plus resolution promise. */
  create(input = {}) {
    this.store.requireUnlocked();
    if (this.active !== null) {
      throw new VaultError(
        'CAPTURE_BUSY',
        'A password prompt is already open. Ask the user to finish or cancel it first.',
        409,
      );
    }
    const token = randomBytes(24).toString('base64url');
    const now = Date.now();
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const request = {
      token,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + CAPTURE_TIMEOUT_MS).toISOString(),
      label: String(input.label ?? '').slice(0, 200),
      username: String(input.username ?? '').slice(0, 500),
      url: String(input.url ?? '').slice(0, 2000),
      notes: String(input.notes ?? '').slice(0, 8000),
      authType: ['none', 'basic', 'bearer', 'header', 'query'].includes(input.authType)
        ? input.authType
        : 'none',
      authKey: String(input.authKey ?? '').slice(0, 120),
      // Hosts are derived from the URL the user sees; the model cannot widen them.
      allowedHosts: '',
      purpose: String(input.purpose ?? '').slice(0, 500),
    };
    const timer = setTimeout(() => {
      try {
        this.cancel(token, 'CAPTURE_TIMEOUT', 'The password prompt expired before it was submitted.');
      } catch {
        // The prompt already completed or was cancelled.
      }
    }, CAPTURE_TIMEOUT_MS);
    timer.unref?.();
    this.active = { ...request, resolve, reject, timer };
    return { token, expiresAt: request.expiresAt, promise };
  }

  /** Save the user's input, then resolve the waiting tool call. */
  async complete(token, entry = {}) {
    const active = this.active;
    if (active === null || active.token !== String(token ?? '')) {
      throw new VaultError('CAPTURE_NOT_FOUND', 'This password prompt is no longer active.', 404);
    }
    if (String(entry.password ?? '') === '') {
      throw new VaultError('CAPTURE_PASSWORD_REQUIRED', 'Enter a password or token before saving.', 400);
    }
    const { id: _ignored, ...payload } = entry;
    const saved = await this.store.save(payload);
    let lease = null;
    if (saved.aiEnabled) {
      try {
        lease = this.store.createLease(saved.id, { purpose: active.purpose });
      } catch {
        lease = null;
      }
    }
    clearTimeout(active.timer);
    this.active = null;
    active.resolve({ saved, lease });
    return {
      captured: true,
      entry: saved,
      lease: lease === null ? null : { lease: lease.lease, expiresAt: lease.expiresAt },
    };
  }

  /** Cancel the prompt and reject the waiting tool call. */
  cancel(token, code = 'CAPTURE_CANCELLED', message = 'The password prompt was cancelled.') {
    const active = this.active;
    if (active === null || active.token !== String(token ?? '')) {
      throw new VaultError('CAPTURE_NOT_FOUND', 'This password prompt is no longer active.', 404);
    }
    clearTimeout(active.timer);
    this.active = null;
    active.reject(new VaultError(code, message, 409));
    return { cancelled: true };
  }
}

/** Register the six model-facing tools. */
function registerTools(ctx, store, capture) {
  ctx.tools.register({
    name: 'vault_status',
    description: 'Check whether the local encrypted password vault is configured and unlocked, and how many credentials are available. Use this before asking the user for any account or password.',
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: statusOutput,
    isConcurrencySafe: () => true,
    execute: async () => {
      const status = store.status();
      return { ...status, protection: status.protection ?? '', error: status.error ?? '' };
    },
  });

  ctx.tools.register({
    name: 'vault_list',
    description: 'List saved accounts that the local password vault allows AI to use. Returns metadata only: no passwords, tokens, usernames, or one-time codes. Filter with a short query. Then call vault_use with an entry id.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: optionalString('Optional case-insensitive filter over label, URL, tags, and masked account.'),
      },
    },
    output: listOutput,
    isConcurrencySafe: () => true,
    execute: async (args) => {
      const { entries } = store.list({ audience: 'ai' });
      const query = String(args.query ?? '').trim().toLowerCase();
      const filtered = query === ''
        ? entries
        : entries.filter((entry) => [entry.label, entry.url, entry.accountHint, ...entry.tags]
            .join(' ')
            .toLowerCase()
            .includes(query));
      return { count: filtered.length, entries: filtered };
    },
  });

  ctx.tools.register({
    name: 'vault_use',
    description: 'Obtain a short-lived lease for one saved credential. The result contains no password or token, only an opaque lease that vault_exec and vault_http accept. The lease expires automatically; never expose it in the final answer.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        id: string('Entry id from vault_list.'),
        purpose: optionalString('Optional short reason for the audit log.'),
      },
      required: ['id'],
    },
    output: useOutput,
    isConcurrencySafe: () => true,
    execute: async (args, exec) => {
      const result = store.createLease(args.id, {
        purpose: args.purpose ?? '',
        sessionId: exec?.agent?.session?.id ?? null,
      });
      return {
        lease: result.lease,
        expiresAt: result.expiresAt,
        expiresInSeconds: result.expiresInSeconds,
        id: result.entry.id,
        label: result.entry.label,
        accountHint: result.entry.accountHint,
        url: result.entry.url,
        tags: result.entry.tags,
        authType: result.entry.authType,
        hasPassword: result.entry.hasPassword,
        hasTotp: result.entry.hasTotp,
        message: 'Pass this lease to vault_exec or vault_http. Do not print it or the underlying secret.',
      };
    },
  });

  ctx.tools.register({
    name: 'vault_capture',
    description: 'Ask the user to enter a password, token, or one-time secret once in a secure local prompt and save it directly to the encrypted vault. Use this when vault_list has no matching entry. The user types the secret into the plugin UI, never into chat; you receive only metadata and, when AI access is enabled, a ready lease. Fill any fields you already know from the task so the user only has to enter the secret and confirm.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        label: optionalString('Suggested account name. The user can edit it.'),
        username: optionalString('Suggested username or account. The user can edit it.'),
        url: optionalString('Suggested sign-in or API URL. The user can edit it.'),
        notes: optionalString('Optional note to prefill. Stored encrypted.'),
        authType: { type: 'string', enum: ['none', 'basic', 'bearer', 'header', 'query'], description: 'How the secret should be attached.' },
        authKey: optionalString('Header or query parameter name for header/query auth.'),
        purpose: optionalString('Short reason shown in the prompt and audit log.'),
      },
    },
    output: captureOutput,
    timeoutMs: 310_000,
    isConcurrencySafe: () => false,
    execute: async (args, exec) => {
      const { token, promise } = capture.create({
        label: args.label,
        username: args.username,
        url: args.url,
        notes: args.notes,
        authType: args.authType,
        authKey: args.authKey,
        purpose: args.purpose,
      });
      const onAbort = () => {
        try {
          capture.cancel(token, 'CAPTURE_CANCELLED', 'The password prompt was cancelled by the agent.');
        } catch {
          // The prompt may already have completed.
        }
      };
      exec?.signal?.addEventListener?.('abort', onAbort, { once: true });
      try {
        const result = await promise;
        const saved = result.saved;
        return {
          captured: true,
          id: saved.id,
          label: saved.label,
          accountHint: saved.accountHint,
          url: saved.url,
          authType: saved.authType,
          hasPassword: saved.hasPassword,
          hasTotp: saved.hasTotp,
          aiEnabled: saved.aiEnabled,
          lease: result.lease?.lease ?? null,
          expiresAt: result.lease?.expiresAt ?? null,
          message: result.lease
            ? 'Saved. Use the lease with vault_exec or vault_http now; do not print it.'
            : saved.aiEnabled
              ? 'Saved, but no lease was issued. Call vault_use with this id.'
              : 'Saved, but AI access was disabled by the user.',
        };
      } finally {
        exec?.signal?.removeEventListener?.('abort', onAbort);
      }
    },
  });

  ctx.tools.register({
    name: 'vault_exec',
    description: 'Run a PowerShell (Windows) or bash command with a leased credential injected as environment variables: VAULT_USERNAME, VAULT_PASSWORD, VAULT_SECRET, VAULT_TOKEN, VAULT_TOTP, VAULT_URL, VAULT_NOTES, VAULT_LABEL, VAULT_AUTH_TYPE, VAULT_AUTH_KEY. This bridge is disabled by default; the user must explicitly enable it in Settings > Password vault > Advanced. The secret never appears in the command arguments. Output is scrubbed of the secret before it is returned. Only run commands you trust; a command can still send environment variables elsewhere, so never run untrusted code.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        lease: string('Lease from vault_use.'),
        command: string('Command to run. Use environment variables instead of embedding secrets.'),
        timeoutSeconds: integer('Timeout in seconds, 1-300. Default 60.'),
        cwd: optionalString('Optional working directory.'),
      },
      required: ['lease', 'command'],
    },
    output: execOutput,
    timeoutMs: 310_000,
    isConcurrencySafe: () => false,
    execute: async (args, exec) => store.execWithLease({
      lease: args.lease,
      command: args.command,
      timeoutSeconds: args.timeoutSeconds,
      cwd: args.cwd,
      signal: exec?.signal,
      sessionId: exec?.agent?.session?.id ?? null,
    }),
  });

  ctx.tools.register({
    name: 'vault_http',
    description: 'Make an HTTP request with a leased credential injected host-side. The entry auth type (none, basic, bearer, header, query) decides how the secret is attached. Credentials are sent only to hosts allowed by the entry, redirects are not followed, and the response is scrubbed of the secret. You can also use {{username}}, {{password}}, {{totp}}, and {{auth_key}} placeholders in the URL, headers, or body. Never print or upload the secret.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        lease: string('Lease from vault_use.'),
        url: optionalString('Request URL. Defaults to the entry URL.'),
        method: optionalString('HTTP method. Default GET.'),
        headers: { type: 'object', additionalProperties: true, description: 'Request headers as string values. Host, content-length, and connection are ignored.' },
        body: optionalString('Request body as a string. JSON requests can pass JSON text.'),
        timeoutSeconds: integer('Timeout in seconds, 1-300. Default 60.'),
      },
      required: ['lease'],
    },
    output: httpOutput,
    timeoutMs: 310_000,
    isConcurrencySafe: () => true,
    execute: async (args, exec) => {
      const headers = {};
      if (args.headers !== undefined && args.headers !== null) {
        if (typeof args.headers !== 'object' || Array.isArray(args.headers)) {
          throw new VaultError('INVALID_HEADERS', 'headers must be an object of string values.');
        }
        for (const [key, value] of Object.entries(args.headers)) headers[key] = String(value);
      }
      return store.httpWithLease({
        lease: args.lease,
        url: args.url,
        method: args.method,
        headers,
        body: args.body,
        timeoutSeconds: args.timeoutSeconds,
        signal: exec?.signal,
        sessionId: exec?.agent?.session?.id ?? null,
      });
    },
  });
}

/** Read a request body up to a fixed limit. */
async function readJsonBody(req, limit = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limit) throw new VaultError('REQUEST_TOO_LARGE', 'The request body is too large.', 413);
    chunks.push(chunk);
  }
  if (total === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new VaultError('INVALID_JSON', 'The request body is not valid JSON.', 400);
  }
}

/** Write one JSON response. */
function sendJson(res, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.end(body);
}

/** Whether a request came from this same loopback origin. */
function sameOrigin(req) {
  const hostHeader = req.headers.host;
  if (typeof hostHeader !== 'string' || hostHeader === '') return false;
  let hostname;
  try {
    hostname = new URL(`http://${hostHeader}`).hostname;
  } catch {
    return false;
  }
  if (!isLoopbackHost(hostname)) return false;
  const site = req.headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin' && site !== 'none') return false;
  const origin = req.headers.origin;
  if (origin === undefined || origin === '') return true;
  if (origin === 'null') return false;
  try {
    const parsed = new URL(origin);
    return parsed.host.toLowerCase() === hostHeader.toLowerCase();
  } catch {
    return false;
  }
}

/** Local management API for the settings page. */
async function handleApi(req, res, store, capture) {
  try {
    if (!sameOrigin(req)) throw new VaultError('ORIGIN_DENIED', 'Cross-origin vault requests are not allowed.', 403);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    if (!path.startsWith('/vault-api/') && path !== '/vault-api') {
      throw new VaultError('NOT_FOUND', 'Not found.', 404);
    }
    const action = path.slice('/vault-api'.length).replace(/^\/+/, '');
    if (req.method === 'GET' && action === 'status') {
      const status = store.status();
      sendJson(res, 200, { ...status, protection: status.protection ?? '', error: status.error ?? '' });
      return;
    }
    if (req.method === 'GET' && action === 'capture/pending') {
      sendJson(res, 200, { request: capture.pending() });
      return;
    }
    if (req.method !== 'POST') {
      throw new VaultError('METHOD_NOT_ALLOWED', 'Use POST for vault actions.', 405);
    }
    const body = await readJsonBody(req);
    switch (action) {
      case 'setup':
        sendJson(res, 200, await store.setup({ masterPassword: body.masterPassword }));
        return;
      case 'unlock':
        sendJson(res, 200, await store.unlock({ masterPassword: body.masterPassword }));
        return;
      case 'lock':
        store.lock();
        sendJson(res, 200, { ...store.status(), protection: store.status().protection ?? '', error: store.status().error ?? '' });
        return;
      case 'protection':
        sendJson(res, 200, await store.changeProtection({ masterPassword: body.masterPassword }));
        return;
      case 'entries/list':
        sendJson(res, 200, store.list({ audience: 'ui' }));
        return;
      case 'entries/get':
        sendJson(res, 200, store.get(body.id, { reveal: body.reveal === true }));
        return;
      case 'entries/save':
        sendJson(res, 200, await store.save(body.entry ?? body));
        return;
      case 'entries/delete':
        sendJson(res, 200, await store.delete(body.id));
        return;
      case 'entries/ai':
        sendJson(res, 200, await store.setAiEnabled(body.id, body.enabled === true));
        return;
      case 'entries/totp':
        sendJson(res, 200, { totp: store.totp(body.id) });
        return;
      case 'capture/complete':
        sendJson(res, 200, await capture.complete(body.token, body.entry ?? {}));
        return;
      case 'capture/cancel':
        sendJson(res, 200, capture.cancel(body.token));
        return;
      case 'settings/exec':
        sendJson(res, 200, await store.setAllowExec(body.enabled === true));
        return;
      case 'audit':
        sendJson(res, 200, await store.readAudit(body.limit));
        return;
      default:
        throw new VaultError('NOT_FOUND', 'Unknown vault action.', 404);
    }
  } catch (error) {
    const known = error instanceof VaultError;
    const status = known ? error.status : 500;
    sendJson(res, status, {
      error: known ? error.code : 'VAULT_ERROR',
      message: known ? error.message : 'The password vault request failed.',
    });
  }
}

/** Host plugin entry. */
export async function apply(ctx, config = {}) {
  const store = new VaultStore({
    leaseMinutes: config?.leaseMinutes,
    autoLockMinutes: config?.autoLockMinutes,
  });
  await store.init();
  ctx.effect(() => () => store.dispose(), 'password-vault: store lifecycle');

  const capture = new CaptureManager(store);
  registerTools(ctx, store, capture);

  ctx.inject(['systemPrompt'], (scope) => {
    scope.effect(() => scope.systemPrompt.section({
      name: 'password-vault',
      order: 9000,
      interpolate: false,
      text: PROMPT_TEXT,
    }), 'password-vault: prompt section');
  });

  ctx.inject(['webServer'], (scope) => {
    scope.effect(() => scope.webServer.register({
      kind: 'prefix',
      path: '/vault-api',
      handler: (req, res) => handleApi(req, res, store, capture),
    }), 'password-vault: local API');
  });
}
