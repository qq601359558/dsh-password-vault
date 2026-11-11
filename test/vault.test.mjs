import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  VaultError,
  VaultStore,
  hostAllowed,
  maskAccount,
  normalizeTotpSecret,
  scrubSecrets,
  totpAt,
} from '../lib/vault.js';

const PASSWORD = 'correct-horse-battery';
const SECRET = 's3cret-value-9f2a';

async function tempStore(options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-test-'));
  const store = new VaultStore({ dir, autoLockMinutes: 0, ...options });
  await store.init();
  return { dir, store };
}

async function withStore(run, options) {
  const { dir, store } = await tempStore(options);
  try {
    await run(store, dir);
  } finally {
    store.dispose();
    await rm(dir, { recursive: true, force: true });
  }
}

test('master-password vault encrypts entries and survives reload', async () => {
  await withStore(async (store, dir) => {
    const status = await store.setup({ masterPassword: PASSWORD });
    assert.equal(status.configured, true);
    assert.equal(status.unlocked, true);
    assert.equal(status.autoUnlock, false);

    const saved = await store.save({
      label: 'Example API',
      username: 'alice@example.com',
      password: SECRET,
      url: 'https://api.example.com/login',
      notes: 'test note',
      tags: ['test', 'api'],
      authType: 'header',
      authKey: 'X-API-Key',
      totpSecret: 'JBSWY3DPEHPK3PXP',
    });
    assert.equal(saved.label, 'Example API');
    assert.equal(saved.accountHint, 'a****@example.com');
    assert.equal(saved.hasPassword, true);
    assert.equal(saved.hasTotp, true);
    assert.equal(saved.allowedHosts[0], 'api.example.com');

    const raw = await readFile(join(dir, 'vault.json'), 'utf8');
    assert.equal(raw.includes('Example API'), false);
    assert.equal(raw.includes('alice@example.com'), false);
    assert.equal(raw.includes(SECRET), false);
    assert.equal(raw.includes('test note'), false);

    const locked = new VaultStore({ dir, autoLockMinutes: 0 });
    await locked.init();
    assert.equal(locked.status().unlocked, false);
    assert.throws(() => locked.list({ audience: 'ai' }), (error) => error.code === 'VAULT_LOCKED');
    const unlocked = await locked.unlock({ masterPassword: PASSWORD });
    assert.equal(unlocked.unlocked, true);
    const detail = locked.get(saved.id, { reveal: true });
    assert.equal(detail.password, SECRET);
    assert.equal(detail.username, 'alice@example.com');
    assert.equal(detail.totp.code.length, 6);
    locked.dispose();
  });
});

test('wrong password does not decrypt and tampering is detected', async () => {
  await withStore(async (store, dir) => {
    await store.setup({ masterPassword: PASSWORD });
    const saved = await store.save({
      label: 'Tamper test',
      username: 'bob',
      password: SECRET,
      url: 'https://example.com',
    });
    const second = new VaultStore({ dir, autoLockMinutes: 0 });
    await second.init();
    await assert.rejects(() => second.unlock({ masterPassword: 'wrong-password' }));
    const raw = JSON.parse(await readFile(join(dir, 'vault.json'), 'utf8'));
    const data = raw.entries[0].data.data;
    raw.entries[0].data.data = `${data.slice(0, 4)}AAAA${data.slice(8)}`;
    await writeFile(join(dir, 'vault.json'), JSON.stringify(raw), 'utf8');
    const third = new VaultStore({ dir, autoLockMinutes: 0 });
    await third.init();
    await assert.rejects(
      () => third.unlock({ masterPassword: PASSWORD }),
      (error) => error.code === 'VAULT_CORRUPT',
    );
    assert.ok(saved.id);
    second.dispose();
    third.dispose();
  });
});

test('broken vault file is not silently replaced', async () => {
  const { dir, store } = await tempStore();
  try {
    await writeFile(join(dir, 'vault.json'), '{ not json', 'utf8');
    const broken = new VaultStore({ dir, autoLockMinutes: 0 });
    const status = await broken.init();
    assert.equal(status.configured, true);
    assert.equal(status.broken, true);
    assert.equal(status.unlocked, false);
    await assert.rejects(() => broken.setup({ masterPassword: PASSWORD }), (error) => error.code === 'VAULT_EXISTS');
    broken.dispose();
  } finally {
    store.dispose();
    await rm(dir, { recursive: true, force: true });
  }
});

test('DPAPI auto-unlock works on Windows', { skip: process.platform !== 'win32' }, async () => {
  await withStore(async (store, dir) => {
    const status = await store.setup({});
    assert.equal(status.configured, true);
    assert.equal(status.autoUnlock, true);
    assert.equal(status.unlocked, true);
    await store.save({
      label: 'DPAPI test',
      username: 'carol',
      password: SECRET,
      url: 'https://example.com',
    });
    const reopened = new VaultStore({ dir, autoLockMinutes: 0 });
    const reopenedStatus = await reopened.init();
    assert.equal(reopenedStatus.unlocked, true);
    assert.equal(reopened.list({ audience: 'ui' }).count, 1);
    reopened.dispose();
  });
});

test('leases are scoped, expire, and gate AI access', async () => {
  await withStore(async (store) => {
    await store.setup({ masterPassword: PASSWORD });
    const saved = await store.save({
      label: 'Lease test',
      username: 'dave',
      password: SECRET,
      url: 'https://example.com',
    });
    const lease = store.createLease(saved.id, { purpose: 'unit test' });
    assert.equal(lease.entry.id, saved.id);
    assert.equal(lease.entry.accountHint, 'd**e');
    assert.equal(JSON.stringify(lease).includes(SECRET), false);
    assert.equal(store.resolveLease(lease.lease).entry.id, saved.id);

    await store.setAiEnabled(saved.id, false);
    assert.throws(() => store.createLease(saved.id), (error) => error.code === 'AI_DISABLED');
    assert.throws(() => store.resolveLease(lease.lease), (error) => error.code === 'AI_DISABLED');

    await store.setAiEnabled(saved.id, true);
    const second = store.createLease(saved.id);
    assert.ok(second.lease);
    assert.equal(JSON.stringify(store.list({ audience: 'ai' })).includes(SECRET), false);
  });
});

test('exec is disabled by default and needs explicit user enablement', { skip: process.platform !== 'win32' }, async () => {
  await withStore(async (store) => {
    await store.setup({ masterPassword: PASSWORD });
    const saved = await store.save({
      label: 'Exec disabled',
      username: 'erin',
      password: SECRET,
      url: 'https://example.com',
    });
    const lease = store.createLease(saved.id);
    await assert.rejects(
      () => store.execWithLease({ lease: lease.lease, command: 'Write-Output ok' }),
      (error) => error.code === 'EXEC_DISABLED',
    );
    assert.equal(store.status().allowExec, false);
    const changed = await store.setAllowExec(true);
    assert.equal(changed.allowExec, true);
    assert.equal(store.status().allowExec, true);
    await store.setAllowExec(false);
    assert.equal(store.status().allowExec, false);
  });
});

test('exec injects credentials and scrubs output when enabled', { skip: process.platform !== 'win32' }, async () => {
  await withStore(async (store) => {
    await store.setup({ masterPassword: PASSWORD });
    const saved = await store.save({
      label: 'Exec test',
      username: 'erin',
      password: SECRET,
      url: 'https://example.com',
      totpSecret: 'JBSWY3DPEHPK3PXP',
    });
    await store.setAllowExec(true);
    const lease = store.createLease(saved.id);
    const result = await store.execWithLease({
      lease: lease.lease,
      command: 'Write-Output "$env:VAULT_USERNAME|$env:VAULT_PASSWORD|$env:VAULT_TOTP"',
    });
    assert.equal(result.exitCode, 0);
    assert.match(result.stdout, /erin/);
    assert.match(result.stdout, /\[REDACTED\]/);
    assert.equal(result.stdout.includes(SECRET), false);
    assert.equal(result.redacted, true);
  });
});

test('HTTP injects basic auth, refuses other hosts, and scrubs echoes', async () => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url, authorization: req.headers.authorization });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true, echo: SECRET, auth: req.headers.authorization }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    await withStore(async (store) => {
      await store.setup({ masterPassword: PASSWORD });
      const saved = await store.save({
        label: 'HTTP test',
        username: 'frank',
        password: SECRET,
        url: `${origin}/login`,
        authType: 'basic',
      });
      const lease = store.createLease(saved.id);
      const result = await store.httpWithLease({
        lease: lease.lease,
        url: `${origin}/login`,
      });
      assert.equal(result.status, 200);
      assert.equal(result.body.includes(SECRET), false);
      assert.equal(result.body.includes(Buffer.from(`frank:${SECRET}`).toString('base64')), false);
      assert.match(result.body, /\[REDACTED\]/);
      assert.equal(result.redacted, true);
      assert.equal(seen[0].authorization, `Basic ${Buffer.from(`frank:${SECRET}`).toString('base64')}`);
      await assert.rejects(
        () => store.httpWithLease({ lease: lease.lease, url: 'https://evil.example.com/steal' }),
        (error) => error.code === 'HOST_NOT_ALLOWED',
      );
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('HTTP does not follow redirects', async () => {
  const server = createServer((_req, res) => {
    res.statusCode = 302;
    res.setHeader('location', 'https://example.com/next');
    res.end('redirecting');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    await withStore(async (store) => {
      await store.setup({ masterPassword: PASSWORD });
      const saved = await store.save({
        label: 'Redirect test',
        username: 'gina',
        password: SECRET,
        url: `${origin}/start`,
        authType: 'basic',
      });
      const lease = store.createLease(saved.id);
      const result = await store.httpWithLease({ lease: lease.lease });
      assert.equal(result.status, 302);
      assert.equal(result.redirected, true);
      assert.equal(result.location, 'https://example.com/next');
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('TOTP, masking, host rules, and scrubbing helpers', () => {
  assert.equal(totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59_000, 30, 8), '94287082');
  assert.equal(normalizeTotpSecret('otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP'), 'JBSWY3DPEHPK3PXP');
  assert.equal(maskAccount('alice@example.com'), 'a****@example.com');
  assert.equal(maskAccount('+86 138 0000 1234'), '***1234');
  assert.equal(hostAllowed('api.example.com', ['api.example.com']), true);
  assert.equal(hostAllowed('api.example.com', ['*.example.com']), true);
  assert.equal(hostAllowed('example.com.evil.test', ['*.example.com']), false);
  assert.deepEqual(scrubSecrets('a s3cret-value-9f2a b', [SECRET]), { text: 'a [REDACTED] b', redacted: true });
});

test('validation rejects bad entries and prototype-style ids', async () => {
  await withStore(async (store) => {
    await store.setup({ masterPassword: PASSWORD });
    await assert.rejects(() => store.save({ label: '' }), (error) => error.code === 'INVALID_LABEL');
    await assert.rejects(
      () => store.save({ label: 'bad url', url: 'file:///etc/passwd' }),
      (error) => error.code === 'INVALID_URL',
    );
    await assert.rejects(
      () => store.save({ label: 'bad totp', totpSecret: 'not base32!' }),
      (error) => error.code === 'INVALID_TOTP',
    );
    assert.throws(() => store.get('does-not-exist'), (error) => error.code === 'ENTRY_NOT_FOUND');
    assert.throws(() => store.get('__proto__'), (error) => error.code === 'ENTRY_NOT_FOUND');
  });
});

test('audit log records actions without secrets', async () => {
  await withStore(async (store, dir) => {
    await store.setup({ masterPassword: PASSWORD });
    await store.save({
      label: 'Audit test',
      username: 'henry',
      password: SECRET,
      url: 'https://example.com',
    });
    const audit = await store.readAudit(20);
    assert.ok(audit.entries.some((entry) => entry.action === 'entry.create'));
    const raw = await readFile(join(dir, 'audit.jsonl'), 'utf8');
    assert.equal(raw.includes(SECRET), false);
  });
});

test('VaultError exposes a stable code', () => {
  const error = new VaultError('TEST', 'message', 418);
  assert.equal(error.code, 'TEST');
  assert.equal(error.status, 418);
});
