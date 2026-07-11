// Vaultly smoke test — boots the real server and exercises the full
// zero-knowledge flow with client crypto mirrored in Node:
//   register (bootstrap gate) → encrypt item client-side → POST →
//   read the RAW SQLite file and assert plaintext is NOT at rest →
//   decrypt round-trip → invites → RSA-wrapped shared vault across two users →
//   audit log → revoke.
// Kills ONLY the spawned server child.
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const TEST_PORT = 5394;
const SETUP_PASSWORD = 'smoke-setup-password';
const DB_PATH = path.join(__dirname, 'smoke.db');
const BASE = `http://127.0.0.1:${TEST_PORT}`;
const SECRET = 'hunter2-SMOKE-PLAINTEXT-MARKER-9f3a';
const MASTER_PW = 'correct horse battery staple SMOKE';
const KDF_ITERS = 10000; // fast for tests; client default is 600k

for (const f of [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm']) if (fs.existsSync(f)) fs.unlinkSync(f);

let serverProc = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, label, tries = 40, delay = 250) {
  for (let i = 0; i < tries; i++) {
    try { const v = await fn(); if (v) return v; } catch { /* retry */ }
    await sleep(delay);
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

// ── mirror of client/src/crypto.js in Node crypto ───────────────────────────
function deriveKeys(password, saltHex, iterations = KDF_ITERS) {
  const bytes = crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), iterations, 64, 'sha256');
  return { encKey: bytes.subarray(0, 32), authKeyHex: bytes.subarray(32).toString('hex') };
}
function aesEncrypt(keyBuf, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final(), c.getAuthTag()]);
  return { iv: iv.toString('hex'), ciphertext: ct.toString('base64') };
}
function aesDecrypt(keyBuf, { iv, ciphertext }) {
  const buf = Buffer.from(ciphertext, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', keyBuf, Buffer.from(iv, 'hex'));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8');
}
function makeUserBundle(password) {
  const kdfSalt = crypto.randomBytes(16).toString('hex');
  const { encKey, authKeyHex } = deriveKeys(password, kdfSalt);
  const userKey = crypto.randomBytes(32);
  const wrappedUserKey = aesEncrypt(encKey, userKey.toString('hex'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const privPkcs8B64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const encPriv = aesEncrypt(userKey, privPkcs8B64);
  return {
    userKey, privateKey, kdfSalt, authKeyHex,
    payload: {
      kdf_salt: kdfSalt,
      kdf_iterations: KDF_ITERS,
      auth_key: authKeyHex,
      encrypted_key_json: JSON.stringify(wrappedUserKey),
      public_key: publicKeyB64,
      encrypted_private_key: JSON.stringify(encPriv)
    }
  };
}
function rsaWrap(publicKeyB64, keyBuf) {
  const pub = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), type: 'spki', format: 'der' });
  return crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, keyBuf).toString('base64');
}
function rsaUnwrap(privateKey, wrappedB64) {
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(wrappedB64, 'base64')
  );
}

// ── tiny cookie-jar HTTP client (one per simulated user) ────────────────────
function makeClient() {
  let cookie = '';
  return async function apiReq(pathname, options = {}) {
    const res = await fetch(BASE + pathname, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}), ...options.headers },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return { status: res.status, data: await res.json().catch(() => ({})) };
  };
}

async function main() {
  console.log('1. Booting Vaultly on port', TEST_PORT);
  serverProc = spawn(process.execPath, ['server/index.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(TEST_PORT), ADMIN_PASSWORD: SETUP_PASSWORD, DB_PATH },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  serverProc.stdout.on('data', (d) => process.stdout.write(`   [server] ${d}`));
  serverProc.stderr.on('data', (d) => process.stderr.write(`   [server] ${d}`));

  const admin = makeClient();
  await waitFor(async () => (await admin('/api/health')).data.ok, 'server health');

  console.log('2. Bootstrap gate: first registration requires ADMIN_PASSWORD');
  const boot = await admin('/api/bootstrap');
  assert.strictEqual(boot.data.needs_setup, true, 'fresh instance must need setup');
  const u1 = makeUserBundle(MASTER_PW);
  const noSetup = await admin('/api/register', { method: 'POST', body: { email: 'ben@example.com', ...u1.payload } });
  assert.strictEqual(noSetup.status, 403, 'first register without setup password must 403');
  const reg = await admin('/api/register', { method: 'POST', body: { email: 'ben@example.com', setup_password: SETUP_PASSWORD, ...u1.payload } });
  assert.strictEqual(reg.status, 201, 'first register must 201');
  assert.strictEqual(reg.data.user.role, 'admin', 'first user must be admin');

  console.log('3. Auth: unauth 401, wrong auth key 401, correct login OK');
  const stranger = makeClient();
  assert.strictEqual((await stranger('/api/items')).status, 401, 'items must require auth');
  const badLogin = await stranger('/api/login', { method: 'POST', body: { email: 'ben@example.com', auth_key: 'f'.repeat(64) } });
  assert.strictEqual(badLogin.status, 401, 'wrong auth key must 401');
  const pre = await stranger('/api/prelogin', { method: 'POST', body: { email: 'ben@example.com' } });
  const rederived = deriveKeys(MASTER_PW, pre.data.kdf_salt, pre.data.kdf_iterations);
  const relogin = await stranger('/api/login', { method: 'POST', body: { email: 'ben@example.com', auth_key: rederived.authKeyHex } });
  assert.strictEqual(relogin.status, 200, 'derived auth key login must succeed');

  console.log('4. Create item encrypted client-side, then verify CIPHERTEXT AT REST');
  const itemPlain = JSON.stringify({ name: 'Prod DB', username: 'root', password: SECRET, url: 'https://db.example.com' });
  const encItem = aesEncrypt(u1.userKey, itemPlain);
  const created = await admin('/api/items', { method: 'POST', body: { type: 'login', ciphertext: encItem.ciphertext, iv: encItem.iv } });
  assert.strictEqual(created.status, 201, 'item create must 201');
  const itemId = created.data.id;

  // flush WAL by reading via better-sqlite3, then scan raw bytes of db+wal
  const Database = require('better-sqlite3');
  const rodb = new Database(DB_PATH, { readonly: true });
  const rawRow = rodb.prepare('SELECT ciphertext, iv FROM vault_items WHERE id = ?').get(itemId);
  assert.ok(rawRow, 'item row must exist in SQLite');
  assert.ok(!rawRow.ciphertext.includes(SECRET), 'stored ciphertext must not contain the plaintext secret');
  for (const f of [DB_PATH, DB_PATH + '-wal']) {
    if (!fs.existsSync(f)) continue;
    const raw = fs.readFileSync(f);
    assert.ok(!raw.includes(SECRET), `raw DB file ${path.basename(f)} must NOT contain the plaintext secret`);
    assert.ok(!raw.includes(MASTER_PW), `raw DB file ${path.basename(f)} must NOT contain the master password`);
  }
  console.log('   ✓ plaintext secret + master password absent from raw SQLite bytes');

  console.log('5. Decrypt round-trip via API');
  const list = await admin('/api/items');
  const fetched = list.data.find((i) => i.id === itemId);
  const roundtrip = JSON.parse(aesDecrypt(u1.userKey, { iv: fetched.iv, ciphertext: fetched.ciphertext }));
  assert.strictEqual(roundtrip.password, SECRET, 'decrypted item must round-trip the secret');

  console.log('6. Invite flow + member isolation');
  const inv = await admin('/api/invites', { method: 'POST', body: { email: 'dev@example.com' } });
  assert.strictEqual(inv.status, 201, 'invite create must 201');
  const member = makeClient();
  const u2 = makeUserBundle('another very long master password');
  const badInvite = await member('/api/register', { method: 'POST', body: { email: 'dev@example.com', invite_token: 'nope', ...u2.payload } });
  assert.strictEqual(badInvite.status, 403, 'bad invite must 403');
  const reg2 = await member('/api/register', { method: 'POST', body: { email: 'dev@example.com', invite_token: inv.data.token, ...u2.payload } });
  assert.strictEqual(reg2.status, 201, 'invited register must 201');
  assert.strictEqual(reg2.data.user.role, 'member');
  const memberItems = await member('/api/items');
  assert.strictEqual(memberItems.data.length, 0, 'member must NOT see admin personal items');

  console.log('7. Shared vault: RSA-wrapped vault key, cross-user decrypt');
  const vaultKey = crypto.randomBytes(32);
  const vc = await admin('/api/vaults', { method: 'POST', body: { name: 'Infra', encrypted_vault_key: rsaWrap(u1.payload.public_key, vaultKey) } });
  assert.strictEqual(vc.status, 201, 'vault create must 201');
  const vaultId = vc.data.id;
  const users = (await admin('/api/users')).data;
  const u2pub = users.find((u) => u.email === 'dev@example.com').public_key;
  const share = await admin(`/api/vaults/${vaultId}/share`, { method: 'POST', body: { email: 'dev@example.com', role: 'member', encrypted_vault_key: rsaWrap(u2pub, vaultKey) } });
  assert.strictEqual(share.status, 200, 'share must 200');

  const sharedPlain = JSON.stringify({ name: 'AWS root', password: SECRET + '-shared' });
  const encShared = aesEncrypt(vaultKey, sharedPlain);
  const sharedItem = await admin('/api/items', { method: 'POST', body: { type: 'login', shared_vault_id: vaultId, ciphertext: encShared.ciphertext, iv: encShared.iv } });
  assert.strictEqual(sharedItem.status, 201);

  const memberVaults = (await member('/api/vaults')).data;
  const mv = memberVaults.find((v) => v.id === vaultId);
  assert.ok(mv, 'member must see the shared vault');
  const unwrapped = rsaUnwrap(u2.privateKey, mv.encrypted_vault_key);
  assert.strictEqual(unwrapped.toString('hex'), vaultKey.toString('hex'), 'member must RSA-unwrap the same vault key');
  const memberList = (await member('/api/items')).data;
  const sharedFetched = memberList.find((i) => i.shared_vault_id === vaultId);
  const sharedRound = JSON.parse(aesDecrypt(unwrapped, { iv: sharedFetched.iv, ciphertext: sharedFetched.ciphertext }));
  assert.strictEqual(sharedRound.password, SECRET + '-shared', 'member decrypts shared item');
  const raw2 = fs.readFileSync(DB_PATH);
  const wal2 = fs.existsSync(DB_PATH + '-wal') ? fs.readFileSync(DB_PATH + '-wal') : Buffer.alloc(0);
  assert.ok(!raw2.includes(SECRET + '-shared') && !wal2.includes(SECRET + '-shared'), 'shared secret plaintext must not be at rest');
  console.log('   ✓ shared vault secret also ciphertext-only at rest');

  console.log('8. Audit log records create/share; admin-only');
  assert.strictEqual((await member('/api/audit')).status, 403, 'audit must be admin-only');
  const audit = (await admin('/api/audit')).data;
  for (const action of ['item.create', 'vault.share', 'user.register']) {
    assert.ok(audit.some((a) => a.action === action), `audit must contain ${action}`);
  }

  console.log('9. Revoke member → their session dies');
  const memberId = users.find((u) => u.email === 'dev@example.com').id;
  await admin(`/api/users/${memberId}/revoke`, { method: 'POST' });
  assert.strictEqual((await member('/api/items')).status, 401, 'revoked user must 401');

  rodb.close();
  console.log('\n✅ All Vaultly smoke tests passed');
}

async function cleanup(code) {
  if (serverProc && !serverProc.killed) serverProc.kill();
  await sleep(300);
  for (const f of [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm']) {
    try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch { /* windows lock */ }
  }
  process.exit(code);
}

main()
  .then(() => cleanup(0))
  .catch(async (err) => {
    console.error('\n❌ Smoke test failed:', err.message);
    await cleanup(1);
  });
