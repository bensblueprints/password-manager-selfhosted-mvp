// Vaultly server — zero-knowledge by design.
// This server only ever stores/relays ciphertext. All encryption/decryption
// happens in the client (Web Crypto). Nothing in this file handles plaintext
// secrets, master passwords, or encryption keys — and nothing here logs bodies.
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const { openDb, genToken, hashAuthKey, verifyAuthKey } = require('./db');

const SESSION_COOKIE = 'vaultly_session';

function createApp({ dbPath, setupPassword, autologin = false } = {}) {
  const db = openDb(dbPath);
  const app = express();
  app.disable('x-powered-by');
  app.use(cookieParser());
  app.use(express.json({ limit: '2mb' }));
  app.locals.db = db;

  const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
  const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');

  function audit(userId, action, itemId = null, vaultId = null, detail = null) {
    db.prepare('INSERT INTO audit_log (user_id, action, item_id, vault_id, detail, at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(userId, action, itemId, vaultId, detail, Date.now());
  }

  function requireAuth(req, res, next) {
    const token = req.cookies[SESSION_COOKIE];
    if (token) {
      const sess = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
      if (sess) {
        const user = findUserById.get(sess.user_id);
        if (user && !user.revoked) { req.user = user; return next(); }
      }
    }
    res.status(401).json({ error: 'unauthorized' });
  }

  function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
    next();
  }

  function createSession(res, userId) {
    const token = genToken();
    db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, userId, Date.now());
    res.cookie(SESSION_COOKIE, token, { httpOnly: true, sameSite: 'lax' });
  }

  function publicUser(u) {
    return { id: u.id, email: u.email, role: u.role, created_at: u.created_at, revoked: u.revoked };
  }

  function cryptoBlobs(u) {
    return {
      kdf_salt: u.kdf_salt,
      kdf_iterations: u.kdf_iterations,
      encrypted_key_json: u.encrypted_key_json,
      public_key: u.public_key,
      encrypted_private_key: u.encrypted_private_key
    };
  }

  // ── health / bootstrap ─────────────────────────────────────────────────────
  app.get('/api/health', (req, res) => res.json({ ok: true, app: 'vaultly' }));

  app.get('/api/bootstrap', (req, res) => {
    const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    res.json({ needs_setup: count === 0 });
  });

  // A user needs their KDF params before deriving keys at login.
  app.post('/api/prelogin', (req, res) => {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    const u = findUserByEmail.get(email);
    // Do not reveal whether the account exists: return plausible params either way.
    if (!u) return res.json({ kdf_salt: crypto.createHash('sha256').update('vaultly' + email).digest('hex').slice(0, 32), kdf_iterations: 600000 });
    res.json({ kdf_salt: u.kdf_salt, kdf_iterations: u.kdf_iterations });
  });

  // ── register / login ───────────────────────────────────────────────────────
  app.post('/api/register', (req, res) => {
    const b = req.body || {};
    const email = String(b.email || '').trim().toLowerCase();
    const required = ['auth_key', 'kdf_salt', 'kdf_iterations', 'encrypted_key_json', 'public_key', 'encrypted_private_key'];
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'valid email required' });
    for (const k of required) if (!b[k]) return res.status(400).json({ error: `${k} required` });
    if (findUserByEmail.get(email)) return res.status(409).json({ error: 'email already registered' });

    const isFirst = db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0;
    let role = 'member';
    if (isFirst) {
      // Bootstrap: creating the first (admin) account requires the instance
      // setup password from .env, so a fresh public deployment can't be claimed
      // by a drive-by visitor.
      if (String(b.setup_password || '') !== String(setupPassword)) {
        return res.status(403).json({ error: 'wrong setup password (ADMIN_PASSWORD from .env)' });
      }
      role = 'admin';
    } else {
      const invite = db.prepare('SELECT * FROM invites WHERE token = ? AND used_by IS NULL').get(String(b.invite_token || ''));
      if (!invite) return res.status(403).json({ error: 'valid invite token required' });
      if (invite.email && invite.email.toLowerCase() !== email) return res.status(403).json({ error: 'invite is for a different email' });
      db.prepare('UPDATE invites SET used_by = -1 WHERE id = ?').run(invite.id); // marked, fixed up below
    }

    const { salt, hash } = hashAuthKey(String(b.auth_key));
    const info = db.prepare(`
      INSERT INTO users (email, role, kdf_salt, kdf_iterations, auth_salt, auth_hash,
                         encrypted_key_json, public_key, encrypted_private_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(email, role, String(b.kdf_salt), Number(b.kdf_iterations), salt, hash,
           String(b.encrypted_key_json), String(b.public_key), String(b.encrypted_private_key), Date.now());
    const userId = info.lastInsertRowid;
    if (!isFirst) db.prepare('UPDATE invites SET used_by = ? WHERE used_by = -1').run(userId);
    audit(userId, 'user.register');
    createSession(res, userId);
    const u = findUserById.get(userId);
    res.status(201).json({ user: publicUser(u), crypto: cryptoBlobs(u) });
  });

  app.post('/api/login', (req, res) => {
    const b = req.body || {};
    const email = String(b.email || '').trim().toLowerCase();
    const u = findUserByEmail.get(email);
    if (!u || u.revoked || !b.auth_key || !verifyAuthKey(String(b.auth_key), u.auth_salt, u.auth_hash)) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    createSession(res, u.id);
    audit(u.id, 'user.login');
    res.json({ user: publicUser(u), crypto: cryptoBlobs(u) });
  });

  app.post('/api/logout', (req, res) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    res.clearCookie(SESSION_COOKIE);
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, (req, res) => {
    res.json({ user: publicUser(req.user), crypto: cryptoBlobs(req.user) });
  });

  // ── users & invites (sharing directory / admin) ────────────────────────────
  app.get('/api/users', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT id, email, role, public_key, revoked, created_at FROM users').all();
    res.json(rows);
  });

  app.post('/api/invites', requireAuth, requireAdmin, (req, res) => {
    const token = genToken(16);
    const email = String((req.body || {}).email || '').trim().toLowerCase() || null;
    db.prepare('INSERT INTO invites (token, email, created_by, created_at) VALUES (?, ?, ?, ?)')
      .run(token, email, req.user.id, Date.now());
    audit(req.user.id, 'invite.create', null, null, email);
    res.status(201).json({ token, email });
  });

  app.get('/api/invites', requireAuth, requireAdmin, (req, res) => {
    res.json(db.prepare('SELECT id, token, email, used_by, created_at FROM invites ORDER BY created_at DESC').all());
  });

  app.post('/api/users/:id/revoke', requireAuth, requireAdmin, (req, res) => {
    const target = findUserById.get(req.params.id);
    if (!target) return res.status(404).json({ error: 'not found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'cannot revoke yourself' });
    db.prepare('UPDATE users SET revoked = 1 WHERE id = ?').run(target.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    audit(req.user.id, 'user.revoke', null, null, target.email);
    res.json({ ok: true });
  });

  // ── shared vaults ──────────────────────────────────────────────────────────
  function vaultRole(vaultId, userId) {
    const row = db.prepare('SELECT role FROM vault_access WHERE vault_id = ? AND user_id = ?').get(vaultId, userId);
    return row ? row.role : null;
  }

  app.get('/api/vaults', requireAuth, (req, res) => {
    const rows = db.prepare(`
      SELECT v.id, v.name, v.created_by, v.created_at, a.role, a.encrypted_vault_key
      FROM shared_vaults v JOIN vault_access a ON a.vault_id = v.id
      WHERE a.user_id = ?
    `).all(req.user.id);
    res.json(rows);
  });

  app.post('/api/vaults', requireAuth, (req, res) => {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    if (!name) return res.status(400).json({ error: 'name required' });
    if (!b.encrypted_vault_key) return res.status(400).json({ error: 'encrypted_vault_key required (vault key wrapped with your public key)' });
    const now = Date.now();
    const info = db.prepare('INSERT INTO shared_vaults (name, created_by, created_at) VALUES (?, ?, ?)')
      .run(name, req.user.id, now);
    db.prepare('INSERT INTO vault_access (vault_id, user_id, role, encrypted_vault_key, added_at) VALUES (?, ?, ?, ?, ?)')
      .run(info.lastInsertRowid, req.user.id, 'owner', String(b.encrypted_vault_key), now);
    audit(req.user.id, 'vault.create', null, info.lastInsertRowid, name);
    res.status(201).json({ id: info.lastInsertRowid, name, role: 'owner' });
  });

  app.get('/api/vaults/:id/members', requireAuth, (req, res) => {
    if (!vaultRole(req.params.id, req.user.id)) return res.status(403).json({ error: 'no access' });
    const rows = db.prepare(`
      SELECT a.user_id, a.role, a.added_at, u.email FROM vault_access a JOIN users u ON u.id = a.user_id
      WHERE a.vault_id = ?
    `).all(req.params.id);
    res.json(rows);
  });

  app.post('/api/vaults/:id/share', requireAuth, (req, res) => {
    const b = req.body || {};
    const myRole = vaultRole(req.params.id, req.user.id);
    if (myRole !== 'owner' && req.user.role !== 'admin') return res.status(403).json({ error: 'owner only' });
    const target = findUserByEmail.get(String(b.email || '').trim().toLowerCase());
    if (!target || target.revoked) return res.status(404).json({ error: 'user not found' });
    if (!b.encrypted_vault_key) return res.status(400).json({ error: 'encrypted_vault_key required (wrapped with target public key)' });
    const role = ['member', 'readonly'].includes(b.role) ? b.role : 'member';
    db.prepare(`
      INSERT INTO vault_access (vault_id, user_id, role, encrypted_vault_key, added_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(vault_id, user_id) DO UPDATE SET role = excluded.role, encrypted_vault_key = excluded.encrypted_vault_key
    `).run(req.params.id, target.id, role, String(b.encrypted_vault_key), Date.now());
    audit(req.user.id, 'vault.share', null, Number(req.params.id), target.email);
    res.json({ ok: true });
  });

  app.delete('/api/vaults/:id/share/:userId', requireAuth, (req, res) => {
    const myRole = vaultRole(req.params.id, req.user.id);
    if (myRole !== 'owner' && req.user.role !== 'admin') return res.status(403).json({ error: 'owner only' });
    db.prepare('DELETE FROM vault_access WHERE vault_id = ? AND user_id = ?').run(req.params.id, req.params.userId);
    audit(req.user.id, 'vault.unshare', null, Number(req.params.id), String(req.params.userId));
    res.json({ ok: true });
  });

  // ── vault items (ciphertext only) ──────────────────────────────────────────
  function canAccessItem(item, user, write = false) {
    if (item.owner_id) return item.owner_id === user.id;
    const role = vaultRole(item.shared_vault_id, user.id);
    if (!role) return false;
    if (write && role === 'readonly') return false;
    return true;
  }

  app.get('/api/items', requireAuth, (req, res) => {
    const rows = db.prepare(`
      SELECT * FROM vault_items
      WHERE owner_id = ?
         OR shared_vault_id IN (SELECT vault_id FROM vault_access WHERE user_id = ?)
      ORDER BY updated_at DESC
    `).all(req.user.id, req.user.id);
    res.json(rows);
  });

  app.post('/api/items', requireAuth, (req, res) => {
    const b = req.body || {};
    if (!b.ciphertext || !b.iv) return res.status(400).json({ error: 'ciphertext and iv required' });
    const type = ['login', 'note', 'card'].includes(b.type) ? b.type : 'login';
    let ownerId = req.user.id;
    let vaultId = null;
    if (b.shared_vault_id) {
      const role = vaultRole(b.shared_vault_id, req.user.id);
      if (!role || role === 'readonly') return res.status(403).json({ error: 'no write access to vault' });
      ownerId = null;
      vaultId = Number(b.shared_vault_id);
    }
    const now = Date.now();
    const info = db.prepare(`
      INSERT INTO vault_items (owner_id, shared_vault_id, type, ciphertext, iv, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(ownerId, vaultId, type, String(b.ciphertext), String(b.iv), now, now);
    audit(req.user.id, 'item.create', info.lastInsertRowid, vaultId);
    res.status(201).json(db.prepare('SELECT * FROM vault_items WHERE id = ?').get(info.lastInsertRowid));
  });

  app.put('/api/items/:id', requireAuth, (req, res) => {
    const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(req.params.id);
    if (!item) return res.status(404).json({ error: 'not found' });
    if (!canAccessItem(item, req.user, true)) return res.status(403).json({ error: 'no access' });
    const b = req.body || {};
    if (!b.ciphertext || !b.iv) return res.status(400).json({ error: 'ciphertext and iv required' });
    db.prepare('UPDATE vault_items SET ciphertext = ?, iv = ?, type = ?, updated_at = ? WHERE id = ?')
      .run(String(b.ciphertext), String(b.iv), b.type || item.type, Date.now(), item.id);
    audit(req.user.id, 'item.update', item.id, item.shared_vault_id);
    res.json(db.prepare('SELECT * FROM vault_items WHERE id = ?').get(item.id));
  });

  app.delete('/api/items/:id', requireAuth, (req, res) => {
    const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(req.params.id);
    if (!item) return res.status(404).json({ error: 'not found' });
    if (!canAccessItem(item, req.user, true)) return res.status(403).json({ error: 'no access' });
    db.prepare('DELETE FROM vault_items WHERE id = ?').run(item.id);
    audit(req.user.id, 'item.delete', item.id, item.shared_vault_id);
    res.json({ ok: true });
  });

  // Client reports decrypt/reveal events so the audit trail covers reads too.
  app.post('/api/items/:id/accessed', requireAuth, (req, res) => {
    const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(req.params.id);
    if (!item || !canAccessItem(item, req.user)) return res.status(404).json({ error: 'not found' });
    audit(req.user.id, 'item.reveal', item.id, item.shared_vault_id);
    res.json({ ok: true });
  });

  // ── audit + export ─────────────────────────────────────────────────────────
  app.get('/api/audit', requireAuth, requireAdmin, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 2000);
    const rows = db.prepare(`
      SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
      ORDER BY a.at DESC LIMIT ?
    `).all(limit);
    res.json(rows);
  });

  // Org-wide export — everything stays exactly as encrypted as it is at rest.
  app.get('/api/export', requireAuth, requireAdmin, (req, res) => {
    audit(req.user.id, 'org.export');
    res.json({
      exported_at: new Date().toISOString(),
      note: 'All item payloads are ciphertext (AES-256-GCM, client-side keys). This export is safe to store but useless without member master passwords.',
      users: db.prepare('SELECT id, email, role, kdf_salt, kdf_iterations, encrypted_key_json, public_key, encrypted_private_key FROM users').all(),
      shared_vaults: db.prepare('SELECT * FROM shared_vaults').all(),
      vault_access: db.prepare('SELECT * FROM vault_access').all(),
      items: db.prepare('SELECT * FROM vault_items').all()
    });
  });

  // ── static frontend ────────────────────────────────────────────────────────
  const dist = path.join(__dirname, '..', 'dist');
  if (fs.existsSync(dist)) {
    app.use(express.static(dist));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) return next();
      res.sendFile(path.join(dist, 'index.html'));
    });
  }

  return app;
}

module.exports = { createApp };
