const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

function nativeBindingPath() {
  // Under Electron the Node-ABI binding won't load; use the vendored Electron prebuild.
  if (!process.versions.electron) return null;
  const p = path.join(__dirname, '..', 'vendor', 'better_sqlite3-electron.node');
  return fs.existsSync(p) ? p : null;
}

function genToken(len = 32) {
  return crypto.randomBytes(len).toString('hex');
}

// Server-side hash of the client auth key (which is itself derived client-side
// from the master password — the master password/encryption key never reach us).
function hashAuthKey(authKeyHex, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const hash = crypto.scryptSync(Buffer.from(authKeyHex, 'utf8'), salt, 32);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

function verifyAuthKey(authKeyHex, storedSaltHex, storedHashHex) {
  const { hash } = hashAuthKey(authKeyHex, storedSaltHex);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHashHex, 'hex'));
}

function openDb(dbPath) {
  fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  const nativeBinding = nativeBindingPath();
  const db = new Database(dbPath, nativeBinding ? { nativeBinding } : {});
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL DEFAULT 'member',          -- admin|member
      kdf_salt TEXT NOT NULL,                       -- client KDF salt (hex)
      kdf_iterations INTEGER NOT NULL,
      auth_salt TEXT NOT NULL,                      -- server-side scrypt salt
      auth_hash TEXT NOT NULL,                      -- scrypt(client auth key)
      encrypted_key_json TEXT NOT NULL,             -- user symmetric key, AES-GCM'd with master-derived key (client-side)
      public_key TEXT NOT NULL,                     -- RSA-OAEP public key (spki b64) — for vault sharing
      encrypted_private_key TEXT NOT NULL,          -- RSA private key AES-GCM'd with user key (client-side)
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS shared_vaults (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vault_access (
      vault_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',          -- owner|member|readonly
      encrypted_vault_key TEXT NOT NULL,            -- vault key wrapped with this user's RSA public key (client-side)
      added_at INTEGER NOT NULL,
      PRIMARY KEY (vault_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS vault_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER,                             -- personal item owner (NULL when in a shared vault)
      shared_vault_id INTEGER,                      -- shared vault (NULL when personal)
      type TEXT NOT NULL DEFAULT 'login',           -- login|note|card
      ciphertext TEXT NOT NULL,                     -- AES-256-GCM, encrypted client-side
      iv TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      email TEXT,
      created_by INTEGER NOT NULL,
      used_by INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      item_id INTEGER,
      vault_id INTEGER,
      detail TEXT,
      at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_items_owner ON vault_items(owner_id);
    CREATE INDEX IF NOT EXISTS idx_items_vault ON vault_items(shared_vault_id);
    CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
  `);

  return db;
}

module.exports = { openDb, genToken, hashAuthKey, verifyAuthKey };
