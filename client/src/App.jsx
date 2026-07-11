import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Lock, Plus, Search, KeyRound, StickyNote, CreditCard, Copy, Check, Eye, EyeOff,
  RefreshCw, Shield, Users, ScrollText, LogOut, Trash2, Share2, FolderLock, X,
  AlertTriangle, Download, UserPlus, Timer
} from 'lucide-react';
import { api } from './api.js';
import {
  deriveKeys, generateUserKey, aesEncrypt, aesDecrypt, wrapKeyWithAes, unwrapKeyWithAes,
  generateRsaKeypair, importPublicKey, importPrivateKey, rsaWrapAesKey, rsaUnwrapAesKey,
  generatePassword, passwordStrength, breachCount, randomHex, KDF_ITERATIONS
} from './crypto.js';
import { totpCode, totpRemaining } from './totp.js';

const IDLE_LOCK_MS = 5 * 60 * 1000;

// ── small bits ───────────────────────────────────────────────────────────────
function CopyBtn({ value, label = 'copy', clearAfter = 30 }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn-ghost px-2! py-1!"
      title={`Copy ${label} (clipboard auto-clears in ${clearAfter}s)`}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
        setTimeout(async () => {
          try {
            const cur = await navigator.clipboard.readText();
            if (cur === value) await navigator.clipboard.writeText('');
          } catch { /* clipboard read may be denied — fine */ }
        }, clearAfter * 1000);
      }}
    >
      {done ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
    </button>
  );
}

function StrengthBar({ password }) {
  const s = passwordStrength(password);
  const colors = ['bg-zinc-700', 'bg-red-500', 'bg-amber-500', 'bg-emerald-500', 'bg-indigo-400'];
  return (
    <div className="flex items-center gap-2">
      <div className="flex gap-1 flex-1">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className={`h-1.5 flex-1 rounded ${i <= s.score ? colors[s.score] : 'bg-zinc-800'}`} />
        ))}
      </div>
      <span className="text-xs text-zinc-500 w-16 text-right">{s.label}</span>
    </div>
  );
}

function TotpChip({ secret }) {
  const [code, setCode] = useState('——————');
  const [left, setLeft] = useState(30);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const c = await totpCode(secret).catch(() => null);
      if (alive) {
        setCode(c || 'invalid');
        setLeft(totpRemaining());
      }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(t); };
  }, [secret]);
  return (
    <div className="flex items-center gap-2 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2">
      <Timer size={14} className="text-indigo-400" />
      <span className="font-mono text-lg tracking-widest text-indigo-300">{code}</span>
      <span className="text-xs text-zinc-500 tabular-nums">{left}s</span>
      <CopyBtn value={code} label="TOTP code" clearAfter={15} />
    </div>
  );
}

const TYPE_ICON = { login: KeyRound, note: StickyNote, card: CreditCard };

// ── auth screens ─────────────────────────────────────────────────────────────
function AuthScreen({ needsSetup, onUnlocked }) {
  const [mode, setMode] = useState(needsSetup ? 'setup' : 'login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [setupPw, setSetupPw] = useState('');
  const [invite, setInvite] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (mode === 'login') {
        const pre = await api.prelogin(email);
        const { encKey, authKeyHex } = await deriveKeys(password, pre.kdf_salt, pre.kdf_iterations);
        const resp = await api.login({ email, auth_key: authKeyHex });
        await onUnlocked(resp, encKey);
      } else {
        const kdfSalt = randomHex(16);
        const { encKey, authKeyHex } = await deriveKeys(password, kdfSalt, KDF_ITERATIONS);
        const userKey = await generateUserKey();
        const wrappedUserKey = await wrapKeyWithAes(encKey, userKey);
        const { publicKeyB64, privateKeyPkcs8B64 } = await generateRsaKeypair();
        const encPriv = await aesEncrypt(userKey, privateKeyPkcs8B64);
        const resp = await api.register({
          email,
          auth_key: authKeyHex,
          kdf_salt: kdfSalt,
          kdf_iterations: KDF_ITERATIONS,
          encrypted_key_json: JSON.stringify(wrappedUserKey),
          public_key: publicKeyB64,
          encrypted_private_key: JSON.stringify(encPriv),
          setup_password: mode === 'setup' ? setupPw : undefined,
          invite_token: mode === 'join' ? invite : undefined
        });
        await onUnlocked(resp, encKey);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <motion.form
        initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        onSubmit={submit}
        className="w-full max-w-sm bg-zinc-925 border border-zinc-800 rounded-2xl p-8 space-y-4 bg-zinc-900/50"
      >
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-indigo-600/20 border border-indigo-500/30 rounded-xl p-2.5">
            <Lock className="text-indigo-400" size={22} />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Vaultly</h1>
            <p className="text-xs text-zinc-500">Zero-knowledge. Self-hosted. Yours.</p>
          </div>
        </div>
        {mode === 'setup' && (
          <p className="text-xs text-amber-400/90 bg-amber-950/40 border border-amber-900/50 rounded-lg p-3">
            First run — create the admin account. Your master password encrypts everything and is <b>never sent to the server</b>. It cannot be recovered.
          </p>
        )}
        <input type="email" placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        <div>
          <input type="password" placeholder="master password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={mode !== 'login' ? 10 : undefined} />
          {mode !== 'login' && <div className="mt-2"><StrengthBar password={password} /></div>}
        </div>
        {mode === 'setup' && (
          <input type="password" placeholder="instance setup password (ADMIN_PASSWORD)" value={setupPw} onChange={(e) => setSetupPw(e.target.value)} required />
        )}
        {mode === 'join' && (
          <input placeholder="invite token" value={invite} onChange={(e) => setInvite(e.target.value)} required />
        )}
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button className="btn-primary w-full justify-center" disabled={busy}>
          {busy ? <RefreshCw className="animate-spin" size={16} /> : <Shield size={16} />}
          {mode === 'login' ? 'Unlock' : 'Create account'}
        </button>
        <div className="text-xs text-zinc-500 text-center space-x-3">
          {mode !== 'login' && <button type="button" className="hover:text-zinc-300" onClick={() => setMode('login')}>Sign in</button>}
          {mode === 'login' && !needsSetup && <button type="button" className="hover:text-zinc-300" onClick={() => setMode('join')}>Join with invite</button>}
        </div>
      </motion.form>
    </div>
  );
}

// ── item editor modal ────────────────────────────────────────────────────────
function ItemModal({ initial, vaults, onSave, onClose, onDelete }) {
  const [data, setData] = useState(initial.data);
  const [vaultId, setVaultId] = useState(initial.shared_vault_id || '');
  const [type, setType] = useState(initial.type || 'login');
  const [showPw, setShowPw] = useState(false);
  const [breach, setBreach] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k, v) => setData((d) => ({ ...d, [k]: v }));

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }}
        className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">{initial.id ? 'Edit item' : 'New item'}</h2>
          <button className="btn-ghost p-1.5!" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="login">Login</option>
            <option value="note">Secure note</option>
            <option value="card">Card</option>
          </select>
          <select value={vaultId} onChange={(e) => setVaultId(e.target.value)} disabled={!!initial.id}>
            <option value="">Personal vault</option>
            {vaults.filter((v) => v.role !== 'readonly').map((v) => <option key={v.id} value={v.id}>🔒 {v.name}</option>)}
          </select>
        </div>
        <input placeholder="name" value={data.name || ''} onChange={(e) => set('name', e.target.value)} autoFocus />
        <input placeholder="folder (optional)" value={data.folder || ''} onChange={(e) => set('folder', e.target.value)} />
        {type === 'login' && (
          <>
            <input placeholder="url" value={data.url || ''} onChange={(e) => set('url', e.target.value)} />
            <input placeholder="username" value={data.username || ''} onChange={(e) => set('username', e.target.value)} />
            <div className="space-y-2">
              <div className="flex gap-2">
                <input type={showPw ? 'text' : 'password'} placeholder="password" value={data.password || ''} onChange={(e) => { set('password', e.target.value); setBreach(null); }} />
                <button type="button" className="btn-ghost px-2.5!" onClick={() => setShowPw(!showPw)}>{showPw ? <EyeOff size={14} /> : <Eye size={14} />}</button>
                <button type="button" className="btn-ghost px-2.5!" title="Generate strong password" onClick={() => { set('password', generatePassword()); setShowPw(true); setBreach(null); }}><RefreshCw size={14} /></button>
              </div>
              <StrengthBar password={data.password || ''} />
              <div className="flex items-center gap-2 text-xs">
                <button type="button" className="btn-ghost px-2! py-1! text-xs!" onClick={async () => {
                  setBreach('...');
                  try { setBreach(await breachCount(data.password || '')); } catch { setBreach('err'); }
                }}>
                  <Shield size={12} /> Check breach (HIBP, k-anonymity)
                </button>
                {breach === 0 && <span className="text-emerald-400">not found in breaches</span>}
                {typeof breach === 'number' && breach > 0 && <span className="text-red-400 flex items-center gap-1"><AlertTriangle size={12} /> seen {breach.toLocaleString()}× in breaches</span>}
                {breach === 'err' && <span className="text-zinc-500">check unavailable</span>}
              </div>
            </div>
            <input placeholder="TOTP secret (base32, optional)" value={data.totp || ''} onChange={(e) => set('totp', e.target.value)} />
            {data.totp && <TotpChip secret={data.totp} />}
          </>
        )}
        {type === 'card' && (
          <>
            <input placeholder="cardholder name" value={data.holder || ''} onChange={(e) => set('holder', e.target.value)} />
            <input placeholder="card number" value={data.number || ''} onChange={(e) => set('number', e.target.value)} />
            <div className="grid grid-cols-2 gap-3">
              <input placeholder="MM/YY" value={data.expiry || ''} onChange={(e) => set('expiry', e.target.value)} />
              <input placeholder="CVV" value={data.cvv || ''} onChange={(e) => set('cvv', e.target.value)} />
            </div>
          </>
        )}
        <textarea placeholder="notes" rows={3} value={data.notes || ''} onChange={(e) => set('notes', e.target.value)} />
        <div className="flex justify-between pt-1">
          {initial.id
            ? <button className="btn-danger" onClick={() => onDelete(initial)}><Trash2 size={14} /> Delete</button>
            : <span />}
          <button className="btn-primary" disabled={busy || !data.name} onClick={async () => {
            setBusy(true);
            try { await onSave({ id: initial.id, type, shared_vault_id: vaultId || null, data }); } finally { setBusy(false); }
          }}>
            <Check size={15} /> Save
          </button>
        </div>
      </motion.div>
    </div>
  );
}

// ── main app ─────────────────────────────────────────────────────────────────
export default function App() {
  const [phase, setPhase] = useState('loading'); // loading|auth|vault
  const [needsSetup, setNeedsSetup] = useState(false);
  const [user, setUser] = useState(null);
  const keys = useRef({ userKey: null, privateKey: null, vaultKeys: new Map() });
  const [items, setItems] = useState([]); // decrypted: {id, type, vault, data,...}
  const [vaults, setVaults] = useState([]);
  const [query, setQuery] = useState('');
  const [modal, setModal] = useState(null);
  const [view, setView] = useState('vault'); // vault|admin
  const [admin, setAdmin] = useState({ users: [], invites: [], audit: [] });
  const [shareTarget, setShareTarget] = useState(null);
  const [toast, setToast] = useState('');

  const say = (m) => { setToast(m); setTimeout(() => setToast(''), 2500); };

  const lock = useCallback(() => {
    keys.current = { userKey: null, privateKey: null, vaultKeys: new Map() };
    setItems([]);
    setUser(null);
    setPhase('auth');
    api.logout().catch(() => {});
  }, []);

  // idle auto-lock
  useEffect(() => {
    if (phase !== 'vault') return;
    let t = setTimeout(lock, IDLE_LOCK_MS);
    const reset = () => { clearTimeout(t); t = setTimeout(lock, IDLE_LOCK_MS); };
    for (const ev of ['mousemove', 'keydown', 'click']) window.addEventListener(ev, reset);
    return () => { clearTimeout(t); for (const ev of ['mousemove', 'keydown', 'click']) window.removeEventListener(ev, reset); };
  }, [phase, lock]);

  useEffect(() => {
    api.bootstrap().then((b) => { setNeedsSetup(b.needs_setup); setPhase('auth'); }).catch(() => setPhase('auth'));
  }, []);

  async function loadVault(userKey, privateKey) {
    const [vaultRows, itemRows] = await Promise.all([api.vaults(), api.items()]);
    const vaultKeys = new Map();
    for (const v of vaultRows) {
      try { vaultKeys.set(v.id, await rsaUnwrapAesKey(privateKey, v.encrypted_vault_key)); } catch { /* wrapped for old key */ }
    }
    keys.current.vaultKeys = vaultKeys;
    const out = [];
    for (const row of itemRows) {
      const key = row.shared_vault_id ? vaultKeys.get(row.shared_vault_id) : userKey;
      if (!key) continue;
      try {
        out.push({ ...row, data: JSON.parse(await aesDecrypt(key, { iv: row.iv, ciphertext: row.ciphertext })) });
      } catch { out.push({ ...row, data: { name: '⚠ decrypt failed' }, broken: true }); }
    }
    setVaults(vaultRows);
    setItems(out);
  }

  async function onUnlocked(resp, encKey) {
    const wrapped = JSON.parse(resp.crypto.encrypted_key_json);
    const userKey = await unwrapKeyWithAes(encKey, wrapped);
    const privPkcs8 = await aesDecrypt(userKey, JSON.parse(resp.crypto.encrypted_private_key));
    const privateKey = await importPrivateKey(privPkcs8);
    keys.current = { userKey, privateKey, vaultKeys: new Map() };
    setUser(resp.user);
    await loadVault(userKey, privateKey);
    setPhase('vault');
  }

  async function saveItem({ id, type, shared_vault_id, data }) {
    const key = shared_vault_id ? keys.current.vaultKeys.get(Number(shared_vault_id)) : keys.current.userKey;
    const { iv, ciphertext } = await aesEncrypt(key, JSON.stringify(data));
    if (id) await api.updateItem(id, { ciphertext, iv, type });
    else await api.createItem({ ciphertext, iv, type, shared_vault_id });
    await loadVault(keys.current.userKey, keys.current.privateKey);
    setModal(null);
    say('Saved (encrypted client-side)');
  }

  async function deleteItem(item) {
    if (!confirm(`Delete "${item.data.name}"?`)) return;
    await api.deleteItem(item.id);
    setItems((xs) => xs.filter((x) => x.id !== item.id));
    setModal(null);
  }

  async function createVault() {
    const name = prompt('Shared vault name:');
    if (!name) return;
    const vaultKey = await generateUserKey();
    const myPub = await importPublicKey((await api.me()).crypto.public_key);
    const wrapped = await rsaWrapAesKey(myPub, vaultKey);
    await api.createVault({ name, encrypted_vault_key: wrapped });
    await loadVault(keys.current.userKey, keys.current.privateKey);
    say(`Vault "${name}" created`);
  }

  async function shareVault(vault, email, role) {
    const users = await api.users();
    const target = users.find((u) => u.email === email.toLowerCase().trim());
    if (!target) return say('No user with that email');
    const vaultKey = keys.current.vaultKeys.get(vault.id);
    const wrapped = await rsaWrapAesKey(await importPublicKey(target.public_key), vaultKey);
    await api.shareVault(vault.id, { email: target.email, role, encrypted_vault_key: wrapped });
    setShareTarget(null);
    say(`Shared "${vault.name}" with ${target.email}`);
  }

  async function openAdmin() {
    const [users, invites, audit] = await Promise.all([api.users(), api.invites(), api.audit()]);
    setAdmin({ users, invites, audit });
    setView('admin');
  }

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return items.filter((i) =>
      !q || `${i.data.name} ${i.data.username} ${i.data.url} ${i.data.folder}`.toLowerCase().includes(q));
  }, [items, query]);

  const grouped = useMemo(() => {
    const g = new Map();
    for (const i of filtered) {
      const label = i.shared_vault_id
        ? `🔒 ${vaults.find((v) => v.id === i.shared_vault_id)?.name || 'Shared'}`
        : (i.data.folder ? `📁 ${i.data.folder}` : 'Personal');
      if (!g.has(label)) g.set(label, []);
      g.get(label).push(i);
    }
    return [...g.entries()];
  }, [filtered, vaults]);

  if (phase === 'loading') return <div className="min-h-screen flex items-center justify-center"><RefreshCw className="animate-spin text-zinc-600" /></div>;
  if (phase === 'auth') return <AuthScreen needsSetup={needsSetup} onUnlocked={onUnlocked} />;

  return (
    <div className="min-h-screen max-w-5xl mx-auto p-6">
      <header className="flex items-center gap-3 mb-6">
        <div className="bg-indigo-600/20 border border-indigo-500/30 rounded-xl p-2"><Lock className="text-indigo-400" size={18} /></div>
        <h1 className="font-semibold">Vaultly</h1>
        <span className="text-xs text-zinc-500">{user.email}</span>
        <div className="flex-1" />
        <button className="btn-ghost" onClick={createVault}><FolderLock size={14} /> New shared vault</button>
        {user.role === 'admin' && (
          view === 'admin'
            ? <button className="btn-ghost" onClick={() => setView('vault')}><KeyRound size={14} /> Vault</button>
            : <button className="btn-ghost" onClick={openAdmin}><Users size={14} /> Admin</button>
        )}
        <button className="btn-ghost" title="Lock now" onClick={lock}><LogOut size={14} /> Lock</button>
      </header>

      {view === 'vault' && (
        <>
          <div className="flex gap-3 mb-5">
            <div className="relative flex-1">
              <Search size={15} className="absolute left-3 top-2.5 text-zinc-500" />
              <input className="!pl-9" placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <button className="btn-primary" onClick={() => setModal({ data: {} })}><Plus size={15} /> New item</button>
          </div>

          {grouped.length === 0 && (
            <div className="text-center text-zinc-500 py-20">
              <Shield className="mx-auto mb-3 text-zinc-700" size=  {40} />
              Your vault is empty. Everything you add is AES-256 encrypted in your browser before it ever touches the server.
            </div>
          )}

          {grouped.map(([label, rows]) => (
            <div key={label} className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs uppercase tracking-wider text-zinc-500">{label}</h3>
                {label.startsWith('🔒') && (() => {
                  const v = vaults.find((x) => `🔒 ${x.name}` === label);
                  return v && (v.role === 'owner' || user.role === 'admin')
                    ? <button className="text-xs text-zinc-500 hover:text-indigo-400 flex items-center gap-1" onClick={() => setShareTarget(v)}><Share2 size={12} /> share</button>
                    : null;
                })()}
              </div>
              <div className="grid gap-2">
                {rows.map((item) => {
                  const Icon = TYPE_ICON[item.type] || KeyRound;
                  return (
                    <motion.div layout key={item.id}
                      className="flex items-center gap-3 bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 rounded-xl px-4 py-3 cursor-pointer"
                      onClick={() => { api.markAccessed(item.id); setModal({ ...item }); }}>
                      <Icon size={16} className="text-indigo-400 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium truncate">{item.data.name}</div>
                        <div className="text-xs text-zinc-500 truncate">{item.data.username || item.data.url || item.type}</div>
                      </div>
                      {item.data.password && <span onClick={(e) => e.stopPropagation()}><CopyBtn value={item.data.password} label="password" /></span>}
                      {item.data.totp && <span onClick={(e) => e.stopPropagation()} className="hidden sm:block"><TotpChip secret={item.data.totp} /></span>}
                    </motion.div>
                  );
                })}
              </div>
            </div>
          ))}
        </>
      )}

      {view === 'admin' && (
        <div className="space-y-8">
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-medium flex items-center gap-2"><Users size={16} /> Team</h2>
              <div className="flex gap-2">
                <button className="btn-ghost" onClick={async () => {
                  const email = prompt('Invite email (optional, locks invite to that address):') || '';
                  const inv = await api.createInvite(email);
                  await navigator.clipboard.writeText(inv.token);
                  say('Invite token copied to clipboard');
                  openAdmin();
                }}><UserPlus size={14} /> Create invite</button>
                <button className="btn-ghost" onClick={async () => {
                  const data = await api.exportOrg();
                  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                  const a = document.createElement('a');
                  a.href = URL.createObjectURL(blob);
                  a.download = 'vaultly-export-encrypted.json';
                  a.click();
                }}><Download size={14} /> Encrypted export</button>
              </div>
            </div>
            <div className="grid gap-2">
              {admin.users.map((u) => (
                <div key={u.id} className="flex items-center gap-3 bg-zinc-900/60 border border-zinc-800 rounded-xl px-4 py-3 text-sm">
                  <span className={u.revoked ? 'line-through text-zinc-600' : ''}>{u.email}</span>
                  <span className="text-xs text-zinc-500">{u.role}</span>
                  <div className="flex-1" />
                  {!u.revoked && u.id !== user.id && (
                    <button className="btn-danger px-2! py-1! text-xs!" onClick={async () => { await api.revokeUser(u.id); openAdmin(); }}>revoke</button>
                  )}
                </div>
              ))}
            </div>
            {admin.invites.filter((i) => !i.used_by).length > 0 && (
              <div className="mt-3 text-xs text-zinc-500">
                Open invites: {admin.invites.filter((i) => !i.used_by).map((i) => (
                  <code key={i.id} className="bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 mr-2">{i.token.slice(0, 10)}… {i.email || 'any email'}</code>
                ))}
              </div>
            )}
          </section>
          <section>
            <h2 className="font-medium flex items-center gap-2 mb-3"><ScrollText size={16} /> Audit log</h2>
            <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl divide-y divide-zinc-800/70 max-h-96 overflow-y-auto">
              {admin.audit.map((a) => (
                <div key={a.id} className="px-4 py-2 text-xs flex gap-3">
                  <span className="text-zinc-500 w-36 shrink-0">{new Date(a.at).toLocaleString()}</span>
                  <span className="text-indigo-300 w-40 shrink-0">{a.email || 'system'}</span>
                  <span className="text-zinc-300">{a.action}{a.item_id ? ` #${a.item_id}` : ''}{a.detail ? ` — ${a.detail}` : ''}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      <AnimatePresence>
        {modal && <ItemModal initial={modal} vaults={vaults} onSave={saveItem} onClose={() => setModal(null)} onDelete={deleteItem} />}
        {shareTarget && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50" onMouseDown={(e) => e.target === e.currentTarget && setShareTarget(null)}>
            <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }}
              className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-sm p-6 space-y-4">
              <h2 className="font-semibold flex items-center gap-2"><Share2 size={16} /> Share “{shareTarget.name}”</h2>
              <form onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.target); shareVault(shareTarget, f.get('email'), f.get('role')); }} className="space-y-3">
                <input name="email" type="email" placeholder="teammate email" required autoFocus />
                <select name="role"><option value="member">member (read/write)</option><option value="readonly">read only</option></select>
                <p className="text-xs text-zinc-500">The vault key is re-encrypted in your browser with their public key — the server never sees it.</p>
                <button className="btn-primary w-full justify-center">Share</button>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {toast && (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-zinc-800 border border-zinc-700 rounded-full px-4 py-2 text-sm shadow-xl">
            {toast}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
