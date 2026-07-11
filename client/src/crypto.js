// Vaultly client-side crypto — Web Crypto API only, no custom primitives.
//
// Model (Bitwarden-style zero knowledge):
//   PBKDF2-SHA256(masterPassword, kdfSalt, iterations) → 64 bytes
//     first 32 bytes  = encKey   (AES-256-GCM key, NEVER leaves the browser)
//     last  32 bytes  = authKey  (sent to server, which scrypt-hashes it again)
//   userKey  = random 32B symmetric key, stored AES-GCM-encrypted with encKey
//   RSA-OAEP-2048 keypair per user: public key on server, private key stored
//     AES-GCM-encrypted with userKey (enables shared-vault key wrapping)
//   items    = AES-256-GCM(userKey | vaultKey, JSON payload)

const enc = new TextEncoder();
const dec = new TextDecoder();

export const KDF_ITERATIONS = 600000;

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBuf(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));
}
function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export function randomHex(bytes = 16) {
  return bufToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function deriveKeys(masterPassword, kdfSaltHex, iterations = KDF_ITERATIONS) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: hexToBuf(kdfSaltHex), iterations },
    baseKey,
    512
  );
  const bytes = new Uint8Array(bits);
  const encKey = await crypto.subtle.importKey('raw', bytes.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const authKeyHex = bufToHex(bytes.slice(32));
  return { encKey, authKeyHex };
}

async function importAesKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, 'AES-GCM', true, ['encrypt', 'decrypt']);
}

export async function generateUserKey() {
  return importAesKey(crypto.getRandomValues(new Uint8Array(32)));
}

export async function aesEncrypt(key, plaintextStr) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintextStr));
  return { iv: bufToHex(iv), ciphertext: bufToB64(ct) };
}

export async function aesDecrypt(key, { iv, ciphertext }) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuf(iv) }, key, b64ToBuf(ciphertext));
  return dec.decode(pt);
}

export async function wrapKeyWithAes(wrappingKey, keyToWrap) {
  const raw = await crypto.subtle.exportKey('raw', keyToWrap);
  return aesEncrypt(wrappingKey, bufToHex(raw));
}

export async function unwrapKeyWithAes(wrappingKey, wrapped) {
  const rawHex = await aesDecrypt(wrappingKey, wrapped);
  return importAesKey(hexToBuf(rawHex));
}

// ── RSA (shared vault key exchange) ─────────────────────────────────────────
export async function generateRsaKeypair() {
  const kp = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKeyB64 = bufToB64(await crypto.subtle.exportKey('spki', kp.publicKey));
  const privateKeyPkcs8B64 = bufToB64(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return { keypair: kp, publicKeyB64, privateKeyPkcs8B64 };
}

export async function importPublicKey(spkiB64) {
  return crypto.subtle.importKey('spki', b64ToBuf(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

export async function importPrivateKey(pkcs8B64) {
  return crypto.subtle.importKey('pkcs8', b64ToBuf(pkcs8B64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

export async function rsaWrapAesKey(publicKey, aesKey) {
  const raw = await crypto.subtle.exportKey('raw', aesKey);
  const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw);
  return bufToB64(ct);
}

export async function rsaUnwrapAesKey(privateKey, wrappedB64) {
  const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, b64ToBuf(wrappedB64));
  return importAesKey(new Uint8Array(raw));
}

// ── password generator + strength ───────────────────────────────────────────
export function generatePassword({ length = 20, symbols = true, digits = true, upper = true } = {}) {
  let chars = 'abcdefghijkmnopqrstuvwxyz';
  if (upper) chars += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if (digits) chars += '23456789';
  if (symbols) chars += '!@#$%^&*-_=+?';
  const rnd = crypto.getRandomValues(new Uint32Array(length));
  return [...rnd].map((n) => chars[n % chars.length]).join('');
}

export function passwordStrength(pw) {
  if (!pw) return { score: 0, label: 'empty' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const entropy = pw.length * Math.log2(pool || 1);
  if (entropy < 40) return { score: 1, label: 'weak', entropy };
  if (entropy < 65) return { score: 2, label: 'fair', entropy };
  if (entropy < 90) return { score: 3, label: 'strong', entropy };
  return { score: 4, label: 'excellent', entropy };
}

// ── HIBP k-anonymity breach check (OFF by default, user-initiated only) ─────
export async function breachCount(password) {
  const digest = await crypto.subtle.digest('SHA-1', enc.encode(password));
  const hex = bufToHex(digest).toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error('breach API unavailable');
  const text = await res.text();
  for (const line of text.split('\n')) {
    const [suf, count] = line.trim().split(':');
    if (suf === suffix) return Number(count);
  }
  return 0;
}
