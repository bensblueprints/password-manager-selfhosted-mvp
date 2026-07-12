# 🔐 Vaultly

**The zero-knowledge team password manager you own forever. Pay once. No per-seat subscription.**

![MIT](https://img.shields.io/badge/license-MIT-green) ![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)

Vaultly is a self-hosted password manager built on the same zero-knowledge model as Bitwarden: everything is encrypted **in your browser** with AES-256-GCM before it ever reaches the server. The server — your server — stores only ciphertext. Your master password never leaves your machine.

![screenshot](docs/screenshot.png)

## Features

- 🔒 **Zero-knowledge, client-side crypto** — PBKDF2 (600k iterations) → AES-256-GCM via the Web Crypto API. Server compromise ≠ vault compromise.
- 👥 **Shared team vaults** — vault keys are wrapped with each member's RSA-OAEP public key, in the browser. The server relays wrapped keys it can't read.
- 🔑 **Logins, secure notes, cards** — with folders, search, and a built-in strong password generator + strength meter.
- ⏱ **Inline TOTP** — store a 2FA secret with a login and get live 6-digit codes with copy-to-clipboard (clipboard auto-clears).
- 🕵️ **Breach check (opt-in)** — HaveIBeenPwned k-anonymity range API, only when you click the button. Off by default; your password never leaves the browser.
- 📜 **Audit log** — registrations, logins, item create/edit/delete/reveal, vault sharing — who did what, when.
- 🧑‍💼 **Admin** — invite links, user revocation, org-wide **encrypted** export.
- 🔐 **Auto-lock** — keys are wiped from memory after 5 minutes idle.

## Quick start

```bash
npm i
npm run build     # build the React frontend
npm start         # → http://localhost:5344
```

Copy `.env.example` to `.env` and set `ADMIN_PASSWORD` — it gates the creation of the *first* account only, so a fresh public deployment can't be claimed by a stranger.

**Run it as a desktop app, or deploy to a $5 VPS when you need it public:**

```bash
npm run desktop   # Electron window, local data dir, same code
# or
docker compose up -d
```

## Vaultly vs 1Password Teams

| | Vaultly | 1Password Teams |
|---|---|---|
| Price | **$39 once** | $7.99/user/**month** |
| 5-person team, 3 years | **$39** | ~$1,438 |
| Zero-knowledge encryption | ✅ | ✅ |
| Your data on your server | ✅ | ❌ |
| Shared vaults | ✅ | ✅ |
| TOTP codes | ✅ | ✅ |
| Audit log | ✅ | Business tier |
| Works offline / air-gapped | ✅ (desktop mode) | limited |
| Source code you can read | ✅ MIT | ❌ |

## Threat model (honest version)

- **Server compromise:** attacker gets ciphertext, scrypt-hashed auth keys, and public keys. Vault contents stay safe — decryption requires each user's master password.
- **Compromised client:** if the machine running your browser is compromised, nothing saves you. Same is true of every password manager.
- **Forgotten master password:** unrecoverable, by design. There is no reset. Export regularly and store the export safely (it's ciphertext too).
- **What the server CAN see:** email addresses, item counts/timestamps, vault names, audit metadata. Not names, URLs, usernames, passwords, or notes — those are inside the ciphertext.

## Tech stack

Node 20+ · Express · better-sqlite3 (ciphertext only) · React + Vite + Tailwind + Framer Motion + Lucide · Web Crypto API (PBKDF2, AES-256-GCM, RSA-OAEP) · Electron desktop wrapper.

## ☕ Skip the setup — get the 1-click installer

Want the packaged Windows installer with everything wired up? Grab it here: **[https://whop.com/benjisaiempire/vaultly-app](https://whop.com/benjisaiempire/vaultly-app)** — pay once, own it forever, no subscription.

## License

MIT © 2026 Ben (bensblueprints)

## macOS build

See [MAC-BUILD.md](MAC-BUILD.md). Quickest path: GitHub **Actions** tab -> run the **Mac Build** (`mac-build.yml`) workflow to get a downloadable `.dmg` (unsigned - right-click -> Open on first launch).
