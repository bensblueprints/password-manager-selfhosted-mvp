# Product Hunt — Vaultly

**Name:** Vaultly

**Tagline (60 chars):** Zero-knowledge team password manager. Pay once, own it.

**Description (260 chars):**
Vaultly is a self-hosted, zero-knowledge password manager for teams. AES-256 encryption happens in your browser — your server only ever stores ciphertext. Shared vaults, TOTP, audit log, breach checks. $39 once instead of $7.99/user/month forever.

**Full description:**
Password managers are a subscription for math you can run on a $5 VPS.

Vaultly gives you the same zero-knowledge architecture the big names use — PBKDF2 key derivation, AES-256-GCM item encryption, RSA-wrapped shared vault keys — but on your own server, with source you can read, for a one-time price.

- Client-side encryption: the master password and encryption keys never leave the browser
- Shared team vaults with per-member public-key key wrapping
- Logins, secure notes, cards, folders, generator, strength meter
- Inline TOTP codes with auto-clearing clipboard
- Opt-in HaveIBeenPwned breach check (k-anonymity)
- Full audit log + admin invites/revocation + encrypted org export
- Run it as a desktop app or deploy with Docker

**Maker first comment:**
Hey PH 👋 I got tired of paying per-seat, per-month for password managers when the actual product — the crypto — is a solved problem that runs fine on hardware I already own. So I built Vaultly: Bitwarden-style zero knowledge (I literally cannot read your vault even if you host with me — but you don't, you host it yourself), shared vaults for the team, TOTP built in, and an audit log so I know who touched the AWS root creds. It's $39 once. The 5-person-team math vs 1Password Teams is about $1,400 saved over 3 years. Source is MIT on GitHub — audit the crypto yourself, that's the whole point. Honest caveat: if you forget your master password, it's gone. That's what zero-knowledge means. AMA!

**Gallery shots (5):**
1. Dark vault dashboard — grouped items, search bar, live TOTP chip on a login row.
2. Item editor with password generator, strength meter, and "seen 3,412× in breaches" warning.
3. Share modal — "The vault key is re-encrypted in your browser with their public key."
4. Admin panel — team list, open invite tokens, scrolling audit log.
5. Comparison graphic: "$39 once vs $1,438 for 5 seats × 3 years of 1Password Teams."
