# Launch strategy — Vaultly

## Target communities

- **r/selfhosted** — perfect fit. Post as "I built a zero-knowledge password manager you can self-host — MIT source" with an honest threat-model section. Lead with the architecture, not the price. Self-promo is tolerated when the repo is genuinely open.
- **r/sysadmin** — angle: per-seat password manager pricing at team scale + audit log requirement. Answer questions, don't hard-sell (rule: no naked product drops; frame as show-and-tell with lessons learned).
- **r/Bitwarden** — CAREFUL: informational only. Participate in "self-hosting alternatives" threads; never post competitive spam. Mention Vaultly only when someone asks for lighter-weight options.
- **r/privacy** — the "your data on your server, source you can read" angle. No pricing talk in the post body.
- **Hacker News** — see Show HN below.

## Show HN draft

**Title:** Show HN: Vaultly – self-hosted, zero-knowledge team password manager (one-time $39)

**Body:**
I got tired of per-seat/month pricing for password managers, so I built one on the Bitwarden model: PBKDF2 (600k) → AES-256-GCM in the browser via Web Crypto; the server stores only ciphertext. Shared vaults work by wrapping the vault key with each member's RSA-OAEP public key client-side.

Stack is deliberately boring: Node/Express + SQLite + React. Runs as an Electron desktop app or in Docker on any $5 VPS.

Honest limitations: no browser extension yet (copy-paste/bookmarklet), a compromised client is still game over (true everywhere), and a forgotten master password is unrecoverable by design.

Source is MIT — the crypto is ~150 lines and I'd genuinely appreciate hostile review of it.

## SEO keywords (10)

1. self hosted password manager
2. bitwarden alternative self hosted
3. 1password alternative team
4. zero knowledge vault self hosted
5. open source password manager team
6. password manager one time purchase
7. password manager no subscription
8. self hosted password manager docker
9. team password vault audit log
10. password manager own server

## AppSumo / PitchGround pitch

Vaultly is a zero-knowledge, self-hosted team password manager — the same client-side AES-256 architecture as 1Password and Bitwarden, but deployed on the buyer's own infrastructure with MIT-licensed source. Teams get shared vaults with public-key key exchange, inline TOTP, breach checking, and a full audit log. It ships as a Docker deployment and a Windows desktop app. Your audience already hates renting software; password managers are the most-rented software there is. A lifetime deal here is a genuinely honest promise, because there is no server bill on our side — buyers host it themselves.

## Pricing math

**$39 one-time.** 1Password Teams is $7.99/user/mo → a 5-person team pays $39.95/month. **Vaultly pays for itself in under one month** for a 5-seat team, and in 5 months even for a solo user vs 1Password Individual ($2.99+/mo × ... ). Three-year cost for 5 seats: Vaultly $39 vs ~$1,438.
