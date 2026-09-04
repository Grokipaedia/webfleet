# WebFleet Scope

WebFleet covers site and domain **health monitoring**. It deliberately does
not cover registrar **write operations**. This line is intentional, not a
missing feature.

## The spectrum

| # | Question | Covered by |
|---|----------|-----------|
| 1 | Is the site up and is HTTPS real? | WebFleet |
| 2 | Will the cert or the name lapse? | WebFleet (SSL expiry + RDAP domain expiry) |
| 3 | What's rotting on the page / in WordPress? | WebFleet |
| 4 | What names do I own, at which registrar, at what renewal cost? | WebFleet (read-only, manually-entered/RDAP-filled) |
| 5 | Change DNS, locks, auto-renew, transfer — in bulk or via an agent | **Not WebFleet** — use [DomBot](https://dombot.ai) |

Items 1–4 are achievable at $0, with no registrar API keys, using GitHub
Actions and public RDAP. Item 5 requires per-registrar write credentials,
encrypted key storage, undo/audit, and a real threat model for
credential-holding automation — that's a different product with a different
risk profile, and DomBot already exists and does it well.

## Why the line is at write-ops, specifically

A GitHub Actions secret capable of a registrar transfer or renewal is a
**standing, unattended credential** with no per-run human confirmation step.
Every scheduled run would be able to act on it silently. That's a strictly
worse authorization posture than even a locally-approved MCP client — it has
no approval prompt, no visible "this is now armed" state, no revocation
step short of deleting the secret. WebFleet's GitHub Action is designed to
run unattended and open Issues; giving it money-moving registrar
credentials would put a highly consequential capability behind zero
runtime gate.

**Rule: WebFleet never holds a credential capable of changing what a domain
resolves to, who owns it, or whether it renews.** WordPress Application
Passwords (used for plugin-version checks) are the one exception, and even
those are read-only checks against a site you already control — not
registrar-level.

## What "item 4" actually looks like here

Read-only portfolio awareness, not a registrar sync:

- `sites.json` gains optional fields per site: `registrar`, `expires`,
  `auto_renew`, `renewal_usd`. Fill them by hand — no API calls, no keys.
- Where a field is left blank, RDAP fills what it can (already wired in
  from the V6.5 domain-expiry work). RDAP is public, free, and thin on some
  ccTLDs (`.hk` has none) — exactly like the existing SSL/WHOIS honesty
  pattern, a blank stays labeled **CHECK MANUALLY**, never guessed.
- No GoDaddy/Dynadot/Cloudflare API sync. Those keys are free to obtain but
  turn WebFleet into a second DomBot — a different maintenance burden and a
  different threat model, for a job DomBot already does for free.

## If someone wants item 5

Point them at DomBot (dombot.ai / github.com/aoxborrow/dombot). It's free,
open source (AGPL), and already solves registrar writes properly — OAuth
approval, encrypted credential storage, per-tool annotations. Two tools,
one job each, no bill either way.
