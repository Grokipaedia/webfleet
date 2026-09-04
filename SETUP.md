# WebFleet Setup Guide

This guide covers configuring WebFleet for your own website portfolio after
forking. It goes beyond the quick-install steps in the README into what
you'll actually need to get real scanning working.

## 1. Fork and enable Actions

1. Fork this repository.
2. Go to **Settings → Actions → General** and make sure Actions are enabled
   for your fork (GitHub disables them by default on forks).
3. Go to **Settings → Pages** and enable Pages (Deploy from branch → `main`
   → `/root`) so the dashboard is viewable.

## 2. Configure your sites

Copy `sites.example.json` to `sites.json` and list your own domains.
`sites.json` is the file the scan actually reads — `sites.example.json` is
just a template so the real config isn't required to be public in a fork's
history.

Two tiers of sites:

- **Public checks only** (HTTP status, SSL, domain expiry, homepage
  broken-link check): just list the domain. No credentials needed.
- **Authenticated WordPress checks** (core version, plugin updates): the
  site needs a WordPress Application Password, added as a GitHub Secret
  (see below) and referenced by name in `sites.json`.

## 3. WordPress Application Passwords (for authenticated sites)

For any WordPress site you want plugin-update checks on:

1. In that site's WordPress admin: **Users → Profile → Application
   Passwords**. Generate one scoped to a dedicated low-privilege user if
   possible, not your main admin account.
2. In your fork's **Settings → Secrets and variables → Actions**, add a new
   repository secret. Pick a short name (e.g. the pattern used in the
   original deployment: `IBOUND`, `AIPAY`, `CMG` — one per site).
3. Reference that secret name against the site's entry in `sites.json`.
4. Never print or log the secret value anywhere in `scan.py` — GitHub
   automatically redacts known secret values in Action logs, but don't rely
   on that as your only safeguard.

Sites without a configured secret simply get public-only checks — the scan
degrades gracefully rather than failing.

## 4. What each check can and can't tell you

Being upfront about this matters more than it sounds:

- **HTTP status / SSL**: real, server-side, accurate. No browser CORS
  limitation applies here since the check runs inside the GitHub Action,
  not a static page.
- **A 401/403/406/429 response** is flagged **CHECK MANUALLY**, not
  treated as downtime. These codes are frequently a WAF or bot-protection
  layer blocking the *scanner specifically*, not evidence the site is
  actually down. Alerting on these directly recreates false-alarm noise —
  deliberately avoided.
- **Domain expiry (RDAP)**: depends entirely on the registry. Some
  ccTLD registries (e.g. `.hk`) currently have no public RDAP endpoint at
  all — WebFleet reports this as a real gap, not a false "unknown" or a
  silent skip.
- **Broken-link check**: homepage-only by design, not a full site crawl.
  This is a deliberate scope boundary, not a limitation to work around.
- **WordPress detection**: uses the public generator meta tag plus
  WordPress.org's version-check API. A site can be WordPress but fail
  detection if the request itself fails (timeout, block) — this is
  distinguished from "confirmed not WordPress" rather than conflated with
  it.

## 5. Reading the Job Summary

Every Action run writes a markdown summary (visible on the run's page in
the **Actions** tab) showing which configured WordPress sites are missing
credentials, and whether alerting and RDAP checks ran successfully. Check
this first if a scan looks incomplete — it's the fastest way to see a
misconfiguration versus a real check failure.

## 6. Alerts

WebFleet opens/updates/closes GitHub Issues automatically using the
Action's own built-in `GITHUB_TOKEN` — no additional secret needed for
alerting itself. An Issue opening for your own site the first time you run
a scan is expected behavior if that site has a real, pre-existing problem
(this is exactly what happened during initial testing — the first real
scan correctly caught a genuine SSL certificate mismatch).

## 7. Making this a template for others

If you want *your* fork to be forkable in turn: repository **Settings →
General → Template repository** checkbox. This can only be toggled by a
repo admin in the GitHub UI — it isn't something a workflow or script can
set.
