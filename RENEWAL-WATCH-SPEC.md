# WebFleet: Renewal Watch + Staleness Fix — Implementation Spec

Concrete enough to hand directly to a coding session against the real
`scan.py` / `index.html`. No code included here since the actual current
source isn't in hand — this is the spec to implement against it.

## 1. Domain-expiry-days next to cert-days-left (cheapest win)

RDAP lookups are already wired in (V6.5). Change: surface the number
that's already being fetched.

- In the per-site result object, alongside the existing SSL
  `days_until_expiry`, add `domain_days_until_expiry` (already computed via
  RDAP, just not currently surfaced in the attention view).
- On the dashboard "What Needs My Attention" panel, show both numbers
  side by side per site: `SSL: 47d · Domain: 312d`.
- Apply the existing severity-ranking logic to whichever of the two is
  sooner — a domain expiring in 10 days should outrank a cert expiring in
  90, even though today's ranking likely only looks at cert data.
- Where RDAP returned nothing (e.g. `.hk`), show `Domain: CHECK MANUALLY`
  in the same style already used for WAF-blocked sites — don't blank it
  and don't guess.

## 2. Schedule-aware stale-scan banner

Don't hardcode 8 hours. Derive the threshold from the Action's own cron
schedule so the banner doesn't fire between normal runs.

- Read the cron expression from `.github/workflows/scan.yml` at build/run
  time (or maintain a single `SCAN_INTERVAL_HOURS` constant that's the
  source of truth for both the cron schedule and the staleness check, so
  they can't drift apart).
- Staleness threshold = `SCAN_INTERVAL_HOURS + buffer` (suggest buffer =
  50% of the interval, minimum 2 hours) — e.g. daily scans → banner at
  ~36h quiet, not 8h.
- Banner text should state the threshold it's using, not just "stale" —
  e.g. "No scan in 40 hours (expected every 24h)."

## 3. Hide the fake V1 demo-data grid

- Locate the toggle/flag that switches `index.html` between demo data and
  real `results.json` data (referenced in commit history as "Implement
  demo data toggle functionality").
- Default it off for the deployed Pages site; keep it available as a
  local dev/demo flag only, clearly labeled, not reachable from the public
  dashboard's normal UI.

## 4. Optional portfolio fields in `sites.json`

Add four optional per-site fields. All default to absent/null — no
migration needed for existing configs.

```json
{
  "domain": "example.com",
  "registrar": "Dynadot",
  "expires": null,
  "auto_renew": null,
  "renewal_usd": null
}
```

- `expires`, when null, is filled from the existing RDAP lookup where
  available; when RDAP has no data for that TLD, leave null and label
  `CHECK MANUALLY` in the UI — same as item 1 above, so this doesn't
  introduce a second inconsistent labeling convention.
- `registrar`, `auto_renew`, `renewal_usd` are manual-entry only — no API
  calls, no registrar credentials. Purely for the Renewal Watch view below.
- Update `sites.example.json` to show the new fields with a comment
  (JSON has none natively — use a `"_comment"` key or document in
  SETUP.md) so forkers know they're optional.

## 5. "Renewal Watch" dashboard section

- New section, separate from the existing "What Needs My Attention"
  operational-health panel — this one is portfolio-planning, not incident
  response.
- List sites where computed/entered `expires` falls within 60 days,
  sorted soonest-first.
- Flag entries with `auto_renew: false` (or unset) first within that list
  — those are the ones that actually need a decision, not just awareness.
- Show `renewal_usd` next to each if present; omit the field entirely if
  absent rather than showing `$0` or `unknown`.

## Explicitly out of scope for this pass

No registrar API calls, no new GitHub Secrets beyond the existing
WordPress Application Passwords, no write operations of any kind. See
`SCOPE.md` for why that line is fixed.
