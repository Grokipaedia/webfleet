# WebFleet: one dashboard, no illusions

Most website-monitoring tools either cost money you don't need to spend for
a handful of sites, or they quietly overstate what they're actually
checking. WebFleet is a small, free, fork-it-yourself alternative built
around a different rule: never claim to check something it can't actually
check.

**What it does:**
- Real HTTP status and SSL certificate checks (expiry, issuer, hostname
  mismatch, self-signed/untrusted-issuer detection) — run server-side via a
  scheduled GitHub Action, not faked from a browser.
- Domain expiry via live RDAP lookups, with registry gaps reported
  honestly instead of hidden.
- WordPress core-version and plugin-update detection, using either public
  signals or your own Application Password.
- A prioritized "what needs my attention" view, with confirmed problems
  separated from ones that are probably just a bot-protection false
  positive — so it doesn't cry wolf.
- Automatic GitHub Issues for anything that's actually wrong. Zero extra
  infrastructure: it's a static GitHub Pages frontend plus a GitHub Action,
  nothing to host or pay for.

**What it deliberately doesn't do:** a full-site crawl, email/SMS alerts,
or anything requiring a paid backend. It checks your homepage, not your
whole sitemap — that boundary is intentional, not a missing feature.

It was built and hardened against a real 7-site personal portfolio,
including catching a genuine SSL hostname mismatch on a live production
site during its very first real scan.

Repo: github.com/Grokipaedia/webfleet — fork it, drop in your own
`sites.json`, and it starts scanning on your existing GitHub Action
schedule with zero paid infrastructure.
