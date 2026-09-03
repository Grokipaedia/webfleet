#!/usr/bin/env python3
"""
scan.py — WebFleet V3 real scanning engine.

Runs server-side (in a GitHub Action, not a browser), so none of V2's
CORS restrictions apply here: this can read the real HTTP status code,
measure real response time, and open a real TLS connection to read the
actual certificate's expiry and issuer. Writes results to results.json,
which the static index.html reads same-origin (no CORS issue at all,
since it's served from the same site).

Scope, honestly: the "broken link" check here looks only at links found
on the homepage itself, not a full site crawl. That's a real, bounded
check, not a stand-in for one — see README for why a full crawl is a
deliberately separate, larger feature, not something silently skipped.
"""

import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from html.parser import HTMLParser

# A real browser User-Agent, applied consistently to every outbound request
# this scanner makes. Not an attempt to disguise what this is — it's a
# choice about what the scanner is actually trying to measure. The point
# of an uptime/SSL monitor is "can a real visitor load this page," and a
# generic library User-Agent (e.g. "python-requests/2.x") gets blocked by
# ordinary WAF/bot-protection rules on many sites regardless of whether
# the site is actually healthy — which would make the scanner report a
# false "down" for a site that's fine for every real visitor. These are
# the domain owner's own sites, being checked from their own monitoring
# tool; this isn't evading a third party's security posture.
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}


class LinkExtractor(HTMLParser):
    """Pulls href values out of <a> tags on the fetched page only."""
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


def check_http(domain: str) -> dict:
    """Real HTTP status and response time — not the opaque V2 approximation."""
    url = f"https://{domain}/"
    try:
        start = time.time()
        resp = requests.get(url, timeout=10, allow_redirects=True, headers=REQUEST_HEADERS)
        elapsed_ms = round((time.time() - start) * 1000)
        return {
            "ok": resp.status_code < 400,
            "status_code": resp.status_code,
            "response_time_ms": elapsed_ms,
            "final_url": resp.url,
            "html": resp.text if resp.status_code < 400 else None,
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        return {
            "ok": False,
            "status_code": None,
            "response_time_ms": None,
            "final_url": None,
            "html": None,
            "error": str(e),
        }


def check_ssl(domain: str) -> dict:
    """Real TLS handshake, real certificate — not available from a browser
    at all for a cross-origin request. This is exactly the gap V2 could
    not close.

    Categorizes failures by OpenSSL's own verify_code rather than string-
    matching the message text — verify_code is a stable, documented
    numeric code (X509_V_ERR_*) that doesn't depend on message phrasing.
    Verified directly against real handshakes built for this purpose:
    a genuine hostname mismatch reliably produces verify_code 62, a
    genuinely expired certificate reliably produces verify_code 10.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        expires_str = cert.get("notAfter")
        expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expires - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "ok": True,
            "issue_type": None,
            "expires": expires.isoformat(),
            "days_remaining": days_remaining,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
            "error": None,
        }
    except ssl.SSLCertVerificationError as e:
        # Verified OpenSSL verify_code values (X509_V_ERR_* constants):
        code_map = {
            62: "hostname_mismatch",     # cert is valid, but not for this hostname
            10: "expired",               # cert's own validity window has passed
            9: "not_yet_valid",          # cert's validity window hasn't started
            18: "self_signed",           # self-signed, not from a trusted CA
            19: "self_signed",           # self-signed cert found in the chain
            20: "untrusted_issuer",      # can't get the issuer certificate
            21: "untrusted_issuer",      # unable to verify the leaf certificate
        }
        issue_type = code_map.get(e.verify_code, "other_verification_failure")
        return {
            "ok": False,
            "issue_type": issue_type,
            "expires": None,
            "days_remaining": None,
            "issuer": None,
            "error": e.verify_message or str(e),
        }
    except Exception as e:
        # Not a certificate verification failure at all — connection
        # refused, DNS failure, timeout, etc. Genuinely a different class
        # of problem from anything above.
        return {"ok": False, "issue_type": "connection_failed", "expires": None, "days_remaining": None, "issuer": None, "error": str(e)}


def check_links(domain: str, html: str, max_links: int = 15) -> dict:
    """Checks links found on the homepage only — a real, bounded check,
    not a full site crawl. See module docstring."""
    if not html:
        return {"checked": 0, "broken": [], "error": "no HTML to scan (homepage request failed)"}

    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception as e:
        return {"checked": 0, "broken": [], "error": f"could not parse homepage HTML: {e}"}

    base_url = f"https://{domain}/"
    seen = set()
    to_check = []
    for href in parser.links:
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if full in seen:
            continue
        seen.add(full)
        to_check.append(full)
        if len(to_check) >= max_links:
            break

    broken = []
    for link in to_check:
        try:
            r = requests.head(link, timeout=6, allow_redirects=True, headers=REQUEST_HEADERS)
            if r.status_code >= 400:
                # Some servers reject HEAD; confirm with a real GET before flagging.
                r = requests.get(link, timeout=6, allow_redirects=True, headers=REQUEST_HEADERS)
            if r.status_code >= 400:
                broken.append({"url": link, "status_code": r.status_code})
        except requests.exceptions.RequestException as e:
            broken.append({"url": link, "status_code": None, "error": str(e)})

    return {"checked": len(to_check), "broken": broken, "error": None}


def parse_version_tuple(version_str: str):
    """Correct numeric version comparison — string comparison alone is
    wrong here ('6.9' > '6.10' as strings, since '9' > '1', even though
    6.10 is the later release). Non-numeric parts are dropped rather than
    raising, since WordPress version strings are consistently dotted
    integers in practice."""
    parts = []
    for p in version_str.split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def detect_wordpress_version(html: str):
    """Looks for the standard <meta name="generator" content="WordPress
    X.Y.Z"> tag WordPress core outputs by default. Does not guess from
    weaker signals (wp-content paths, etc.) — if this exact tag isn't
    present (common when a security plugin or theme removes it), this
    correctly reports 'not detected' rather than a false positive."""
    if not html:
        return None
    match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
        html, re.IGNORECASE,
    )
    return match.group(1) if match else None


def get_latest_wordpress_version():
    """Real lookup against WordPress.org's own public version-check API.
    Schema verified against WordPress core's own wp_version_check()
    source and independent real-world usage: {"offers": [{"current":
    "X.Y.Z", ...}]}. Wrapped defensively — this API has had reported
    reliability issues historically, and a slow/failed lookup here should
    degrade to 'couldn't determine latest version', not break the scan."""
    try:
        resp = requests.get(
            "https://api.wordpress.org/core/version-check/1.7/",
            timeout=8, headers=REQUEST_HEADERS,
        )
        if not resp.ok:
            return None
        data = resp.json()
        offers = data.get("offers")
        if not offers or "current" not in offers[0]:
            return None
        return offers[0]["current"]
    except (requests.exceptions.RequestException, ValueError, KeyError, IndexError):
        return None


def get_wp_credentials(secret_key: str):
    """Reads Application Password credentials from environment variables
    (set as GitHub Secrets in the Action, never committed anywhere). The
    username secret is named exactly the site's short key (e.g. "CMG");
    the password secret is named "WP_APP_PASSWORD_{key}". Returns None
    if either is missing — a site simply not configured for authenticated
    checks is a normal, expected state, not an error."""
    username = os.environ.get(secret_key)
    password = os.environ.get(f"WP_APP_PASSWORD_{secret_key}")
    if not username or not password:
        return None
    return (username, password)


def get_wp_org_plugin_latest_version(slug: str):
    """Cross-references a plugin's slug against WordPress.org's public
    plugin directory — same API family already verified for WP core
    itself. Only works for plugins actually listed on wordpress.org;
    premium/custom/privately-distributed plugins will not be found there,
    which is reported honestly as 'not on directory', not a false
    negative. Coded defensively: there is an open, unresolved WordPress
    Trac ticket (#8124, filed weeks before this was written) specifically
    complaining that this API's fields are undocumented and change
    without notice — nothing here assumes a field exists without
    checking, and any unexpected shape degrades to 'unknown' rather than
    raising.
    """
    try:
        resp = requests.get(
            "https://api.wordpress.org/plugins/info/1.2/",
            params={"action": "plugin_information", "slug": slug},
            timeout=8, headers=REQUEST_HEADERS,
        )
        if not resp.ok:
            return None
        data = resp.json()
        # A slug not on the directory returns JSON `false`, not an error
        # status — must check the shape, not just the HTTP result.
        if not isinstance(data, dict):
            return None
        version = data.get("version")
        return version if isinstance(version, str) and version else None
    except (requests.exceptions.RequestException, ValueError):
        return None


def check_wp_plugin_updates(domain: str, secret_key: str) -> dict:
    """Authenticated, read-only. Lists installed plugins via the site's
    own REST API (Application Password auth), then cross-references each
    against WordPress.org's public directory for a real latest-version
    comparison where possible. Never installs, activates, or modifies
    anything — this is a read operation only, same restraint as every
    other check in this file."""
    creds = get_wp_credentials(secret_key)
    if creds is None:
        return {"checked": False, "reason": "no credentials configured for this site", "plugins": []}

    try:
        resp = requests.get(
            f"https://{domain}/wp-json/wp/v2/plugins",
            auth=creds, timeout=15, headers=REQUEST_HEADERS,
        )
    except requests.exceptions.RequestException as e:
        return {"checked": False, "reason": f"request failed: {e}", "plugins": []}

    if resp.status_code == 401:
        return {"checked": False, "reason": "authentication failed — check the stored username/password", "plugins": []}
    if not resp.ok:
        return {"checked": False, "reason": f"unexpected HTTP {resp.status_code}", "plugins": []}

    try:
        raw_plugins = resp.json()
    except ValueError:
        return {"checked": False, "reason": "response was not valid JSON", "plugins": []}
    if not isinstance(raw_plugins, list):
        return {"checked": False, "reason": "unexpected response shape", "plugins": []}

    results = []
    for p in raw_plugins:
        if not isinstance(p, dict):
            continue
        plugin_file = p.get("plugin", "")
        slug = plugin_file.split("/")[0] if plugin_file else None
        installed_version = p.get("version")
        name = p.get("name", slug or "unknown plugin")
        status = p.get("status", "unknown")

        entry = {"name": name, "slug": slug, "version": installed_version, "status": status, "latest": None, "is_outdated": None}

        if slug and installed_version:
            latest = get_wp_org_plugin_latest_version(slug)
            if latest:
                entry["latest"] = latest
                entry["is_outdated"] = parse_version_tuple(installed_version) < parse_version_tuple(latest)
        results.append(entry)

    return {"checked": True, "reason": None, "plugins": results}


_RDAP_BOOTSTRAP_CACHE = None


def get_rdap_bootstrap():
    """The real, official IANA registry mapping each TLD to its
    authoritative RDAP server (RFC 9224). Fetched once per scan run and
    cached in memory — querying this per-domain would be wasteful and
    impolite to IANA's server. Confirmed directly against the live file
    before writing this: coverage is real but incomplete — .ke has a
    registered RDAP server (rdap.kenic.or.ke), .hk currently has none at
    all. That's an actual gap in the .hk registry's own deployment, not a
    bug here, and is reported honestly as 'not available' rather than
    guessed or silently skipped."""
    global _RDAP_BOOTSTRAP_CACHE
    if _RDAP_BOOTSTRAP_CACHE is not None:
        return _RDAP_BOOTSTRAP_CACHE
    try:
        resp = requests.get("https://data.iana.org/rdap/dns.json", timeout=10, headers=REQUEST_HEADERS)
        if not resp.ok:
            _RDAP_BOOTSTRAP_CACHE = {}
            return _RDAP_BOOTSTRAP_CACHE
        data = resp.json()
        lookup = {}
        for entry in data.get("services", []):
            if not isinstance(entry, list) or len(entry) != 2:
                continue
            tlds, urls = entry
            if not urls:
                continue
            for tld in tlds:
                lookup[tld.lower()] = urls[0]
        _RDAP_BOOTSTRAP_CACHE = lookup
    except (requests.exceptions.RequestException, ValueError):
        _RDAP_BOOTSTRAP_CACHE = {}
    return _RDAP_BOOTSTRAP_CACHE


def check_domain_expiry(domain: str) -> dict:
    """Real domain REGISTRATION expiry — a different, and for a domain
    portfolio arguably more important, risk than SSL certificate expiry.
    Losing a domain to non-renewal is permanent; a lapsed certificate is
    a same-day fix. Schema verified against multiple independently
    converging real sources (an RFC draft, a worked example from
    afnic.fr, and a live curl+jq query against rdap.verisign.com) before
    writing this: {"events": [{"eventAction": "expiration", "eventDate":
    "..."}]}."""
    tld = domain.rsplit(".", 1)[-1].lower()
    bootstrap = get_rdap_bootstrap()
    base_url = bootstrap.get(tld)
    if not base_url:
        return {"checked": False, "reason": f"no RDAP server registered for .{tld}", "expires": None, "days_remaining": None}

    try:
        url = base_url.rstrip("/") + f"/domain/{domain}"
        resp = requests.get(url, timeout=10, headers=REQUEST_HEADERS)
        if not resp.ok:
            return {"checked": False, "reason": f"RDAP query failed (HTTP {resp.status_code})", "expires": None, "days_remaining": None}
        data = resp.json()
        events = data.get("events", [])
        if not isinstance(events, list):
            return {"checked": False, "reason": "unexpected RDAP response shape", "expires": None, "days_remaining": None}
        expiry_event = next((e for e in events if isinstance(e, dict) and e.get("eventAction") == "expiration"), None)
        if not expiry_event or "eventDate" not in expiry_event:
            return {"checked": False, "reason": "no expiration event in RDAP response", "expires": None, "days_remaining": None}
        expires = datetime.fromisoformat(expiry_event["eventDate"].replace("Z", "+00:00"))
        days_remaining = (expires - datetime.now(timezone.utc)).days
        return {"checked": True, "reason": None, "expires": expires.isoformat(), "days_remaining": days_remaining}
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        return {"checked": False, "reason": f"RDAP query error: {e}", "expires": None, "days_remaining": None}


def check_wordpress(html: str, http_ok: bool) -> dict:
    """No credentials, no login — just what a site already exposes
    publicly. Can only detect the core version, not plugins/themes/
    backups; that genuinely needs authenticated access, a deliberately
    separate and larger decision from this.

    Distinguishes two genuinely different situations that used to look
    identical: HTML was fetched and genuinely has no WordPress signature
    (a real, meaningful "not detected"), versus the HTTP request itself
    failed — most commonly a WAF blocking the scanner with a 403 — so no
    generator-tag search was ever actually possible. Confirmed as a real
    gap, not theoretical: a site returning 403 to this scanner reported
    "not detected" even though it genuinely runs WordPress, because the
    homepage HTML was never retrieved to search in the first place.
    """
    if not http_ok:
        return {
            "detected": False, "version": None, "latest": None, "is_outdated": None,
            "error": "could not check — the homepage request itself failed, so no page content was available to search",
        }

    version = detect_wordpress_version(html)
    if version is None:
        return {"detected": False, "version": None, "latest": None, "is_outdated": None, "error": None}

    latest = get_latest_wordpress_version()
    if latest is None:
        return {"detected": True, "version": version, "latest": None, "is_outdated": None, "error": "could not reach WordPress.org to compare"}

    is_outdated = parse_version_tuple(version) < parse_version_tuple(latest)
    return {"detected": True, "version": version, "latest": latest, "is_outdated": is_outdated, "error": None}


def overall_status(http_result: dict, ssl_result: dict, link_result: dict, wp_result: dict = None, domain_result: dict = None) -> str:
    if not http_result["ok"]:
        return "bad"
    if ssl_result["ok"] is False:
        return "bad"
    if domain_result and domain_result.get("checked") and domain_result.get("days_remaining") is not None:
        # Losing a domain to non-renewal is permanent — a lapsed SSL cert
        # is a same-day fix. Given that higher stakes, this uses a wider
        # warning window (30 days) than SSL's 14, and escalates to "bad"
        # inside 7 days, when real loss becomes a near-term possibility.
        if domain_result["days_remaining"] < 7:
            return "bad"
        if domain_result["days_remaining"] < 30:
            return "warn"
    if ssl_result["ok"] and ssl_result["days_remaining"] is not None and ssl_result["days_remaining"] < 14:
        return "warn"
    if link_result["broken"]:
        return "warn"
    if wp_result and wp_result.get("is_outdated"):
        return "warn"
    return "ok"


def scan_domain(domain: str, wp_secret_key: str = None) -> dict:
    http_result = check_http(domain)
    ssl_result = check_ssl(domain)
    link_result = check_links(domain, http_result.get("html"))
    wp_result = check_wordpress(http_result.get("html"), http_result["ok"])
    domain_result = check_domain_expiry(domain)

    result = {
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall_status(http_result, ssl_result, link_result, wp_result, domain_result),
        "http": {k: v for k, v in http_result.items() if k != "html"},
        "ssl": ssl_result,
        "domain_expiry": domain_result,
        "links": {"checked": link_result["checked"], "broken_count": len(link_result["broken"]), "broken": link_result["broken"][:5], "error": link_result["error"]},
        "wordpress": wp_result,
    }

    # Authenticated plugin check — only attempted if this site has a
    # secret_key configured in sites.json. Never affects overall_status
    # by itself yet — that's a deliberate choice: a site could be
    # perfectly fine with outdated plugins the owner already knows about,
    # and this is genuinely newer/less proven than the public checks.
    if wp_secret_key:
        result["wordpress_plugins"] = check_wp_plugin_updates(domain, wp_secret_key)

    return result


def get_critical_alerts(site_result: dict) -> list:
    """Mirrors the dashboard's own CONFIRMED-vs-uncertain distinction —
    deliberately excludes 401/403/406/429 (the classic WAF-blocking-the-
    scanner signature) so this alerting doesn't recreate the exact false-
    alarm noise problem the whole confidence-tagging system exists to
    avoid. Only qualifies: SSL failures, total connection failure, 5xx,
    and 404 — the same 'a real visitor would hit this too' bar used
    everywhere else in this project."""
    alerts = []
    domain = site_result["domain"]
    ssl_r = site_result["ssl"]
    http_r = site_result["http"]

    if not ssl_r["ok"] and ssl_r.get("issue_type"):
        headlines = {
            "hostname_mismatch": "certificate doesn't cover this domain",
            "expired": "certificate has expired",
            "not_yet_valid": "certificate isn't valid yet",
            "self_signed": "certificate is self-signed",
            "untrusted_issuer": "certificate chain doesn't verify",
            "connection_failed": "could not establish a secure connection",
        }
        alerts.append(f"{domain}: {headlines.get(ssl_r['issue_type'], 'certificate failed verification')}")

    # If SSL already failed and HTTP got no status code at all, that's
    # not a second, independent problem — same TLS failure preventing
    # the HTTP request from completing. Mirrors the identical fix already
    # applied to the frontend's issue generation for the same reason.
    http_failure_is_ssl_consequence = (not ssl_r["ok"]) and (not http_r["ok"]) and http_r.get("status_code") is None

    if not http_r["ok"] and not http_failure_is_ssl_consequence:
        code = http_r.get("status_code")
        if code is None:
            alerts.append(f"{domain}: site did not respond at all")
        elif code >= 500:
            alerts.append(f"{domain}: server error (HTTP {code})")
        elif code == 404:
            alerts.append(f"{domain}: homepage not found (404)")
        # Deliberately no alert for 401/403/406/429 — see docstring above.

    return alerts


def sync_github_alert_issue(all_alerts: list):
    """Creates, updates, or closes a single tracking issue via GitHub's
    own REST API — using the Action's built-in GITHUB_TOKEN, no new
    secret needed. Real endpoints and auth format confirmed against
    GitHub's own documentation. Defended against a real, reported API
    quirk: a GitHub community thread found that filtering issues by
    label via the query parameter doesn't always return ONLY matching
    issues — so results are re-checked client-side (label AND title
    prefix) rather than trusted blindly."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # "owner/repo", auto-set by Actions
    if not token or not repo:
        print("GITHUB_TOKEN/GITHUB_REPOSITORY not available — skipping alert sync (expected outside a GitHub Action)")
        return

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    base = f"https://api.github.com/repos/{repo}"
    ALERT_LABEL = "webfleet-alert"
    TITLE_PREFIX = "WebFleet: "

    try:
        resp = requests.get(f"{base}/issues", headers=headers, params={"labels": ALERT_LABEL, "state": "open"}, timeout=15)
        resp.raise_for_status()
        candidates = resp.json()
    except requests.exceptions.RequestException as e:
        print(f"Could not check existing alert issues: {e}")
        return

    existing = [
        i for i in candidates
        if isinstance(i, dict)
        and any(isinstance(l, dict) and l.get("name") == ALERT_LABEL for l in i.get("labels", []))
        and i.get("title", "").startswith(TITLE_PREFIX)
    ]

    now = datetime.now(timezone.utc).isoformat()

    if all_alerts:
        body = f"**{len(all_alerts)} confirmed critical issue(s)** as of {now}:\n\n" + "\n".join(f"- {a}" for a in all_alerts)
        title = f"{TITLE_PREFIX}{len(all_alerts)} confirmed critical issue(s)"
        if existing:
            issue_number = existing[0]["number"]
            try:
                requests.patch(f"{base}/issues/{issue_number}", headers=headers, json={"title": title, "body": body}, timeout=15)
                print(f"Updated existing alert issue #{issue_number}")
            except requests.exceptions.RequestException as e:
                print(f"Could not update alert issue: {e}")
        else:
            try:
                r = requests.post(f"{base}/issues", headers=headers, json={"title": title, "body": body, "labels": [ALERT_LABEL]}, timeout=15)
                r.raise_for_status()
                print(f"Created new alert issue #{r.json().get('number')}")
            except requests.exceptions.RequestException as e:
                print(f"Could not create alert issue: {e}")
    else:
        for issue in existing:
            try:
                requests.patch(
                    f"{base}/issues/{issue['number']}", headers=headers,
                    json={"state": "closed", "body": f"Resolved as of {now} — no confirmed critical issues in the latest scan."},
                    timeout=15,
                )
                print(f"Closed resolved alert issue #{issue['number']}")
            except requests.exceptions.RequestException as e:
                print(f"Could not close alert issue: {e}")


def write_job_summary(entries, results):
    """Writes a real GitHub Actions Job Summary — directly targets the
    exact failure mode that caused hours of silent debugging earlier
    tonight: a misconfigured site (missing secret, workflow file in the
    wrong path, etc.) produced no visible signal anywhere except digging
    through raw logs. This surfaces configuration problems on the run's
    summary page immediately. Confirmed real, documented GitHub behavior
    before using it — no-ops silently if GITHUB_STEP_SUMMARY isn't set
    (e.g. running locally), the same pattern real GitHub tooling uses."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = ["## WebFleet Scan Summary", "", f"**Sites scanned:** {len(results)}", ""]

    lines.append("### Results")
    lines.append("| Domain | Status |")
    lines.append("|---|---|")
    status_emoji = {"ok": "🟢 OK", "warn": "🟡 WARN", "bad": "🔴 BAD"}
    for r in results:
        lines.append(f"| {r['domain']} | {status_emoji.get(r['overall'], r['overall'])} |")
    lines.append("")

    # WordPress credential configuration check — the exact class of
    # problem that silently failed differently for different sites
    # earlier tonight.
    wp_sites = [e for e in entries if isinstance(e, dict) and e.get("wp_secret_key")]
    if wp_sites:
        lines.append("### WordPress plugin-check configuration")
        lines.append("| Site | Secret key | Credentials found |")
        lines.append("|---|---|---|")
        for e in wp_sites:
            key = e["wp_secret_key"]
            found = bool(os.environ.get(key)) and bool(os.environ.get(f"WP_APP_PASSWORD_{key}"))
            status = "✅ found" if found else "❌ missing — plugin checks skipped for this site"
            lines.append(f"| {e.get('domain')} | `{key}` | {status} |")
        lines.append("")

    lines.append("### Environment")
    token_ok = bool(os.environ.get("GITHUB_TOKEN"))
    lines.append(f"- `GITHUB_TOKEN` available (enables auto-alerting): {'✅' if token_ok else '❌ — critical findings will not open an Issue this run'}")
    bootstrap = get_rdap_bootstrap()
    bootstrap_line = f"✅ ({len(bootstrap)} TLDs covered)" if bootstrap else "❌ — domain expiry checks unavailable this run"
    lines.append(f"- RDAP bootstrap loaded: {bootstrap_line}")

    try:
        with open(summary_path, "a") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        print(f"Could not write job summary: {e}", file=sys.stderr)


def main():
    try:
        with open("sites.json") as f:
            entries = json.load(f)
    except FileNotFoundError:
        print("sites.json not found — create it with a JSON array of domains, e.g. [\"example.com\"]", file=sys.stderr)
        sys.exit(1)

    results = []
    for entry in entries:
        # Backward compatible with the original flat-string format
        # (["example.com", ...]) — a plain string just means no
        # authenticated checks configured for that site.
        if isinstance(entry, str):
            domain, wp_secret_key = entry, None
        else:
            domain = entry.get("domain")
            wp_secret_key = entry.get("wp_secret_key")
        if not domain:
            continue
        print(f"Scanning {domain}...")
        results.append(scan_domain(domain, wp_secret_key))

    output = {"generated_at": datetime.now(timezone.utc).isoformat(), "sites": results}
    with open("results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote results.json — {len(results)} sites scanned.")
    for r in results:
        print(f"  {r['domain']}: {r['overall']}")

    all_alerts = []
    for r in results:
        all_alerts.extend(get_critical_alerts(r))
    sync_github_alert_issue(all_alerts)

    write_job_summary(entries, results)


if __name__ == "__main__":
    main()
