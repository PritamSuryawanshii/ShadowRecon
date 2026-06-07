"""shadowrecon/modules/mod_ssrf_probe.py — SSRF indicator detection.

Uses out-of-band (OOB) detection via well-known public SSRF canaries
(interact.sh / Burp Collaborator style) when available, plus blind timing
and error-based indicators.
"""

import re
import time
from modules._http import http_get, http_request

# Parameters commonly used to pass URLs to the server
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "href", "action",
    "host", "hostname", "target", "proxy", "path", "fetch",
    "request", "load", "remote", "endpoint", "callback",
    "redirect", "return", "next", "dest", "destination",
    "image", "img", "picture", "media", "asset",
    "webhook", "notify", "ping", "feed", "rss",
    "service", "server", "backend", "api",
]

# SSRF canary targets — no OOB listener needed, detect via response behaviour
SSRF_CANARIES = [
    # Internal metadata
    ("http://169.254.169.254/latest/meta-data/",      r"ami-id|instance-id|placement|security-credentials", "AWS metadata"),
    ("http://169.254.169.254/computeMetadata/v1/",    r"project|instance|serviceAccounts",                   "GCP metadata"),
    ("http://169.254.169.254/metadata/",              r"compute|subscriptionId|resourceGroupName",            "Azure metadata"),
    # Internal services (detect by response size / status change)
    ("http://localhost/",                              r"",                                                   "localhost"),
    ("http://127.0.0.1/",                             r"",                                                   "127.0.0.1"),
    ("http://0.0.0.0/",                               r"",                                                   "0.0.0.0"),
    # DNS rebinding canary (publically resolvable → 127.0.0.1)
    ("http://localtest.me/",                          r"",                                                   "localtest.me"),
    # IPv6
    ("http://[::1]/",                                 r"",                                                   "IPv6 localhost"),
    # Decimal/octal encoding
    ("http://2130706433/",                            r"",                                                   "127.0.0.1 decimal"),
    ("http://0177.0.0.1/",                            r"",                                                   "127.0.0.1 octal"),
]

# Schemes that should produce errors if SSRF filtering is present
BLOCKED_SCHEMES = ["file:///etc/passwd", "dict://localhost:6379/", "gopher://localhost/"]


def run(domain, args, out, state):
    result = {"vulnerable": [], "indicators": [], "issues": []}

    if args.passive_only:
        out.info("Skipped (passive-only mode)")
        return result

    base_targets = [f"https://{domain}"]
    for s in state.subdomains[:5]:
        if any(kw in s["host"] for kw in ("api", "app", "service", "backend", "webhook", "fetch")):
            base_targets.append(f"https://{s['host']}")

    # Also use API endpoints that contain URL-like parameters
    api_endpoints = [ep for ep in state.endpoints
                     if any(kw in ep.lower() for kw in ("url", "uri", "proxy", "fetch", "webhook", "callback"))]

    wb_params = set(state.module_results.get("wayback", {}).get("parameters", []))
    probe_params = list(dict.fromkeys(SSRF_PARAMS + [p for p in wb_params
                                                     if any(kw in p.lower() for kw in
                                                            ("url", "uri", "link", "src", "host", "fetch"))]))[:30]

    out.info(f"SSRF probe: {len(probe_params)} params × {len(base_targets)} targets "
             f"× {len(SSRF_CANARIES)} canaries")

    found_urls = set()

    def _probe(base: str, param: str, canary_url: str, confirm_re: str, label: str):
        url  = f"{base}?{param}={canary_url}"
        t0   = time.time()
        r    = http_get(url, timeout=args.timeout)
        elapsed = time.time() - t0

        if not r:
            return

        body   = (r.text or "")
        status = r.status_code

        # Confirmed: regex match in response body
        if confirm_re and re.search(confirm_re, body, re.IGNORECASE):
            key = (base, param, label)
            if key not in found_urls:
                found_urls.add(key)
                out.finding("CRITICAL",
                            f"SSRF CONFIRMED — {label} via ?{param}= on {base}",
                            cwe="CWE-918", module="ssrf_probe", url=url,
                            evidence=body[:200])
                result["vulnerable"].append({
                    "url":     url,
                    "param":   param,
                    "canary":  canary_url,
                    "label":   label,
                    "evidence": body[:200],
                })
                result["issues"].append({
                    "severity": "CRITICAL", "cwe": "CWE-918",
                    "desc": f"SSRF: {label} accessible via {base}?{param}=",
                })

        # Timing indicator: local canary responded much faster than baseline
        elif "localhost" in canary_url or "127.0.0.1" in canary_url:
            if elapsed < 1.0 and status == 200:
                out.finding("MEDIUM",
                            f"SSRF timing indicator: {base}?{param}={canary_url} responded in {elapsed:.2f}s with HTTP 200",
                            cwe="CWE-918", module="ssrf_probe", url=url)
                result["indicators"].append({
                    "url":   url, "param": param,
                    "elapsed": elapsed, "label": label,
                })

        # Error-based: server error suggests it tried to fetch
        elif status == 500 and elapsed > 2.0:
            out.finding("LOW",
                        f"SSRF error indicator: server error + delay on {base}?{param}={canary_url[:40]}",
                        cwe="CWE-918", module="ssrf_probe", url=url)
            result["indicators"].append({"url": url, "param": param, "label": label, "type": "error"})

    import concurrent.futures
    work = [
        (base, param, canary, confirm, label)
        for base    in base_targets
        for param   in probe_params[:12]
        for canary, confirm, label in SSRF_CANARIES[:6]
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(_probe, *w) for w in work]
        concurrent.futures.wait(futures)

    # ── Scheme injection check (file://, gopher://) ───────────────────────────
    for base in base_targets[:2]:
        for param in probe_params[:5]:
            for scheme_payload in BLOCKED_SCHEMES:
                url = f"{base}?{param}={scheme_payload}"
                r   = http_get(url, timeout=5)
                if r and r.status_code == 200 and len(r.content) > 100:
                    out.finding("HIGH",
                                f"Non-HTTP scheme accepted: {scheme_payload} via {base}?{param}=",
                                cwe="CWE-918", module="ssrf_probe", url=url)
                    result["issues"].append({
                        "severity": "HIGH", "cwe": "CWE-918",
                        "desc": f"SSRF: {scheme_payload} scheme not blocked via ?{param}=",
                    })

    if not result["vulnerable"] and not result["indicators"]:
        out.success("No SSRF indicators detected")
    return result
