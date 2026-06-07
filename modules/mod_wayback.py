"""shadowrecon/modules/mod_wayback.py — Wayback Machine / historical URL mining."""

import re
from modules._http import http_get

INTERESTING_PATTERNS = [
    # (regex, severity, description, cwe)
    (r"\.(?:env|bak|sql|sqlite|gz|tar|zip|7z|rar|log|backup|old|orig|swp)$",
     "CRITICAL", "Sensitive/backup file in historical index", "CWE-538"),
    (r"/\.git/(?:config|HEAD|FETCH_HEAD|index|packed-refs)",
     "CRITICAL", ".git directory contents exposed historically", "CWE-538"),
    (r"/(?:wp-config|config|database|db|settings|credentials|secrets|application)\.(?:php|py|rb|json|yml|yaml|xml|ini|cfg|conf)",
     "HIGH", "Config/credential file in historical index", "CWE-538"),
    (r"/(?:admin|phpMyAdmin|phpmyadmin|administrator|wp-admin|cpanel|whm|plesk|webmin)",
     "HIGH", "Admin interface in historical index", "CWE-284"),
    (r"/(?:api|v\d)/(?:admin|internal|debug|test|dev|private)",
     "HIGH", "Internal API path in historical index", "CWE-200"),
    (r"(?:password|passwd|secret|token|key|credential|apikey|api_key)=",
     "HIGH", "Credential parameter in historical URL (GET-based)", "CWE-598"),
    (r"/(?:test|dev|staging|qa|uat|debug|sandbox)/",
     "MEDIUM", "Non-production environment path in history", "CWE-200"),
    (r"/(?:phpinfo|info)\.php",
     "MEDIUM", "PHP info page in historical index", "CWE-200"),
    (r"/(?:server-status|server-info|status|metrics|actuator)",
     "MEDIUM", "Server status/metrics endpoint in history", "CWE-200"),
    (r"/(?:upload|uploads?|files?)/.*\.(?:php|asp|aspx|jsp|cgi)",
     "CRITICAL", "Uploaded script file in history — possible webshell", "CWE-434"),
    (r"/(?:graphql|gql|playground|graphiql)",
     "INFO", "GraphQL endpoint in historical index", "CWE-200"),
    (r"/(?:swagger|openapi|api-docs)",
     "INFO", "API documentation in historical index", "CWE-200"),
    (r"(?:session|token|jwt|auth)=[A-Za-z0-9+/=._-]{20,}",
     "HIGH", "Session token / JWT in historical URL (GET-based)", "CWE-598"),
]

PARAM_INTEREST_PATTERNS = [
    r"(?:id|uid|user_id|account|order|invoice)=\d+",   # IDOR
    r"(?:file|path|dir|folder|include|require)=",       # LFI/path traversal
    r"(?:url|redirect|return|next|goto|link|ref)=",     # Open redirect
    r"(?:q|search|query|term|keyword)=",                # Injection surface
    r"(?:cmd|exec|command|shell|run|ping)=",            # Command injection
]


def run(domain, args, out, state):
    result = {"urls": [], "interesting": [], "parameters": [], "issues": []}

    # ── CDX API fetch ─────────────────────────────────────────────────────────
    out.info("Querying Wayback Machine CDX API ...")
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original,statuscode,timestamp"
        f"&collapse=urlkey&limit=2000&filter=statuscode:200"
    )
    r = http_get(cdx_url, timeout=20)
    if not r or r.status_code != 200:
        out.fail("Wayback CDX API unreachable")
        return result

    try:
        rows = r.json()
    except Exception:
        out.fail("CDX API returned invalid JSON")
        return result

    urls = [row[0] for row in rows[1:] if row and row[0]]   # skip header row
    result["urls"] = urls
    out.info(f"CDX returned {len(urls)} historical URLs (200-only, collapsed)")

    # Extract all unique parameters for manual review
    seen_params = set()
    for url in urls:
        if "?" in url:
            qs = url.split("?", 1)[1]
            for kv in qs.split("&"):
                param = kv.split("=")[0].strip()
                if param and param not in seen_params:
                    seen_params.add(param)
    result["parameters"] = sorted(seen_params)
    if seen_params:
        out.info(f"Unique query parameters discovered: {len(seen_params)}")
        out.debug(f"  Params: {', '.join(sorted(seen_params)[:40])}")

    # ── Interesting URL classification ────────────────────────────────────────
    seen_hits = set()
    for url in urls:
        for pattern, severity, desc, cwe in INTERESTING_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE) and url not in seen_hits:
                out.finding(severity, f"{desc}: {url}", cwe=cwe, module="wayback", url=url)
                result["interesting"].append({
                    "url": url, "severity": severity, "reason": desc, "cwe": cwe
                })
                result["issues"].append({
                    "severity": severity, "cwe": cwe, "desc": f"{desc}: {url[:80]}"
                })
                seen_hits.add(url)
                break

        # Parameter-of-interest pattern (separate pass)
        if "?" in url:
            for pat in PARAM_INTEREST_PATTERNS:
                if re.search(pat, url, re.IGNORECASE) and url not in seen_hits:
                    out.finding("INFO",
                                f"Interesting parameter pattern: {url}",
                                cwe="CWE-200", module="wayback", url=url)
                    result["interesting"].append({
                        "url": url, "severity": "INFO",
                        "reason": "Interesting parameter", "cwe": "CWE-200"
                    })
                    seen_hits.add(url)
                    break

    # ── Unique subdomain discovery from Wayback URLs ──────────────────────────
    import re as _re
    wayback_hosts = set()
    for url in urls:
        m = _re.match(r"https?://([^/]+)", url)
        if m:
            host = m.group(1).lower().rstrip(".")
            if host.endswith(f".{domain}") and host != domain:
                wayback_hosts.add(host)

    existing = {s["host"] for s in state.subdomains}
    new_from_wb = wayback_hosts - existing
    if new_from_wb:
        out.info(f"Wayback revealed {len(new_from_wb)} additional subdomains not found by brute/CT")
        from modules._http import resolve as _resolve
        for host in new_from_wb:
            ips = _resolve(host)
            entry = {"host": host, "ips": ips, "source": "wayback"}
            state.subdomains.append(entry)
            out.success(f"{host}  →  {', '.join(ips) if ips else '[unresolved]'}  [wayback]")

    out.info(f"Wayback: {len(result['interesting'])} interesting URLs flagged")
    return result
