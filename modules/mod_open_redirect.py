"""shadowrecon/modules/mod_open_redirect.py — Open redirect probing."""

import re
from modules._http import http_get

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_to",
    "returnTo", "returnUrl", "return_url", "next", "target", "url",
    "goto", "go", "link", "to", "redir", "r", "u", "ref", "callback",
    "continue", "dest", "destination", "forward", "location", "out",
    "view", "logoutUrl", "checkout_url", "success_url", "cancel_url",
]

CANARY = "https://evil.com/redirect_test"


def run(domain, args, out, state):
    result = {"vulnerable": [], "issues": []}

    # Build target URLs from API fuzzer / wayback / subdomains
    base_targets = [f"https://{domain}"]
    for s in state.subdomains[:5]:
        base_targets.append(f"https://{s['host']}")

    # Also probe endpoints discovered via JS recon / API fuzzer
    js_endpoints = state.endpoints[:30]

    for base in base_targets:
        for param in REDIRECT_PARAMS:
            url = f"{base}?{param}={CANARY}"
            r   = http_get(url, timeout=args.timeout, allow_redirects=False)
            if not r:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    out.finding("HIGH",
                                f"Open redirect via ?{param}= on {base} → {loc}",
                                cwe="CWE-601", module="open_redirect", url=url,
                                evidence=f"Location: {loc}")
                    result["vulnerable"].append({"url": url, "param": param,
                                                 "location": loc, "status": r.status_code})
                    result["issues"].append({"url": url, "param": param,
                                             "severity": "HIGH", "cwe": "CWE-601",
                                             "desc": f"Open redirect: {param}"})

    for ep in js_endpoints:
        # Only try endpoints that look like they could have redirect params
        if any(kw in ep.lower() for kw in ("login", "auth", "return", "redirect", "callback", "logout", "sso")):
            for param in REDIRECT_PARAMS[:8]:
                base = f"https://{domain}{ep}"
                url  = f"{base}?{param}={CANARY}"
                r    = http_get(url, timeout=args.timeout, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        out.finding("HIGH",
                                    f"Open redirect on API endpoint {ep}?{param}= → {loc}",
                                    cwe="CWE-601", module="open_redirect", url=url)
                        result["vulnerable"].append({"url": url, "param": param, "location": loc})
                        result["issues"].append({"url": url, "param": param,
                                                 "severity": "HIGH", "cwe": "CWE-601",
                                                 "desc": f"Open redirect on endpoint {ep}"})

    if not result["vulnerable"]:
        out.success("No open redirect vulnerabilities detected")
    return result
