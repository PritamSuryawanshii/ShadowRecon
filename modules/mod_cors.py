"""shadowrecon/modules/mod_cors.py — CORS misconfiguration probing."""

from modules._http import http_get


EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def run(domain, args, out, state):
    result = {"issues": []}

    # Build target list: root + discovered subdomains
    targets = [f"https://{domain}"]
    for s in state.subdomains[:10]:
        targets.append(f"https://{s['host']}")

    for url in targets:
        _probe_target(url, domain, args, out, result)

    if not result["issues"]:
        out.success("No CORS misconfigurations detected across tested targets")
    return result


def _probe_target(url, domain, args, out, result):
    # Dynamic evil origins based on target domain
    evil_origins = list(EVIL_ORIGINS) + [
        f"https://{domain}.evil.com",
        f"https://evil{domain}",
        f"https://sub.{domain}.attacker.com",
    ]

    for origin in evil_origins:
        r = http_get(url, timeout=args.timeout, extra_headers={"Origin": origin})
        if not r:
            return

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        acah = r.headers.get("Access-Control-Allow-Headers", "")

        if acao == "*":
            if acac == "true":
                out.finding("CRITICAL",
                            f"CORS wildcard (*) WITH credentials=true on {url} — full credential theft",
                            cwe="CWE-942", module="cors", url=url)
                result["issues"].append({"url": url, "origin": origin, "severity": "CRITICAL",
                                         "desc": "Wildcard CORS + credentials", "cwe": "CWE-942"})
            else:
                out.finding("MEDIUM", f"CORS wildcard (*) on {url} — unauthenticated data exposure",
                            cwe="CWE-942", module="cors", url=url)
                result["issues"].append({"url": url, "origin": "*", "severity": "MEDIUM",
                                         "desc": "Wildcard CORS", "cwe": "CWE-942"})
            break

        elif acao == origin and origin not in ("", "null"):
            if acac == "true":
                out.finding("HIGH",
                            f"CORS reflects arbitrary origin WITH credentials on {url}",
                            cwe="CWE-942", module="cors", url=url,
                            evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: true")
                result["issues"].append({"url": url, "origin": origin, "severity": "HIGH",
                                         "desc": "Reflected origin + credentials=true", "cwe": "CWE-942"})
            else:
                out.finding("LOW", f"CORS reflects arbitrary origin (no credentials) on {url}",
                            cwe="CWE-942", module="cors", url=url)
                result["issues"].append({"url": url, "origin": origin, "severity": "LOW",
                                         "desc": "Reflected CORS origin", "cwe": "CWE-942"})
            break

        elif acao == "null":
            out.finding("MEDIUM", f"null-origin CORS accepted on {url} — sandbox/file:// bypass",
                        cwe="CWE-942", module="cors", url=url)
            result["issues"].append({"url": url, "severity": "MEDIUM",
                                     "desc": "null-origin CORS", "cwe": "CWE-942"})
            break

        # Check vary: origin (for caching attacks)
        vary = r.headers.get("Vary", "")
        if "origin" not in vary.lower() and acao:
            out.finding("INFO",
                        f"CORS response missing 'Vary: Origin' on {url} — potential cache poisoning",
                        cwe="CWE-346", module="cors", url=url)
