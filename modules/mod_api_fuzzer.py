"""shadowrecon/modules/mod_api_fuzzer.py — API endpoint fuzzing."""

import concurrent.futures
from modules._constants import API_WORDLIST
from modules._http import http_get

INTERESTING_CODES = {200, 201, 204, 301, 302, 400, 401, 403, 405, 500}
# 404 is boring; 401/403 means it EXISTS but is protected (still a finding)


def run(domain, args, out, state):
    result = {"found": [], "issues": []}

    bases = [f"https://{domain}"]
    for s in state.subdomains[:8]:
        if any(kw in s["host"] for kw in ("api", "app", "portal", "admin", "dev", "staging")):
            bases.append(f"https://{s['host']}")

    # Combine wordlist + JS-extracted endpoints (deduplicated)
    paths = list(dict.fromkeys(API_WORDLIST + state.endpoints))
    out.info(f"Fuzzing {len(paths)} paths across {len(bases)} targets ...")

    def probe(base_url, path):
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        r   = http_get(url, timeout=args.timeout, allow_redirects=False)
        if not r or r.status_code not in INTERESTING_CODES:
            return None
        return {
            "url":    url,
            "status": r.status_code,
            "size":   len(r.content),
            "ct":     r.headers.get("Content-Type", "")[:40],
        }

    work = [(b, p) for b in bases for p in paths]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(probe, b, p): (b, p) for b, p in work}
        for f in concurrent.futures.as_completed(futures):
            hit = f.result()
            if not hit:
                continue
            status = hit["status"]
            url    = hit["url"]
            result["found"].append(hit)

            # Classify severity
            if any(kw in url for kw in (".env", ".git", "backup", "dump", "config", "credentials",
                                         "aws", "ssh", "id_rsa", ".sql", ".zip", "phpinfo")):
                out.finding("CRITICAL", f"Sensitive file exposed: {url} (HTTP {status})",
                            cwe="CWE-538", module="api_fuzzer", url=url)
                result["issues"].append({"url": url, "status": status, "severity": "CRITICAL",
                                         "cwe": "CWE-538", "desc": "Sensitive file"})
            elif any(kw in url for kw in ("actuator", "debug", "trace", "metrics", "prometheus")):
                out.finding("HIGH", f"Monitoring/debug endpoint: {url} (HTTP {status})",
                            cwe="CWE-200", module="api_fuzzer", url=url)
                result["issues"].append({"url": url, "status": status, "severity": "HIGH",
                                         "cwe": "CWE-200", "desc": "Debug/monitoring endpoint"})
            elif status in (200, 201):
                out.success(f"HTTP {status}  {url}  [{hit['size']}b]  {hit['ct']}")
            elif status in (401, 403):
                out.info(f"HTTP {status}  {url}  [protected — exists]")
            elif status in (301, 302):
                out.debug(f"HTTP {status}  {url}  [redirect]")
            elif status == 500:
                out.finding("MEDIUM", f"HTTP 500 on {url} — possible unhandled exception/info leak",
                            cwe="CWE-200", module="api_fuzzer", url=url)
                result["issues"].append({"url": url, "status": status, "severity": "MEDIUM",
                                         "cwe": "CWE-200", "desc": "HTTP 500 error"})

    out.info(f"API fuzzer: {len(result['found'])} responsive endpoints found")
    return result
