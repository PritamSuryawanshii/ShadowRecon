"""shadowrecon/modules/mod_vhost.py — Virtual host brute-force via Host header."""

import concurrent.futures
import hashlib
from modules._constants import SUBDOMAIN_WORDLIST
from modules._http import http_get, resolve

EXTRA_VHOST_WORDS = [
    "intranet", "internal", "corp", "employee", "staff", "hr", "erp",
    "crm", "vpn", "citrix", "remote", "helpdesk", "ticketing",
    "confluence", "jira", "jenkins", "gitlab", "git", "svn",
    "monitoring", "grafana", "kibana", "elastic", "splunk",
    "database", "db", "mysql", "mongo", "redis", "postgres",
    "payment", "billing", "finance", "treasury", "accounts",
    "reporting", "analytics", "insight", "dashboard",
    "test", "dev", "staging", "uat", "qa", "demo", "sandbox",
    "legacy", "old", "v1", "v2", "backup",
    "admin", "administrator", "superadmin", "root",
    "api-internal", "api-private", "api-admin",
    "mgmt", "management", "control",
    "partners", "b2b", "vendor", "supplier",
]

VHOST_WORDLIST = list(dict.fromkeys(SUBDOMAIN_WORDLIST + EXTRA_VHOST_WORDS))


def _fingerprint(r) -> str:
    """Quick fingerprint: status + body-length + first 200 chars hash."""
    body = (r.text or "")[:200] if r else ""
    return f"{r.status_code if r else 0}_{len(r.content) if r else 0}_{hashlib.md5(body.encode()).hexdigest()[:8]}"


def run(domain, args, out, state):
    result = {"found": [], "issues": []}
    ips = resolve(domain) or state.ips
    if not ips:
        out.fail("Cannot resolve domain IP for vhost probe")
        return result

    ip = ips[0]
    out.info(f"Probing vhosts on {ip} with {len(VHOST_WORDLIST)} words ...")

    # Baseline — what does the server return for unknown Host?
    baseline_r = http_get(f"https://{ip}", timeout=args.timeout,
                          extra_headers={"Host": f"nonexistent-{domain}"},
                          verify=False)
    baseline_fp = _fingerprint(baseline_r)
    out.debug(f"Baseline fingerprint: {baseline_fp}")

    def probe_vhost(word: str):
        host = f"{word}.{domain}"
        r = http_get(f"https://{ip}", timeout=args.timeout,
                     extra_headers={"Host": host},
                     verify=False)
        if not r:
            return None
        fp = _fingerprint(r)
        if fp != baseline_fp and r.status_code not in (400, 404, 502, 503):
            return {
                "host":   host,
                "status": r.status_code,
                "size":   len(r.content),
                "fp":     fp,
                "title":  _extract_title(r.text),
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(probe_vhost, w): w for w in VHOST_WORDLIST}
        for f in concurrent.futures.as_completed(futures):
            hit = f.result()
            if hit:
                sev = "HIGH" if any(kw in hit["host"] for kw in
                      ("internal", "admin", "intranet", "corp", "employee",
                       "legacy", "dev", "staging", "payment", "db", "database")) else "MEDIUM"
                out.finding(sev,
                            f"Virtual host discovered: {hit['host']}  "
                            f"HTTP {hit['status']}  {hit['size']}b  \"{hit['title']}\"",
                            cwe="CWE-284", module="vhost_bruteforce")
                result["found"].append(hit)
                result["issues"].append({
                    "severity": sev, "cwe": "CWE-284",
                    "desc": f"VHost: {hit['host']} (HTTP {hit['status']})"
                })
                # Add to shared subdomain state
                state.subdomains.append({
                    "host": hit["host"], "ips": [ip], "source": "vhost"
                })

    if not result["found"]:
        out.success("No virtual hosts found beyond the baseline response")
    else:
        out.warn(f"{len(result['found'])} virtual hosts detected — "
                 "these may host internal apps not exposed by DNS")
    return result


def _extract_title(html: str) -> str:
    if not html:
        return ""
    import re
    m = re.search(r"<title[^>]*>([^<]{1,80})</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""
