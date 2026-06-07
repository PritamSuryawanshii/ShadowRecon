"""shadowrecon/modules/mod_takeover.py — Subdomain takeover detection."""

import concurrent.futures
import dns.resolver
from modules._constants import TAKEOVER_SIGS
from modules._http import http_get


def run(domain, args, out, state):
    result = {"vulnerable": [], "dangling": [], "issues": []}

    if not state.subdomains:
        out.warn("No subdomains in state — run cert_transparency/subdomains modules first")
        return result

    out.info(f"Checking {len(state.subdomains)} subdomains for takeover vectors ...")

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 3

    def check(sub_entry: dict):
        host = sub_entry["host"]
        cnames = []
        try:
            ans = resolver.resolve(host, "CNAME")
            cnames = [str(r).rstrip(".").lower() for r in ans]
        except Exception:
            pass

        # Walk the CNAME chain against all signatures
        for cname in cnames:
            for sig_domain, (service, fingerprint) in TAKEOVER_SIGS.items():
                if sig_domain in cname:
                    # HTTP probe to confirm fingerprint string in response body
                    r = http_get(f"http://{host}", timeout=5)
                    if r and fingerprint.lower() in (r.text or "").lower():
                        return {
                            "host":        host,
                            "cname":       cname,
                            "service":     service,
                            "fingerprint": fingerprint,
                            "status":      "VULNERABLE",
                        }
                    else:
                        # Cannot confirm — CNAME points to external service but
                        # fingerprint not matched (could be race / transient)
                        return {
                            "host":        host,
                            "cname":       cname,
                            "service":     service,
                            "fingerprint": fingerprint,
                            "status":      "DANGLING",
                        }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check, s): s for s in state.subdomains}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res:
                continue
            host    = res["host"]
            service = res["service"]
            cname   = res["cname"]

            if res["status"] == "VULNERABLE":
                out.finding("CRITICAL",
                            f"TAKEOVER CONFIRMED: {host} → {cname} ({service}) — "
                            f"fingerprint '{res['fingerprint'][:40]}' found",
                            cwe="CWE-284", module="takeover", url=f"http://{host}")
                result["vulnerable"].append(res)
                result["issues"].append({
                    "severity": "CRITICAL", "cwe": "CWE-284",
                    "desc": f"Takeover: {host} → {cname} ({service})"
                })
            else:
                out.finding("HIGH",
                            f"DANGLING CNAME: {host} → {cname} ({service}) — "
                            f"fingerprint unconfirmed, verify manually",
                            cwe="CWE-284", module="takeover", url=f"http://{host}")
                result["dangling"].append(res)
                result["issues"].append({
                    "severity": "HIGH", "cwe": "CWE-284",
                    "desc": f"Dangling CNAME: {host} → {cname} ({service})"
                })

    total = len(result["vulnerable"]) + len(result["dangling"])
    if total == 0:
        out.success("No subdomain takeover vectors detected")
    else:
        out.warn(f"{len(result['vulnerable'])} confirmed takeovers, "
                 f"{len(result['dangling'])} dangling CNAMEs")
    return result
