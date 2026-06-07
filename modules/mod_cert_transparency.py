"""shadowrecon/modules/mod_cert_transparency.py — CT log mining."""

import concurrent.futures
from modules._http import http_get, resolve


def run(domain, args, out, state):
    result = {"subdomains": [], "raw_count": 0}
    found_names = set()

    # Source 1: crt.sh
    out.info("Querying crt.sh ...")
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r and r.status_code == 200:
            entries = r.json()
            result["raw_count"] = len(entries)
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(f".{domain}") or name == domain:
                        found_names.add(name)
            out.info(f"crt.sh: {result['raw_count']} certs → {len(found_names)} unique names")
    except Exception as e:
        out.fail(f"crt.sh query failed: {e}")

    # Source 2: certspotter
    out.info("Querying certspotter ...")
    try:
        r = http_get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                     timeout=12)
        if r and r.status_code == 200:
            before = len(found_names)
            for entry in r.json():
                for name in entry.get("dns_names", []):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(f".{domain}"):
                        found_names.add(name)
            out.info(f"certspotter: +{len(found_names) - before} new names")
    except Exception:
        pass

    # Source 3: RapidDNS (no auth needed)
    try:
        r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=10)
        if r and r.status_code == 200:
            import re
            matches = re.findall(r'<td>([a-z0-9\-\.]+\.' + re.escape(domain) + r')</td>', r.text)
            before = len(found_names)
            for m in matches:
                found_names.add(m.lower())
            out.info(f"RapidDNS: +{len(found_names) - before} new names")
    except Exception:
        pass

    # Resolve each unique name and update shared state
    out.info(f"Resolving {len(found_names)} CT/passive subdomains ...")

    def resolve_name(fqdn):
        ips = resolve(fqdn)
        return (fqdn, ips) if ips else None

    existing = {s["host"] for s in state.subdomains}
    new_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(resolve_name, n): n for n in found_names}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                fqdn, ips = res
                entry = {"host": fqdn, "ips": ips, "source": "CT"}
                result["subdomains"].append(entry)
                if fqdn not in existing:
                    state.subdomains.append(entry)
                    existing.add(fqdn)
                    new_count += 1
                    out.success(f"{fqdn}  →  {', '.join(ips[:3])}")

    out.info(f"CT resolved: {new_count} new subdomains added to state")
    return result
