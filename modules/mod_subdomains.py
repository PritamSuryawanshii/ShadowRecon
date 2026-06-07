"""shadowrecon/modules/mod_subdomains.py — Brute-force + permutation expansion."""

import concurrent.futures
import dns.resolver
import itertools

from modules._constants import SUBDOMAIN_WORDLIST
from modules._http import resolve


def run(domain, args, out, state):
    result = {"subdomains": [], "permutations_checked": 0}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 3

    existing_hosts = {s["host"] for s in state.subdomains}

    def check_sub(fqdn):
        try:
            ans = resolver.resolve(fqdn, "A")
            return fqdn, [str(r) for r in ans]
        except Exception:
            return None

    # ── Phase 1: wordlist brute-force ─────────────────────────────────────────
    out.info(f"Brute-forcing {len(SUBDOMAIN_WORDLIST)} subdomains ...")
    candidates = [f"{w}.{domain}" for w in SUBDOMAIN_WORDLIST]
    found_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_sub, c): c for c in candidates}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                fqdn, ips = res
                entry = {"host": fqdn, "ips": ips, "source": "brute"}
                result["subdomains"].append(entry)
                if fqdn not in existing_hosts:
                    state.subdomains.append(entry)
                    existing_hosts.add(fqdn)
                    found_count += 1
                    out.success(f"{fqdn}  →  {', '.join(ips[:3])}  [brute]")

    out.info(f"Brute-force: {found_count} new subdomains")

    # ── Phase 2: permutation expansion on discovered subdomains ──────────────
    # Take already-found hosts and generate alt variations
    already_found = [s["host"].split(".")[0] for s in state.subdomains if s["host"].endswith(f".{domain}")]
    if not already_found:
        return result

    perm_prefixes = list(set(already_found))[:20]
    alt_keywords  = ["dev", "staging", "api", "new", "old", "test", "v2", "internal",
                     "admin", "beta", "backup", "prod", "uat"]
    permutations  = set()
    for prefix in perm_prefixes:
        for kw in alt_keywords:
            permutations.add(f"{prefix}-{kw}.{domain}")
            permutations.add(f"{kw}-{prefix}.{domain}")
            permutations.add(f"{prefix}.{kw}.{domain}")
    permutations -= existing_hosts

    result["permutations_checked"] = len(permutations)
    out.info(f"DNS permutation expansion: checking {len(permutations)} generated names ...")
    perm_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_sub, p): p for p in permutations}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                fqdn, ips = res
                entry = {"host": fqdn, "ips": ips, "source": "permutation"}
                result["subdomains"].append(entry)
                if fqdn not in existing_hosts:
                    state.subdomains.append(entry)
                    existing_hosts.add(fqdn)
                    perm_count += 1
                    out.success(f"{fqdn}  →  {', '.join(ips[:3])}  [perm]")

    out.info(f"Permutation expansion: {perm_count} additional subdomains")
    out.info(f"Total subdomains in state: {len(state.subdomains)}")
    return result
