"""shadowrecon/modules/mod_dns.py — Full DNS enumeration."""

import dns.resolver
import dns.zone
import dns.query
import dns.exception


def run(domain, args, out, state):
    result = {"records": {}, "issues": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = args.timeout
    resolver.lifetime = args.timeout

    RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "DNSKEY", "DS"]

    for rtype in RTYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            recs = [str(r) for r in answers]
            result["records"][rtype] = recs
            out.success(f"{rtype:8s} {', '.join(recs[:5])}")
            if rtype == "A":
                state.ips = list(set(state.ips + recs))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            out.fail("NXDOMAIN — domain does not exist")
            return result
        except Exception:
            pass

    # DNSSEC check
    if "DNSKEY" not in result["records"]:
        out.finding("LOW", "DNSSEC not configured — DNS spoofing possible",
                    cwe="CWE-350", module="dns")
        result["issues"].append({"severity": "LOW", "desc": "DNSSEC absent", "cwe": "CWE-350"})
    else:
        out.success("DNSSEC: DNSKEY records found")

    # Zone transfer attempt against all NS
    ns_list = result["records"].get("NS", [])
    for ns in ns_list:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            hosts = list(z.nodes.keys())
            out.finding("CRITICAL", f"ZONE TRANSFER ALLOWED on {ns} — {len(hosts)} records leaked",
                        cwe="CWE-200", module="dns")
            result["zone_transfer"] = {"ns": ns, "record_count": len(hosts),
                                       "records": [str(h) for h in hosts]}
            result["issues"].append({"severity": "CRITICAL",
                                     "desc": f"Zone transfer on {ns}", "cwe": "CWE-200"})
        except Exception:
            out.debug(f"Zone transfer denied on {ns}")

    # Wildcard detection
    import socket, random
    rand_sub = f"zxcv{random.randint(10000,99999)}.{domain}"
    try:
        socket.gethostbyname(rand_sub)
        out.warn("Wildcard DNS active — brute-force results may include false positives")
        result["wildcard"] = True
    except Exception:
        result["wildcard"] = False

    # SPT: look for internal IPs in A records (split-horizon leakage)
    for ip in result["records"].get("A", []):
        if ip.startswith(("10.", "192.168.", "172.")):
            out.finding("MEDIUM", f"Private/internal IP in DNS A record: {ip} — split-horizon leak",
                        cwe="CWE-200", module="dns")
            result["issues"].append({"severity": "MEDIUM", "desc": f"Internal IP in A: {ip}", "cwe": "CWE-200"})

    return result
