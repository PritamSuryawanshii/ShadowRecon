"""shadowrecon/modules/mod_asn.py — ASN & IP range expansion."""

import ipaddress
from modules._http import http_get, resolve


def run(domain, args, out, state):
    result = {"asn": [], "ip_ranges": []}
    ips = resolve(domain) or state.ips
    if not ips:
        out.fail("Cannot resolve domain IP for ASN lookup")
        return result

    out.info(f"Resolved IPs: {', '.join(ips[:5])}")
    seen_asns = set()

    for ip in ips[:3]:
        # ipwhois RDAP
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn     = res.get("asn", "?")
            org     = res.get("asn_description", "?")
            cidr    = res.get("asn_cidr", "?")
            country = res.get("asn_country_code", "?")
            out.success(f"IP: {ip}  AS{asn}  ORG: {org}  CIDR: {cidr}  ({country})")
            entry = {"ip": ip, "asn": asn, "org": org, "cidr": cidr, "country": country}
            result["asn"].append(entry)
            if cidr and "/" in cidr:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    out.info(f"  CIDR {cidr} → {net.num_addresses:,} addresses in org range")
                    result["ip_ranges"].append(str(cidr))
                except Exception:
                    pass
            seen_asns.add(str(asn))
        except Exception as e:
            out.fail(f"ASN lookup failed for {ip}: {e}")

    # BGPView: expand all prefixes for the ASN
    for asn_entry in result["asn"][:2]:
        asn_num = asn_entry.get("asn")
        if not asn_num or str(asn_num) == "?":
            continue
        if str(asn_num) in seen_asns:
            pass
        try:
            r = http_get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=10)
            if r and r.status_code == 200:
                prefixes = r.json().get("data", {}).get("ipv4_prefixes", [])
                out.info(f"BGPView: AS{asn_num} has {len(prefixes)} IPv4 prefixes")
                for p in prefixes[:15]:
                    cidr_p = p.get("prefix", "")
                    desc   = p.get("description", "")
                    if cidr_p and cidr_p not in result["ip_ranges"]:
                        result["ip_ranges"].append(cidr_p)
                        out.kv("Prefix", f"{cidr_p}  [{desc}]")
        except Exception:
            pass

    # Also try team-cymru whois for quick ASN
    if not result["asn"]:
        for ip in ips[:2]:
            try:
                import socket as _sock
                s = _sock.socket()
                s.settimeout(5)
                s.connect(("whois.cymru.com", 43))
                s.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                s.close()
                lines = data.decode(errors="ignore").splitlines()
                for line in lines:
                    if "|" in line and not line.startswith("AS"):
                        parts = [x.strip() for x in line.split("|")]
                        if len(parts) >= 3:
                            out.kv("Cymru ASN", " | ".join(parts))
            except Exception:
                pass

    return result
