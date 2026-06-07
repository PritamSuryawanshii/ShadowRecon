"""shadowrecon/modules/mod_shodan.py — Shodan host/org lookup."""

from modules._http import http_get, resolve, company_name


def run(domain, args, out, state):
    result = {"hosts": [], "issues": [], "vulns": []}
    key = args.shodan_key

    if not key:
        out.warn("No --shodan-key provided — Shodan module skipped")
        out.info("  Tip: free Shodan account gives API key at https://account.shodan.io")
        return result

    ips = resolve(domain) or state.ips
    company = company_name(domain)

    def _shodan_get(path: str):
        r = http_get(f"https://api.shodan.io{path}&key={key}", timeout=args.timeout)
        if r and r.status_code == 200:
            return r.json()
        if r and r.status_code == 401:
            out.fail("Shodan: invalid API key")
        return None

    # ── Per-IP host lookup ────────────────────────────────────────────────────
    for ip in ips[:3]:
        out.info(f"Shodan host lookup: {ip} ...")
        data = _shodan_get(f"/shodan/host/{ip}?")
        if not data:
            continue

        org      = data.get("org", "?")
        os_name  = data.get("os", "?")
        hostnames = data.get("hostnames", [])
        ports    = [str(s.get("port")) for s in data.get("data", [])]
        vulns    = list(data.get("vulns", {}).keys())
        tags     = data.get("tags", [])

        out.success(f"IP: {ip}  Org: {org}  OS: {os_name}")
        out.kv("Open ports (Shodan)", ", ".join(sorted(ports, key=int)))
        if hostnames:
            out.kv("Hostnames", ", ".join(hostnames[:8]))
        if tags:
            out.kv("Tags", ", ".join(tags))

        entry = {"ip": ip, "org": org, "os": os_name,
                 "ports": ports, "hostnames": hostnames, "vulns": vulns}
        result["hosts"].append(entry)

        # Merge Shodan-seen ports into state
        for port_str in ports:
            try:
                port_int = int(port_str)
                if not any(p["port"] == port_int for p in state.open_ports):
                    state.open_ports.append({"port": port_int, "service": "shodan", "ip": ip})
            except Exception:
                pass

        # Merge Shodan hostnames into state subdomains
        existing = {s["host"] for s in state.subdomains}
        for h in hostnames:
            h = h.lower()
            if h.endswith(f".{domain}") and h not in existing:
                state.subdomains.append({"host": h, "ips": [ip], "source": "shodan"})
                out.success(f"Shodan hostname: {h}  →  {ip}")

        # CVE findings
        if vulns:
            for cve in vulns:
                out.finding("HIGH",
                            f"Shodan reports {cve} on {ip} — verify and exploit chain as appropriate",
                            cwe="CWE-1035", module="shodan_query", url=f"https://nvd.nist.gov/vuln/detail/{cve}")
                result["vulns"].append({"ip": ip, "cve": cve})
                result["issues"].append({
                    "severity": "HIGH", "cwe": "CWE-1035",
                    "desc": f"Shodan CVE: {cve} on {ip}"
                })
        else:
            out.info(f"No Shodan-flagged CVEs on {ip}")

        # Services detail
        for svc in data.get("data", []):
            port   = svc.get("port")
            banner = (svc.get("data") or "")[:120].replace("\n", " ")
            product = svc.get("product", "")
            version = svc.get("version", "")
            out.info(f"  Port {port}: {product} {version}  |  {banner}")

    # ── Org-level search (finds all hosts under org name) ────────────────────
    out.info(f"Shodan org search: '{company}' ...")
    data = _shodan_get(f"/shodan/host/search?query=org:{company}&")
    if data:
        total = data.get("total", 0)
        out.info(f"Shodan org search: {total} total hosts for org '{company}'")
        for match in data.get("matches", [])[:10]:
            ip2   = match.get("ip_str", "")
            ports2 = [str(match.get("port", "?"))]
            out.kv("Host", f"{ip2}  port {ports2[0]}")

    return result
