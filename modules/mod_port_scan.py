"""shadowrecon/modules/mod_port_scan.py — TCP port scan with banner grabbing."""

import concurrent.futures
import socket
import ssl
from modules._constants import COMMON_PORTS, PORT_NAMES, RISKY_PORTS
from modules._http import resolve

BANNER_PROBES = {
    21:   b"",
    22:   b"",
    25:   b"EHLO shadowrecon\r\n",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    110:  b"",
    143:  b"",
    443:  None,   # TLS — handled separately
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00",
}


def _grab_banner(ip: str, port: int, timeout: int) -> str:
    probe = BANNER_PROBES.get(port, b"")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe is not None and probe != b"":
                s.sendall(probe)
            data = s.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _scan_port(ip: str, port: int, timeout: int) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result != 0:
            return None
    except Exception:
        return None

    service = PORT_NAMES.get(port, "unknown")
    banner  = _grab_banner(ip, port, min(timeout, 3))

    return {"port": port, "service": service, "ip": ip, "banner": banner}


def run(domain, args, out, state):
    result = {"open_ports": [], "issues": []}

    ips = resolve(domain) or state.ips
    if not ips:
        out.fail("Cannot resolve domain for port scanning")
        return result

    ip = ips[0]
    out.info(f"Scanning {ip}  [{len(COMMON_PORTS)} ports]  timeout={min(args.timeout, 3)}s ...")

    scan_timeout = min(args.timeout, 3)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 30)) as ex:
        futures = {ex.submit(_scan_port, ip, p, scan_timeout): p for p in COMMON_PORTS}
        for f in concurrent.futures.as_completed(futures):
            hit = f.result()
            if not hit:
                continue

            port    = hit["port"]
            service = hit["service"]
            banner  = hit["banner"]
            result["open_ports"].append(hit)
            state.open_ports.append(hit)

            if port in RISKY_PORTS:
                svc_name, severity, desc = RISKY_PORTS[port]
                out.finding(severity,
                            f"Port {port}/tcp OPEN — {service} — {desc}",
                            cwe="CWE-200", module="port_scan")
                result["issues"].append({
                    "port": port, "severity": severity, "cwe": "CWE-200",
                    "desc": f"Risky port {port} ({service}): {desc}"
                })
            else:
                out.success(f"Port {port:5d}/tcp  {service}")

            if banner:
                out.kv(f"  [{port}] Banner", banner[:120])

                # Inline version extraction from banner
                import re
                for pattern, prod in [
                    (r"SSH-[\d\.]+-OpenSSH_([\w\.]+)", "OpenSSH"),
                    (r"220.*(?:ProFTPd?|vsFTPd?|FileZilla|Pure-FTPd?) ([\d\.]+)", "FTP"),
                    (r"220.*Postfix",                  "Postfix SMTP"),
                    (r"Elasticsear[a-z]+ ([\d\.]+)",   "Elasticsearch"),
                    (r"Redis ([\d\.]+)",               "Redis"),
                    (r"MongoDB ([\d\.]+)",             "MongoDB"),
                ]:
                    m = re.search(pattern, banner, re.IGNORECASE)
                    if m and len(m.groups()) > 0:
                        ver = m.group(1)
                        out.finding("LOW",
                                    f"Version disclosure in banner on port {port}: {prod} {ver}",
                                    cwe="CWE-200", module="port_scan")
                        result["issues"].append({
                            "port": port, "severity": "LOW", "cwe": "CWE-200",
                            "desc": f"Banner version: {prod} {ver} on port {port}"
                        })

    result["open_ports"].sort(key=lambda x: x["port"])
    total_open = len(result["open_ports"])
    total_risky = sum(1 for p in result["open_ports"] if p["port"] in RISKY_PORTS)
    out.info(f"Port scan complete: {total_open} open ports ({total_risky} high-risk)")
    return result
