"""shadowrecon/modules/mod_http_smuggling.py — HTTP request smuggling detection."""

import socket
import time
from modules._http import resolve

# CL.TE probe: we send Content-Length that matches outer body,
# but include Transfer-Encoding: chunked so a confused back-end
# treats the leftover bytes as the start of a next request.
# If the timing delta is large (back-end is waiting for a chunk)
# that's an indicator.

CL_TE_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"  # extra byte only a TE-confused backend would queue
)

TE_CL_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 3\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
)

# TE.TE obfuscation variants to detect TE normalization differences
TE_OBFUSCATION_VARIANTS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked, x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: chunked\x0b",
    "Transfer-Encoding: CHUNKED",
    "Transfer-Encoding: x-custom, chunked",
    "X-Transfer-Encoding: chunked",
]

TIMING_THRESHOLD = 5.0   # seconds — a delay above this is suspicious


def _raw_send(ip: str, port: int, payload: str, timeout: float) -> tuple[float, str]:
    """Send raw bytes, return (elapsed_seconds, response_snippet)."""
    t0 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port == 443:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.sendall(payload.encode("utf-8", errors="replace"))
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except Exception:
                pass
            elapsed = time.time() - t0
            return elapsed, resp[:300].decode("utf-8", errors="replace")
    except socket.timeout:
        return time.time() - t0, "TIMEOUT"
    except Exception as e:
        return time.time() - t0, f"ERROR: {e}"


def run(domain, args, out, state):
    result = {"issues": [], "indicators": []}

    ips = resolve(domain) or state.ips
    if not ips:
        out.fail("Cannot resolve domain for smuggling probe")
        return result

    ip = ips[0]
    ports_to_test = [443, 80]
    # Also test any discovered HTTP ports from port scan
    for p in state.open_ports:
        if p["port"] in (8080, 8443, 8000, 8008) and p["port"] not in ports_to_test:
            ports_to_test.append(p["port"])

    out.info(f"HTTP smuggling probe on {ip} ports {ports_to_test} ...")
    out.warn("Note: timing-based detection only — manual confirmation required for any positive")

    for port in ports_to_test:
        out.info(f"  Testing port {port} ...")

        # ── CL.TE probe ───────────────────────────────────────────────────────
        payload_cl_te = CL_TE_PROBE.format(host=domain)
        elapsed, resp = _raw_send(ip, port, payload_cl_te, timeout=10)

        if elapsed >= TIMING_THRESHOLD and "TIMEOUT" in resp or elapsed >= TIMING_THRESHOLD:
            out.finding("MEDIUM",
                        f"CL.TE smuggling indicator on port {port}: "
                        f"response delayed {elapsed:.1f}s (threshold {TIMING_THRESHOLD}s) — "
                        f"front-end uses CL, back-end uses TE",
                        cwe="CWE-444", module="http_smuggling",
                        url=f"https://{domain}")
            result["indicators"].append({
                "type": "CL.TE", "port": port, "elapsed": elapsed,
                "response": resp[:80]
            })
            result["issues"].append({
                "severity": "MEDIUM", "cwe": "CWE-444",
                "desc": f"CL.TE smuggling indicator on port {port} ({elapsed:.1f}s delay)"
            })
        else:
            out.success(f"CL.TE probe port {port}: {elapsed:.1f}s — no timing anomaly")

        # ── TE.CL probe ───────────────────────────────────────────────────────
        payload_te_cl = TE_CL_PROBE.format(host=domain)
        elapsed2, resp2 = _raw_send(ip, port, payload_te_cl, timeout=10)

        if elapsed2 >= TIMING_THRESHOLD:
            out.finding("MEDIUM",
                        f"TE.CL smuggling indicator on port {port}: "
                        f"response delayed {elapsed2:.1f}s — "
                        f"front-end uses TE, back-end uses CL",
                        cwe="CWE-444", module="http_smuggling",
                        url=f"https://{domain}")
            result["indicators"].append({
                "type": "TE.CL", "port": port, "elapsed": elapsed2,
                "response": resp2[:80]
            })
            result["issues"].append({
                "severity": "MEDIUM", "cwe": "CWE-444",
                "desc": f"TE.CL smuggling indicator on port {port} ({elapsed2:.1f}s delay)"
            })
        else:
            out.success(f"TE.CL probe port {port}: {elapsed2:.1f}s — no timing anomaly")

        # ── TE.TE obfuscation header check ────────────────────────────────────
        # Just check which TE header variants the server accepts without 400
        import requests
        import urllib3; urllib3.disable_warnings()
        for te_variant in TE_OBFUSCATION_VARIANTS[:4]:
            hdr_name, hdr_val = te_variant.split(": ", 1)
            try:
                r = requests.post(
                    f"https://{domain}" if port == 443 else f"http://{domain}:{port}",
                    headers={hdr_name: hdr_val, "Content-Length": "0"},
                    timeout=5, verify=False, allow_redirects=False
                )
                if r.status_code not in (400, 501):
                    out.finding("INFO",
                                f"Server accepted non-standard TE variant: '{te_variant}' → HTTP {r.status_code} — "
                                f"TE.TE obfuscation may be possible",
                                cwe="CWE-444", module="http_smuggling")
                    result["indicators"].append({
                        "type": "TE.TE", "port": port,
                        "variant": te_variant, "status": r.status_code
                    })
            except Exception:
                pass

    if not result["issues"]:
        out.success("No HTTP smuggling timing indicators detected")
    return result
