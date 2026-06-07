"""shadowrecon/modules/mod_tls_audit.py — Deep TLS/SSL analysis."""

import socket
import ssl
import subprocess
from datetime import datetime, timezone


def run(domain, args, out, state):
    result = {"cert": {}, "issues": []}

    # ── Live TLS handshake ────────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=args.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert         = ssock.getpeercert()
                protocol     = ssock.version()
                cipher_name, tls_ver, bits = ssock.cipher()

                out.kv("Protocol",     protocol)
                out.kv("Cipher Suite", f"{cipher_name} ({bits}-bit)")
                result["cert"].update({"protocol": protocol, "cipher": cipher_name, "bits": bits})

                # Weak cipher check
                WEAK = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]
                for wc in WEAK:
                    if wc.upper() in cipher_name.upper():
                        out.finding("HIGH", f"Weak cipher in use: {cipher_name}",
                                    cwe="CWE-326", module="tls_audit")
                        result["issues"].append({"severity": "HIGH",
                                                  "desc": f"Weak cipher: {cipher_name}", "cwe": "CWE-326"})
                if bits and int(bits) < 128:
                    out.finding("CRITICAL", f"Cipher key too short: {bits} bits",
                                cwe="CWE-326", module="tls_audit")

                # Cert fields
                if cert:
                    subj      = dict(x[0] for x in cert.get("subject", []))
                    issuer    = dict(x[0] for x in cert.get("issuer", []))
                    not_after = cert.get("notAfter", "")
                    sans      = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                    out.kv("Subject CN",  subj.get("commonName", "?"))
                    out.kv("Issuer",      issuer.get("organizationName", "?"))
                    out.kv("SAN count",   str(len(sans)))
                    if sans:
                        out.kv("SANs (first 6)", ", ".join(sans[:6]))
                    result["cert"].update({
                        "cn":        subj.get("commonName"),
                        "issuer":    issuer.get("organizationName"),
                        "sans":      sans,
                        "not_after": not_after,
                    })

                    # Expiry
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            exp = exp.replace(tzinfo=timezone.utc)
                            days = (exp - datetime.now(timezone.utc)).days
                            out.kv("Cert Expires", f"{not_after}  ({days} days)")
                            if days < 0:
                                out.finding("CRITICAL", f"Certificate EXPIRED {abs(days)} days ago",
                                            cwe="CWE-295", module="tls_audit")
                                result["issues"].append({"severity": "CRITICAL",
                                                          "desc": "Cert expired", "cwe": "CWE-295"})
                            elif days < 14:
                                out.finding("HIGH", f"Cert expires in {days} days",
                                            cwe="CWE-295", module="tls_audit")
                                result["issues"].append({"severity": "HIGH",
                                                          "desc": f"Cert expires in {days}d", "cwe": "CWE-295"})
                            elif days < 30:
                                out.finding("MEDIUM", f"Cert expires in {days} days — renew soon",
                                            cwe="CWE-295", module="tls_audit")
                        except Exception:
                            pass

                    # Self-signed
                    if subj.get("commonName") == issuer.get("commonName"):
                        out.finding("HIGH", "Self-signed certificate detected",
                                    cwe="CWE-295", module="tls_audit")
                        result["issues"].append({"severity": "HIGH", "desc": "Self-signed cert", "cwe": "CWE-295"})
                    else:
                        out.success(f"Certificate signed by trusted CA: {issuer.get('organizationName', '?')}")

                    # Wildcard cert SAN disclosure
                    for san in sans:
                        if san.startswith("*."):
                            out.info(f"Wildcard SAN: {san} — enumerates org infrastructure")

                    # CN mismatch
                    cn = subj.get("commonName", "")
                    if cn and not (domain.endswith(cn.lstrip("*")) or cn.lstrip("*.") == domain):
                        out.finding("LOW", f"Cert CN '{cn}' may not match target '{domain}'",
                                    cwe="CWE-295", module="tls_audit")
    except ConnectionRefusedError:
        out.fail("Port 443 refused — HTTPS not available")
        return result
    except socket.timeout:
        out.fail("TLS connection timeout")
        return result
    except Exception as e:
        out.fail(f"TLS handshake error: {e}")
        return result

    # ── Deprecated protocol probes via openssl ────────────────────────────────
    proto_tests = [
        ("SSLv3",   ["-ssl3"]),
        ("TLS 1.0", ["-tls1"]),
        ("TLS 1.1", ["-tls1_1"]),
    ]
    for proto_name, flags in proto_tests:
        try:
            proc = subprocess.run(
                ["openssl", "s_client"] + flags + ["-connect", f"{domain}:443", "-quiet"],
                input=b"", capture_output=True, timeout=5
            )
            combined = proc.stdout + proc.stderr
            if b"CONNECTED" in combined or b"Certificate chain" in combined:
                out.finding("MEDIUM", f"Deprecated {proto_name} is SUPPORTED",
                            cwe="CWE-326", module="tls_audit")
                result["issues"].append({"severity": "MEDIUM",
                                          "desc": f"{proto_name} supported", "cwe": "CWE-326"})
            else:
                out.success(f"{proto_name}: rejected (good)")
        except FileNotFoundError:
            out.debug("openssl not in PATH — skipping deprecated protocol tests")
            break
        except Exception:
            pass

    # ── HSTS preload check ────────────────────────────────────────────────────
    from modules._http import http_get
    r = http_get(f"https://{domain}", timeout=args.timeout)
    if r:
        hsts = r.headers.get("Strict-Transport-Security", "")
        if hsts:
            out.kv("HSTS", hsts)
            if "preload" not in hsts:
                out.finding("LOW", "HSTS missing 'preload' directive — not eligible for browser HSTS preload list",
                            cwe="CWE-319", module="tls_audit")
            if "includeSubDomains" not in hsts:
                out.finding("LOW", "HSTS missing 'includeSubDomains' — subdomains not covered",
                            cwe="CWE-319", module="tls_audit")
        else:
            out.finding("HIGH", "No HSTS header on HTTPS response — protocol downgrade possible",
                        cwe="CWE-319", module="tls_audit")
            result["issues"].append({"severity": "HIGH", "desc": "No HSTS", "cwe": "CWE-319"})

    return result
