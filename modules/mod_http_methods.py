"""shadowrecon/modules/mod_http_methods.py — Dangerous HTTP method detection."""

from modules._http import http_request, http_get


DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "PROPFIND",
                     "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
                     "OPTIONS", "DEBUG", "TRACK"]

SEVERITY_MAP = {
    "TRACE":     ("HIGH",   "Enables cross-site tracing (XST) — cookie theft vector (CWE-16)", "CWE-16"),
    "TRACK":     ("HIGH",   "TRACK mirrors TRACE — cross-site tracing risk (CWE-16)", "CWE-16"),
    "PUT":       ("HIGH",   "HTTP PUT may allow arbitrary file upload / webshell (CWE-434)", "CWE-434"),
    "DELETE":    ("HIGH",   "HTTP DELETE may allow resource deletion (CWE-284)", "CWE-284"),
    "DEBUG":     ("CRITICAL","ASP.NET DEBUG method enables internal state disclosure (CWE-200)", "CWE-200"),
    "PROPFIND":  ("MEDIUM", "WebDAV PROPFIND — directory traversal/listing possible (CWE-548)", "CWE-548"),
    "PROPPATCH": ("MEDIUM", "WebDAV PROPPATCH enabled (CWE-284)", "CWE-284"),
    "MKCOL":     ("MEDIUM", "WebDAV MKCOL — directory creation possible", "CWE-284"),
    "CONNECT":   ("MEDIUM", "HTTP CONNECT proxy pivoting possible", "CWE-284"),
}


def run(domain, args, out, state):
    result = {"allowed_methods": [], "issues": []}

    targets = [f"https://{domain}", f"https://{domain}/api"]
    for s in state.subdomains[:5]:
        targets.append(f"https://{s['host']}")

    for url in targets:
        # OPTIONS to discover allowed methods
        r = http_request("OPTIONS", url, timeout=args.timeout)
        if r:
            allow_hdr = r.headers.get("Allow", "") or r.headers.get("Public", "")
            if allow_hdr:
                advertised = [m.strip().upper() for m in allow_hdr.split(",")]
                out.kv(f"OPTIONS {url}", allow_hdr)
                for method in advertised:
                    if method in DANGEROUS_METHODS and method != "OPTIONS":
                        sev, desc, cwe = SEVERITY_MAP.get(method, ("LOW", f"Unusual method: {method}", "CWE-284"))
                        out.finding(sev, f"{method} allowed on {url} — {desc}", cwe=cwe, module="http_methods", url=url)
                        result["issues"].append({"method": method, "url": url, "severity": sev, "cwe": cwe, "desc": desc})
                result["allowed_methods"].append({"url": url, "methods": advertised})

        # Direct TRACE probe
        r_trace = http_request("TRACE", url, timeout=args.timeout)
        if r_trace and r_trace.status_code == 200 and "TRACE" in (r_trace.text or "").upper():
            out.finding("HIGH", f"TRACE method confirmed active on {url} — XST attack possible",
                        cwe="CWE-16", module="http_methods", url=url)
            result["issues"].append({"method": "TRACE", "url": url, "severity": "HIGH",
                                     "cwe": "CWE-16", "desc": "TRACE confirmed"})

    if not result["issues"]:
        out.success("No dangerous HTTP methods detected")
    return result
