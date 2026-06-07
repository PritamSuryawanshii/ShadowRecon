"""shadowrecon/modules/mod_headers.py — Security header audit."""

import re
from modules._constants import SECURITY_HEADERS
from modules._http import http_get


DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Runtime", "X-Version", "X-Debug-Token",
    "X-Application-Context", "X-CF-Powered-By", "X-Drupal-Cache",
    "X-PHP-Version", "X-Backend-Server", "X-Upstream",
]


def run(domain, args, out, state):
    result = {"headers": {}, "score": 0, "max_score": 0, "issues": []}

    for scheme in ("https", "http"):
        r = http_get(f"{scheme}://{domain}", timeout=args.timeout)
        if r:
            break
    if not r:
        out.fail("Cannot reach target")
        return result

    resp_headers = r.headers
    out.kv("Status", str(r.status_code))
    out.kv("Final URL", r.url)

    # ── Info disclosure ───────────────────────────────────────────────────────
    out.info("Checking info-disclosure headers ...")
    for h in DISCLOSURE_HEADERS:
        val = resp_headers.get(h)
        if val:
            out.finding("LOW", f"Info disclosure via header {h}: {val}",
                        cwe="CWE-200", module="headers")
            result["headers"][h] = val
            result["issues"].append({"header": h, "severity": "LOW", "cwe": "CWE-200",
                                     "desc": f"Version/tech disclosed: {val}"})

    # ── Security header scoring ───────────────────────────────────────────────
    out.info("Scoring security headers ...")
    score = 0
    max_score = len(SECURITY_HEADERS)

    for header, cfg in SECURITY_HEADERS.items():
        val     = resp_headers.get(header)
        sev     = cfg["severity"]
        cwe     = cfg["cwe"]
        desc    = cfg["desc"]

        if not val:
            out.finding(sev, f"Missing: {header} — {desc}", cwe=cwe, module="headers")
            result["issues"].append({"header": header, "severity": sev, "cwe": cwe, "desc": desc})
        else:
            try:
                ok = cfg["good"](val)
            except Exception:
                ok = True
            if ok:
                out.success(f"{header}: {val[:80]}")
                score += 1
            else:
                out.finding(sev, f"Misconfigured {header}: {val[:80]}", cwe=cwe, module="headers")
                result["issues"].append({"header": header, "severity": sev, "cwe": cwe,
                                         "desc": f"Misconfigured: {val[:80]}"})
                score += 0.5

        result["headers"][header] = val or "(missing)"

    grade_thresholds = [0.9, 0.7, 0.5, 0.3, 0.0]
    grade_letters    = ["A", "B", "C", "D", "F"]
    ratio = score / max_score if max_score else 0
    grade = grade_letters[next(i for i, t in enumerate(grade_thresholds) if ratio >= t)]

    result["score"]     = round(score)
    result["max_score"] = max_score
    result["grade"]     = grade
    out.info(f"Security Header Score: {round(score)}/{max_score}  (Grade: {grade})")

    # ── Cookie flags ──────────────────────────────────────────────────────────
    set_cookies = resp_headers.get("Set-Cookie", "")
    if set_cookies:
        if "Secure" not in set_cookies:
            out.finding("MEDIUM", "Set-Cookie missing 'Secure' flag — cookie sent over HTTP",
                        cwe="CWE-614", module="headers")
            result["issues"].append({"header": "Set-Cookie", "severity": "MEDIUM",
                                     "cwe": "CWE-614", "desc": "Missing Secure flag"})
        if "HttpOnly" not in set_cookies:
            out.finding("MEDIUM", "Set-Cookie missing 'HttpOnly' — cookie accessible via JS (XSS risk)",
                        cwe="CWE-1004", module="headers")
            result["issues"].append({"header": "Set-Cookie", "severity": "MEDIUM",
                                     "cwe": "CWE-1004", "desc": "Missing HttpOnly flag"})
        if "SameSite" not in set_cookies:
            out.finding("LOW", "Set-Cookie missing 'SameSite' attribute — CSRF risk elevated",
                        cwe="CWE-352", module="headers")

    return result
