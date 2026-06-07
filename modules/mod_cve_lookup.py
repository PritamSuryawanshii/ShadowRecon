"""shadowrecon/modules/mod_cve_lookup.py — Technology → CVE correlation engine.

Uses NVD API (no key needed for basic queries) + a curated local high-value
CVE table for the most dangerous web-application CVEs by product.
"""

import re
import time
from modules._http import http_get

# ── Local high-value CVE table (product_keyword → list of CVE dicts) ──────────
# Curated from NVD, Shodan, Exploit-DB — covers the most commonly weaponised
# CVEs in web-app/infra pentesting as of 2025.
LOCAL_CVE_DB: dict[str, list[dict]] = {
    "wordpress": [
        {"cve": "CVE-2023-2745",  "cvss": 8.8, "desc": "Core directory traversal / LFI (< 6.2.1)",      "exploit": True},
        {"cve": "CVE-2022-21663", "cvss": 7.2, "desc": "Object injection in multisite installs",         "exploit": True},
        {"cve": "CVE-2021-39200", "cvss": 5.3, "desc": "REST API user enumeration",                      "exploit": True},
        {"cve": "CVE-2019-17671", "cvss": 7.5, "desc": "Unauthenticated content exposure",               "exploit": True},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Path traversal + RCE (mod_cgi) 2.4.49",         "exploit": True},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "desc": "Path traversal bypass 2.4.49-2.4.50",           "exploit": True},
        {"cve": "CVE-2022-31813", "cvss": 9.8, "desc": "X-Forwarded-For header smuggling",               "exploit": True},
        {"cve": "CVE-2017-7679",  "cvss": 9.8, "desc": "mod_mime buffer overread",                       "exploit": False},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 9.4, "desc": "1-byte memory overwrite in DNS resolver",        "exploit": False},
        {"cve": "CVE-2019-20372", "cvss": 5.3, "desc": "HTTP request smuggling (alias + error_page)",    "exploit": True},
        {"cve": "CVE-2017-7529",  "cvss": 7.5, "desc": "Integer overflow in range filter module",        "exploit": True},
    ],
    "iis": [
        {"cve": "CVE-2022-30209", "cvss": 8.1, "desc": "IIS auth bypass (EoP)",                         "exploit": False},
        {"cve": "CVE-2021-31166", "cvss": 9.8, "desc": "HTTP protocol stack RCE (HTTP.sys)",             "exploit": True},
        {"cve": "CVE-2017-7269",  "cvss": 9.8, "desc": "WebDAV ScStoragePathFromUrl buffer overflow",    "exploit": True},
    ],
    "struts": [
        {"cve": "CVE-2023-50164", "cvss": 9.8, "desc": "File upload path traversal → RCE (S2-066)",     "exploit": True},
        {"cve": "CVE-2021-31805", "cvss": 9.8, "desc": "OGNL injection (S2-062)",                       "exploit": True},
        {"cve": "CVE-2020-17530", "cvss": 9.8, "desc": "Forced double OGNL evaluation (S2-061)",        "exploit": True},
        {"cve": "CVE-2017-5638",  "cvss": 10.0,"desc": "Content-Type OGNL RCE (S2-045) — Equifax",      "exploit": True},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "cvss": 9.8, "desc": "Spring4Shell — ClassLoader manipulation RCE",   "exploit": True},
        {"cve": "CVE-2022-22963", "cvss": 9.8, "desc": "Spring Cloud Function SpEL RCE",                "exploit": True},
        {"cve": "CVE-2021-22053", "cvss": 8.8, "desc": "Spring Security OAuth2 RCE via SPEL",           "exploit": True},
        {"cve": "CVE-2018-1270",  "cvss": 9.8, "desc": "Spring Messaging STOMP RCE",                    "exploit": True},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600",  "cvss": 9.8, "desc": "Drupalgeddon 2 — unauthenticated RCE",         "exploit": True},
        {"cve": "CVE-2018-7602",  "cvss": 9.8, "desc": "Drupalgeddon 3 — authenticated RCE",            "exploit": True},
        {"cve": "CVE-2023-29197", "cvss": 7.5, "desc": "Improper input validation in HTTP headers",     "exploit": False},
    ],
    "joomla": [
        {"cve": "CVE-2023-23752", "cvss": 7.5, "desc": "Unauthenticated information disclosure",        "exploit": True},
        {"cve": "CVE-2015-8562",  "cvss": 9.8, "desc": "PHP object injection RCE",                      "exploit": True},
    ],
    "magento": [
        {"cve": "CVE-2022-24086", "cvss": 9.8, "desc": "Template injection pre-auth RCE (CVSS 9.8)",   "exploit": True},
        {"cve": "CVE-2019-8144",  "cvss": 9.8, "desc": "Unauthenticated RCE via REST API",              "exploit": True},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129",  "cvss": 9.8, "desc": "Ignition debug page RCE via log poisoning",    "exploit": True},
        {"cve": "CVE-2018-15133", "cvss": 8.1, "desc": "Unserialise RCE via APP_KEY leak",              "exploit": True},
    ],
    "tomcat": [
        {"cve": "CVE-2025-24813", "cvss": 9.8, "desc": "Partial PUT session file deserialization RCE", "exploit": True},
        {"cve": "CVE-2020-1938",  "cvss": 9.8, "desc": "Ghostcat — AJP connector LFI/RCE",             "exploit": True},
        {"cve": "CVE-2019-0232",  "cvss": 9.8, "desc": "CGI servlet RCE on Windows",                   "exploit": True},
        {"cve": "CVE-2017-12617", "cvss": 9.8, "desc": "PUT method JSP upload RCE",                    "exploit": True},
    ],
    "weblogic": [
        {"cve": "CVE-2023-21839", "cvss": 9.8, "desc": "IIOP/T3 deserialization RCE",                  "exploit": True},
        {"cve": "CVE-2021-2109",  "cvss": 9.8, "desc": "Admin Console JNDI injection RCE",             "exploit": True},
        {"cve": "CVE-2020-14882", "cvss": 9.8, "desc": "Console component bypass + RCE",               "exploit": True},
        {"cve": "CVE-2019-2725",  "cvss": 9.8, "desc": "wls9_async deserialization RCE",               "exploit": True},
    ],
    "jboss": [
        {"cve": "CVE-2017-12149", "cvss": 9.8, "desc": "Jboss EAP deserialization RCE",                "exploit": True},
        {"cve": "CVE-2015-7501",  "cvss": 9.8, "desc": "Java deserialization Commons-Collections",     "exploit": True},
    ],
    "elasticsearch": [
        {"cve": "CVE-2023-31419", "cvss": 7.5, "desc": "ReDoS via specially crafted regexp",            "exploit": False},
        {"cve": "CVE-2021-22145", "cvss": 6.5, "desc": "Sensitive information in exception messages",  "exploit": False},
        {"cve": "CVE-2015-1427",  "cvss": 9.8, "desc": "Groovy sandbox bypass RCE",                   "exploit": True},
    ],
    "redis": [
        {"cve": "CVE-2022-0543",  "cvss": 10.0,"desc": "Debian/Ubuntu Lua sandbox escape RCE",         "exploit": True},
        {"cve": "CVE-2021-32762", "cvss": 8.8, "desc": "Integer overflow in RESP parsing",             "exploit": False},
    ],
    "mongodb": [
        {"cve": "CVE-2021-32036", "cvss": 6.5, "desc": "Insufficient access control in diagnostics",   "exploit": False},
        {"cve": "CVE-2015-7882",  "cvss": 9.8, "desc": "Unauthenticated server compromise (no auth)",  "exploit": True},
    ],
    "php": [
        {"cve": "CVE-2024-4577",  "cvss": 9.8, "desc": "CGI argument injection RCE (Windows, all ver)","exploit": True},
        {"cve": "CVE-2023-3824",  "cvss": 9.8, "desc": "Stack buffer overflow in phar_find_entry",     "exploit": False},
        {"cve": "CVE-2021-21703", "cvss": 7.8, "desc": "FPM local privilege escalation",               "exploit": False},
        {"cve": "CVE-2019-11043", "cvss": 9.8, "desc": "FPM + nginx path_info buffer overflow RCE",   "exploit": True},
    ],
    "openssl": [
        {"cve": "CVE-2022-0778",  "cvss": 7.5, "desc": "Infinite loop in certificate parsing (DoS)",   "exploit": False},
        {"cve": "CVE-2014-0160",  "cvss": 7.5, "desc": "Heartbleed — memory disclosure",               "exploit": True},
    ],
    "keycloak": [
        {"cve": "CVE-2023-6927",  "cvss": 8.1, "desc": "Open redirect in account console",             "exploit": True},
        {"cve": "CVE-2023-2422",  "cvss": 7.4, "desc": "Client-initiated backchannel auth bypass",     "exploit": False},
        {"cve": "CVE-2022-2668",  "cvss": 7.2, "desc": "Realm configuration SSRF",                     "exploit": True},
    ],
    "jenkins": [
        {"cve": "CVE-2024-23897", "cvss": 9.8, "desc": "Arbitrary file read via CLI path traversal",  "exploit": True},
        {"cve": "CVE-2023-27898", "cvss": 9.8, "desc": "XSS in plugin manager → RCE (RepoSHIFT)",     "exploit": True},
        {"cve": "CVE-2019-1003000","cvss":9.8, "desc": "Script Security sandbox bypass → RCE",         "exploit": True},
        {"cve": "CVE-2016-9299",  "cvss": 9.8, "desc": "Remoting library deserialization RCE",         "exploit": True},
    ],
    "gitlab": [
        {"cve": "CVE-2023-7028",  "cvss": 10.0,"desc": "Account takeover via unverified email reset",  "exploit": True},
        {"cve": "CVE-2021-22205", "cvss": 10.0,"desc": "ExifTool RCE via image upload (pre-auth)",     "exploit": True},
        {"cve": "CVE-2022-2884",  "cvss": 9.9, "desc": "GitHub import RCE",                            "exploit": True},
    ],
    "grafana": [
        {"cve": "CVE-2021-43798", "cvss": 7.5, "desc": "Directory traversal via plugin path",          "exploit": True},
        {"cve": "CVE-2022-21702", "cvss": 6.8, "desc": "CSRF + XSS via Markdown renderer",             "exploit": True},
    ],
    "nextjs": [
        {"cve": "CVE-2025-29927", "cvss": 9.1, "desc": "Middleware auth bypass via x-middleware-subrequest header", "exploit": True},
    ],
    "mssql": [
        {"cve": "CVE-2020-0618",  "cvss": 8.8, "desc": "Reporting Services deserialization RCE",       "exploit": True},
        {"cve": "CVE-2019-1068",  "cvss": 8.8, "desc": "Full-text search RCE",                         "exploit": False},
    ],
    "docker": [
        {"cve": "CVE-2019-5736",  "cvss": 8.6, "desc": "runc container escape (overwrite host binary)","exploit": True},
        {"cve": "CVE-2024-21626", "cvss": 8.6, "desc": "Leaky root file descriptor container escape",  "exploit": True},
    ],
}


def _nvd_lookup(product: str, version: str | None, timeout: int) -> list[dict]:
    """Query NVD CVE API 2.0 for recent CVEs for a keyword."""
    results = []
    keyword = f"{product} {version}".strip() if version else product
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
        r   = http_get(url, timeout=timeout)
        if not r or r.status_code != 200:
            return results
        data  = r.json()
        items = data.get("vulnerabilities", [])
        for item in items:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            descs    = cve_data.get("descriptions", [])
            desc     = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:120]
            metrics  = cve_data.get("metrics", {})
            cvss     = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(key, [])
                if mlist:
                    cvss = mlist[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            if cve_id:
                results.append({
                    "cve":     cve_id,
                    "cvss":    cvss,
                    "desc":    desc,
                    "exploit": False,
                    "source":  "nvd_api",
                })
        time.sleep(0.6)  # NVD rate limit: 5 req/30s without API key
    except Exception:
        pass
    return results


def run(domain, args, out, state):
    result = {"cve_hits": [], "issues": []}

    if not state.technologies:
        out.warn("No technologies detected yet — run tech_fingerprint module first")
        return result

    out.info(f"Correlating {len(state.technologies)} detected technologies to CVE database ...")

    all_hits = []
    queried_nvd = set()

    versions = state.module_results.get("tech_fingerprint", {}).get("versions", {})

    for tech_name, category in state.technologies.items():
        tech_lower = tech_name.lower()

        # ── Local DB lookup ───────────────────────────────────────────────────
        for keyword, cves in LOCAL_CVE_DB.items():
            if keyword in tech_lower or tech_lower in keyword:
                ver = versions.get(tech_name, "")
                for cve in cves:
                    entry = dict(cve)
                    entry["product"]  = tech_name
                    entry["version"]  = ver
                    entry["source"]   = "local_db"
                    all_hits.append(entry)

                    sev = "CRITICAL" if cve["cvss"] >= 9.0 else (
                          "HIGH"     if cve["cvss"] >= 7.0 else
                          "MEDIUM"   if cve["cvss"] >= 4.0 else "LOW")
                    exploit_flag = " [bold red][POC/EXPLOIT AVAILABLE][/bold red]" if cve["exploit"] else ""
                    out.finding(sev,
                                f"{cve['cve']} (CVSS {cve['cvss']}) — {tech_name}: {cve['desc']}{exploit_flag}",
                                cwe="CWE-1035", module="cve_lookup")
                    result["issues"].append({
                        "severity": sev,
                        "cwe":      "CWE-1035",
                        "desc":     f"{cve['cve']} ({tech_name}): {cve['desc']}",
                    })
                    state.cves.append({"cve": cve["cve"], "product": tech_name, "severity": sev})
                break  # one keyword match per tech is enough for local DB

    # ── NVD live API for versions we have exact strings for ───────────────────
    for product, ver in versions.items():
        key = f"{product.lower()}_{ver}"
        if key in queried_nvd:
            continue
        queried_nvd.add(key)
        out.info(f"NVD API lookup: {product} {ver} ...")
        nvd_hits = _nvd_lookup(product, ver, args.timeout)
        for hit in nvd_hits:
            hit["product"] = product
            hit["version"] = ver
            all_hits.append(hit)
            sev = "CRITICAL" if hit["cvss"] >= 9.0 else (
                  "HIGH"     if hit["cvss"] >= 7.0 else
                  "MEDIUM"   if hit["cvss"] >= 4.0 else "INFO")
            out.finding(sev,
                        f"{hit['cve']} (CVSS {hit['cvss']}) — {product} {ver}: {hit['desc']}",
                        cwe="CWE-1035", module="cve_lookup")

    result["cve_hits"] = all_hits

    if all_hits:
        exploitable = [h for h in all_hits if h.get("exploit")]
        out.warn(f"CVE correlation: {len(all_hits)} CVEs found  "
                 f"({len(exploitable)} with known exploits)")
    else:
        out.success("No CVEs matched from local database or NVD for detected technologies")

    return result
