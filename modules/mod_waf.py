"""shadowrecon/modules/mod_waf.py — WAF fingerprinting + bypass hints."""

import urllib.parse
from modules._constants import WAF_SIGNATURES, WAF_BYPASS_HINTS
from modules._http import http_get


PROBE_PAYLOADS = [
    "?q=<script>alert(1)</script>",
    "?id=1' OR '1'='1",
    "?x=../../../etc/passwd",
    "?cmd=;id",
]


def run(domain, args, out, state):
    result = {"waf": None, "bypass_hints": [], "issues": []}

    r = http_get(f"https://{domain}", timeout=args.timeout)
    if not r:
        r = http_get(f"http://{domain}", timeout=args.timeout)
    if not r:
        out.fail("Cannot reach target for WAF detection")
        return result

    all_hdr_vals = " ".join(v.lower() for v in r.headers.values())
    cookie_vals  = " ".join(r.cookies.keys()).lower()
    combined     = all_hdr_vals + " " + cookie_vals + " " + r.headers.get("Server","").lower()

    detected = []
    for waf_name, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            detected.append(waf_name)

    # Probe with attack-like payloads and observe response changes
    baseline_status = r.status_code
    for payload in PROBE_PAYLOADS:
        rp = http_get(f"https://{domain}/{payload}", timeout=args.timeout)
        if rp and rp.status_code in (403, 406, 429, 503) and rp.status_code != baseline_status:
            if not detected:
                detected.append("Unknown WAF")
            out.info(f"WAF probe triggered: {payload[:40]}  → HTTP {rp.status_code}")
            break
        # Also check for WAF-specific response body patterns
        if rp and rp.text:
            body_l = rp.text.lower()
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(sig.lower() in body_l for sig in sigs) and waf_name not in detected:
                    detected.append(waf_name)

    if detected:
        waf_str = ", ".join(detected)
        result["waf"] = waf_str
        out.success(f"WAF Detected: [bold]{waf_str}[/bold]")

        for waf in detected:
            hints = WAF_BYPASS_HINTS.get(waf, [
                "Try HTTP verb tunnelling (X-HTTP-Method-Override)",
                "Use chunked Transfer-Encoding",
                "Exploit parameter name case sensitivity",
            ])
            for hint in hints:
                out.info(f"  Bypass hint [{waf}]: {hint}")
                result["bypass_hints"].append({"waf": waf, "hint": hint})

        result["issues"].append({
            "severity": "INFO",
            "desc": f"WAF detected: {waf_str}",
            "cwe": "",
        })
    else:
        out.success("No WAF detected — raw target (or WAF not in signature set)")

    # CDN detection
    cdn_map = {
        "x-cache":            "CDN caching detected",
        "x-fastly-request-id":"Fastly CDN",
        "cf-ray":             "Cloudflare",
        "x-amz-cf-id":       "AWS CloudFront",
        "x-akamai-transformed":"Akamai",
        "x-nf-request-id":   "Netlify",
    }
    for hdr, cdn_name in cdn_map.items():
        if hdr in {k.lower() for k in r.headers}:
            out.info(f"CDN/Proxy layer: {cdn_name} — origin IP may differ from DNS")
            result["cdn"] = cdn_name
            break

    return result
