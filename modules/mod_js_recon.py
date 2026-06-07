"""shadowrecon/modules/mod_js_recon.py — JS crawl: endpoints + secrets."""

import concurrent.futures
import math
import re

from modules._constants import JS_SECRET_PATTERNS
from modules._http import http_get

ENDPOINT_PATTERNS = [
    r'["\'](\/(api|v\d|rest|graphql|internal|admin|auth|oauth|user|account|payment|webhook|service|endpoint|backend)[^"\'<>\s]{0,150})["\']',
    r'fetch\(["\']([^"\']{5,200})["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']{5,200})["\']',
    r'(?:xhr|http)\.(?:open|get|post)\([^,]+,\s*["\']([^"\']{5,200})["\']',
    r'url\s*[:=]\s*["\']([^"\']{5,200})["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']{5,200})["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']{5,200})["\']',
    r'path\s*[:=]\s*["\'](\/([\w\-/]+))["\']',
]

FALSE_POSITIVE_STRINGS = [
    "example", "placeholder", "your_", "YOUR_", "xxxxxxx", "undefined",
    "null", "true", "false", "lorem", "ipsum", "sample", "changeme",
    "test123", "password123", "enter_your", "<YOUR", "INSERT_", "REPLACE_",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in probs.values())


def _extract_from_js(js_text: str, domain: str, result: dict, source: str, out):
    if not js_text:
        return

    # Endpoints
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js_text, re.IGNORECASE):
            ep = m.group(1)
            if ep and len(ep) < 200 and not ep.startswith("//cdn"):
                result["endpoints"].append(ep)

    # Secrets — with entropy gating for reduced false positives
    for secret_type, pattern in JS_SECRET_PATTERNS.items():
        for m in re.finditer(pattern, js_text):
            hit = m.group(0)
            # Skip false positives
            if any(fp.lower() in hit.lower() for fp in FALSE_POSITIVE_STRINGS):
                continue
            # Entropy gate for generic patterns
            if "Key in JS" in secret_type or "password" in secret_type.lower():
                # Extract the value portion
                val_match = re.search(r'[:=]\s*["\']([^"\']+)["\']', hit)
                if val_match:
                    val = val_match.group(1)
                    if _shannon_entropy(val) < 3.2:
                        continue  # Low entropy = likely placeholder
            sev = "HIGH" if any(x in secret_type for x in
                                 ("AWS", "Key", "Token", "Private", "JWT", "Stripe", "Secret")) else "MEDIUM"
            src_short = source.split("/")[-1][:40]
            out.finding(sev, f"{secret_type}: ...{hit[:60]}... [{src_short}]",
                        cwe="CWE-312", module="js_recon", url=source, evidence=hit[:120])
            result["secrets"].append({
                "type":    secret_type,
                "match":   hit[:200],
                "source":  source,
                "entropy": round(_shannon_entropy(hit), 2),
            })


def run(domain, args, out, state):
    result = {"js_files": [], "endpoints": [], "secrets": []}
    js_urls = set()

    # Crawl main page + common entry points
    seed_urls = [f"https://{domain}", f"https://www.{domain}",
                 f"https://app.{domain}", f"https://api.{domain}"]
    for s in state.subdomains[:5]:
        seed_urls.append(f"https://{s['host']}")

    for base in seed_urls:
        r = http_get(base, timeout=args.timeout)
        if not r or not r.text:
            continue
        # External <script src="">
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE):
            src = m.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base.rstrip("/") + src
            elif not src.startswith("http"):
                src = base.rstrip("/") + "/" + src
            # Only include same-domain or obvious asset CDNs to avoid noise
            if domain in src or any(cdn in src for cdn in ["cdn.", "static.", "assets."]):
                js_urls.add(src.split("?")[0])
        # Inline JS
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL | re.IGNORECASE):
            _extract_from_js(m.group(1), domain, result, f"{base}[inline]", out)

    out.info(f"Crawled {len(js_urls)} unique JS files")
    state.js_files = list(js_urls)

    def analyse_js(url):
        r = http_get(url, timeout=args.timeout)
        if r and r.text and "javascript" in r.headers.get("Content-Type", "text/javascript"):
            result["js_files"].append(url)
            _extract_from_js(r.text, domain, result, url, out)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 5)) as ex:
        list(ex.map(analyse_js, list(js_urls)[:40]))

    # Deduplicate
    result["endpoints"] = list(set(result["endpoints"]))
    state.endpoints = result["endpoints"]

    seen = set()
    deduped = []
    for s in result["secrets"]:
        key = (s["type"], s["match"][:40])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    result["secrets"] = deduped

    out.info(f"JS files analysed: {len(result['js_files'])}")
    out.info(f"Endpoints extracted: {len(result['endpoints'])}")
    out.info(f"Potential secrets: {len(result['secrets'])}")

    if result["secrets"]:
        out.warn(f"{len(result['secrets'])} potential secret(s) detected — manual verification required")
    return result
