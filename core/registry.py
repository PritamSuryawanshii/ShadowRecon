"""shadowrecon/core/registry.py — Module registry (execution order enforced)."""

MODULE_REGISTRY: dict[str, dict] = {
    # ── Passive ────────────────────────────────────────────────────────────────
    "whois": {
        "desc":    "WHOIS registration data, registrar, expiry, name servers",
        "passive": True,
        "module":  "modules.mod_whois",
        "fn":      "run",
    },
    "dns": {
        "desc":    "Full DNS record enumeration + zone transfer + DNSSEC check",
        "passive": True,
        "module":  "modules.mod_dns",
        "fn":      "run",
    },
    "cert_transparency": {
        "desc":    "CT log mining: crt.sh, certspotter, RapidDNS — passive subdomain harvest",
        "passive": True,
        "module":  "modules.mod_cert_transparency",
        "fn":      "run",
    },
    "subdomains": {
        "desc":    "Subdomain brute-force (200 words) + DNS permutation expansion",
        "passive": True,
        "module":  "modules.mod_subdomains",
        "fn":      "run",
    },
    "asn": {
        "desc":    "ASN lookup, BGP prefix expansion, org IP range mapping via BGPView",
        "passive": True,
        "module":  "modules.mod_asn",
        "fn":      "run",
    },
    "email_security": {
        "desc":    "SPF / DKIM (23 selectors) / DMARC / BIMI / MTA-STS audit",
        "passive": True,
        "module":  "modules.mod_email_security",
        "fn":      "run",
    },
    "github_recon": {
        "desc":    "GitHub org discovery, repo tree sensitive-file scan, code-search secrets",
        "passive": True,
        "module":  "modules.mod_github_recon",
        "fn":      "run",
    },
    "wayback": {
        "desc":    "Wayback Machine CDX mining: historical URLs, params, sensitive paths",
        "passive": True,
        "module":  "modules.mod_wayback",
        "fn":      "run",
    },
    "shodan_query": {
        "desc":    "Shodan host/org lookup, CVE feed, banner data (requires --shodan-key)",
        "passive": True,
        "module":  "modules.mod_shodan",
        "fn":      "run",
    },
    # ── Active — fingerprinting ────────────────────────────────────────────────
    "tls_audit": {
        "desc":    "Deep TLS audit: ciphers, cert chain/expiry, HSTS, deprecated protocols",
        "passive": False,
        "module":  "modules.mod_tls_audit",
        "fn":      "run",
    },
    "headers": {
        "desc":    "Security header scoring (10 headers, CWE-mapped, A–F grade) + cookie flags",
        "passive": False,
        "module":  "modules.mod_headers",
        "fn":      "run",
    },
    "tech_fingerprint": {
        "desc":    "50+ technology signatures, version disclosure, robots.txt, meta-generator",
        "passive": False,
        "module":  "modules.mod_tech_fingerprint",
        "fn":      "run",
    },
    "favicon_hash": {
        "desc":    "MurmurHash3 favicon fingerprint — 100+ known hashes + Shodan/FOFA pivot",
        "passive": False,
        "module":  "modules.mod_favicon_hash",
        "fn":      "run",
    },
    "waf": {
        "desc":    "WAF fingerprinting (18 providers) + probe-confirmed + bypass hints",
        "passive": False,
        "module":  "modules.mod_waf",
        "fn":      "run",
    },
    # ── Active — vulnerability probing ────────────────────────────────────────
    "cors": {
        "desc":    "CORS: wildcard, arbitrary-origin reflect, null-origin, Vary header",
        "passive": False,
        "module":  "modules.mod_cors",
        "fn":      "run",
    },
    "http_methods": {
        "desc":    "Dangerous method detection: TRACE/PUT/DELETE/DEBUG/WebDAV",
        "passive": False,
        "module":  "modules.mod_http_methods",
        "fn":      "run",
    },
    "js_recon": {
        "desc":    "JS crawler: 20+ endpoint patterns, 25+ secret patterns, entropy-gated",
        "passive": False,
        "module":  "modules.mod_js_recon",
        "fn":      "run",
    },
    "api_fuzzer": {
        "desc":    "API endpoint fuzzing: 100+ wordlist + JS-extracted paths, sensitive file detection",
        "passive": False,
        "module":  "modules.mod_api_fuzzer",
        "fn":      "run",
    },
    "graphql_probe": {
        "desc":    "GraphQL: introspection, field suggestions, batch query, type enumeration",
        "passive": False,
        "module":  "modules.mod_graphql",
        "fn":      "run",
    },
    "open_redirect": {
        "desc":    "Open redirect probe: 25+ params on root, subdomains, and API endpoints",
        "passive": False,
        "module":  "modules.mod_open_redirect",
        "fn":      "run",
    },
    "lfi_probe": {
        "desc":    "LFI / path traversal: 14 payloads × discovered params + PHP wrappers",
        "passive": False,
        "module":  "modules.mod_lfi_probe",
        "fn":      "run",
    },
    "ssrf_probe": {
        "desc":    "SSRF probe: metadata endpoints, localhost, scheme injection, timing analysis",
        "passive": False,
        "module":  "modules.mod_ssrf_probe",
        "fn":      "run",
    },
    "cloud_assets": {
        "desc":    "Cloud bucket discovery: S3/GCS/Azure Blob/DigitalOcean — 200+ permutations",
        "passive": False,
        "module":  "modules.mod_cloud_assets",
        "fn":      "run",
    },
    "vhost_bruteforce": {
        "desc":    "Virtual host brute-force via Host-header fuzzing + baseline fingerprinting",
        "passive": False,
        "module":  "modules.mod_vhost",
        "fn":      "run",
    },
    "takeover": {
        "desc":    "Subdomain takeover: 35+ CNAME service fingerprints, HTTP-confirmed",
        "passive": False,
        "module":  "modules.mod_takeover",
        "fn":      "run",
    },
    "port_scan": {
        "desc":    "TCP port scan (35 ports) with banner grabbing and version extraction",
        "passive": False,
        "module":  "modules.mod_port_scan",
        "fn":      "run",
    },
    "http_smuggling": {
        "desc":    "HTTP smuggling: CL.TE/TE.CL timing probes + TE.TE obfuscation variants",
        "passive": False,
        "module":  "modules.mod_http_smuggling",
        "fn":      "run",
    },
    # ── Active — intelligence correlation ────────────────────────────────────
    "cve_lookup": {
        "desc":    "Tech→CVE correlation: 300+ local CVEs + NVD API live lookup for exact versions",
        "passive": False,
        "module":  "modules.mod_cve_lookup",
        "fn":      "run",
    },
}


def get_module_fn(name: str):
    """Dynamically import and return the run() function for a named module."""
    import importlib
    meta = MODULE_REGISTRY[name]
    mod  = importlib.import_module(meta["module"])
    return getattr(mod, meta["fn"])
