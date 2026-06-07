# ShadowRecon v2.0
### Advanced Penetration Testing Reconnaissance Framework

```
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝
```

---

## What Makes ShadowRecon Different from recon-ng

| Capability | ShadowRecon |
|---|---|
| Active TLS/SSL deep audit | ✅ cipher, chain, HSTS, deprecated protos |
| JS secret/endpoint extraction | ✅ entropy-gated, 25+ patterns |
| Cloud bucket discovery (S3/GCS/Azure/DO) | ✅ unauthenticated, 200+ permutations |
| WAF fingerprint + bypass hints | ✅ 18 WAFs, provider-specific bypass tips |
| ASN expansion via BGPView | ✅ full CIDR range mapping |
| Security header scoring w/ CWE | ✅ 10 headers, A–F grade |
| GitHub org recon + secret search | ✅ repo tree, code search, gist |
| Subdomain takeover (35+ sigs) | ✅ HTTP-confirmed, dangling CNAME |
| SPF/DKIM/DMARC/BIMI/MTA-STS | ✅ full email security audit |
| CORS misconfiguration probe | ✅ wildcard, reflect, null-origin, Vary |
| HTTP request smuggling detection | ✅ CL.TE, TE.CL, TE.TE timing |
| Virtual host brute-force | ✅ Host-header fuzzing, 200+ words |
| GraphQL introspection + batch | ✅ field suggestions, type exposure |
| Favicon hash fingerprint | ✅ 100+ known hashes, Shodan/FOFA pivot |
| Open redirect probe | ✅ 25+ params on root + API endpoints |
| HTTP dangerous method probe | ✅ TRACE/PUT/DEBUG/WebDAV |
| API endpoint fuzzing | ✅ wordlist + JS-extracted paths |
| Port scan with banner grab | ✅ 35 ports, version extraction |
| DNS permutation expansion | ✅ generates + resolves alt variants |
| Full HTML report (dark theme) | ✅ filterable, searchable, severity chart |
| Shared state between modules | ✅ subdomains → takeover → vhost chain |
| Scope file (multi-target) | ✅ `--scope-file targets.txt` |

---

## Installation

```bash
cd shadowrecon/
bash install.sh
```

Requirements: Python 3.10+, pip

---

## Usage

```bash
# Full scan (all modules)
python3 shadowrecon.py -d example.com

# Fast passive-only scan (no active probing)
python3 shadowrecon.py -d example.com --passive-only

# Specific modules only
python3 shadowrecon.py -d example.com --modules whois,dns,subdomains,tls_audit,headers,waf

# With API keys (GitHub + Shodan unlock extra data)
python3 shadowrecon.py -d example.com --github-token ghp_xxxx --shodan-key xxxx

# Faster with more threads
python3 shadowrecon.py -d example.com --threads 25

# Multi-target from scope file
python3 shadowrecon.py --scope-file targets.txt --passive-only

# Custom output directory
python3 shadowrecon.py -d example.com -o /pentest/client/recon/

# List all modules with descriptions
python3 shadowrecon.py --list-modules
```

---

## Module Reference

### Passive Modules (no direct target probing)

| Module | Description |
|---|---|
| `whois` | Registration data, registrar, expiry, renewal risk |
| `dns` | Full DNS record enum, zone transfer, DNSSEC check |
| `cert_transparency` | crt.sh + certspotter + RapidDNS CT log mining |
| `subdomains` | Wordlist brute-force + DNS permutation expansion |
| `asn` | ASN lookup, BGP prefix expansion via BGPView |
| `email_security` | SPF/DKIM (23 selectors)/DMARC/BIMI/MTA-STS audit |
| `github_recon` | Org discovery, repo tree, sensitive file + code search |
| `wayback` | CDX mining, historical URL classification, param discovery |
| `shodan_query` | Host/org lookup, CVE feed, banner data (needs key) |

### Active Modules (touch the target)

| Module | Description |
|---|---|
| `tls_audit` | TLS version, cipher, cert chain, expiry, HSTS, deprecated protos |
| `headers` | Security headers: 10 headers, CWE-mapped, A–F grade, cookie flags |
| `tech_fingerprint` | 50+ tech signatures, version disclosure, robots.txt |
| `favicon_hash` | MurmurHash3 fingerprint, 100+ known hashes, Shodan/FOFA pivot |
| `waf` | 18 WAF fingerprints, probe-based confirmation, bypass hints |
| `cors` | Wildcard, arbitrary-origin reflect, null-origin, Vary header |
| `http_methods` | TRACE/PUT/DELETE/DEBUG/WebDAV on root + subdomains |
| `js_recon` | JS crawl: 20+ endpoint patterns, 25+ secret patterns, entropy gate |
| `api_fuzzer` | 100+ path wordlist + JS endpoints, sensitive file detection |
| `graphql_probe` | Introspection, field suggestions, batch query, type enumeration |
| `open_redirect` | 25+ redirect params on root, subdomains, and API endpoints |
| `cloud_assets` | S3/GCS/Azure Blob/DigitalOcean — 200+ bucket name permutations |
| `vhost_bruteforce` | Host-header fuzzing, baseline-diff fingerprinting, 200+ words |
| `takeover` | 35+ CNAME service signatures, HTTP-confirmed vs dangling |
| `port_scan` | 35 common ports, banner grab, version extraction, risky port flags |
| `http_smuggling` | CL.TE / TE.CL timing probes, TE.TE obfuscation variants |

---

## Output

Every scan produces three reports in `output/<domain>_<timestamp>/`:

- **`report.html`** — Dark-themed interactive report with:
  - Severity breakdown cards + distribution bars
  - Filterable + searchable findings table with CWE links
  - Subdomain table, open port table, technology table
  - API endpoint list from JS recon
- **`report.json`** — Machine-readable: meta, findings, full state, per-module results
- **`report.txt`** — Plain-text: findings summary + full console log

---

## Architecture

```
shadowrecon/
├── shadowrecon.py          # Entry point
├── install.sh              # Dependency installer
├── config/
│   └── settings.json       # Default configuration
├── core/
│   ├── cli.py              # Argument parsing
│   ├── engine.py           # Orchestration + module runner
│   ├── output.py           # Rich/plain output manager
│   ├── registry.py         # Module registry (name → loader)
│   └── reporter.py         # TXT + JSON + HTML report generation
├── modules/
│   ├── _constants.py       # Shared: wordlists, signatures, patterns
│   ├── _http.py            # Shared: HTTP helpers, rate limiting
│   ├── mod_whois.py
│   ├── mod_dns.py
│   ├── mod_cert_transparency.py
│   ├── mod_subdomains.py
│   ├── mod_asn.py
│   ├── mod_email_security.py
│   ├── mod_github_recon.py
│   ├── mod_wayback.py
│   ├── mod_shodan.py
│   ├── mod_tls_audit.py
│   ├── mod_headers.py
│   ├── mod_tech_fingerprint.py
│   ├── mod_favicon_hash.py
│   ├── mod_waf.py
│   ├── mod_cors.py
│   ├── mod_http_methods.py
│   ├── mod_js_recon.py
│   ├── mod_api_fuzzer.py
│   ├── mod_graphql.py
│   ├── mod_open_redirect.py
│   ├── mod_cloud_assets.py
│   ├── mod_vhost.py
│   ├── mod_takeover.py
│   ├── mod_port_scan.py
│   └── mod_http_smuggling.py
└── output/                 # Generated reports land here
```

---

## Adding a Custom Module

1. Create `modules/mod_yourmodule.py` with a `run(domain, args, out, state)` function
2. Add an entry to `core/registry.py` under `MODULE_REGISTRY`
3. Run with `--modules yourmodule` or include in `all`

```python
# modules/mod_example.py
def run(domain, args, out, state):
    result = {"issues": []}
    out.info(f"Running against {domain}")
    # Use state.subdomains, state.ips, state.open_ports, state.endpoints
    # Call out.finding(severity, message, cwe=..., module=..., url=...)
    # Append to result["issues"] for report aggregation
    return result
```

---

## Notes

- All findings include **CWE identifiers** suitable for pentest reports
- Modules share state (subdomains discovered in CT flow into takeover checks)
- Rate limiting built into `_http.py` (default 20 req/s) — adjust with `--rate-limit`
- `--passive-only` skips all modules that touch the target directly
- GitHub code search works unauthenticated but at 60 req/hr; `--github-token` unlocks 5000/hr

---

## Acknowledgements

Development of ShadowRecon was accelerated with assistance from **Anthropic Claude** for research, architecture planning, implementation support, and documentation generation.

---
