#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                         ShadowRecon v1.0                                 ║
║          Advanced Penetration Testing Reconnaissance Framework            ║
║                                                                           ║
║  What recon-ng can't do:                                                  ║
║  • Active TLS/SSL deep analysis (cipher, cert chain, HSTS, CT logs)      ║
║  • JavaScript endpoint/secret extraction (no API key required)            ║
║  • Cloud asset discovery (S3, GCS, Azure blob — unauthenticated)         ║
║  • WAF fingerprinting with bypass hints                                   ║
║  • ASN → IP range expansion                                               ║
║  • Security header scoring with CWE mapping                               ║
║  • GitHub org secret/exposure hunting (unauthenticated)                  ║
║  • Subdomain takeover detection (30+ CNAME signatures)                   ║
║  • SPF/DKIM/DMARC email security audit                                    ║
║  • CORS misconfiguration probe                                            ║
║  • Full pipeline: passive → active → report (no interactive shell needed) ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
    python3 shadow_recon.py -d example.com [OPTIONS]

    Options:
        -d, --domain        Target domain (required)
        -o, --output        Output file (default: shadow_recon_<domain>.txt)
        --modules           Comma-separated list of modules to run (default: all)
        --passive-only      Skip active probing modules
        --threads           Thread count (default: 10)
        --timeout           Request timeout seconds (default: 8)
        --github-token      GitHub API token (optional, increases rate limit)
        --shodan-key        Shodan API key (optional)
        --no-color          Disable colored output
        -v, --verbose       Verbose output
        --list-modules      Print all available modules and exit

    Available modules:
        whois, dns, subdomains, cert_transparency, asn, cloud_assets,
        tls_audit, headers, cors, waf, js_recon, takeover, email_security,
        github_recon, wayback, tech_fingerprint, port_scan, report

Author: ShadowRecon Framework
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

# ── Dependency guard ──────────────────────────────────────────────────────────
MISSING = []
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    MISSING.append("requests")

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    import dns.rdatatype
except ImportError:
    MISSING.append("dnspython")

try:
    import whois as pywhois
except ImportError:
    MISSING.append("python-whois")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
    from rich.text import Text
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False

if MISSING:
    print(f"[!] Missing required packages: {', '.join(MISSING)}")
    print(f"    pip install {' '.join(MISSING)} --break-system-packages")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "1.0"
BANNER = r"""
  _____ _               _              _____
 / ____| |             | |            |  __ \
| (___ | |__   __ _  __| | _____      | |__) |___  ___ ___  _ __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  _  // _ \/ __/ _ \| '_ \
 ____) | | | | (_| | (_| | (_) \ V  V /| | \ \  __/ (_| (_) | | | |
|_____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_|  \_\___|\___\___/|_| |_|
"""

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
HEADERS_DEFAULT = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

# Subdomain takeover fingerprints  {cname_fragment: (service, fingerprint_string)}
TAKEOVER_SIGS = {
    "github.io":            ("GitHub Pages",       "There isn't a GitHub Pages site here"),
    "amazonaws.com":        ("AWS S3",             "NoSuchBucket"),
    "s3.amazonaws.com":     ("AWS S3",             "NoSuchBucket"),
    "cloudfront.net":       ("CloudFront",         "Bad request"),
    "azurewebsites.net":    ("Azure Web Apps",     "404 Web Site not found"),
    "blob.core.windows.net":("Azure Blob",         "No webpage was found"),
    "fastly.net":           ("Fastly",             "Fastly error: unknown domain"),
    "herokussl.com":        ("Heroku",             "No such app"),
    "herokudns.com":        ("Heroku",             "No such app"),
    "herokuapp.com":        ("Heroku",             "No such app"),
    "shopify.com":          ("Shopify",            "Sorry, this shop is currently unavailable"),
    "desk.com":             ("Desk",               "Sorry, We Couldn't Find That Page"),
    "zendesk.com":          ("Zendesk",            "Help Center Closed"),
    "readme.io":            ("Readme.io",          "Project doesnt exist"),
    "surge.sh":             ("Surge.sh",           "project not found"),
    "unbounce.com":         ("Unbounce",           "The requested URL was not found on this server"),
    "tumblr.com":           ("Tumblr",             "Whatever you were looking for doesn't live here"),
    "ghost.io":             ("Ghost",              "The thing you were looking for is no longer here"),
    "pantheon.io":          ("Pantheon",           "404 error unknown site"),
    "wpengine.com":         ("WP Engine",          "The site you were looking for couldn't be found"),
    "strikingly.com":       ("Strikingly",         "page not found"),
    "statuspage.io":        ("Statuspage",         "Better Uptime"),
    "bitbucket.io":         ("Bitbucket",          "Repository not found"),
    "webflow.io":           ("Webflow",            "The page you are looking for doesn't exist"),
    "helpscout.net":        ("Help Scout",         "No settings were found for this company"),
    "freshdesk.com":        ("Freshdesk",          "There is no helpdesk here"),
    "aftership.com":        ("AfterShip",          "Oops."),
    "mailchimp.com":        ("Mailchimp",          "Oops! That page doesn't exist"),
    "intercom.io":          ("Intercom",           "This page is reserved"),
    "fly.dev":              ("Fly.io",             "404 Not Found"),
    "vercel.app":           ("Vercel",             "The deployment could not be found"),
}

# Cloud bucket prefixes per provider
CLOUD_PROVIDERS = {
    "s3": {
        "check": lambda b: f"https://{b}.s3.amazonaws.com",
        "not_exist": ["NoSuchBucket", "InvalidBucketName"],
        "public":    ["ListBucketResult", "Contents"],
        "exists":    ["AccessDenied", "AllAccessDisabled", "RequestTimeTooSkewed"],
    },
    "gcs": {
        "check": lambda b: f"https://storage.googleapis.com/{b}",
        "not_exist": ["NoSuchBucket", "The specified bucket does not exist"],
        "public":    ["<Contents>", "<?xml"],
        "exists":    ["AccessDenied", "Forbidden", "BucketNotPublic"],
    },
    "azure": {
        "check": lambda b: f"https://{b}.blob.core.windows.net",
        "not_exist": ["BlobServiceProperties", "ResourceNotFound", "The specified resource does not exist"],
        "public":    ["EnumerationResults", "<Blobs>"],
        "exists":    ["PublicAccessNotPermitted", "AuthorizationFailure"],
    },
}

# JS secret regex patterns
JS_SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Slack Token":          r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "GitHub Token":         r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Private Key":          r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":         r"https://[a-z0-9-]+\.firebaseio\.com",
    "Twilio":               r"SK[0-9a-fA-F]{32}",
    "SendGrid":             r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "JWT":                  r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Basic Auth URL":       r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+",
    "Stripe Key":           r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Mailgun Key":          r"key-[0-9a-zA-Z]{32}",
    "Password in JS":       r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "API Key in JS":        r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    "Bearer Token":         r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "S3 Bucket URL":        r"https?://[a-z0-9\-\.]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com",
    "Internal IP":          r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}",
    "GraphQL Endpoint":     r"(?i)/graphql[\"'\s]|graphql.{0,5}endpoint",
    "Debug/Admin Path":     r"(?i)['\"/](?:admin|debug|console|test|dev|staging|internal)['\"/]",
}

# WAF fingerprints
WAF_SIGNATURES = {
    "Cloudflare":       ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF":          ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai":           ["akamai", "ak_bmsc", "x-akamai-transformed", "x-check-cacheable"],
    "F5 BIG-IP ASM":    ["ts", "x-wa-info", "bigipserver", "f5-ltm"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "_incapsula_"],
    "Sucuri":           ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "Barracuda":        ["bni__", "bni_persistence"],
    "ModSecurity":      ["mod_security", "modsec", "NOYB"],
    "Nginx WAF":        ["x-nginx-cache", "x-content-type-options"],
    "Fortinet":         ["fortigate", "fortibalancer", "cookiesession1"],
    "DDoS-Guard":       ["ddos-guard", "__ddg"],
    "Fastly":           ["fastly", "x-fastly-request-id", "x-served-by"],
    "Reblaze":          ["rbzid", "rbzsessionid"],
    "Wallarm":          ["x-wallarm-node"],
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "cwe": "CWE-319",
        "severity": "HIGH",
        "desc": "Missing HSTS — allows protocol downgrade/MITM",
        "good": lambda v: "max-age" in v and int(re.search(r"max-age=(\d+)", v).group(1)) >= 31536000 if re.search(r"max-age=(\d+)", v) else False,
    },
    "Content-Security-Policy": {
        "cwe": "CWE-79",
        "severity": "MEDIUM",
        "desc": "Missing CSP — XSS risk elevated",
        "good": lambda v: len(v) > 20 and "unsafe-inline" not in v,
    },
    "X-Frame-Options": {
        "cwe": "CWE-1021",
        "severity": "MEDIUM",
        "desc": "Missing X-Frame-Options — clickjacking risk",
        "good": lambda v: v.strip().upper() in ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "cwe": "CWE-116",
        "severity": "LOW",
        "desc": "Missing X-Content-Type-Options — MIME sniffing risk",
        "good": lambda v: v.strip().lower() == "nosniff",
    },
    "Referrer-Policy": {
        "cwe": "CWE-200",
        "severity": "LOW",
        "desc": "Missing Referrer-Policy — information disclosure",
        "good": lambda v: any(x in v.lower() for x in ["no-referrer", "strict-origin", "same-origin"]),
    },
    "Permissions-Policy": {
        "cwe": "CWE-276",
        "severity": "INFO",
        "desc": "Missing Permissions-Policy — browser features unrestricted",
        "good": lambda v: len(v) > 5,
    },
    "X-XSS-Protection": {
        "cwe": "CWE-79",
        "severity": "INFO",
        "desc": "Missing/disabled X-XSS-Protection",
        "good": lambda v: v.startswith("1"),
    },
    "Cache-Control": {
        "cwe": "CWE-524",
        "severity": "LOW",
        "desc": "Missing Cache-Control — sensitive data may be cached",
        "good": lambda v: "no-store" in v or "private" in v,
    },
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 2222, 3000, 3306, 3389, 4443, 5432, 5900, 6379,
                7443, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 9300, 27017]

WORDLIST_SUBDOMAINS = [
    "www","mail","ftp","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","portal","api","dev","staging","test","admin","app","mobile",
    "beta","mx","email","cloud","cdn","media","static","assets","images","git","gitlab",
    "jira","confluence","jenkins","ci","cd","sso","auth","login","oauth","status",
    "support","helpdesk","forum","wiki","docs","download","internal","intranet","extranet",
    "sandbox","uat","qa","prod","dashboard","manage","panel","control","cpanel","whm",
    "phpmyadmin","db","database","sql","mysql","mongo","redis","elastic","kibana","grafana",
    "prometheus","backup","bak","old","legacy","archive","v1","v2","new","web","website",
    "microservice","service","svc","gateway","gw","proxy","lb","load-balancer","waf",
    "edge","api-v1","api-v2","rest","graphql","grpc","ws","websocket","stream",
]

# ── Colour / Rich wrappers ────────────────────────────────────────────────────

class Output:
    """Thin wrapper so the tool works with or without rich."""
    def __init__(self, no_color: bool = False):
        self.use_rich = HAS_RICH and not no_color
        if self.use_rich:
            self.console = Console()
        self.lines: list[str] = []  # raw text log for file output

    def _strip(self, msg: str) -> str:
        return re.sub(r"\[/?[a-z_ ]+\]", "", msg)

    def print(self, msg: str = "", **kwargs):
        clean = self._strip(msg)
        self.lines.append(clean)
        if self.use_rich:
            self.console.print(msg, **kwargs)
        else:
            print(clean)

    def rule(self, title: str = ""):
        self.lines.append(f"\n{'─'*60} {title} {'─'*60}\n")
        if self.use_rich:
            self.console.rule(f"[bold cyan]{title}[/bold cyan]")
        else:
            print(f"\n{'─'*60} {title} {'─'*60}\n")

    def success(self, msg: str):
        self.print(f"[bold green][+][/bold green] {msg}")

    def warn(self, msg: str):
        self.print(f"[bold yellow][!][/bold yellow] {msg}")

    def fail(self, msg: str):
        self.print(f"[bold red][-][/bold red] {msg}")

    def info(self, msg: str):
        self.print(f"[cyan][*][/cyan] {msg}")

    def finding(self, severity: str, msg: str):
        color_map = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                     "LOW": "blue", "INFO": "dim"}
        color = color_map.get(severity, "white")
        self.print(f"  [{color}][{severity}][/{color}] {msg}")

    def kv(self, key: str, val: str):
        self.print(f"  [bold]{key}:[/bold] {val}")


out = Output()  # global, replaced after arg parse


# ── Helpers ───────────────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = 8, allow_redirects: bool = True,
             verify: bool = False, extra_headers: dict = None) -> Optional[requests.Response]:
    headers = dict(HEADERS_DEFAULT)
    if extra_headers:
        headers.update(extra_headers)
    try:
        return requests.get(url, headers=headers, timeout=timeout,
                            allow_redirects=allow_redirects, verify=verify)
    except Exception:
        return None


def extract_root_domain(domain: str) -> str:
    if HAS_TLDEXTRACT:
        e = tldextract.extract(domain)
        return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else domain
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def resolve_domain(domain: str) -> list[str]:
    ips = []
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
    except Exception:
        pass
    return ips


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── Module: WHOIS ─────────────────────────────────────────────────────────────

def module_whois(domain: str, args) -> dict:
    out.rule("WHOIS")
    result = {}
    try:
        w = pywhois.whois(domain)
        fields = {
            "Registrar":        getattr(w, "registrar", None),
            "Org":              getattr(w, "org", None),
            "Registrant Email": getattr(w, "emails", None),
            "Created":          getattr(w, "creation_date", None),
            "Expires":          getattr(w, "expiration_date", None),
            "Updated":          getattr(w, "updated_date", None),
            "Name Servers":     getattr(w, "name_servers", None),
            "Status":           getattr(w, "status", None),
        }
        for k, v in fields.items():
            if v:
                if isinstance(v, list):
                    v = v[0] if len(v) == 1 else str(v[:3])
                out.kv(k, str(v))
                result[k] = str(v)

        # Check expiry
        exp = getattr(w, "expiration_date", None)
        if exp:
            if isinstance(exp, list):
                exp = exp[0]
            try:
                if hasattr(exp, "replace"):
                    exp_aware = exp.replace(tzinfo=timezone.utc) if exp.tzinfo is None else exp
                    days_left = (exp_aware - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        out.warn(f"Domain expires in {days_left} days — renewal risk")
                        result["EXPIRY_ALERT"] = f"{days_left} days"
            except Exception:
                pass
    except Exception as e:
        out.fail(f"WHOIS lookup failed: {e}")
    return result


# ── Module: DNS Enumeration ────────────────────────────────────────────────────

def module_dns(domain: str, args) -> dict:
    out.rule("DNS Records")
    result = {"records": {}}
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    for rtype in rtypes:
        try:
            answers = resolver.resolve(domain, rtype)
            recs = [str(r) for r in answers]
            result["records"][rtype] = recs
            out.success(f"{rtype}: {', '.join(recs)}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            out.fail("Domain does not resolve (NXDOMAIN)")
            break
        except Exception:
            pass

    # Zone transfer attempt
    ns_list = result["records"].get("NS", [])
    for ns in ns_list:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            out.finding("HIGH", f"ZONE TRANSFER ALLOWED on {ns}! (CWE-200)")
            result["zone_transfer"] = {"ns": ns, "records": list(z.nodes.keys())}
        except Exception:
            pass

    # Check for wildcard DNS
    random_sub = f"zxcv1337qwer.{domain}"
    if resolve_domain(random_sub):
        out.finding("INFO", "Wildcard DNS detected — subdomain results may include false positives")
        result["wildcard"] = True

    return result


# ── Module: Subdomain Enumeration ─────────────────────────────────────────────

def module_subdomains(domain: str, args) -> dict:
    out.rule("Subdomain Enumeration")
    found = set()
    result = {"subdomains": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            return fqdn, ips
        except Exception:
            return None

    out.info(f"Brute-forcing {len(WORDLIST_SUBDOMAINS)} common subdomains ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_sub, s): s for s in WORDLIST_SUBDOMAINS}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                fqdn, ips = res
                if fqdn not in found:
                    found.add(fqdn)
                    out.success(f"{fqdn}  →  {', '.join(ips)}")
                    result["subdomains"].append({"host": fqdn, "ips": ips})

    # Certificate Transparency (crt.sh) — passive, no brute
    out.info("Querying crt.sh for certificate transparency records ...")
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=12)
        if r and r.status_code == 200:
            entries = r.json()
            ct_subs = set()
            for e in entries:
                names = e.get("name_value", "").split("\n")
                for n in names:
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") and n not in found:
                        ct_subs.add(n)
            # Resolve ct subs
            def resolve_ct(fqdn):
                ips = resolve_domain(fqdn)
                return (fqdn, ips) if ips else None

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                futures2 = {ex.submit(resolve_ct, s): s for s in ct_subs}
                for f in concurrent.futures.as_completed(futures2):
                    res = f.result()
                    if res:
                        fqdn, ips = res
                        if fqdn not in found:
                            found.add(fqdn)
                            out.success(f"{fqdn}  →  {', '.join(ips)}  [CT]")
                            result["subdomains"].append({"host": fqdn, "ips": ips, "source": "CT"})
            out.info(f"Certificate transparency revealed {len(ct_subs)} unique names")
    except Exception as e:
        out.fail(f"crt.sh query failed: {e}")

    out.info(f"Total subdomains found: {len(result['subdomains'])}")
    return result


# ── Module: ASN / IP Range Expansion ─────────────────────────────────────────

def module_asn(domain: str, args) -> dict:
    out.rule("ASN & IP Range Expansion")
    result = {"asn": [], "ip_ranges": []}
    ips = resolve_domain(domain)
    if not ips:
        out.fail("Cannot resolve domain to IP for ASN lookup")
        return result

    out.info(f"Resolved IPs: {', '.join(ips)}")

    for ip in ips[:3]:
        if not HAS_IPWHOIS:
            out.warn("ipwhois not installed — skipping ASN lookup")
            break
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn = res.get("asn", "?")
            asn_desc = res.get("asn_description", "?")
            cidr = res.get("asn_cidr", "?")
            country = res.get("asn_country_code", "?")
            out.success(f"IP: {ip}  ASN: AS{asn}  ORG: {asn_desc}  CIDR: {cidr}  Country: {country}")
            entry = {"ip": ip, "asn": asn, "org": asn_desc, "cidr": cidr, "country": country}
            result["asn"].append(entry)

            # Count IPs in range
            if cidr and "/" in cidr:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    out.info(f"  → ASN CIDR {cidr} contains {net.num_addresses:,} IPs — potential org-wide scan scope")
                    result["ip_ranges"].append(cidr)
                except Exception:
                    pass
        except Exception as e:
            out.fail(f"ASN lookup for {ip}: {e}")

    # Try BGPView for additional ranges
    for asn_entry in result["asn"][:1]:
        asn_num = asn_entry.get("asn")
        if not asn_num:
            continue
        try:
            r = http_get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=10)
            if r and r.status_code == 200:
                data = r.json().get("data", {})
                v4 = data.get("ipv4_prefixes", [])
                for prefix in v4[:10]:
                    cidr_prefix = prefix.get("prefix", "")
                    out.info(f"  Prefix: {cidr_prefix}  ({prefix.get('description','')})")
                    if cidr_prefix not in result["ip_ranges"]:
                        result["ip_ranges"].append(cidr_prefix)
        except Exception:
            pass

    return result


# ── Module: TLS / SSL Deep Audit ──────────────────────────────────────────────

def module_tls_audit(domain: str, args) -> dict:
    out.rule("TLS / SSL Audit")
    result = {"cert": {}, "issues": []}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force TLS 1.2+ check
        with socket.create_connection((domain, 443), timeout=args.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, tls_ver, bits = ssock.cipher()

                out.kv("Protocol", protocol)
                out.kv("Cipher Suite", f"{cipher_name} ({bits}-bit)")

                result["cert"]["protocol"] = protocol
                result["cert"]["cipher"] = cipher_name
                result["cert"]["bits"] = bits

                # Check for weak ciphers
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]
                for wc in weak_ciphers:
                    if wc.upper() in cipher_name.upper():
                        out.finding("HIGH", f"Weak cipher in use: {cipher_name} (CWE-326)")
                        result["issues"].append({"severity": "HIGH", "desc": f"Weak cipher: {cipher_name}", "cwe": "CWE-326"})

                # Check key size
                if bits and int(bits) < 128:
                    out.finding("CRITICAL", f"Cipher key too short: {bits} bits (CWE-326)")
                    result["issues"].append({"severity": "CRITICAL", "desc": f"Key size too short: {bits}", "cwe": "CWE-326"})

                # Parse cert fields
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    not_after_str = cert.get("notAfter", "")
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                    out.kv("Subject CN", subj.get("commonName", "?"))
                    out.kv("Issuer", issuer.get("organizationName", "?"))
                    out.kv("SANs", ", ".join(sans[:8]) + ("..." if len(sans) > 8 else ""))

                    result["cert"].update({"cn": subj.get("commonName"), "issuer": issuer.get("organizationName"),
                                           "sans": sans, "not_after": not_after_str})

                    # Expiry check
                    if not_after_str:
                        try:
                            exp = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            exp = exp.replace(tzinfo=timezone.utc)
                            days_left = (exp - datetime.now(timezone.utc)).days
                            out.kv("Expires", f"{not_after_str}  ({days_left} days)")
                            if days_left < 0:
                                out.finding("CRITICAL", f"Certificate EXPIRED {abs(days_left)} days ago (CWE-295)")
                                result["issues"].append({"severity": "CRITICAL", "desc": "Cert expired", "cwe": "CWE-295"})
                            elif days_left < 14:
                                out.finding("HIGH", f"Cert expires in {days_left} days")
                                result["issues"].append({"severity": "HIGH", "desc": f"Cert expires soon: {days_left}d", "cwe": "CWE-295"})
                        except Exception:
                            pass

                    # Self-signed check
                    if subj.get("commonName") == issuer.get("commonName"):
                        out.finding("HIGH", "Self-signed certificate detected (CWE-295)")
                        result["issues"].append({"severity": "HIGH", "desc": "Self-signed cert", "cwe": "CWE-295"})

                    # Wildcard cert
                    for san in sans:
                        if san.startswith("*."):
                            out.finding("INFO", f"Wildcard cert SAN: {san}")

    except ConnectionRefusedError:
        out.fail("Port 443 refused — TLS not available")
    except socket.timeout:
        out.fail("TLS connection timed out")
    except Exception as e:
        out.fail(f"TLS audit error: {e}")

    # Check for SSLv3/TLS 1.0/1.1 (via openssl s_client if available)
    for bad_proto, flag in [("TLS 1.0", "-tls1"), ("TLS 1.1", "-tls1_1")]:
        try:
            proc = subprocess.run(
                ["openssl", "s_client", flag, "-connect", f"{domain}:443", "-quiet"],
                input=b"", capture_output=True, timeout=5
            )
            if b"CONNECTED" in proc.stdout or b"Certificate chain" in proc.stderr:
                out.finding("MEDIUM", f"{bad_proto} supported — deprecated protocol (CWE-326)")
                result["issues"].append({"severity": "MEDIUM", "desc": f"{bad_proto} supported", "cwe": "CWE-326"})
        except Exception:
            pass

    return result


# ── Module: Security Headers ──────────────────────────────────────────────────

def module_headers(domain: str, args) -> dict:
    out.rule("Security Headers")
    result = {"headers": {}, "score": 0, "max_score": 0, "issues": []}
    r = http_get(f"https://{domain}", timeout=args.timeout)
    if not r:
        r = http_get(f"http://{domain}", timeout=args.timeout)
    if not r:
        out.fail("Could not reach target")
        return result

    # Record interesting response headers
    interesting = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
                   "X-Runtime", "X-Version", "X-Debug-Token"]
    for h in interesting:
        val = r.headers.get(h)
        if val:
            out.finding("INFO", f"Info disclosure via header {h}: {val}")
            result["headers"][h] = val

    score = 0
    max_score = 0
    for header, cfg in SECURITY_HEADERS.items():
        max_score += 1
        val = r.headers.get(header)
        if not val:
            sev = cfg["severity"]
            cwe = cfg["cwe"]
            desc = cfg["desc"]
            out.finding(sev, f"Missing {header} — {desc} ({cwe})")
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
                out.finding(cfg["severity"], f"Misconfigured {header}: {val[:80]} ({cfg['cwe']})")
                result["issues"].append({"header": header, "severity": cfg["severity"],
                                         "cwe": cfg["cwe"], "desc": f"Misconfigured: {val[:80]}"})
                score += 0.5

    result["score"] = round(score)
    result["max_score"] = max_score
    grade_map = [(max_score*0.9, "A"), (max_score*0.7, "B"), (max_score*0.5, "C"),
                 (max_score*0.3, "D"), (0, "F")]
    grade = next(g for threshold, g in grade_map if score >= threshold)
    out.info(f"Security Header Score: {round(score)}/{max_score}  (Grade: {grade})")
    result["grade"] = grade
    return result


# ── Module: CORS Misconfiguration Probe ──────────────────────────────────────

def module_cors(domain: str, args) -> dict:
    out.rule("CORS Misconfiguration")
    result = {"issues": []}
    if args.passive_only:
        out.info("Skipped (passive-only mode)")
        return result

    targets = [f"https://{domain}", f"https://api.{domain}"]
    evil_origins = [
        f"https://evil.com",
        f"https://{domain}.evil.com",
        f"null",
        f"https://evil{domain}",
    ]

    for url in targets:
        for origin in evil_origins:
            r = http_get(url, timeout=args.timeout,
                         extra_headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                out.finding("MEDIUM", f"Wildcard CORS on {url} (CWE-942)")
                result["issues"].append({"url": url, "severity": "MEDIUM", "desc": "Wildcard CORS", "cwe": "CWE-942"})
                break
            elif acao == origin and origin != "null":
                if acac.lower() == "true":
                    out.finding("HIGH", f"CORS reflects arbitrary origin WITH credentials on {url} — credential theft risk (CWE-942)")
                    result["issues"].append({"url": url, "origin": origin, "severity": "HIGH",
                                             "desc": "Reflected CORS + credentials", "cwe": "CWE-942"})
                else:
                    out.finding("LOW", f"CORS reflects arbitrary origin on {url} (no credentials) (CWE-942)")
                    result["issues"].append({"url": url, "origin": origin, "severity": "LOW",
                                             "desc": "Reflected CORS", "cwe": "CWE-942"})
                break
            elif acao == "null":
                out.finding("MEDIUM", f"null-origin CORS accepted on {url} — sandbox bypass risk (CWE-942)")
                result["issues"].append({"url": url, "severity": "MEDIUM", "desc": "null-origin CORS", "cwe": "CWE-942"})
                break

    if not result["issues"]:
        out.success("No CORS misconfigurations detected")
    return result


# ── Module: WAF Fingerprinting ────────────────────────────────────────────────

def module_waf(domain: str, args) -> dict:
    out.rule("WAF Fingerprinting")
    result = {"waf": None, "bypass_hints": []}

    r = http_get(f"https://{domain}", timeout=args.timeout)
    if not r:
        out.fail("Cannot reach target for WAF detection")
        return result

    all_headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
    server = r.headers.get("Server", "")
    combined = " ".join(all_headers_lower.values()) + " " + server.lower()

    detected = []
    for waf_name, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            detected.append(waf_name)

    # Also try a malicious payload to trigger WAF
    xss_payload = "<script>alert(1)</script>"
    r2 = http_get(f"https://{domain}/?q={urllib.parse.quote(xss_payload)}", timeout=args.timeout)
    if r2 and r2.status_code in [403, 406, 429, 503]:
        if not detected:
            out.finding("INFO", f"WAF likely present — XSS probe returned HTTP {r2.status_code}")
            result["waf"] = f"Unknown WAF (triggered by XSS probe, status {r2.status_code})"

    if detected:
        waf_str = ", ".join(detected)
        out.finding("INFO", f"WAF Detected: {waf_str}")
        result["waf"] = waf_str

        # Bypass hints per WAF
        hints_map = {
            "Cloudflare":       ["Use Unicode obfuscation", "Try HTTP/2", "Use Cloudflare Workers bypass via Host header"],
            "Akamai":           ["Try chunked transfer encoding", "Use HTTP header injection", "Test with slow POST"],
            "AWS WAF":          ["Try JSON-encoded payloads", "Use double URL encoding", "Exploit regex anchor issues"],
            "Imperva/Incapsula":["Use multipart/form-data", "Try HPP (HTTP Parameter Pollution)", "Use charset confusion"],
            "F5 BIG-IP ASM":    ["Try alternating case in keywords", "Use line continuation characters"],
            "ModSecurity":      ["Try comment injection in SQL", "Use UNION SELECT with null bytes"],
        }
        for detected_waf in detected:
            hints = hints_map.get(detected_waf, ["Manual fingerprinting recommended"])
            for hint in hints:
                out.info(f"  Bypass hint ({detected_waf}): {hint}")
                result["bypass_hints"].append({"waf": detected_waf, "hint": hint})
    else:
        out.success("No WAF detected (or WAF not fingerprinted)")

    return result


# ── Module: JS Endpoint & Secret Extraction ───────────────────────────────────

def module_js_recon(domain: str, args) -> dict:
    out.rule("JavaScript Recon (Endpoints & Secrets)")
    result = {"js_files": [], "endpoints": [], "secrets": []}

    # Crawl main page for JS files
    base_urls = [f"https://{domain}", f"https://www.{domain}"]
    js_urls = set()

    for base in base_urls:
        r = http_get(base, timeout=args.timeout)
        if not r:
            continue
        # Extract JS src
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base.rstrip("/") + src
            elif not src.startswith("http"):
                src = base.rstrip("/") + "/" + src
            if domain in src or src.startswith(base):
                js_urls.add(src)

        # Also grab inline JS to check for endpoints
        inline_js = " ".join(re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL | re.IGNORECASE))
        _extract_from_js(inline_js, domain, result, source="inline")

    out.info(f"Found {len(js_urls)} JS files to analyse")

    def analyse_js(url):
        r = http_get(url, timeout=args.timeout)
        if not r or not r.text:
            return
        result["js_files"].append(url)
        _extract_from_js(r.text, domain, result, source=url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 5)) as ex:
        list(ex.map(analyse_js, list(js_urls)[:30]))

    # Deduplicate
    result["endpoints"] = list(set(result["endpoints"]))
    seen_secs = set()
    deduped_secrets = []
    for s in result["secrets"]:
        key = (s["type"], s["match"][:40])
        if key not in seen_secs:
            seen_secs.add(key)
            deduped_secrets.append(s)
    result["secrets"] = deduped_secrets

    out.info(f"Endpoints extracted: {len(result['endpoints'])}")
    out.info(f"Potential secrets found: {len(result['secrets'])}")
    return result


def _extract_from_js(js_text: str, domain: str, result: dict, source: str):
    # Endpoints
    endpoint_patterns = [
        r'["\'](/(?:api|v\d|rest|graphql|internal|admin|auth|oauth|endpoint|service|backend|user|account|payment|webhook)[^"\'<>\s]{0,100})["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        r'(?:xhr|ajax|http)\.(?:open|get|post)\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']{5,100})["\']',
    ]
    for pat in endpoint_patterns:
        for match in re.finditer(pat, js_text, re.IGNORECASE):
            ep = match.group(1)
            if ep and not ep.startswith("//") and len(ep) < 200:
                result["endpoints"].append(ep)

    # Secrets
    for secret_type, pattern in JS_SECRET_PATTERNS.items():
        for match in re.finditer(pattern, js_text):
            hit = match.group(0)
            # Skip obvious false positives
            if any(fp in hit.lower() for fp in ["example", "placeholder", "your_", "YOUR_", "xxxxxxx", "undefined"]):
                continue
            out.finding("HIGH" if any(x in secret_type for x in ["AWS", "Key", "Token", "Private", "JWT"]) else "MEDIUM",
                        f"{secret_type} in {source.split('/')[-1]}: {hit[:60]}...")
            result["secrets"].append({"type": secret_type, "match": hit, "source": source})


# ── Module: Subdomain Takeover ────────────────────────────────────────────────

def module_takeover(domain: str, args, subdomains: list) -> dict:
    out.rule("Subdomain Takeover Detection")
    result = {"vulnerable": [], "dangling": []}

    if not subdomains:
        out.info("No subdomains to check")
        return result

    def check_takeover(sub_entry):
        host = sub_entry["host"]
        # Get CNAME chain
        cnames = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(host, "CNAME")
            cnames = [str(r).rstrip(".") for r in answers]
        except Exception:
            pass

        for cname in cnames:
            for sig_domain, (service, fingerprint) in TAKEOVER_SIGS.items():
                if sig_domain in cname:
                    # Probe HTTP to confirm fingerprint
                    r = http_get(f"http://{host}", timeout=5)
                    if r and fingerprint.lower() in r.text.lower():
                        return {"host": host, "cname": cname, "service": service,
                                "status": "VULNERABLE", "fingerprint": fingerprint}
                    elif r is None:
                        return {"host": host, "cname": cname, "service": service,
                                "status": "DANGLING (unconfirmed)", "fingerprint": fingerprint}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_takeover, s): s for s in subdomains}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                if "VULNERABLE" in res["status"]:
                    out.finding("CRITICAL", f"TAKEOVER: {res['host']} → {res['cname']} ({res['service']}) (CWE-284)")
                    result["vulnerable"].append(res)
                else:
                    out.finding("HIGH", f"DANGLING CNAME: {res['host']} → {res['cname']} ({res['service']})")
                    result["dangling"].append(res)

    if not result["vulnerable"] and not result["dangling"]:
        out.success("No subdomain takeover vectors detected")
    return result


# ── Module: Email Security (SPF/DKIM/DMARC) ──────────────────────────────────

def module_email_security(domain: str, args) -> dict:
    out.rule("Email Security (SPF / DKIM / DMARC)")
    result = {"spf": None, "dmarc": None, "dkim": [], "issues": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    # SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"] = txt
                out.kv("SPF", txt)
                if "+all" in txt:
                    out.finding("CRITICAL", "SPF uses +all — ANY server can send as this domain! (email spoofing) (CWE-290)")
                    result["issues"].append({"type": "SPF", "severity": "CRITICAL", "cwe": "CWE-290",
                                             "desc": "+all in SPF record"})
                elif "~all" in txt:
                    out.finding("LOW", "SPF uses ~all (softfail) — spoofing may still succeed depending on recipient policy")
                    result["issues"].append({"type": "SPF", "severity": "LOW", "cwe": "CWE-290",
                                             "desc": "~all softfail"})
                elif "-all" in txt:
                    out.success("SPF hardened: -all")
    except Exception:
        out.finding("HIGH", "No SPF record — email spoofing possible (CWE-290)")
        result["issues"].append({"type": "SPF", "severity": "HIGH", "cwe": "CWE-290", "desc": "Missing SPF"})

    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = txt
                out.kv("DMARC", txt)
                if "p=none" in txt:
                    out.finding("MEDIUM", "DMARC policy is p=none — monitoring only, no enforcement (CWE-290)")
                    result["issues"].append({"type": "DMARC", "severity": "MEDIUM", "cwe": "CWE-290",
                                             "desc": "DMARC p=none"})
                elif "p=quarantine" in txt:
                    out.finding("LOW", "DMARC p=quarantine — partially enforced")
                elif "p=reject" in txt:
                    out.success("DMARC fully enforced: p=reject")
    except Exception:
        out.finding("HIGH", "No DMARC record — email spoofing enforcement missing (CWE-290)")
        result["issues"].append({"type": "DMARC", "severity": "HIGH", "cwe": "CWE-290", "desc": "Missing DMARC"})

    # DKIM (check common selectors)
    dkim_selectors = ["default", "google", "mail", "dkim", "s1", "s2", "k1", "email", "selector1", "selector2"]
    for sel in dkim_selectors:
        try:
            answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    out.success(f"DKIM selector '{sel}': {txt[:80]}")
                    result["dkim"].append({"selector": sel, "record": txt})
        except Exception:
            pass

    if not result["dkim"]:
        out.finding("MEDIUM", "No common DKIM selectors found — DKIM may not be configured")
        result["issues"].append({"type": "DKIM", "severity": "MEDIUM", "cwe": "CWE-290", "desc": "DKIM not detected"})

    return result


# ── Module: Cloud Asset Discovery ────────────────────────────────────────────

def module_cloud_assets(domain: str, args) -> dict:
    out.rule("Cloud Asset Discovery (S3 / GCS / Azure)")
    result = {"found": [], "public": []}
    root = extract_root_domain(domain)
    company = root.split(".")[0]

    # Generate bucket name permutations
    permutations = []
    suffixes = ["", "-dev", "-prod", "-staging", "-test", "-backup", "-data",
                "-media", "-assets", "-static", "-files", "-docs", "-images",
                "-uploads", "-public", "-private", "-internal", "-logs",
                "-archive", "-api", "-cdn", "-store", "-bucket"]
    for suffix in suffixes:
        permutations.append(f"{company}{suffix}")
        permutations.append(f"{company.replace('-', '')}{suffix}")
        permutations.append(f"{root.replace('.', '-')}{suffix}")

    permutations = list(set(permutations))
    out.info(f"Testing {len(permutations)} bucket name permutations ...")

    def check_bucket(bucket_name):
        hits = []
        for provider, cfg in CLOUD_PROVIDERS.items():
            url = cfg["check"](bucket_name)
            r = http_get(url, timeout=5, allow_redirects=False)
            if not r:
                continue
            body = r.text[:500] if r.text else ""
            status = r.status_code

            if any(fp in body for fp in cfg["not_exist"]) or status == 404:
                continue  # bucket doesn't exist
            elif any(fp in body for fp in cfg["public"]) or status == 200:
                hits.append({"provider": provider, "bucket": bucket_name,
                             "url": url, "status": "PUBLIC_LISTING", "http": status})
            elif any(fp in body for fp in cfg["exists"]) or status in [403, 400]:
                hits.append({"provider": provider, "bucket": bucket_name,
                             "url": url, "status": "EXISTS_PRIVATE", "http": status})
        return hits

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 8)) as ex:
        futures = {ex.submit(check_bucket, b): b for b in permutations}
        for f in concurrent.futures.as_completed(futures):
            hits = f.result()
            for hit in hits:
                if hit["status"] == "PUBLIC_LISTING":
                    out.finding("CRITICAL", f"PUBLIC BUCKET: {hit['url']} ({hit['provider']}) — unauthenticated listing enabled!")
                    result["public"].append(hit)
                else:
                    out.success(f"Bucket exists (private): {hit['url']} ({hit['provider']})")
                result["found"].append(hit)

    if not result["found"]:
        out.success("No cloud buckets found for this target's naming patterns")
    return result


# ── Module: GitHub Recon ──────────────────────────────────────────────────────

def module_github_recon(domain: str, args) -> dict:
    out.rule("GitHub Recon (Org Exposure)")
    result = {"repos": [], "secrets": [], "issues": []}
    root = extract_root_domain(domain)
    company = root.split(".")[0]

    headers = dict(HEADERS_DEFAULT)
    if args.github_token:
        headers["Authorization"] = f"token {args.github_token}"

    # Search for org
    out.info(f"Searching GitHub for organization '{company}' ...")
    try:
        r = requests.get(f"https://api.github.com/orgs/{company}", headers=headers, timeout=args.timeout)
        if r.status_code == 200:
            org = r.json()
            out.success(f"GitHub org found: {org.get('login')} — {org.get('public_repos',0)} public repos")
            result["org"] = {"login": org.get("login"), "repos": org.get("public_repos", 0)}

            # Fetch repos
            repos_r = requests.get(f"https://api.github.com/orgs/{company}/repos?per_page=100&sort=pushed",
                                   headers=headers, timeout=args.timeout)
            if repos_r.status_code == 200:
                repos = repos_r.json()
                for repo in repos[:20]:
                    name = repo.get("full_name", "")
                    pushed = repo.get("pushed_at", "")
                    lang = repo.get("language", "")
                    result["repos"].append({"name": name, "pushed": pushed, "lang": lang})
                    out.kv("Repo", f"{name} [{lang}] pushed {pushed[:10]}")

                    # Search for secrets in repo via code search
                    _search_repo_secrets(name, company, domain, headers, result, args)
        else:
            out.info(f"No GitHub org found for '{company}' (HTTP {r.status_code})")
            # Try code search anyway
            _github_code_search(domain, company, headers, result, args)
    except Exception as e:
        out.fail(f"GitHub API error: {e}")

    return result


def _search_repo_secrets(repo_name: str, company: str, domain: str,
                         headers: dict, result: dict, args):
    secret_queries = [
        f"repo:{repo_name} password",
        f"repo:{repo_name} api_key",
        f"repo:{repo_name} secret",
        f"repo:{repo_name} AWS_",
    ]
    for query in secret_queries[:2]:  # rate limit friendly
        try:
            r = requests.get("https://api.github.com/search/code",
                             params={"q": query}, headers=headers, timeout=args.timeout)
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items[:3]:
                    out.finding("HIGH", f"Potential secret in {item.get('html_url','')}")
                    result["secrets"].append({"repo": repo_name, "file": item.get("path", ""),
                                              "url": item.get("html_url", "")})
            time.sleep(0.5)  # avoid rate limit
        except Exception:
            pass


def _github_code_search(domain: str, company: str, headers: dict, result: dict, args):
    queries = [f'"{domain}" password', f'"{domain}" api_key', f'"{company}" secret_key']
    for query in queries[:2]:
        try:
            r = requests.get("https://api.github.com/search/code",
                             params={"q": query}, headers=headers, timeout=args.timeout)
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items[:5]:
                    out.finding("MEDIUM", f"Domain referenced in code: {item.get('html_url','')}")
                    result["issues"].append({"query": query, "url": item.get("html_url", "")})
            time.sleep(1)
        except Exception:
            pass


# ── Module: Wayback Machine ───────────────────────────────────────────────────

def module_wayback(domain: str, args) -> dict:
    out.rule("Wayback Machine / Historical URLs")
    result = {"urls": [], "interesting": []}

    try:
        r = http_get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
            timeout=15
        )
        if r and r.status_code == 200:
            data = r.json()
            urls = [row[0] for row in data[1:] if row]  # skip header
            result["urls"] = urls
            out.info(f"Wayback Machine: {len(urls)} historical URLs found")

            # Flag interesting paths
            interesting_patterns = [
                (r"\.(?:env|bak|sql|zip|tar|gz|config|log|backup|old|git)$", "CRITICAL", "Sensitive file in history"),
                (r"/(?:admin|phpMyAdmin|phpmyadmin|wp-admin|administrator|dashboard|internal)", "HIGH", "Admin/internal path"),
                (r"/(?:api/v\d|rest|graphql|endpoint)", "INFO", "API endpoint discovered"),
                (r"(?:password|passwd|secret|token|key|credential)", "HIGH", "Credential path in URL"),
                (r"/\.git/", "CRITICAL", ".git directory exposed"),
                (r"/(?:test|dev|staging|debug|qa)/", "MEDIUM", "Non-production environment path"),
            ]
            seen = set()
            for url in urls:
                for pattern, severity, desc in interesting_patterns:
                    if re.search(pattern, url, re.IGNORECASE) and url not in seen:
                        out.finding(severity, f"{desc}: {url}")
                        result["interesting"].append({"url": url, "severity": severity, "reason": desc})
                        seen.add(url)
                        break
        else:
            out.fail("Wayback CDX API unavailable")
    except Exception as e:
        out.fail(f"Wayback lookup failed: {e}")

    return result


# ── Module: Technology Fingerprinting ────────────────────────────────────────

def module_tech_fingerprint(domain: str, args) -> dict:
    out.rule("Technology Fingerprinting")
    result = {"technologies": {}, "cves": []}

    r = http_get(f"https://{domain}", timeout=args.timeout)
    if not r:
        r = http_get(f"http://{domain}", timeout=args.timeout)
    if not r:
        out.fail("Cannot reach target")
        return result

    body = r.text.lower()
    headers = {k.lower(): v for k, v in r.headers.items()}

    tech_patterns = {
        "WordPress":    (r"wp-content|wp-includes|/wp-json/", "CMS"),
        "Drupal":       (r"drupal\.js|drupal\.settings|sites/all/", "CMS"),
        "Joomla":       (r"/media/jui/|/components/com_", "CMS"),
        "Magento":      (r"mage/|/skin/frontend/", "eCommerce"),
        "Shopify":      (r"cdn\.shopify\.com|myshopify\.com", "eCommerce"),
        "Laravel":      (r"laravel_session|/vendor/laravel", "Framework"),
        "Django":       (r"csrfmiddlewaretoken|/static/admin/", "Framework"),
        "React":        (r"react\.development\.js|__reactfiber|__react", "Frontend"),
        "Angular":      (r"ng-version|angular\.min\.js|ng-app", "Frontend"),
        "Vue.js":       (r"__vue__|vue\.runtime\.min\.js", "Frontend"),
        "jQuery":       (r"jquery[\.\-][\d\.]+\.min\.js", "Library"),
        "Bootstrap":    (r"bootstrap\.min\.css|bootstrap\.bundle", "UI"),
        "Apache":       (r"", "Server"),  # from header
        "Nginx":        (r"", "Server"),
        "IIS":          (r"", "Server"),
        "PHP":          (r"", "Runtime"),
        "ASP.NET":      (r"__viewstate|__eventtarget|\.aspx", "Runtime"),
        "Node.js":      (r"express|node\.js", "Runtime"),
        "Cloudflare":   (r"", "CDN"),
        "AWS CloudFront":(r"", "CDN"),
        "GraphQL":      (r"graphql|\"__schema\"", "API"),
        "Swagger/OpenAPI":(r"swagger-ui|openapi\.json|api-docs", "API"),
        "Elasticsearch":(r"elasticsearch", "Database"),
        "MongoDB":      (r"mongodb", "Database"),
        "Redis":        (r"redis", "Database"),
    }

    server_hdr = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    # Server/runtime from headers
    for name in ["Apache", "Nginx", "IIS", "LiteSpeed"]:
        if name.lower() in server_hdr.lower():
            out.success(f"Server: {name} ({server_hdr})")
            result["technologies"][name] = {"category": "Server", "evidence": server_hdr}
            # Version disclosure
            ver_match = re.search(r"[\d\.]+", server_hdr)
            if ver_match:
                out.finding("MEDIUM", f"Server version disclosed: {server_hdr} — enables targeted exploits (CWE-200)")

    for name in ["PHP", "ASP.NET"]:
        if name.lower() in powered_by.lower():
            out.success(f"Runtime: {name} ({powered_by})")
            result["technologies"][name] = {"category": "Runtime", "evidence": powered_by}
            ver_match = re.search(r"[\d\.]+", powered_by)
            if ver_match:
                out.finding("MEDIUM", f"Runtime version disclosed in X-Powered-By: {powered_by} (CWE-200)")

    for tech, (pattern, category) in tech_patterns.items():
        if not pattern:
            continue
        if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, str(headers)):
            out.success(f"Technology: {tech} ({category})")
            result["technologies"][tech] = {"category": category}

    # CDN from headers
    if "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers:
        result["technologies"]["Cloudflare"] = {"category": "CDN"}
        out.success("CDN: Cloudflare")
    if "cloudfront" in headers.get("via", "").lower() or "x-amz-cf-id" in headers:
        result["technologies"]["AWS CloudFront"] = {"category": "CDN"}
        out.success("CDN: AWS CloudFront")

    return result


# ── Module: Port Scanner ──────────────────────────────────────────────────────

def module_port_scan(domain: str, args) -> dict:
    out.rule("Port Scan (Common Ports)")
    result = {"open_ports": []}
    if args.passive_only:
        out.info("Skipped (passive-only mode)")
        return result

    ips = resolve_domain(domain)
    if not ips:
        out.fail("Cannot resolve domain for port scanning")
        return result

    ip = ips[0]
    out.info(f"Scanning {ip} for {len(COMMON_PORTS)} common ports ...")

    service_names = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle DB", 2222: "SSH-alt", 3000: "Dev/Node",
        3306: "MySQL", 3389: "RDP", 4443: "HTTPS-alt", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 7443: "HTTPS-alt", 8000: "Dev/Django",
        8080: "HTTP-alt", 8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
        9000: "PHP-FPM/Portainer", 9200: "Elasticsearch", 9300: "Elasticsearch",
        27017: "MongoDB",
    }
    risky_ports = {23: "Telnet — plaintext", 3389: "RDP — bruteforce/BlueKeep",
                   5900: "VNC — often unauth", 6379: "Redis — often unauthenticated",
                   9200: "Elasticsearch — often unauthenticated",
                   9300: "Elasticsearch — often unauthenticated",
                   27017: "MongoDB — often unauthenticated", 1433: "MSSQL direct exposure",
                   1521: "Oracle DB direct exposure", 3306: "MySQL direct exposure",
                   5432: "PostgreSQL direct exposure"}

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            res = sock.connect_ex((ip, port))
            sock.close()
            return port if res == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 20)) as ex:
        futures = {ex.submit(check_port, p): p for p in COMMON_PORTS}
        for f in concurrent.futures.as_completed(futures):
            port = f.result()
            if port:
                svc = service_names.get(port, "unknown")
                entry = {"port": port, "service": svc, "ip": ip}
                result["open_ports"].append(entry)
                if port in risky_ports:
                    out.finding("HIGH", f"Port {port}/tcp OPEN — {svc} — {risky_ports[port]}")
                else:
                    out.success(f"Port {port}/tcp OPEN — {svc}")

    result["open_ports"].sort(key=lambda x: x["port"])
    return result


# ── Report Generation ─────────────────────────────────────────────────────────

def generate_report(domain: str, all_results: dict, output_file: str):
    out.rule("Final Report")

    # Collect all findings across modules
    critical, high, medium, low, info_items = [], [], [], [], []

    def harvest_issues(issues_list, module_name):
        for issue in issues_list:
            sev = issue.get("severity", "INFO")
            desc = issue.get("desc", issue.get("reason", str(issue)))
            cwe = issue.get("cwe", "")
            entry = f"[{module_name}] {desc} {f'({cwe})' if cwe else ''}"
            if sev == "CRITICAL":
                critical.append(entry)
            elif sev == "HIGH":
                high.append(entry)
            elif sev == "MEDIUM":
                medium.append(entry)
            elif sev == "LOW":
                low.append(entry)
            else:
                info_items.append(entry)

    for module, data in all_results.items():
        if isinstance(data, dict):
            harvest_issues(data.get("issues", []), module)
            harvest_issues(data.get("vulnerable", []), module)
            harvest_issues(data.get("dangling", []), module)
            harvest_issues(data.get("public", []), module)
            for secret in data.get("secrets", []):
                high.append(f"[{module}] Secret exposure: {secret.get('type','?')} in {secret.get('source','?')[:60]}")

    out.print()
    out.print(f"[bold]Target:[/bold] {domain}")
    out.print(f"[bold]Scan Date:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    out.print()
    out.print(f"[bold red]CRITICAL ({len(critical)}):[/bold red]")
    for c in critical:
        out.print(f"  • {c}")
    out.print(f"[bold red]HIGH ({len(high)}):[/bold red]")
    for h in high:
        out.print(f"  • {h}")
    out.print(f"[bold yellow]MEDIUM ({len(medium)}):[/bold yellow]")
    for m in medium:
        out.print(f"  • {m}")
    out.print(f"[bold blue]LOW ({len(low)}):[/bold blue]")
    for l in low:
        out.print(f"  • {l}")
    out.print(f"[dim]INFO ({len(info_items)}):[/dim]")
    for i in info_items:
        out.print(f"  • {i}")

    total = len(critical) + len(high) + len(medium) + len(low)
    out.print()
    out.print(f"[bold]Total actionable findings: {total}[/bold]  "
              f"(CRITICAL:{len(critical)} HIGH:{len(high)} MEDIUM:{len(medium)} LOW:{len(low)})")

    # Write full text log
    report_lines = "\n".join(out.lines)
    with open(output_file, "w") as fh:
        fh.write(f"ShadowRecon v{VERSION} — Target: {domain}\n")
        fh.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        fh.write("=" * 80 + "\n\n")
        fh.write(report_lines)
        fh.write("\n\n")
        fh.write("=" * 80 + "\n")
        fh.write(f"FINDINGS SUMMARY\n{'='*80}\n")
        fh.write(f"CRITICAL ({len(critical)}):\n" + "\n".join(f"  • {c}" for c in critical) + "\n")
        fh.write(f"HIGH ({len(high)}):\n" + "\n".join(f"  • {h}" for h in high) + "\n")
        fh.write(f"MEDIUM ({len(medium)}):\n" + "\n".join(f"  • {m}" for m in medium) + "\n")
        fh.write(f"LOW ({len(low)}):\n" + "\n".join(f"  • {l}" for l in low) + "\n")

    # JSON report
    json_file = output_file.replace(".txt", ".json")
    with open(json_file, "w") as fh:
        json.dump({
            "target": domain,
            "scan_date": datetime.now().isoformat(),
            "summary": {"critical": len(critical), "high": len(high),
                        "medium": len(medium), "low": len(low)},
            "findings": {"critical": critical, "high": high, "medium": medium,
                         "low": low, "info": info_items},
            "modules": all_results,
        }, fh, indent=2, default=str)

    out.success(f"Text report: {output_file}")
    out.success(f"JSON report: {json_file}")


# ── Module Registry ───────────────────────────────────────────────────────────

ALL_MODULES = [
    "whois", "dns", "subdomains", "asn", "tls_audit", "headers", "cors",
    "waf", "js_recon", "takeover", "email_security", "cloud_assets",
    "github_recon", "wayback", "tech_fingerprint", "port_scan",
]

PASSIVE_ONLY_MODULES = {
    "whois", "dns", "subdomains", "asn", "tls_audit", "headers",
    "email_security", "cloud_assets", "github_recon", "wayback", "tech_fingerprint",
}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global out

    parser = argparse.ArgumentParser(
        description="ShadowRecon — Advanced Penetration Testing Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-d", "--domain", required=False, help="Target domain")
    parser.add_argument("-o", "--output", default=None, help="Output file base name")
    parser.add_argument("--modules", default="all", help="Comma-separated modules (default: all)")
    parser.add_argument("--passive-only", action="store_true", help="Skip active probing")
    parser.add_argument("--threads", type=int, default=10, help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout seconds (default: 8)")
    parser.add_argument("--github-token", default=None, help="GitHub API token")
    parser.add_argument("--shodan-key", default=None, help="Shodan API key")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--list-modules", action="store_true", help="List all modules and exit")

    args = parser.parse_args()

    out = Output(no_color=args.no_color)

    if args.list_modules:
        print("Available modules:")
        for m in ALL_MODULES:
            marker = "[passive]" if m in PASSIVE_ONLY_MODULES else "[active] "
            print(f"  {marker}  {m}")
        sys.exit(0)

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    domain = args.domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")
    if "/" in domain:
        domain = domain.split("/")[0]

    output_file = args.output or f"shadow_recon_{domain.replace('.', '_')}.txt"

    # Banner
    out.print(f"[bold cyan]{BANNER}[/bold cyan]")
    out.print(f"[bold]ShadowRecon v{VERSION}[/bold] — [cyan]Target: {domain}[/cyan]")
    out.print(f"[dim]Passive-only: {args.passive_only} | Threads: {args.threads} | Timeout: {args.timeout}s[/dim]")
    out.print()

    # Determine which modules to run
    if args.modules == "all":
        modules_to_run = list(ALL_MODULES)
    else:
        modules_to_run = [m.strip() for m in args.modules.split(",") if m.strip() in ALL_MODULES]

    if args.passive_only:
        modules_to_run = [m for m in modules_to_run if m in PASSIVE_ONLY_MODULES]

    out.info(f"Running modules: {', '.join(modules_to_run)}")

    all_results = {}
    subdomains_data = []

    for mod in modules_to_run:
        try:
            if mod == "whois":
                all_results["whois"] = module_whois(domain, args)
            elif mod == "dns":
                all_results["dns"] = module_dns(domain, args)
            elif mod == "subdomains":
                res = module_subdomains(domain, args)
                all_results["subdomains"] = res
                subdomains_data = res.get("subdomains", [])
            elif mod == "asn":
                all_results["asn"] = module_asn(domain, args)
            elif mod == "tls_audit":
                all_results["tls_audit"] = module_tls_audit(domain, args)
            elif mod == "headers":
                all_results["headers"] = module_headers(domain, args)
            elif mod == "cors":
                all_results["cors"] = module_cors(domain, args)
            elif mod == "waf":
                all_results["waf"] = module_waf(domain, args)
            elif mod == "js_recon":
                all_results["js_recon"] = module_js_recon(domain, args)
            elif mod == "takeover":
                all_results["takeover"] = module_takeover(domain, args, subdomains_data)
            elif mod == "email_security":
                all_results["email_security"] = module_email_security(domain, args)
            elif mod == "cloud_assets":
                all_results["cloud_assets"] = module_cloud_assets(domain, args)
            elif mod == "github_recon":
                all_results["github_recon"] = module_github_recon(domain, args)
            elif mod == "wayback":
                all_results["wayback"] = module_wayback(domain, args)
            elif mod == "tech_fingerprint":
                all_results["tech_fingerprint"] = module_tech_fingerprint(domain, args)
            elif mod == "port_scan":
                all_results["port_scan"] = module_port_scan(domain, args)
        except KeyboardInterrupt:
            out.warn(f"Module {mod} interrupted by user")
            break
        except Exception as e:
            out.fail(f"Module {mod} failed: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()

    generate_report(domain, all_results, output_file)


if __name__ == "__main__":
    main()
