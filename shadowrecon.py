#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗  ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝  ║
║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║       ║
║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║       ║
║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗  ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ║
║                    R E C O N N A I S S A N C E   F R A M E W O R K   v2.0       ║
║                                                                                  ║
║   Beyond recon-ng: Active TLS audit • JS secret extraction • Cloud discovery    ║
║   WAF fingerprint+bypass • ASN expansion • Subdomain takeover (35+ sigs)        ║
║   CORS probe • SPF/DKIM/DMARC • GitHub org recon • HTTP smuggling detect        ║
║   Virtual host bruteforce • GraphQL introspection • API endpoint fuzzing         ║
║   Favicon hash fingerprint • Open redirect probe • HTML+JSON+Markdown reports    ║
╚══════════════════════════════════════════════════════════════════════════════════╝

USAGE:
    python3 shadowrecon.py -d <domain> [OPTIONS]
    python3 shadowrecon.py -d example.com --modules all
    python3 shadowrecon.py -d example.com --modules whois,dns,subdomains,tls_audit
    python3 shadowrecon.py -d example.com --passive-only --output results/
    python3 shadowrecon.py --list-modules
    python3 shadowrecon.py -d example.com --scope-file ips.txt

OPTIONS:
    -d, --domain         Target domain (required unless --scope-file)
    --scope-file         File with list of domains/IPs to scan
    -o, --output         Output directory (default: ./output/<domain>_<timestamp>/)
    --modules            Modules to run, comma-separated or 'all' (default: all)
    --passive-only       Skip all active probing modules
    --threads            Concurrent thread count (default: 15)
    --timeout            HTTP/socket timeout in seconds (default: 8)
    --rate-limit         Max requests/second (default: 20)
    --github-token       GitHub API token (boosts rate limits significantly)
    --shodan-key         Shodan API key (enables port/banner data)
    --no-color           Disable ANSI colour output
    --no-html            Skip HTML report generation
    --no-json            Skip JSON report generation
    -v, --verbose        Verbose/debug output
    --list-modules       Print all modules with descriptions and exit
    --config             Path to config file (default: config/settings.json)

MODULES (pass comma-separated or 'all'):
    Passive:  whois  dns  subdomains  asn  cert_transparency  email_security
              tech_fingerprint  wayback  github_recon  shodan_query
    Active:   tls_audit  headers  cors  waf  js_recon  cloud_assets
              takeover  port_scan  vhost_bruteforce  graphql_probe
              open_redirect  http_methods  favicon_hash  api_fuzzer

AUTHOR: ShadowRecon Framework v2.0
"""

import sys
import os

# Ensure core/ is on the path
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import Engine
from core.cli import parse_args, print_banner
from core.output import OutputManager


def main():
    args = parse_args()
    out = OutputManager(no_color=args.no_color, verbose=args.verbose)
    print_banner(out)

    if args.list_modules:
        from core.registry import MODULE_REGISTRY
        out.rule("Available Modules")
        for name, meta in sorted(MODULE_REGISTRY.items()):
            mode = "[bold green][passive][/bold green]" if meta.get("passive") else "[bold yellow][active] [/bold yellow]"
            out.print(f"  {mode} [bold]{name:<22}[/bold] {meta['desc']}")
        sys.exit(0)

    targets = []
    if args.scope_file:
        with open(args.scope_file) as fh:
            targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    elif args.domain:
        targets = [args.domain]
    else:
        out.fail("Provide -d <domain> or --scope-file <file>")
        sys.exit(1)

    for target in targets:
        engine = Engine(target=target, args=args, out=out)
        engine.run()


if __name__ == "__main__":
    main()
