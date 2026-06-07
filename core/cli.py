"""shadowrecon/core/cli.py — Argument parsing & banner."""

import argparse
import sys

BANNER = """[bold cyan]
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold cyan]
[bold white]  ShadowRecon v2.0 — Advanced Recon Framework[/bold white]
[dim]  What recon-ng can't do — and then some[/dim]
"""


def print_banner(out):
    out.print(BANNER)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="shadowrecon",
        description="ShadowRecon v2.0 — Advanced Penetration Testing Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Target
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-d", "--domain", metavar="DOMAIN",
                               help="Single target domain")
    target_group.add_argument("--scope-file", metavar="FILE",
                               help="File with domains/IPs (one per line)")

    # Output
    parser.add_argument("-o", "--output", metavar="DIR", default=None,
                        help="Output directory (default: ./output/<domain>_<ts>/)")

    # Module control
    parser.add_argument("--modules", default="all", metavar="MOD1,MOD2",
                        help="Modules to run: comma-separated list or 'all' (default: all)")
    parser.add_argument("--exclude-modules", default="", metavar="MOD1,MOD2",
                        help="Modules to skip (comma-separated)")
    parser.add_argument("--passive-only", action="store_true",
                        help="Run only passive (non-touching) modules")

    # Performance
    parser.add_argument("--threads", type=int, default=15, metavar="N",
                        help="Concurrent threads (default: 15)")
    parser.add_argument("--timeout", type=int, default=8, metavar="SEC",
                        help="Request timeout in seconds (default: 8)")
    parser.add_argument("--rate-limit", type=float, default=20.0, metavar="RPS",
                        help="Max requests/second (default: 20)")

    # API keys
    parser.add_argument("--github-token", metavar="TOKEN", default=None,
                        help="GitHub API token (boosts rate limits to 5000/hr)")
    parser.add_argument("--shodan-key", metavar="KEY", default=None,
                        help="Shodan API key for host/org lookups")

    # Network
    parser.add_argument("--proxy", metavar="URL", default=None,
                        help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080 for Burp)")

    # Session
    parser.add_argument("--resume", action="store_true",
                        help="Resume the most recent scan session for this target")
    parser.add_argument("--config", metavar="FILE", default=None,
                        help="Config file path (default: config/settings.json)")

    # Report
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")

    # UX
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colour output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug output")
    parser.add_argument("--list-modules", action="store_true",
                        help="Print all available modules with descriptions and exit")

    args = parser.parse_args()

    if not args.list_modules and not args.domain and not args.scope_file:
        parser.print_help()
        sys.exit(1)

    # Handle --exclude-modules
    if args.exclude_modules and args.modules == "all":
        from core.registry import MODULE_REGISTRY
        excluded = {m.strip() for m in args.exclude_modules.split(",") if m.strip()}
        args.modules = ",".join(
            m for m in MODULE_REGISTRY.keys() if m not in excluded
        )

    # Expose proxy as dict for requests
    args.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    return args
