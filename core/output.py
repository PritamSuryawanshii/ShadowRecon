"""shadowrecon/core/output.py — Output manager (rich + plain fallback)."""

import re
import sys
from typing import Optional

try:
    from rich.console import Console
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
    "OK":       "bold green",
}


class OutputManager:
    def __init__(self, no_color: bool = False, verbose: bool = False):
        self.use_rich = HAS_RICH and not no_color
        self.verbose  = verbose
        self.lines: list[str] = []          # plain-text log for file output
        self.findings: list[dict] = []      # structured finding accumulator

        if self.use_rich:
            self.console = Console(highlight=False)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _strip_markup(msg: str) -> str:
        return re.sub(r"\[/?[^\[\]]*\]", "", msg)

    def _record(self, text: str):
        self.lines.append(self._strip_markup(text))

    # ── Public API ────────────────────────────────────────────────────────────

    def print(self, msg: str = "", **kwargs):
        self._record(msg)
        if self.use_rich:
            self.console.print(msg, **kwargs)
        else:
            print(self._strip_markup(msg))

    def rule(self, title: str = ""):
        sep = "─" * 70
        self._record(f"\n{sep}\n  {title}\n{sep}")
        if self.use_rich:
            self.console.rule(f"[bold cyan]{title}[/bold cyan]")
        else:
            print(f"\n{'─'*70}\n  {title}\n{'─'*70}")

    def success(self, msg: str):
        self.print(f"[bold green][+][/bold green] {msg}")

    def warn(self, msg: str):
        self.print(f"[bold yellow][!][/bold yellow] {msg}")

    def fail(self, msg: str):
        self.print(f"[bold red][-][/bold red] {msg}")

    def info(self, msg: str):
        self.print(f"[cyan][*][/cyan] {msg}")

    def debug(self, msg: str):
        if self.verbose:
            self.print(f"[dim][~][/dim] {msg}")

    def kv(self, key: str, val: str):
        self.print(f"  [bold]{key}:[/bold] {val}")

    def finding(self, severity: str, msg: str, cwe: str = "",
                module: str = "", url: str = "", evidence: str = ""):
        """Emit a coloured finding AND record it structurally."""
        color = SEV_COLOR.get(severity.upper(), "white")
        label = f"[{severity}]"
        cwe_str = f" [dim]({cwe})[/dim]" if cwe else ""
        self.print(f"  [{color}]{label}[/{color}] {msg}{cwe_str}")

        self.findings.append({
            "severity": severity.upper(),
            "message":  msg,
            "cwe":      cwe,
            "module":   module,
            "url":      url,
            "evidence": evidence,
        })

    def header_finding(self, header: str, present: bool, val: str,
                       severity: str, cwe: str, desc: str):
        if present:
            try:
                from modules._constants import SECURITY_HEADERS
                good = SECURITY_HEADERS[header]["good"](val)
            except Exception:
                good = True
            if good:
                self.success(f"{header}: [dim]{val[:80]}[/dim]")
            else:
                self.finding(severity, f"Misconfigured {header}: {val[:80]}", cwe=cwe)
        else:
            self.finding(severity, f"Missing header: {header} — {desc}", cwe=cwe)
