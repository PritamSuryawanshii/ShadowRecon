"""shadowrecon/core/engine.py — Orchestration engine with resume, progress, config."""

import json
import os
import sys
import time
import traceback
from datetime import datetime

from core.output import OutputManager
from core.registry import MODULE_REGISTRY, get_module_fn
from core.reporter import Reporter
from core.config import load_config
from core.state_manager import (
    save_state, load_state, find_latest_session, restore_state_into
)


class ScanState:
    """Shared mutable state passed between modules during a scan."""
    def __init__(self, domain: str):
        self.domain       = domain
        self.subdomains   = []   # list of {"host": str, "ips": list[str], "source": str}
        self.ips          = []   # list of str (resolved IPs for root domain)
        self.open_ports   = []   # list of {"port": int, "service": str, "ip": str, "banner": str}
        self.js_files     = []   # list of str (JS file URLs)
        self.endpoints    = []   # list of str (discovered API paths)
        self.technologies = {}   # name → category string
        self.asn_info     = []   # list of ASN dicts
        self.cves         = []   # list of {"cve": str, "product": str, "severity": str}
        self.emails       = []   # list of str (discovered email addresses)
        self.module_results: dict[str, dict] = {}
        self.module_timings: dict[str, float] = {}


class Engine:
    def __init__(self, target: str, args, out: OutputManager):
        self.target   = self._normalize(target)
        self.args     = args
        self.out      = out
        self.cfg      = load_config(getattr(args, "config", None), args)
        self.state    = ScanState(self.target)
        self.start_ts = datetime.utcnow()
        self._completed: list[str] = []

        # Resolve output directory
        ts   = self.start_ts.strftime("%Y%m%d_%H%M%S")
        base = args.output or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "output"
        )
        os.makedirs(base, exist_ok=True)

        # Resume: look for existing session
        self._resuming   = False
        self._resume_dir = None
        if getattr(args, "resume", False):
            existing = find_latest_session(base, self.target)
            if existing:
                self._resume_dir = existing
                self._resuming   = True
                self.out_dir     = existing
                out.warn(f"Resuming previous session: {existing}")
            else:
                out.warn("No previous session found — starting fresh")

        if not self._resuming:
            self.out_dir = os.path.join(base, f"{self.target.replace('.', '_')}_{ts}")
            os.makedirs(self.out_dir, exist_ok=True)

    @staticmethod
    def _normalize(domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://", "www."):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0]

    def _select_modules(self) -> list[str]:
        requested = self.args.modules
        if requested == "all":
            names = list(MODULE_REGISTRY.keys())
        else:
            names = [m.strip() for m in requested.split(",") if m.strip()]

        valid   = [n for n in names if n in MODULE_REGISTRY]
        invalid = [n for n in names if n not in MODULE_REGISTRY]
        if invalid:
            self.out.warn(f"Unknown modules ignored: {', '.join(invalid)}")

        if self.args.passive_only:
            valid = [n for n in valid if MODULE_REGISTRY[n].get("passive")]

        # Enforce registry ordering
        order = list(MODULE_REGISTRY.keys())
        valid.sort(key=lambda n: order.index(n) if n in order else 999)
        return valid

    def _restore_session(self):
        """Load previous session state and restore into self.state."""
        if not self._resuming or not self._resume_dir:
            return []
        data, completed, prev_findings = load_state(self._resume_dir)
        if data:
            restore_state_into(data, self.state)
            # Restore findings into output manager
            self.out.findings = prev_findings
            self.out.info(f"Restored {len(completed)} completed modules, "
                          f"{len(self.state.subdomains)} subdomains, "
                          f"{len(prev_findings)} findings from previous session")
            return completed
        return []

    def run(self):
        self.out.rule(f"TARGET: {self.target}")
        self.out.info(f"Output directory : {self.out_dir}")
        self.out.info(f"Start time       : {self.start_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        self.out.info(f"Threads          : {self.args.threads}  |  Timeout: {self.args.timeout}s  |  Rate: {self.args.rate_limit} rps")

        # Restore state if resuming
        already_done = self._restore_session()

        all_modules = self._select_modules()
        pending     = [m for m in all_modules if m not in already_done]

        self.out.info(f"Modules total    : {len(all_modules)}  "
                      f"(queued: {len(pending)}, skipped/resumed: {len(already_done)})")
        if already_done:
            self.out.info(f"Skipping already completed: {', '.join(already_done)}")
        self.out.print()

        # ── Rich progress bar (optional) ──────────────────────────────────────
        use_progress = self.out.use_rich and not self.args.verbose
        if use_progress:
            try:
                from rich.progress import (
                    Progress, SpinnerColumn, TextColumn,
                    BarColumn, MofNCompleteColumn, TimeElapsedColumn
                )
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}"),
                    BarColumn(bar_width=30),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    transient=False,
                )
                task = progress.add_task("Scanning ...", total=len(pending))
                progress.start()
            except Exception:
                use_progress = False
                progress     = None
                task         = None
        else:
            progress = None
            task     = None

        for mod_name in pending:
            if use_progress and progress:
                progress.update(task, description=f"[cyan]{mod_name:<22}")

            self.out.rule(f"MODULE » {mod_name.upper()}")
            t0 = time.time()
            try:
                fn     = get_module_fn(mod_name)
                result = fn(
                    domain=self.target,
                    args=self.args,
                    out=self.out,
                    state=self.state,
                )
                elapsed = time.time() - t0
                self.state.module_results[mod_name] = result or {}
                self.state.module_timings[mod_name] = round(elapsed, 2)
                self._completed.append(mod_name)

                # Persist state after every module
                save_state(
                    self.out_dir,
                    self.state,
                    already_done + self._completed,
                    self.out.findings,
                )
                self.out.debug(f"[{mod_name}] completed in {elapsed:.1f}s")

            except KeyboardInterrupt:
                self.out.warn(f"Interrupted at module '{mod_name}' — saving partial state ...")
                save_state(self.out_dir, self.state,
                           already_done + self._completed, self.out.findings)
                if use_progress and progress:
                    progress.stop()
                break
            except Exception as exc:
                self.out.fail(f"Module '{mod_name}' error: {exc}")
                if self.args.verbose:
                    traceback.print_exc()
            finally:
                if use_progress and progress:
                    progress.advance(task)

        if use_progress and progress:
            progress.stop()

        # ── Reports ───────────────────────────────────────────────────────────
        reporter = Reporter(
            domain=self.target,
            out_dir=self.out_dir,
            state=self.state,
            findings=self.out.findings,
            start_ts=self.start_ts,
            args=self.args,
        )
        reporter.write_txt(self.out.lines)
        reporter.write_markdown()
        if not self.args.no_json:
            reporter.write_json()
        if not self.args.no_html:
            reporter.write_html()

        reporter.print_summary(self.out)

        end_ts  = datetime.utcnow()
        elapsed = (end_ts - self.start_ts).total_seconds()
        self.out.info(f"Scan finished in {elapsed:.0f}s  |  Output: {self.out_dir}")
