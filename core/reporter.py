"""shadowrecon/core/reporter.py — TXT / JSON / HTML report generation."""

import json
import os
from datetime import datetime

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}
SEV_BADGE = {
    "CRITICAL": "badge-critical",
    "HIGH":     "badge-high",
    "MEDIUM":   "badge-medium",
    "LOW":      "badge-low",
    "INFO":     "badge-info",
}


class Reporter:
    def __init__(self, domain, out_dir, state, findings, start_ts, args):
        self.domain    = domain
        self.out_dir   = out_dir
        self.state     = state
        self.findings  = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity","INFO"), 4))
        self.start_ts  = start_ts
        self.args      = args
        self.end_ts    = datetime.utcnow()

    # ─── helpers ──────────────────────────────────────────────────────────────

    def _counts(self):
        counts = {s: 0 for s in SEV_ORDER}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _txt_path(self):
        return os.path.join(self.out_dir, "report.txt")

    def _json_path(self):
        return os.path.join(self.out_dir, "report.json")

    def _html_path(self):
        return os.path.join(self.out_dir, "report.html")

    # ─── TXT ──────────────────────────────────────────────────────────────────

    def write_txt(self, log_lines: list[str]):
        counts = self._counts()
        sep    = "=" * 80
        with open(self._txt_path(), "w", encoding="utf-8") as fh:
            fh.write(f"ShadowRecon v2.0 — Penetration Testing Reconnaissance Report\n")
            fh.write(f"{sep}\n")
            fh.write(f"Target   : {self.domain}\n")
            fh.write(f"Started  : {self.start_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            fh.write(f"Finished : {self.end_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            fh.write(f"Duration : {(self.end_ts - self.start_ts).total_seconds():.0f}s\n")
            fh.write(f"{sep}\n\n")

            fh.write("FINDINGS SUMMARY\n")
            fh.write("-" * 40 + "\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                fh.write(f"  {sev:<10} {counts[sev]}\n")
            fh.write(f"\n{'─'*40}\n\n")

            fh.write("DETAILED FINDINGS\n")
            fh.write("-" * 40 + "\n")
            for f in self.findings:
                sev  = f.get("severity", "INFO")
                msg  = f.get("message", "")
                cwe  = f.get("cwe", "")
                mod  = f.get("module", "")
                url  = f.get("url", "")
                ev   = f.get("evidence", "")
                fh.write(f"\n[{sev}]  {msg}\n")
                if cwe:
                    fh.write(f"  CWE     : {cwe}\n")
                if mod:
                    fh.write(f"  Module  : {mod}\n")
                if url:
                    fh.write(f"  URL     : {url}\n")
                if ev:
                    fh.write(f"  Evidence: {ev[:200]}\n")

            fh.write(f"\n\n{'='*80}\nFULL SCAN LOG\n{'='*80}\n\n")
            fh.write("\n".join(log_lines))

    # ─── JSON ─────────────────────────────────────────────────────────────────

    def write_json(self):
        counts = self._counts()
        payload = {
            "meta": {
                "tool":    "ShadowRecon v2.0",
                "target":  self.domain,
                "started":  self.start_ts.isoformat(),
                "finished": self.end_ts.isoformat(),
                "duration_seconds": (self.end_ts - self.start_ts).total_seconds(),
            },
            "summary": counts,
            "findings": self.findings,
            "state": {
                "subdomains":  self.state.subdomains,
                "ips":         self.state.ips,
                "open_ports":  self.state.open_ports,
                "technologies": self.state.technologies,
                "endpoints":   self.state.endpoints[:200],
                "js_files":    self.state.js_files[:100],
                "asn_info":    self.state.asn_info,
            },
            "modules": self.state.module_results,
        }
        with open(self._json_path(), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    # ─── HTML ─────────────────────────────────────────────────────────────────

    def write_html(self):
        counts  = self._counts()
        elapsed = (self.end_ts - self.start_ts).total_seconds()
        html    = self._build_html(counts, elapsed)
        with open(self._html_path(), "w", encoding="utf-8") as fh:
            fh.write(html)

    def _build_html(self, counts: dict, elapsed: float) -> str:
        # ── finding rows ──────────────────────────────────────────────────────
        finding_rows = ""
        for f in self.findings:
            sev      = f.get("severity", "INFO").upper()
            msg      = _esc(f.get("message", ""))
            cwe      = _esc(f.get("cwe", ""))
            mod      = _esc(f.get("module", ""))
            url      = _esc(f.get("url", ""))
            evidence = _esc(f.get("evidence", ""))
            badge    = SEV_BADGE.get(sev, "badge-info")
            cwe_link = (f'<a href="https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-","")}.html" '
                        f'target="_blank">{cwe}</a>') if cwe.startswith("CWE-") else cwe

            url_cell = (f'<a href="{url}" target="_blank">{url[:60]}{"…" if len(url) > 60 else ""}</a>'
                        if url else "")

            finding_rows += f"""
            <tr class="finding-row" data-sev="{sev}">
              <td><span class="badge {badge}">{sev}</span></td>
              <td>{msg}</td>
              <td>{cwe_link}</td>
              <td><code>{mod}</code></td>
              <td class="url-cell">{url_cell}</td>
            </tr>"""
            if evidence:
                finding_rows += f"""
            <tr class="evidence-row" data-sev="{sev}">
              <td></td>
              <td colspan="4"><pre class="evidence">{evidence[:300]}</pre></td>
            </tr>"""

        # ── subdomain rows ────────────────────────────────────────────────────
        sub_rows = ""
        for s in self.state.subdomains:
            host   = _esc(s.get("host", ""))
            ips    = ", ".join(s.get("ips", []))
            source = _esc(s.get("source", "brute"))
            sub_rows += f"<tr><td>{host}</td><td>{ips}</td><td>{source}</td></tr>"

        # ── port rows ─────────────────────────────────────────────────────────
        port_rows = ""
        from modules._constants import RISKY_PORTS
        for p in sorted(self.state.open_ports, key=lambda x: x.get("port", 0)):
            port    = p.get("port", "")
            svc     = _esc(p.get("service", ""))
            ip      = _esc(p.get("ip", ""))
            banner  = _esc((p.get("banner") or "")[:80])
            risky   = port in RISKY_PORTS
            cls     = 'class="risky-port"' if risky else ""
            port_rows += f"<tr {cls}><td>{port}</td><td>{svc}</td><td>{ip}</td><td><code>{banner}</code></td></tr>"

        # ── tech rows ─────────────────────────────────────────────────────────
        tech_rows = ""
        for name, cat in self.state.technologies.items():
            tech_rows += f"<tr><td>{_esc(name)}</td><td>{_esc(str(cat))}</td></tr>"

        # ── endpoint rows (first 100) ─────────────────────────────────────────
        ep_rows = ""
        for ep in self.state.endpoints[:100]:
            ep_rows += f"<tr><td><code>{_esc(ep)}</code></td></tr>"

        # ── module timing rows ────────────────────────────────────────────────
        timing_rows = ""
        timings = getattr(self.state, "module_timings", {})
        for mod, dur in sorted(timings.items(), key=lambda x: -x[1]):
            bar_pct = min(100, dur / max(timings.values(), default=1) * 100)
            timing_rows += (
                f"<tr><td><code>{_esc(mod)}</code></td>"
                f"<td>{dur:.1f}s</td>"
                f"<td><div style='width:{bar_pct:.0f}%;height:6px;"
                f"background:var(--accent);border-radius:3px'></div></td></tr>"
            )

        # ── CVE rows ──────────────────────────────────────────────────────────
        cve_rows = ""
        for cve in getattr(self.state, "cves", []):
            sev  = cve.get("severity","INFO")
            badge = SEV_BADGE.get(sev, "badge-info")
            cve_id = _esc(cve.get("cve",""))
            prod   = _esc(cve.get("product",""))
            cve_rows += (
                f"<tr><td><a href='https://nvd.nist.gov/vuln/detail/{cve_id}' "
                f"target='_blank'>{cve_id}</a></td>"
                f"<td>{prod}</td>"
                f"<td><span class='badge {badge}'>{sev}</span></td></tr>"
            )
        total_f = max(sum(counts.values()), 1)
        stat_bars = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt  = counts.get(sev, 0)
            pct  = cnt / total_f * 100
            col  = SEV_COLOR[sev]
            stat_bars += f"""
              <div class="stat-bar-row">
                <span class="stat-label">{sev}</span>
                <div class="stat-bar-track">
                  <div class="stat-bar-fill" style="width:{pct:.1f}%;background:{col}"></div>
                </div>
                <span class="stat-count">{cnt}</span>
              </div>"""

        return HTML_TEMPLATE.format(
            domain        = _esc(self.domain),
            started       = self.start_ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            finished      = self.end_ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            elapsed       = f"{elapsed:.0f}",
            count_crit    = counts["CRITICAL"],
            count_high    = counts["HIGH"],
            count_med     = counts["MEDIUM"],
            count_low     = counts["LOW"],
            count_info    = counts["INFO"],
            count_sub     = len(self.state.subdomains),
            count_ports   = len(self.state.open_ports),
            count_tech    = len(self.state.technologies),
            count_cves    = len(getattr(self.state, "cves", [])),
            count_ep      = len(self.state.endpoints),
            stat_bars     = stat_bars,
            finding_rows  = finding_rows,
            sub_rows      = sub_rows,
            port_rows     = port_rows,
            tech_rows     = tech_rows,
            ep_rows       = ep_rows,
            timing_rows   = timing_rows,
            cve_rows      = cve_rows,
        )

    # ─── console summary ──────────────────────────────────────────────────────

    def print_summary(self, out):
        counts = self._counts()
        out.rule("SCAN COMPLETE — FINDINGS SUMMARY")
        out.print(f"  [bold]Target:[/bold] {self.domain}")
        out.print(f"  [bold]Duration:[/bold] {(self.end_ts - self.start_ts).total_seconds():.0f}s")
        out.print()
        sev_colors = {"CRITICAL": "bold red", "HIGH": "red",
                      "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for sev, cnt in counts.items():
            if cnt:
                c = sev_colors[sev]
                out.print(f"  [{c}]{sev:<10}[/{c}] {cnt}")
        out.print()
        out.print(f"  [bold green]Reports written to:[/bold green] {self.out_dir}/")
        out.print(f"    report.txt  |  report.json  |  report.html  |  report.md")

    # ─── Markdown report ──────────────────────────────────────────────────────

    def write_markdown(self):
        counts  = self._counts()
        elapsed = (self.end_ts - self.start_ts).total_seconds()
        md_path = os.path.join(self.out_dir, "report.md")
        lines = [
            f"# ShadowRecon Report — {self.domain}", "",
            "| Field | Value |", "|-------|-------|",
            f"| Target | `{self.domain}` |",
            f"| Started | {self.start_ts.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
            f"| Duration | {elapsed:.0f}s |", "",
            "## Findings Summary", "",
            "| Severity | Count |", "|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts[sev]} |")
        lines += ["", "## Detailed Findings", ""]
        for f in self.findings:
            sev, msg = f.get("severity","INFO"), f.get("message","")
            cwe, mod = f.get("cwe",""),          f.get("module","")
            url, ev  = f.get("url",""),          f.get("evidence","")
            lines.append(f"### [{sev}] {msg}")
            if cwe: lines.append(f"- **CWE**: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)")
            if mod: lines.append(f"- **Module**: `{mod}`")
            if url: lines.append(f"- **URL**: `{url}`")
            if ev:  lines.append(f"- **Evidence**: `{ev[:200]}`")
            lines.append("")
        if self.state.subdomains:
            lines += ["## Subdomains","","| Hostname | IPs | Source |","|----------|-----|--------|"]
            for s in self.state.subdomains:
                lines.append(f"| `{s.get('host','')}` | {', '.join(s.get('ips',[]))} | {s.get('source','')} |")
        if self.state.technologies:
            lines += ["","## Technologies","","| Technology | Category |","|------------|----------|"]
            for name, cat in self.state.technologies.items():
                lines.append(f"| {name} | {cat} |")
        timings = getattr(self.state, "module_timings", {})
        if timings:
            lines += ["","## Module Timings","","| Module | Duration |","|--------|----------|"]
            for mod, dur in sorted(timings.items(), key=lambda x: -x[1]):
                lines.append(f"| `{mod}` | {dur}s |")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return md_path


def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ── HTML Template ──────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowRecon — {domain}</title>
<style>
  :root {{
    --bg:       #0f0f13;
    --surface:  #1a1a24;
    --surface2: #22222f;
    --border:   #2e2e42;
    --text:     #e2e2f0;
    --muted:    #8888aa;
    --accent:   #7c5cfc;
    --green:    #22c55e;
    --crit:     #dc2626;
    --high:     #ea580c;
    --med:      #d97706;
    --low:      #2563eb;
    --info:     #6b7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.5;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 12px; }}
  pre.evidence {{
    background: #0a0a10;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-all;
    color: #aaa;
    margin: 4px 0 8px;
  }}

  /* ── Layout ── */
  .sidebar {{
    position: fixed; top: 0; left: 0;
    width: 220px; height: 100vh;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 24px 0;
    overflow-y: auto;
    z-index: 10;
  }}
  .sidebar-logo {{
    padding: 0 20px 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
  }}
  .sidebar-logo h1 {{ font-size: 16px; color: var(--accent); font-weight: 700; letter-spacing: 1px; }}
  .sidebar-logo p {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .nav-item {{
    display: block;
    padding: 9px 20px;
    color: var(--muted);
    font-size: 13px;
    transition: all .15s;
    cursor: pointer;
    border-left: 3px solid transparent;
  }}
  .nav-item:hover {{ color: var(--text); background: var(--surface2); border-left-color: var(--accent); }}
  .nav-section {{
    padding: 16px 20px 4px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
  }}

  .main {{
    margin-left: 220px;
    padding: 32px 40px;
    max-width: 1400px;
  }}

  /* ── Hero ── */
  .hero {{
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px;
    margin-bottom: 32px;
  }}
  .hero h2 {{ font-size: 26px; font-weight: 700; color: #fff; }}
  .hero .meta {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
  .hero .meta span {{ margin-right: 24px; }}

  /* ── Cards ── */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 16px;
    text-align: center;
  }}
  .card-num {{ font-size: 34px; font-weight: 800; }}
  .card-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; margin-top: 4px; }}
  .c-crit {{ color: var(--crit); }}
  .c-high {{ color: var(--high); }}
  .c-med  {{ color: var(--med); }}
  .c-low  {{ color: var(--low); }}
  .c-info {{ color: var(--info); }}
  .c-sub  {{ color: #a78bfa; }}
  .c-port {{ color: #34d399; }}

  /* ── Stat bars ── */
  .stat-bars {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; margin-bottom: 32px; }}
  .stat-bars h3 {{ font-size: 14px; margin-bottom: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .stat-bar-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
  .stat-label {{ width: 80px; font-size: 12px; font-weight: 600; }}
  .stat-bar-track {{ flex: 1; height: 8px; background: var(--surface2); border-radius: 4px; overflow: hidden; }}
  .stat-bar-fill {{ height: 100%; border-radius: 4px; transition: width .5s; }}
  .stat-count {{ width: 30px; text-align: right; font-size: 12px; color: var(--muted); }}

  /* ── Section ── */
  .section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 16px; font-weight: 700;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px; margin-bottom: 20px;
    color: var(--text);
  }}
  .section-title .count {{
    font-size: 12px; font-weight: 400;
    color: var(--muted); margin-left: 8px;
  }}

  /* ── Filter bar ── */
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
  .filter-btn {{
    padding: 5px 14px; border-radius: 20px;
    border: 1px solid var(--border);
    background: var(--surface2); color: var(--muted);
    cursor: pointer; font-size: 12px; transition: all .15s;
  }}
  .filter-btn.active, .filter-btn:hover {{ border-color: var(--accent); color: var(--text); background: var(--accent)22; }}

  /* ── Table ── */
  .tbl-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: var(--surface2);
    color: var(--muted);
    font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
    padding: 10px 14px; text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    font-size: 13px;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface2); }}
  .finding-row td {{ vertical-align: middle; }}
  .evidence-row td {{ background: #0a0a1088; }}
  .url-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .risky-port td {{ color: #fca5a5; }}

  /* ── Badges ── */
  .badge {{
    display: inline-block;
    padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700;
    letter-spacing: .5px; white-space: nowrap;
  }}
  .badge-critical {{ background: #dc262622; color: var(--crit); border: 1px solid var(--crit); }}
  .badge-high     {{ background: #ea580c22; color: var(--high); border: 1px solid var(--high); }}
  .badge-medium   {{ background: #d9770622; color: var(--med);  border: 1px solid var(--med); }}
  .badge-low      {{ background: #2563eb22; color: var(--low);  border: 1px solid var(--low); }}
  .badge-info     {{ background: #6b728022; color: var(--info); border: 1px solid var(--info); }}

  /* ── Search box ── */
  .search-box {{
    padding: 8px 14px; border-radius: 6px;
    border: 1px solid var(--border); background: var(--surface2);
    color: var(--text); font-size: 13px; width: 280px;
    margin-bottom: 16px;
  }}
  .search-box:focus {{ outline: none; border-color: var(--accent); }}

  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}

  @media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; padding: 16px; }}
  }}
</style>
</head>
<body>

<!-- Sidebar -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <h1>SHADOWRECON</h1>
    <p>v2.0 Pentest Recon</p>
  </div>
  <span class="nav-section">Navigation</span>
  <a class="nav-item" onclick="scrollTo('overview')">📊 Overview</a>
  <a class="nav-item" onclick="scrollTo('findings')">🔴 Findings</a>
  <a class="nav-item" onclick="scrollTo('subdomains')">🌐 Subdomains</a>
  <a class="nav-item" onclick="scrollTo('ports')">🔌 Open Ports</a>
  <a class="nav-item" onclick="scrollTo('technologies')">🛠 Technologies</a>
  <a class="nav-item" onclick="scrollTo('cves')">🐛 CVEs</a>
  <a class="nav-item" onclick="scrollTo('endpoints')">📡 API Endpoints</a>
  <a class="nav-item" onclick="scrollTo('timings')">⏱ Module Timings</a>
</nav>

<!-- Main -->
<main class="main">

  <!-- Hero -->
  <div class="hero" id="overview">
    <h2>🔍 {domain}</h2>
    <div class="meta">
      <span>🕐 Started: {started}</span>
      <span>✅ Finished: {finished}</span>
      <span>⏱ Duration: {elapsed}s</span>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="cards">
    <div class="card"><div class="card-num c-crit">{count_crit}</div><div class="card-label">Critical</div></div>
    <div class="card"><div class="card-num c-high">{count_high}</div><div class="card-label">High</div></div>
    <div class="card"><div class="card-num c-med">{count_med}</div><div class="card-label">Medium</div></div>
    <div class="card"><div class="card-num c-low">{count_low}</div><div class="card-label">Low</div></div>
    <div class="card"><div class="card-num c-info">{count_info}</div><div class="card-label">Info</div></div>
    <div class="card"><div class="card-num c-sub">{count_sub}</div><div class="card-label">Subdomains</div></div>
    <div class="card"><div class="card-num c-port">{count_ports}</div><div class="card-label">Open Ports</div></div>
    <div class="card"><div class="card-num" style="color:#f9a8d4">{count_tech}</div><div class="card-label">Technologies</div></div>
    <div class="card"><div class="card-num" style="color:#fb923c">{count_cves}</div><div class="card-label">CVEs</div></div>
    <div class="card"><div class="card-num" style="color:#34d399">{count_ep}</div><div class="card-label">Endpoints</div></div>
  </div>

  <!-- Distribution bars -->
  <div class="stat-bars">
    <h3>Finding Distribution</h3>
    {stat_bars}
  </div>

  <!-- Findings -->
  <div class="section" id="findings">
    <div class="section-title">
      Security Findings
      <span class="count">({count_crit} Critical · {count_high} High · {count_med} Medium · {count_low} Low · {count_info} Info)</span>
    </div>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="color:var(--crit)">Critical</button>
      <button class="filter-btn" onclick="filterFindings('HIGH')" style="color:var(--high)">High</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="color:var(--med)">Medium</button>
      <button class="filter-btn" onclick="filterFindings('LOW')" style="color:var(--low)">Low</button>
      <button class="filter-btn" onclick="filterFindings('INFO')">Info</button>
    </div>
    <input class="search-box" id="findingSearch" placeholder="Search findings..." oninput="searchFindings(this.value)">

    <div class="tbl-wrap">
      <table id="findingsTable">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Description</th>
            <th>CWE</th>
            <th>Module</th>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Subdomains -->
  <div class="section" id="subdomains">
    <div class="section-title">Subdomains <span class="count">({count_sub} discovered)</span></div>
    <input class="search-box" id="subSearch" placeholder="Search subdomains..." oninput="searchTable('subTable', this.value)">
    <div class="tbl-wrap">
      <table id="subTable">
        <thead><tr><th>Hostname</th><th>IP Addresses</th><th>Source</th></tr></thead>
        <tbody>{sub_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Open Ports -->
  <div class="section" id="ports">
    <div class="section-title">Open Ports <span class="count">({count_ports} open)</span></div>
    <div class="tbl-wrap">
      <table id="portTable">
        <thead><tr><th>Port</th><th>Service</th><th>IP</th><th>Banner</th></tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Technologies -->
  <div class="section" id="technologies">
    <div class="section-title">Technologies <span class="count">({count_tech} detected)</span></div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Technology</th><th>Category</th></tr></thead>
        <tbody>{tech_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- CVEs -->
  <div class="section" id="cves">
    <div class="section-title">CVE Correlation <span class="count">({count_cves} matched)</span></div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>CVE ID</th><th>Product</th><th>Severity</th></tr></thead>
        <tbody>{cve_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- API Endpoints -->
  <div class="section" id="endpoints">
    <div class="section-title">API Endpoints <span class="count">({count_ep} from JS recon)</span></div>
    <input class="search-box" id="epSearch" placeholder="Filter endpoints..." oninput="searchTable('epTable', this.value)">
    <div class="tbl-wrap">
      <table id="epTable">
        <thead><tr><th>Endpoint Path</th></tr></thead>
        <tbody>{ep_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Module Timings -->
  <div class="section" id="timings">
    <div class="section-title">Module Timings</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Module</th><th>Duration</th><th>Relative</th></tr></thead>
        <tbody>{timing_rows}</tbody>
      </table>
    </div>
  </div>

</main>

<script>
function scrollTo(id) {{
  document.getElementById(id)?.scrollIntoView({{behavior:'smooth', block:'start'}});
}}

let currentFilter = 'ALL';
function filterFindings(sev) {{
  currentFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  applyFindingFilter();
}}

function applyFindingFilter() {{
  const term = (document.getElementById('findingSearch')?.value || '').toLowerCase();
  document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
    const rowSev = row.dataset.sev || '';
    const text   = row.textContent.toLowerCase();
    const sevOk  = currentFilter === 'ALL' || rowSev === currentFilter;
    const termOk = !term || text.includes(term);
    row.style.display = (sevOk && termOk) ? '' : 'none';
  }});
}}

function searchFindings(val) {{ applyFindingFilter(); }}

function searchTable(tableId, val) {{
  const term = val.toLowerCase();
  document.querySelectorAll(`#${{tableId}} tbody tr`).forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(term) ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""