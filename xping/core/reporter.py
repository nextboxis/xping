"""
xping.core.reporter
~~~~~~~~~~~~~~~~~~~~~~~~
Report generation in three formats:
  - Terminal: Colored, human-readable output with severity icons
  - JSON: Structured data for automation and SIEM integration
  - HTML: Self-contained report with embedded CSS for sharing

Design decision: HTML reports embed all CSS inline so they can be
opened standalone without a web server or external dependencies.
"""

import json
import os
import html as html_lib
from datetime import datetime
from typing import Optional

from xping import __version__
from xping.core.models import ScanResult, Severity
from xping.core.logger import get_logger
from xping.utils.helpers import Colors, ansi_color, severity_icon

log = get_logger("reporter")


class Reporter:
    """Generate reports from scan results in multiple formats."""

    def __init__(self, scan_result: ScanResult):
        self.result = scan_result

    # ── Terminal Report ──────────────────────────────────────────────────

    def print_terminal(self) -> None:
        """Print a colored, formatted report to the terminal."""
        r = self.result

        # Header
        print()
        print(ansi_color("╔══════════════════════════════════════════════════════════════╗", Colors.CYAN))
        print(ansi_color("║                  X P I N G   R E P O R T                    ║", Colors.CYAN + Colors.BOLD))
        print(ansi_color("╚══════════════════════════════════════════════════════════════╝", Colors.CYAN))
        print()
        print(f"  Scan ID:    {r.scan_id}")
        print(f"  Timestamp:  {r.timestamp}")
        print(f"  Hostname:   {r.hostname}")
        if r.target_ip:
            print(f"  Target IP:  {r.target_ip}")
        print(f"  Kernel:     {r.kernel}")
        print(f"  Run as:     {'root' if r.run_as_root else 'unprivileged'}")
        print(f"  Duration:   {r.total_execution_time:.2f}s")
        print()

        # Overall risk banner
        risk = r.overall_risk
        risk_colors = {
            "CRITICAL": Colors.BG_RED + Colors.WHITE,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.GREEN,
        }
        risk_color = risk_colors.get(risk, Colors.GREEN)
        print(ansi_color(f"  ▶ OVERALL RISK: {risk}", risk_color + Colors.BOLD))
        print(f"  ▶ TOTAL FINDINGS: {r.total_findings}")
        print()

        # Severity breakdown
        severity_counts = {s.name: 0 for s in Severity}
        for mr in r.module_results:
            for f in mr.findings:
                severity_counts[f.severity.name] += 1

        print("  ┌─────────────┬───────┐")
        print("  │  Severity   │ Count │")
        print("  ├─────────────┼───────┤")
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts[sev_name]
            count_str = str(count).rjust(5)
            if sev_name == "CRITICAL" and count > 0:
                count_str = ansi_color(count_str, Colors.RED + Colors.BOLD)
            elif sev_name == "HIGH" and count > 0:
                count_str = ansi_color(count_str, Colors.RED)
            elif sev_name == "MEDIUM" and count > 0:
                count_str = ansi_color(count_str, Colors.YELLOW)
            print(f"  │ {sev_name:11s} │{count_str} │")
        print("  └─────────────┴───────┘")
        print()

        # Module results
        for mr in r.module_results:
            if mr.skipped:
                print(ansi_color(f"  ⊘ {mr.module_name} — SKIPPED ({mr.skip_reason})", Colors.DIM))
                continue

            # Module header
            sev_indicator = ""
            if mr.has_critical:
                sev_indicator = ansi_color(" [CRITICAL]", Colors.RED + Colors.BOLD)
            elif mr.max_severity >= Severity.HIGH:
                sev_indicator = ansi_color(" [HIGH]", Colors.RED)

            print(ansi_color(f"  ━━━ {mr.module_name.upper()} ", Colors.CYAN + Colors.BOLD) +
                  ansi_color(f"({mr.description})", Colors.DIM) + sev_indicator)
            print(f"      {len(mr.findings)} findings in {mr.execution_time:.2f}s")

            if mr.errors:
                for err in mr.errors:
                    print(ansi_color(f"      ⚠ Error: {err}", Colors.YELLOW))

            # Findings (skip INFO unless verbose or few findings)
            for finding in sorted(mr.findings, key=lambda f: -f.severity_score):
                if finding.severity == Severity.INFO:
                    continue  # Skip INFO in terminal (too noisy)

                print()
                print(f"      {severity_icon(finding.severity.name)}  {finding.title}")
                print(f"      {ansi_color('Description:', Colors.DIM)} {finding.description}")

                if finding.evidence:
                    evidence_lines = finding.evidence.splitlines()
                    print(f"      {ansi_color('Evidence:', Colors.DIM)}")
                    for eline in evidence_lines[:5]:
                        print(f"        {eline}")
                    if len(evidence_lines) > 5:
                        print(f"        ... ({len(evidence_lines) - 5} more lines)")

                if finding.remediation:
                    print(f"      {ansi_color('Fix:', Colors.GREEN)} {finding.remediation}")

            print()

        # Footer
        print(ansi_color("─" * 64, Colors.DIM))
        print(f"  Scan complete. Use --format json for machine-readable output.")
        print()

    # ── JSON Report ──────────────────────────────────────────────────────

    def write_json(self, output_path: str) -> str:
        """Write full structured report to JSON file."""
        data = self.result.to_dict()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        log.info(f"JSON report written to: {output_path}")
        return output_path

    # ── HTML Report ──────────────────────────────────────────────────────

    def write_html(self, output_path: str) -> str:
        """Generate a self-contained HTML report with embedded CSS."""
        r = self.result
        data = r.to_dict()

        # Count severities
        severity_counts = data["severity_summary"]

        # Build findings HTML
        modules_html = ""
        for mr in r.module_results:
            if mr.skipped:
                modules_html += f'<div class="module skipped"><h3>⊘ {esc(mr.module_name)} — Skipped</h3><p>{esc(mr.skip_reason)}</p></div>'
                continue

            findings_html = ""
            for f in sorted(mr.findings, key=lambda x: -x.severity_score):
                sev_class = f.severity.name.lower()
                evidence_html = ""
                if f.evidence:
                    evidence_html = f'<div class="evidence"><strong>Evidence:</strong><pre>{esc(f.evidence[:2000])}</pre></div>'
                remediation_html = ""
                if f.remediation:
                    remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {esc(f.remediation)}</div>'
                cve_html = ""
                if f.cve_refs:
                    cve_html = f'<div class="cves"><strong>CVEs:</strong> {", ".join(esc(c) for c in f.cve_refs)}</div>'

                findings_html += f'''
                <div class="finding {sev_class}">
                    <div class="finding-header">
                        <span class="severity-badge {sev_class}">{esc(f.severity.name)}</span>
                        <span class="finding-title">{esc(f.title)}</span>
                    </div>
                    <p>{esc(f.description)}</p>
                    {evidence_html}
                    {remediation_html}
                    {cve_html}
                </div>'''

            error_html = ""
            if mr.errors:
                error_html = '<div class="errors"><strong>Errors:</strong><ul>'
                for e in mr.errors:
                    error_html += f'<li>{esc(e)}</li>'
                error_html += '</ul></div>'

            modules_html += f'''
            <div class="module">
                <h3>{esc(mr.module_name.upper())}
                    <span class="module-meta">{esc(mr.description)} — {len(mr.findings)} findings in {mr.execution_time:.2f}s</span>
                </h3>
                {error_html}
                {findings_html}
            </div>'''

        risk_class = r.overall_risk.lower()

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XPing Security Report — {esc(r.hostname)}</title>
    <style>
        :root {{
            --bg: #0a0e17;
            --surface: #111827;
            --surface2: #1f2937;
            --border: #374151;
            --text: #e5e7eb;
            --text-dim: #9ca3af;
            --accent: #3b82f6;
            --critical: #dc2626;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #6b7280;
            --green: #10b981;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0a0e17 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 1.5rem;
        }}
        .header h1 {{
            font-size: 1.8rem;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem; color: var(--text-dim); font-size: 0.9rem; }}
        .risk-banner {{
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            font-size: 1.3rem;
            font-weight: 700;
            margin: 1.5rem 0;
            border: 2px solid;
        }}
        .risk-banner.critical {{ background: rgba(220,38,38,0.15); border-color: var(--critical); color: var(--critical); }}
        .risk-banner.high {{ background: rgba(239,68,68,0.15); border-color: var(--high); color: var(--high); }}
        .risk-banner.medium {{ background: rgba(245,158,11,0.15); border-color: var(--medium); color: var(--medium); }}
        .risk-banner.low {{ background: rgba(16,185,129,0.15); border-color: var(--green); color: var(--green); }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }}
        .stat {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .stat .count {{ font-size: 2rem; font-weight: 700; }}
        .stat .label {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; }}
        .stat.critical .count {{ color: var(--critical); }}
        .stat.high .count {{ color: var(--high); }}
        .stat.medium .count {{ color: var(--medium); }}
        .stat.low .count {{ color: var(--low); }}
        .stat.info .count {{ color: var(--info); }}
        .module {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .module.skipped {{ opacity: 0.5; padding: 1rem; }}
        .module h3 {{
            background: var(--surface2);
            padding: 1rem 1.5rem;
            font-size: 1rem;
            border-bottom: 1px solid var(--border);
        }}
        .module-meta {{ font-weight: 400; color: var(--text-dim); font-size: 0.85rem; margin-left: 0.5rem; }}
        .finding {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .finding:last-child {{ border-bottom: none; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
        .finding-title {{ font-weight: 600; }}
        .severity-badge {{
            padding: 0.15rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .severity-badge.critical {{ background: var(--critical); color: white; }}
        .severity-badge.high {{ background: var(--high); color: white; }}
        .severity-badge.medium {{ background: var(--medium); color: black; }}
        .severity-badge.low {{ background: var(--low); color: white; }}
        .severity-badge.info {{ background: var(--info); color: white; }}
        .evidence {{ margin: 0.75rem 0; }}
        .evidence pre {{
            background: var(--bg);
            padding: 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 0.25rem;
            max-height: 200px;
            overflow-y: auto;
        }}
        .remediation {{
            margin-top: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: rgba(16,185,129,0.1);
            border-left: 3px solid var(--green);
            border-radius: 0 4px 4px 0;
            font-size: 0.9rem;
        }}
        .errors {{ padding: 0.75rem 1.5rem; color: var(--medium); }}
        .errors ul {{ margin-left: 1.5rem; }}
        .footer {{
            text-align: center;
            color: var(--text-dim);
            font-size: 0.8rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }}
        @media (max-width: 768px) {{
            .stats {{ grid-template-columns: repeat(3, 1fr); }}
            body {{ padding: 1rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡 XPing Security Report</h1>
            <div class="meta">
                <span>Scan ID: {esc(r.scan_id)}</span>
                <span>Host: {esc(r.hostname)}</span>
                <span>Target IP: {esc(r.target_ip or 'N/A')}</span>
                <span>Kernel: {esc(r.kernel)}</span>
                <span>Time: {esc(r.timestamp)}</span>
                <span>Run as: {"root" if r.run_as_root else "unprivileged"}</span>
                <span>Duration: {r.total_execution_time:.2f}s</span>
            </div>
        </div>

        <div class="risk-banner {risk_class}">
            OVERALL RISK: {esc(r.overall_risk)} — {r.total_findings} total findings
        </div>

        <div class="stats">
            <div class="stat critical">
                <div class="count">{severity_counts.get("CRITICAL", 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat high">
                <div class="count">{severity_counts.get("HIGH", 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat medium">
                <div class="count">{severity_counts.get("MEDIUM", 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat low">
                <div class="count">{severity_counts.get("LOW", 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat info">
                <div class="count">{severity_counts.get("INFO", 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>

        {modules_html}

        <div class="footer">
            Generated by XPing v{__version__} — {esc(r.timestamp)}
        </div>
    </div>
</body>
</html>'''

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        log.info(f"HTML report written to: {output_path}")
        return output_path

    # ── Convenience Method ───────────────────────────────────────────────

    def generate(
        self,
        fmt: str = "terminal",
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate report in the specified format.

        Args:
            fmt:         "terminal", "json", or "html"
            output_path: File path for json/html output

        Returns:
            Output file path for json/html, None for terminal
        """
        if fmt == "terminal":
            self.print_terminal()
            return None
        elif fmt == "json":
            path = output_path or f"XPing_report_{self.result.scan_id}.json"
            return self.write_json(path)
        elif fmt == "html":
            path = output_path or f"XPing_report_{self.result.scan_id}.html"
            return self.write_html(path)
        elif fmt == "sarif":
            path = output_path or f"XPing_report_{self.result.scan_id}.sarif"
            return self.write_sarif(path)
        else:
            log.error(f"Unknown report format: {fmt}")
            return None

    # ── SARIF Export (GitHub Code Scanning) ────────────────────────────────

    def write_sarif(self, output_path: str) -> str:
        """Write findings in SARIF v2.1.0 JSON format for GitHub Security integration."""
        r = self.result
        rules = []
        sarif_results = []
        rule_ids = set()

        sev_mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }

        for mr in r.module_results:
            for f in mr.findings:
                rule_id = f"XPING-{f.module.upper()}-{hash(f.title) % 10000:04d}"
                if rule_id not in rule_ids:
                    rule_ids.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "name": f.title.replace(" ", ""),
                        "shortDescription": {"text": f.title},
                        "fullDescription": {"text": f.description},
                        "help": {"text": f.remediation or "Review configuration and system state."},
                        "properties": {
                            "tags": ["security", f.module, f.severity.name.lower()] + ([f.cis_tag] if f.cis_tag else []) + ([f.nist_tag] if f.nist_tag else [])
                        }
                    })

                sarif_results.append({
                    "ruleId": rule_id,
                    "level": sev_mapping.get(f.severity.name, "note"),
                    "message": {
                        "text": f"{f.title}: {f.description}" + (f"\nEvidence: {f.evidence}" if f.evidence else "")
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.metadata.get("path", "/etc/system")
                            }
                        }
                    }]
                })

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "XPing Security Auditor",
                        "version": __version__,
                        "informationUri": "https://github.com/giridharan-dev/xping",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }]
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)

        log.info(f"SARIF report written to: {output_path}")
        return output_path

    # ── Automated Remediation Generator ────────────────────────────────────

    def generate_remediation_script(self, output_path: str) -> str:
        """Generate executable bash script (remediation.sh) based on scan findings."""
        r = self.result
        lines = [
            "#!/usr/bin/env bash",
            "# ==================================================================",
            f"# XPing Automated Remediation Script (Scan ID: {r.scan_id})",
            f"# Target Host: {r.hostname} | Generated: {r.timestamp}",
            "# WARNING: Review all commands carefully before running in production!",
            "# ==================================================================",
            "",
            "set -euo pipefail",
            "",
            'if [ "$EUID" -ne 0 ]; then',
            '    echo "[-] Error: Remediation script must be executed as root (sudo)."',
            "    exit 1",
            "fi",
            "",
            'echo "[+] Applying XPing automated remediation rules..."',
            "",
        ]

        count = 0
        for mr in r.module_results:
            for f in mr.findings:
                if f.remediation and f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM):
                    count += 1
                    lines.append(f"# [{mr.module_name.upper()}] [{f.severity.name}] {f.title}")
                    lines.append(f"# Remediation note: {f.remediation}")
                    
                    # Extract shell command lines if remediation specifies commands
                    for line in f.remediation.splitlines():
                        cmd_line = line.strip()
                        if cmd_line.startswith("chmod ") or cmd_line.startswith("chown ") or cmd_line.startswith("sysctl ") or cmd_line.startswith("sudo "):
                            if cmd_line.startswith("sudo "):
                                cmd_line = cmd_line[5:]
                            lines.append(f"{cmd_line}")
                    lines.append("")

        if count == 0:
            lines.append('# No High/Critical findings requiring automated shell remediation.')

        lines.append('echo "[+] Remediation script execution complete."')

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        log.info(f"Remediation script written to: {output_path}")
        return output_path

    # ── Security Drift Comparison ─────────────────────────────────────────

    @staticmethod
    def compare_scans(baseline: dict, current: dict) -> dict:
        """
        Compare baseline and current scan JSON data to identify security drift.

        Returns dict containing:
            added_findings:       Findings in current but not in baseline
            resolved_findings:    Findings in baseline but fixed in current
            persistent_findings:  Findings present in both scans
        """
        def _finding_key(f: dict) -> tuple:
            return (f.get("module", ""), f.get("title", ""), f.get("severity", ""))

        baseline_findings = {}
        for mod in baseline.get("modules", []):
            for f in mod.get("findings", []):
                baseline_findings[_finding_key(f)] = f

        current_findings = {}
        for mod in current.get("modules", []):
            for f in mod.get("findings", []):
                current_findings[_finding_key(f)] = f

        added = [f for key, f in current_findings.items() if key not in baseline_findings]
        resolved = [f for key, f in baseline_findings.items() if key not in current_findings]
        persistent = [f for key, f in current_findings.items() if key in baseline_findings]

        return {
            "baseline_id": baseline.get("scan_id", "unknown"),
            "current_id": current.get("scan_id", "unknown"),
            "added_count": len(added),
            "resolved_count": len(resolved),
            "persistent_count": len(persistent),
            "added_findings": added,
            "resolved_findings": resolved,
            "persistent_findings": persistent,
        }


def esc(text: str) -> str:
    """HTML-escape a string."""
    return html_lib.escape(str(text))
