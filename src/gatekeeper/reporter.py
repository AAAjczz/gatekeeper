"""Report generation — terminal, JSON, and HTML output for infra audits."""

import html
import json
from datetime import datetime

from .probes import AuditFinding


class Reporter:
    """Generate infrastructure audit reports in multiple formats."""

    def __init__(self, findings: list[AuditFinding], summary: dict):
        self.findings = findings
        self.summary = summary

    @staticmethod
    def _risk_default(finding: AuditFinding) -> tuple[str, str]:
        """Get risk explanation and effort — check probe first, then knowledge base, then defaults."""
        # 1. Probe set its own values
        if finding.risk_what and finding.effort:
            return finding.risk_what, finding.effort

        # 2. Check centralized knowledge base
        from .probes import RISK_KNOWLEDGE
        kb = RISK_KNOWLEDGE.get(finding.id, {})
        risk = finding.risk_what or kb.get("risk_what", "")
        effort = finding.effort or kb.get("effort", "")

        # 3. Fall back to severity-based defaults
        risk_defaults = {
            "critical": ("Immediate compromise possible -- full system access, "
                         "data theft, or financial loss.", "Requires immediate attention"),
            "high": ("Likely exploitable -- could lead to data exposure, "
                     "abuse, or service disruption.", "Fix today"),
            "medium": ("Increases attack surface -- makes other vulnerabilities "
                       "easier to exploit.", "Fix this week"),
            "low": ("Best-practice gap -- not directly exploitable but "
                    "weakens overall security posture.", "Fix when convenient"),
            "info": ("", ""),
        }
        r_default, e_default = risk_defaults.get(finding.severity, ("", ""))
        return (risk or r_default, effort or e_default)

    def terminal(self):
        """Print a formatted table to the terminal with risk analysis."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        console = Console()

        # Score banner
        score = self.summary["score"]
        if score >= 95:
            color = "green"
        elif score >= 80:
            color = "yellow"
        elif score >= 60:
            color = "yellow3"
        elif score >= 40:
            color = "red"
        else:
            color = "red3"

        console.print()
        console.print(Panel(
            f"[bold {color}]Security Score: {score}%[/bold {color}]",
            title="Gatekeeper Infrastructure Audit",
            subtitle=datetime.now().strftime("%Y-%m-%d %H:%M"),
        ))
        console.print(f"  Project:   {self.summary['project_dir']}")
        console.print(f"  Endpoint:  {self.summary['endpoint']}")
        console.print(f"  Passed:    [green]{self.summary['passed']}[/green] / {self.summary['total_probes']}")
        console.print(f"  Failed:    [red]{self.summary['failed']}[/red] / {self.summary['total_probes']}")
        console.print(f"  {self.summary['interpretation']}")
        console.print(f"  [dim]{self.summary['note']}[/dim]")
        console.print()

        # ================================================================
        # PRIORITY ACTION PLAN — failed findings ranked by risk
        # ================================================================
        failed = [f for f in self.findings if not f.passed]
        if failed:
            # Sort: critical > high > medium > low > info
            sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            failed_sorted = sorted(failed, key=lambda f: sev_order.get(f.severity, 0), reverse=True)

            priority_table = Table(
                title="Priority Action Plan -- Fix These First",
                caption="Ordered by risk: what to fix, what happens if you don't, how long it takes.",
            )
            priority_table.add_column("#", style="dim")
            priority_table.add_column("ID", style="bold")
            priority_table.add_column("Issue")
            priority_table.add_column("Severity")
            priority_table.add_column("Effort")
            priority_table.add_column("What Happens If Ignored")

            sev_color_pri = {"critical": "red", "high": "red3", "medium": "yellow", "low": "dim", "info": "dim"}
            for i, f in enumerate(failed_sorted, 1):
                risk, effort = self._risk_default(f)
                priority_table.add_row(
                    str(i),
                    f.id,
                    f.name,
                    f"[{sev_color_pri.get(f.severity, '')}]{f.severity.upper()}[/{sev_color_pri.get(f.severity, '')}]",
                    effort,
                    risk[:100] + ("..." if len(risk) > 100 else ""),
                )
            console.print(priority_table)
            console.print()

        # Category breakdown
        cat_table = Table(title="Results by Category")
        cat_table.add_column("Category", style="bold")
        cat_table.add_column("Passed", justify="right")
        cat_table.add_column("Total", justify="right")
        cat_table.add_column("Rate", justify="right")

        for cat, stats in self.summary["by_category"].items():
            rate = f"{stats['passed']/stats['total']*100:.0f}%" if stats["total"] > 0 else "N/A"
            rcolor = "green" if stats["passed"] == stats["total"] else "yellow" if stats["passed"] > 0 else "red"
            cat_table.add_row(cat, f"[{rcolor}]{stats['passed']}[/{rcolor}]", str(stats["total"]), rate)
        console.print(cat_table)
        console.print()

        # ================================================================
        # PER-FINDING DETAIL — what it means + how to fix
        # ================================================================
        if failed:
            console.print(Text("Details & Fixes", style="bold underline"))
            console.print()
            for i, f in enumerate(failed_sorted, 1):
                risk, effort = self._risk_default(f)

                console.print(
                    f"[red]> #{i}  {f.id} — {f.name}[/red]  "
                    f"[dim]({f.severity.upper()} | {effort})[/dim]"
                )
                console.print(f"    [yellow]Risk:[/yellow] {risk}")
                if f.detail:
                    console.print(f"    [dim]Detail: {f.detail}[/dim]")
                if f.fix:
                    console.print(f"    [green]How to fix:[/green]")
                    for line in f.fix.split("\n"):
                        console.print(f"      {line}")
                console.print()

    def json(self, path: str):
        """Write JSON report to file."""
        data = {
            **self.summary,
            "timestamp": datetime.now().isoformat(),
            "findings": [
                {
                    "id": f.id,
                    "name": f.name,
                    "category": f.category,
                    "severity": f.severity,
                    "passed": f.passed,
                    "description": f.description,
                    "detail": f.detail,
                    "fix": f.fix,
                    "risk_what": f.risk_what,
                    "effort": f.effort,
                }
                for f in self.findings
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"JSON report saved: {path}")

    def html(self, path: str):
        """Write HTML report to file."""
        score = self.summary["score"]
        if score >= 95:
            color = "#22c55e"
        elif score >= 80:
            color = "#eab308"
        elif score >= 60:
            color = "#f97316"
        else:
            color = "#ef4444"

        rows = ""
        for f in self.findings:
            badge = '<span style="color:#22c55e">PASS</span>' if f.passed else '<span style="color:#ef4444">FAIL</span>'
            sev_c = {"critical": "#ef4444", "high": "#dc2626", "medium": "#eab308", "low": "#9ca3af", "info": "#6b7280"}.get(f.severity, "#9ca3af")
            fix_html = f'<pre style="background:#0f172a;padding:0.5rem;border-radius:0.25rem;font-size:0.85em;white-space:pre-wrap">{html.escape(f.fix)}</pre>' if f.fix else ""
            rows += f"""
            <tr>
                <td><code>{html.escape(f.id)}</code></td>
                <td>{html.escape(f.name)}</td>
                <td style="color:{sev_c};font-weight:bold">{html.escape(f.severity.upper())}</td>
                <td>{badge}</td>
                <td style="max-width:300px">{html.escape(f.detail)}{fix_html}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gatekeeper Infrastructure Audit</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }}
        h1 {{ color: {color}; }}
        .score {{ font-size: 4rem; font-weight: bold; color: {color}; margin: 0; }}
        .meta {{ color: #94a3b8; margin: 0.5rem 0 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1.5rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ color: #94a3b8; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }}
        code {{ background: #1e293b; padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.9em; }}
        .cards {{ display: flex; gap: 1rem; margin: 1.5rem 0; }}
        .card {{ background: #1e293b; padding: 1.25rem; border-radius: 0.5rem; flex: 1; text-align: center; }}
        .card .val {{ font-size: 2rem; font-weight: bold; }}
        .card .lbl {{ color: #94a3b8; font-size: 0.85em; margin-top: 0.25rem; }}
        .bar {{ height: 8px; border-radius: 4px; background: #334155; margin: 0.5rem 0; }}
        .bar-fill {{ height: 100%; border-radius: 4px; background: {color}; }}
        pre {{ margin: 0; }}
    </style>
</head>
<body>
    <h1>Gatekeeper Infrastructure Audit</h1>
    <div class="meta">
        Project: {self.summary['project_dir']} &middot;
        Endpoint: {self.summary['endpoint']} &middot;
        {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </div>

    <div class="cards">
        <div class="card">
            <div class="val" style="color:{color}">{self.summary['score']}%</div>
            <div class="lbl">Security Score</div>
        </div>
        <div class="card">
            <div class="val" style="color:#22c55e">{self.summary['passed']}</div>
            <div class="lbl">Passed</div>
        </div>
        <div class="card">
            <div class="val" style="color:#ef4444">{self.summary['failed']}</div>
            <div class="lbl">Failed</div>
        </div>
        <div class="card">
            <div class="val" style="color:#94a3b8">{self.summary['total_probes']}</div>
            <div class="lbl">Total Checks</div>
        </div>
    </div>

    <div class="bar"><div class="bar-fill" style="width:{score}%"></div></div>
    <p style="color:#94a3b8">{self.summary['interpretation']}</p>
    <p style="color:#64748b;font-size:0.85em">{self.summary['note']}</p>

    <h2>Findings</h2>
    <table>
        <thead><tr><th>ID</th><th>Check</th><th>Severity</th><th>Result</th><th>Detail & Fix</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>

    <p style="color:#475569;font-size:0.85em;margin-top:2rem">
        Generated by <a href="https://github.com/AAAjczz/gatekeeper" style="color:#3b82f6">Gatekeeper</a> v0.2.0 —
        audited {self.summary['total_probes']} deployment-level checks
    </p>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"HTML report saved: {path}")

    def sarif(self, path: str):
        """Write SARIF (Static Analysis Results Interchange Format) report.

        Compatible with GitHub code scanning — upload to see results in
        the Security tab and on PR diffs.
        """
        sarif_severity = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "warning",
            "info": "note",
        }

        # Only report FAILED findings — passing checks are not security alerts
        failed = [f for f in self.findings if not f.passed]

        rules = {}
        results_list = []
        for i, f in enumerate(failed):
            rule_id = f.id
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.name,
                    "shortDescription": {"text": f.description},
                    "help": {
                        "text": f"Risk: {f.risk_what or 'See details'}\n\n"
                                f"How to fix:\n{f.fix}" if f.fix
                                else f"Category: {f.category}",
                    },
                    "properties": {"category": f.category, "severity": f.severity},
                }

            results_list.append({
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": sarif_severity.get(f.severity, "warning"),
                "message": {"text": f"{f.name}: {f.detail or f.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "docker-compose.yml",
                        },
                    },
                }],
            })

        if not failed:
            sarif = {
                "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "Gatekeeper",
                            "version": "1.3.0",
                            "informationUri": "https://github.com/AAAjczz/gatekeeper",
                        },
                    },
                    "results": [],
                }],
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(sarif, fh, indent=2, ensure_ascii=False)
            print(f"SARIF report saved: {path} (no failures)")
            return

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Gatekeeper",
                        "version": "1.3.0",
                        "informationUri": "https://github.com/AAAjczz/gatekeeper",
                        "rules": list(rules.values()),
                    },
                },
                "results": results_list,
            }],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, ensure_ascii=False)
        print(f"SARIF report saved: {path}")
        print("  Upload to GitHub: actions/upload-sarif@v1")
