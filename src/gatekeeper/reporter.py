"""Report generation — terminal, JSON, and HTML output for infra audits."""

import json
from datetime import datetime

from .probes import AuditFinding


class Reporter:
    """Generate infrastructure audit reports in multiple formats."""

    def __init__(self, findings: list[AuditFinding], summary: dict):
        self.findings = findings
        self.summary = summary

    def terminal(self):
        """Print a formatted table to the terminal."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

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

        # Failed by severity
        if self.summary["failed_by_severity"]:
            sev_table = Table(title="Failed by Severity")
            sev_table.add_column("Severity", style="bold")
            sev_table.add_column("Count", justify="right")
            severity_colors = {
                "critical": "red", "high": "red3",
                "medium": "yellow", "low": "dim", "info": "dim",
            }
            for sev in ("critical", "high", "medium", "low", "info"):
                count = self.summary["failed_by_severity"].get(sev, 0)
                if count > 0:
                    sev_table.add_row(
                        f"[{severity_colors.get(sev, '')}]{sev.upper()}[/{severity_colors.get(sev, '')}]",
                        str(count),
                    )
            console.print(sev_table)
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

        # Detail table
        detail_table = Table(title="Findings")
        detail_table.add_column("ID", style="dim")
        detail_table.add_column("Check")
        detail_table.add_column("Severity")
        detail_table.add_column("Result")

        sev_color = {"critical": "red", "high": "red3", "medium": "yellow", "low": "dim", "info": "dim"}
        for f in self.findings:
            status = "[green]PASS[/green]" if f.passed else "[red]FAIL[/red]"
            detail_table.add_row(
                f.id,
                f.name,
                f"[{sev_color.get(f.severity, '')}]{f.severity.upper()}[/{sev_color.get(f.severity, '')}]",
                status,
            )
        console.print(detail_table)

        # Failed findings with fixes
        failed = [f for f in self.findings if not f.passed]
        if failed:
            console.print()
            for f in failed:
                console.print(f"[red]FAIL  {f.id} — {f.name}[/red]")
                console.print(f"       {f.detail}")
                if f.fix:
                    console.print(f"       [green]Fix:[/green]")
                    for line in f.fix.split("\n"):
                        console.print(f"       [green]  {line}[/green]")
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
            fix_html = f'<pre style="background:#0f172a;padding:0.5rem;border-radius:0.25rem;font-size:0.85em;white-space:pre-wrap">{f.fix}</pre>' if f.fix else ""
            rows += f"""
            <tr>
                <td><code>{f.id}</code></td>
                <td>{f.name}</td>
                <td style="color:{sev_c};font-weight:bold">{f.severity.upper()}</td>
                <td>{badge}</td>
                <td style="max-width:300px">{f.detail}{fix_html}</td>
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

        rules = {}
        results_list = []
        for f in self.findings:
            rule_id = f.id
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.name,
                    "shortDescription": {"text": f.description},
                    "help": {"text": f"Category: {f.category}\n\nFix:\n{f.fix}" if f.fix else f"Category: {f.category}"},
                    "properties": {"category": f.category},
                }
            results_list.append({
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": sarif_severity.get(f.severity, "warning"),
                "message": {"text": f.detail or f.description},
                "kind": "fail" if not f.passed else "pass",
            })

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Gatekeeper",
                        "version": "1.0.0",
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
