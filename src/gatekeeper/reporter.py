"""Report generation — terminal, JSON, and HTML output."""

import json
from datetime import datetime

from .probes import ProbeResult


class Reporter:
    """Generate security scan reports in multiple formats."""

    def __init__(self, results: list[ProbeResult], summary: dict):
        self.results = results
        self.summary = summary

    def terminal(self):
        """Print a formatted table to the terminal."""
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
            title="Gatekeeper Scan Report",
            subtitle=datetime.now().strftime("%Y-%m-%d %H:%M"),
        ))
        console.print(f"  Endpoint: {self.summary['endpoint']}")
        console.print(f"  Model:    {self.summary['model']}")
        console.print(f"  Passed:   [green]{self.summary['passed']}[/green] / {self.summary['total_probes']}")
        console.print(f"  Failed:   [red]{self.summary['failed']}[/red] / {self.summary['total_probes']}")
        console.print(f"  {self.summary['interpretation']}")
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
            color = "green" if stats["passed"] == stats["total"] else "yellow" if stats["passed"] > 0 else "red"
            cat_table.add_row(
                cat,
                f"[{color}]{stats['passed']}[/{color}]",
                str(stats["total"]),
                rate,
            )
        console.print(cat_table)
        console.print()

        # Detail table
        detail_table = Table(title="Probe Details")
        detail_table.add_column("ID", style="dim")
        detail_table.add_column("Name")
        detail_table.add_column("Severity")
        detail_table.add_column("Result")
        detail_table.add_column("Time (ms)", justify="right")

        for r in self.results:
            status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
            sev_color = {"critical": "red", "high": "red3", "medium": "yellow", "low": "dim", "info": "dim"}
            sev_style = sev_color.get(r.severity, "")
            detail_table.add_row(
                r.probe_id,
                r.name,
                f"[{sev_style}]{r.severity.upper()}[/{sev_style}]",
                status,
                str(int(r.response_time_ms)),
            )
        console.print(detail_table)

        # Failed probe details
        failed = [r for r in self.results if not r.passed]
        if failed:
            console.print()
            for r in failed:
                console.print(f"[red]FAIL  {r.probe_id} — {r.name}[/red]")
                console.print(f"       Details: {r.details}")
                console.print(f"       Response: {r.response[:200]}")
                console.print()

    def json(self, path: str):
        """Write JSON report to file."""
        data = {
            **self.summary,
            "timestamp": datetime.now().isoformat(),
            "results": [
                {
                    "id": r.probe_id,
                    "name": r.name,
                    "category": r.category,
                    "severity": r.severity,
                    "passed": r.passed,
                    "details": r.details,
                    "response_time_ms": int(r.response_time_ms),
                    "prompt_preview": r.prompt[:200],
                    "response_preview": r.response[:200],
                }
                for r in self.results
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
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

        results_html = ""
        for r in self.results:
            status_badge = (
                '<span style="color:#22c55e">PASS</span>'
                if r.passed
                else '<span style="color:#ef4444">FAIL</span>'
            )
            sev_color = {
                "critical": "#ef4444", "high": "#dc2626",
                "medium": "#eab308", "low": "#9ca3af", "info": "#6b7280",
            }.get(r.severity, "#9ca3af")

            results_html += f"""
            <tr>
                <td><code>{r.probe_id}</code></td>
                <td>{r.name}</td>
                <td style="color:{sev_color};font-weight:bold">{r.severity.upper()}</td>
                <td>{status_badge}</td>
                <td style="font-size:0.85em;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="{r.details}">{r.details}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gatekeeper Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }}
        h1 {{ color: {color}; }}
        .score {{ font-size: 4rem; font-weight: bold; color: {color}; margin: 0; }}
        .meta {{ color: #94a3b8; margin: 0.5rem 0 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1.5rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ color: #94a3b8; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }}
        code {{ background: #1e293b; padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.9em; }}
        .summary-cards {{ display: flex; gap: 1rem; margin: 1.5rem 0; }}
        .card {{ background: #1e293b; padding: 1.25rem; border-radius: 0.5rem; flex: 1; text-align: center; }}
        .card .value {{ font-size: 2rem; font-weight: bold; }}
        .card .label {{ color: #94a3b8; font-size: 0.85em; margin-top: 0.25rem; }}
        .chart-bar {{ height: 8px; border-radius: 4px; background: #334155; margin: 0.5rem 0; }}
        .chart-fill {{ height: 100%; border-radius: 4px; background: {color}; }}
    </style>
</head>
<body>
    <h1>Gatekeeper Scan Report</h1>
    <div class="meta">
        Target: {self.summary['endpoint']} &middot;
        Model: {self.summary['model']} &middot;
        {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </div>

    <div class="summary-cards">
        <div class="card">
            <div class="value" style="color:{color}">{self.summary['score']}%</div>
            <div class="label">Security Score</div>
        </div>
        <div class="card">
            <div class="value" style="color:#22c55e">{self.summary['passed']}</div>
            <div class="label">Passed</div>
        </div>
        <div class="card">
            <div class="value" style="color:#ef4444">{self.summary['failed']}</div>
            <div class="label">Failed</div>
        </div>
        <div class="card">
            <div class="value" style="color:#94a3b8">{self.summary['total_probes']}</div>
            <div class="label">Total Probes</div>
        </div>
    </div>

    <div class="chart-bar"><div class="chart-fill" style="width:{self.summary['score']}%"></div></div>
    <p style="color:#94a3b8">{self.summary['interpretation']}</p>

    <h2>Probe Results</h2>
    <table>
        <thead>
            <tr><th>ID</th><th>Name</th><th>Severity</th><th>Result</th><th>Details</th></tr>
        </thead>
        <tbody>
            {results_html}
        </tbody>
    </table>

    <p style="color:#475569;font-size:0.85em;margin-top:2rem;">
        Generated by <a href="https://github.com/AAAjczz/gatekeeper" style="color:#3b82f6">Gatekeeper</a> v0.1.0
    </p>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML report saved: {path}")
