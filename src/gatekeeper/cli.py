"""CLI entry point — gatekeeper audit."""

import sys
from datetime import datetime
from pathlib import Path

import click

from .scanner import Auditor
from .reporter import Reporter


@click.group()
@click.version_option(version="1.3.0", prog_name="gatekeeper")
def main():
    """Gatekeeper — AI Infrastructure Security Auditor.

    Audits your AI API DEPLOYMENT for misconfigurations:
    hardcoded keys, missing CORS, exposed admin routes,
    rate limiting gaps, privileged containers, and more.

    This is NOT a model red-teaming tool (use garak/augustus for that).
    This audits what THEY don't: docker-compose, .env, Nginx, CORS.
    """
    pass


@main.command()
@click.option(
    "--dir", "-d",
    "project_dir",
    default=".",
    help="Project directory to audit (docker-compose.yml, .env, etc.)",
    show_default=True,
)
@click.option(
    "--endpoint", "-e",
    default=None,
    help="API endpoint to check (network-level probes)",
)
@click.option(
    "--api-key", "-k",
    default="sk-test",
    help="API key for endpoint auth checks",
    show_default=True,
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output directory for reports",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["terminal", "json", "html", "sarif", "all"]),
    default="terminal",
    help="Output format",
    show_default=True,
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show each probe as it runs",
)
def audit(project_dir: str, endpoint: str, api_key: str,
          output: str, output_format: str, verbose: bool):
    """Audit an AI API deployment for security misconfigurations.

    \b
    Examples:
      gatekeeper audit
      gatekeeper audit --dir /path/to/chinai-gateway
      gatekeeper audit -d . -e http://localhost:4000/v1 -f all
    """

    auditor = Auditor(
        project_dir=project_dir,
        endpoint=endpoint,
        api_key=api_key,
        verbose=verbose,
    )

    findings = auditor.audit()
    summary = auditor.summary(findings)

    reporter = Reporter(findings, summary)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    if output_format in ("terminal", "all"):
        reporter.terminal()

    if output_format in ("json", "all"):
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        reporter.json(str(out_dir / f"gatekeeper_{timestamp}.json"))

    if output_format in ("html", "all"):
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        reporter.html(str(out_dir / f"gatekeeper_{timestamp}.html"))

    if output_format in ("sarif", "all"):
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        reporter.sarif(str(out_dir / f"gatekeeper_{timestamp}.sarif"))

    # Exit code: non-zero if critical/high failures found
    critical_high_fails = sum(
        1 for f in findings
        if not f.passed and f.severity in ("critical", "high")
    )
    if critical_high_fails > 0:
        sys.exit(1)


@main.command()
@click.option(
    "--dir", "-d",
    "project_dir",
    default=".",
    help="Project directory to check",
)
def files(project_dir: str):
    """List all configuration files detected in the project directory."""
    import os

    print(f"Scanning: {os.path.abspath(project_dir)}\n")
    patterns = [
        "docker-compose.yml", "docker-compose.yaml",
        ".env", ".env.example",
        "config.yaml", "config.yml",
        ".gitignore",
        "nginx.conf", "Dockerfile",
        "README.md",
    ]
    for pat in patterns:
        path = os.path.join(project_dir, pat)
        status = "✓" if os.path.isfile(path) else "✗"
        print(f"  [{status}] {pat}")


if __name__ == "__main__":
    main()
