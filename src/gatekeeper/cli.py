"""CLI entry point — gatekeeper scan."""

import json
import sys
from datetime import datetime
from pathlib import Path

import click

from .scanner import Scanner
from .reporter import Reporter


@click.group()
@click.version_option(version="0.1.0", prog_name="gatekeeper")
def main():
    """Gatekeeper — LLM API security scanner.

    Red-team your AI API endpoints in one command.
    """
    pass


@main.command()
@click.option(
    "--endpoint", "-e",
    default="http://localhost:4000/v1",
    help="OpenAI-compatible API endpoint",
    show_default=True,
)
@click.option(
    "--api-key", "-k",
    default="sk-test",
    help="API key for the endpoint",
    show_default=True,
)
@click.option(
    "--model", "-m",
    default=None,
    help="Model name (auto-detect if not specified)",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output directory for reports",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["terminal", "json", "html", "all"]),
    default="terminal",
    help="Output format",
    show_default=True,
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show each probe result as it runs",
)
@click.option(
    "--timeout", "-t",
    default=30,
    help="API request timeout in seconds",
    show_default=True,
)
def scan(endpoint: str, api_key: str, model: str, output: str,
         output_format: str, verbose: bool, timeout: int):
    """Run a full security scan against an LLM endpoint.

    \b
    Examples:
      gatekeeper scan
      gatekeeper scan --endpoint https://api.deepseek.com/v1 -k sk-xxx
      gatekeeper scan -e http://localhost:4000/v1 -o ./reports -f all
    """

    scanner = Scanner(
        endpoint=endpoint,
        api_key=api_key,
        model=model,
        timeout=timeout,
        verbose=verbose,
    )

    results = scanner.scan()
    summary = scanner.summary(results)

    reporter = Reporter(results, summary)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    if output_format in ("terminal", "all"):
        reporter.terminal()

    if output_format in ("json", "all"):
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"gatekeeper_{timestamp}.json"
        reporter.json(str(json_path))

    if output_format in ("html", "all"):
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"gatekeeper_{timestamp}.html"
        reporter.html(str(html_path))

    # Exit code: non-zero if critical/high failures found
    critical_high_fails = sum(
        1 for r in results
        if not r.passed and r.severity in ("critical", "high")
    )
    if critical_high_fails > 0:
        sys.exit(1)


@main.command()
@click.option(
    "--endpoint", "-e",
    default="http://localhost:4000/v1",
    help="OpenAI-compatible API endpoint",
)
@click.option(
    "--api-key", "-k",
    default="sk-test",
    help="API key for the endpoint",
)
def probe(endpoint: str, api_key: str):
    """Quick connectivity check — lists available models."""
    from openai import OpenAI

    try:
        client = OpenAI(api_key=api_key, base_url=endpoint.rstrip("/"))
        models = client.models.list()
        print(f"Endpoint: {endpoint}")
        print(f"Models available: {len(models.data)}")
        for m in models.data:
            print(f"  - {m.id}")
    except Exception as e:
        print(f"ERROR: Cannot connect to {endpoint}")
        print(f"  {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
