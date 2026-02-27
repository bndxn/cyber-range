#!/usr/bin/env python3
"""
CLI entry point for the Cyber Range Security Agent.

Usage:
    python -m agent.main                          # defaults to http://localhost:8080
    python -m agent.main --target http://host:port
    python -m agent.main --model gpt-4o-mini      # use a cheaper model
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

load_dotenv()

console = Console()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Security Agent — Cyber Range Assessment"
    )
    parser.add_argument(
        "--target",
        default=os.getenv("TARGET_URL", "http://localhost:8080"),
        help="Base URL of the vulnerable target",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("OPENAI_MODEL", "gpt-4o"),
        help="OpenAI model to use",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress intermediate reasoning steps",
    )
    return parser.parse_args()


def _print_report(raw: str) -> None:
    """Pretty-print the structured JSON report."""
    try:
        report = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        console.print(Panel(str(raw), title="Assessment Output"))
        return

    console.print()
    console.print(
        Panel(
            f"[bold]{report.get('summary', 'N/A')}[/bold]\n\n"
            f"Target: {report.get('target', 'N/A')}\n"
            f"Total findings: {report.get('total_findings', 0)}  "
            f"(CRITICAL: {report.get('critical_count', 0)}, "
            f"HIGH: {report.get('high_count', 0)})",
            title="Vulnerability Assessment Report",
            border_style="red",
        )
    )

    table = Table(title="Findings", show_lines=True)
    table.add_column("#", style="bold", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=30)
    table.add_column("CVE", width=16)
    table.add_column("Endpoint", width=25)

    for i, vuln in enumerate(report.get("vulnerabilities", []), 1):
        sev = vuln.get("severity", "?")
        sev_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(sev, "white")
        table.add_row(
            str(i),
            f"[{sev_style}]{sev}[/{sev_style}]",
            vuln.get("title", ""),
            vuln.get("cve_id", "N/A"),
            vuln.get("endpoint", ""),
        )

    console.print(table)

    flags = report.get("flags_captured", [])
    if flags:
        console.print()
        console.print(
            Panel(
                "\n".join(f"  [bold green]{f}[/bold green]" for f in flags),
                title="Flags Captured",
                border_style="green",
            )
        )


def main() -> None:
    args = _parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        console.print(
            "[bold red]Error:[/bold red] OPENAI_API_KEY not set. "
            "Copy .env.example to .env and add your key.",
            style="red",
        )
        sys.exit(1)

    console.print(
        Panel(
            f"[bold]Target:[/bold] {args.target}\n"
            f"[bold]Model:[/bold]  {args.model}\n"
            f"[bold]Mode:[/bold]   {'quiet' if args.quiet else 'verbose'}",
            title="CyberAgent — AI Security Assessment",
            border_style="cyan",
        )
    )
    console.print()

    from agent.security_agent import run_assessment

    result = run_assessment(
        target_url=args.target,
        model=args.model,
        verbose=not args.quiet,
    )

    output = result["output"]

    if "{" in output and "}" in output:
        json_start = output.index("{")
        json_end = output.rindex("}") + 1
        _print_report(output[json_start:json_end])
    else:
        _print_report(output)

    steps = result.get("intermediate_steps", [])
    console.print(
        f"\n[dim]Agent completed in {len(steps)} reasoning steps.[/dim]"
    )


if __name__ == "__main__":
    main()
