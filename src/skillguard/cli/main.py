"""SkillGuard CLI - Click-based command line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from skillguard.cli.formatters import print_scan_result, print_banner, print_error
from skillguard.core.models import ScanRequest, SkillPlatform


@click.group()
@click.version_option(package_name="skillguard")
def cli() -> None:
    """SkillGuard - VirusTotal for AI Agent Skills.

    Multi-engine security scanner for AI skills, MCP servers, and agentic tools.
    """


@cli.command()
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--git", "git_url", help="Git repository URL to scan.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "sarif"]),
    default="rich",
    help="Output format.",
)
@click.option("--output", "-o", "output_file", type=click.Path(), help="Write output to file.")
@click.option(
    "--platform",
    type=click.Choice([p.value for p in SkillPlatform]),
    default="generic",
    help="Skill platform.",
)
@click.option("--quick", is_flag=True, help="Quick scan (hash lookup only).")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with code 1 if findings at or above this severity.",
)
@click.option("--rules-dir", type=click.Path(exists=True), help="Custom rules directory.")
def scan(
    path: str | None,
    git_url: str | None,
    output_format: str,
    output_file: str | None,
    platform: str,
    quick: bool,
    fail_on: str | None,
    rules_dir: str | None,
) -> None:
    """Scan a skill directory or repository for security issues."""
    if not path and not git_url:
        print_error("Provide a PATH or --git URL to scan.")
        sys.exit(1)

    if output_format == "rich":
        print_banner()

    request = ScanRequest(
        skill_path=path,
        git_url=git_url,
        scan_type="quick" if quick else "full",
        platform=SkillPlatform(platform),
    )

    result = asyncio.run(_run_scan(request, rules_dir))

    if output_format == "json":
        from skillguard.reporting.json_report import generate_json_report

        report = generate_json_report(result)
        if output_file:
            Path(output_file).write_text(report, encoding="utf-8")
            click.echo(f"JSON report written to {output_file}")
        else:
            click.echo(report)
    elif output_format == "sarif":
        from skillguard.reporting.sarif_report import generate_sarif_report

        report = generate_sarif_report(result)
        if output_file:
            Path(output_file).write_text(report, encoding="utf-8")
            click.echo(f"SARIF report written to {output_file}")
        else:
            click.echo(report)
    else:
        print_scan_result(result)
        if output_file:
            from skillguard.reporting.json_report import generate_json_report

            Path(output_file).write_text(
                generate_json_report(result), encoding="utf-8"
            )
            click.echo(f"\nFull report written to {output_file}")

    # Exit code based on --fail-on
    if fail_on:
        from skillguard.core.models import Severity

        threshold = Severity(fail_on)
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold_idx = severity_order.index(threshold)
        for sev in severity_order[: threshold_idx + 1]:
            if result.findings_by_severity.get(sev.value, 0) > 0:
                sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def monitor(path: str) -> None:
    """Monitor a skills directory for changes and auto-rescan."""
    click.echo(f"Monitoring {path} for changes... (Ctrl+C to stop)")
    click.echo("(File watcher will be implemented in Phase 2)")


@cli.command("rules")
@click.option("--list", "list_rules", is_flag=True, help="List all detection rules.")
@click.option("--category", help="Filter by category.")
def rules_cmd(list_rules: bool, category: str | None) -> None:
    """Manage detection rules."""
    from skillguard.core.rules_loader import load_rules

    if list_rules or True:
        loaded = load_rules(category_filter=category)
        if not loaded:
            click.echo("No rules found.")
            return
        click.echo(f"Loaded {len(loaded)} rules:\n")
        for rule in loaded:
            sev_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "cyan",
                "low": "green",
            }.get(rule.severity.value, "white")
            click.echo(
                f"  [{rule.severity.value.upper():8s}] {rule.id:15s} {rule.name}"
            )


@cli.command()
def server() -> None:
    """Start the SkillGuard API server."""
    click.echo("Starting SkillGuard API server...")
    try:
        import uvicorn

        from skillguard.api.app import create_app

        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=8080)
    except ImportError:
        print_error("uvicorn not installed. Run: pip install skillguard[api]")
        sys.exit(1)


async def _run_scan(request: ScanRequest, rules_dir: str | None = None) -> "ScanResult":
    """Run a scan using the orchestrator."""
    from skillguard.core.scanner import ScanOrchestrator
    from skillguard.engines.prompt_injection.regex_scanner import RegexScanner
    from skillguard.engines.prompt_injection.yara_scanner import YaraScanner
    from skillguard.engines.sast.secret_detector import SecretDetector

    engines = [
        RegexScanner(rules_dir=rules_dir),
        YaraScanner(),
        SecretDetector(),
    ]

    orchestrator = ScanOrchestrator(engines=engines)
    return await orchestrator.scan(request)
