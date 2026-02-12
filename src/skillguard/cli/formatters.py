"""Rich terminal output formatters for the CLI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillguard.core.models import ScanResult, Severity, Verdict

console = Console()

_VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "clean": ("bold green", "CLEAN"),
    "low_risk": ("bold cyan", "LOW RISK"),
    "suspicious": ("bold yellow", "SUSPICIOUS"),
    "high_risk": ("bold red", "HIGH RISK"),
    "malicious": ("bold white on red", "MALICIOUS"),
}

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "dim",
}


def print_banner() -> None:
    """Print the SkillGuard banner."""
    banner = Text()
    banner.append("SkillGuard", style="bold cyan")
    banner.append(" v0.1.0", style="dim")
    banner.append(" - Security Scanner for AI Agent Skills", style="")
    console.print(Panel(banner, border_style="cyan"))


def print_error(msg: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]Error:[/] {msg}")


def print_scan_result(result: ScanResult) -> None:
    """Print a formatted scan result to the terminal."""
    console.print()

    # Verdict header
    verdict_str = result.verdict if isinstance(result.verdict, str) else result.verdict.value
    style, label = _VERDICT_STYLES.get(verdict_str, ("", verdict_str.upper()))
    score_bar = _score_bar(result.composite_score)

    verdict_text = Text()
    verdict_text.append(f"  Score: {result.composite_score}/100 ", style="bold")
    verdict_text.append(score_bar)
    verdict_text.append(f"\n  Verdict: ")
    verdict_text.append(f" {label} ", style=style)
    verdict_text.append(f"\n  Skill: {result.skill_name}")
    verdict_text.append(f"\n  SHA256: {result.skill_sha256[:16]}...")
    verdict_text.append(f"\n  Files scanned: {result.files_scanned}")
    verdict_text.append(f"\n  Engines: {len(result.engine_results)}")
    verdict_text.append(f"\n  Total findings: {result.total_findings}")

    border = "green"
    if result.composite_score > 80:
        border = "red"
    elif result.composite_score > 60:
        border = "red"
    elif result.composite_score > 40:
        border = "yellow"
    elif result.composite_score > 20:
        border = "cyan"

    console.print(Panel(verdict_text, title="Scan Summary", border_style=border))

    # Findings by severity
    if result.findings_by_severity:
        sev_table = Table(title="Findings by Severity", show_lines=False)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = result.findings_by_severity.get(sev, 0)
            if count > 0:
                sev_style = _SEVERITY_STYLES.get(sev, "")
                sev_table.add_row(
                    Text(sev.upper(), style=sev_style),
                    str(count),
                )
        console.print(sev_table)

    # Engine results
    if result.engine_results:
        engine_table = Table(title="Engine Results", show_lines=True)
        engine_table.add_column("Engine", style="bold")
        engine_table.add_column("Verdict")
        engine_table.add_column("Confidence", justify="right")
        engine_table.add_column("Findings", justify="right")
        engine_table.add_column("Time (ms)", justify="right")

        for er in result.engine_results:
            v_style = ""
            v_val = er.verdict if isinstance(er.verdict, str) else er.verdict.value
            if v_val == "malicious":
                v_style = "bold red"
            elif v_val == "suspicious":
                v_style = "bold yellow"
            else:
                v_style = "green"

            engine_table.add_row(
                er.engine_name,
                Text(v_val.upper(), style=v_style),
                f"{er.confidence:.0%}",
                str(len(er.findings)),
                str(er.duration_ms),
            )

        console.print(engine_table)

    # Detailed findings
    all_findings = []
    for er in result.engine_results:
        all_findings.extend(er.findings)

    if all_findings:
        # Sort by severity
        sev_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        findings_table = Table(title="Findings Detail", show_lines=True)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Rule", width=20)
        findings_table.add_column("File", width=25)
        findings_table.add_column("Line")
        findings_table.add_column("Description", width=50)

        for f in all_findings[:50]:  # Limit to first 50
            sev_style = _SEVERITY_STYLES.get(f.severity.value, "")
            findings_table.add_row(
                Text(f.severity.value.upper(), style=sev_style),
                f.rule_id,
                f.file_path,
                str(f.line_start or ""),
                f.description[:80] + "..." if len(f.description) > 80 else f.description,
            )

        console.print(findings_table)

        if len(all_findings) > 50:
            console.print(
                f"\n  [dim]... and {len(all_findings) - 50} more findings. "
                "Use --format json for full details.[/]"
            )

    # OWASP coverage
    if result.owasp_coverage:
        console.print(
            f"\n  [bold]OWASP LLM Top 10 Coverage:[/] {', '.join(result.owasp_coverage)}"
        )

    console.print()


def _score_bar(score: int) -> str:
    """Generate a visual score bar."""
    filled = score // 5
    empty = 20 - filled
    if score > 80:
        char = "[red]" + "█" * filled + "[/]"
    elif score > 60:
        char = "[red]" + "█" * (score - 60) // 5 + "[/][yellow]" + "█" * ((60 - 40) // 5) + "[/]"
        filled_str = char
        return filled_str + "░" * empty
    elif score > 40:
        char = "[yellow]" + "█" * filled + "[/]"
    elif score > 20:
        char = "[cyan]" + "█" * filled + "[/]"
    else:
        char = "[green]" + "█" * filled + "[/]"
    return char + "░" * empty
