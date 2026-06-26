"""Render a `ReviewReport` for humans (rich table) and machines (JSON).

Kept separate from `cli.py` so the rendering is unit-testable without going
through argument parsing, and reusable by the eval harness.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .reviewer import ReviewReport

# Severity → rich style, ordered most-to-least urgent.
_SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "dim",
}


def _location(file: str, start: int, end: int) -> str:
    return f"{file}:{start}" if end == start else f"{file}:{start}-{end}"


def render_terminal(report: ReviewReport, console: Console | None = None) -> None:
    """Print a findings table (or an all-clear line) to the terminal."""
    console = console or Console()
    n_files = len(report.files_reviewed)

    if not report.findings:
        console.print(f"[green]✓ No security findings[/green] across {n_files} reviewed file(s).")
        return

    table = Table(title=f"Security findings ({report.finding_count})")
    table.add_column("Location", style="cyan", no_wrap=True)
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Conf", justify="right")
    table.add_column("Rationale")

    for f in report.findings:
        severity = Text(f.severity.value, style=_SEV_STYLE.get(f.severity.value, ""))
        table.add_row(
            _location(f.file, f.start_line, f.end_line),
            f.category.value,
            severity,
            f"{f.confidence:.2f}",
            f.rationale,
        )

    console.print(table)
    console.print(
        f"\n[bold]{report.finding_count}[/bold] finding(s) across "
        f"{n_files} reviewed file(s)."
    )


def to_json(report: ReviewReport) -> str:
    """Serialize the report to machine-readable JSON (findings + files_reviewed)."""
    return report.model_dump_json(indent=2)
