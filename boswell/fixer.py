"""Offer to apply fixes for identified leak findings after each scan."""

import subprocess
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from .secret_check import LeakFinding

# These categories carry shell commands that can be applied safely.
# hardcoded-secret requires manual code edits — we show location + instructions.
# history-leak is a destructive rewrite — we show instructions only.
AUTO_FIX_CATEGORIES = {"gitignore-gap", "tracked-env-file"}

SEVERITY_COLOUR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "INFO": "dim"}


def display_findings(findings: list[LeakFinding], console: Console) -> None:
    if not findings:
        console.print("\n  [green]No security findings.[/green]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Severity", width=10)
    table.add_column("Category", width=20)
    table.add_column("Description")

    for f in findings:
        c = SEVERITY_COLOUR.get(f.severity, "white")
        table.add_row(f"[{c}]{f.severity}[/{c}]", f.category, f.description)

    console.print()
    console.print(table)


def _run_shell(cmd: str, cwd: Path) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            cmd, shell=True, cwd=cwd,
            capture_output=True, text=True, timeout=60, errors="replace",
        )
        ok = r.returncode == 0
        out = (r.stdout.strip() or r.stderr.strip())
        return ok, out
    except Exception as e:
        return False, str(e)


def offer_fixes(
    findings: list[LeakFinding],
    repo_path: Path,
    console: Console,
    db_url: str | None = None,
    finding_ids: list[int] | None = None,
) -> int:
    """
    Display all findings, then offer to apply fixes for auto-fixable ones.
    Manual findings (hardcoded secrets, history leaks) are shown with instructions.
    Returns the count of fixes successfully applied.
    """
    if not findings:
        return 0

    display_findings(findings, console)

    fixable = [(i, f) for i, f in enumerate(findings) if f.category in AUTO_FIX_CATEGORIES]
    manual  = [(i, f) for i, f in enumerate(findings) if f.category not in AUTO_FIX_CATEGORIES]

    applied = 0

    if fixable:
        console.print(
            f"\n[bold yellow]{len(fixable)} issue(s) can be fixed automatically.[/bold yellow]"
        )
        for orig_idx, f in fixable:
            c = SEVERITY_COLOUR.get(f.severity, "white")
            console.print(f"\n  [{c}][{f.severity}][/{c}] {f.description}")
            console.print(f"  [dim]Command: {f.fix}[/dim]")

            if Confirm.ask("  Apply this fix now?", default=True):
                ok, out = _run_shell(f.fix, repo_path)
                if ok:
                    console.print(
                        f"  [green]✓ Applied.[/green]" + (f" ({out})" if out else "")
                    )
                    applied += 1
                    if db_url and finding_ids and orig_idx < len(finding_ids):
                        try:
                            from .db import mark_resolved
                            mark_resolved(db_url, finding_ids[orig_idx])
                        except Exception:
                            pass
                else:
                    console.print(f"  [red]✗ Failed:[/red] {out}")

    if manual:
        console.print(
            f"\n[bold red]{len(manual)} finding(s) require manual action:[/bold red]"
        )
        for _, f in manual:
            c = SEVERITY_COLOUR.get(f.severity, "white")
            console.print(f"\n  [{c}][{f.severity}][/{c}] {f.description}")
            console.print(f"  [dim]  Location : {f.location}[/dim]")
            console.print(f"  [dim]  Action   : {f.fix}[/dim]")

    if applied:
        console.print(
            f"\n[green]{applied} fix(es) applied.[/green] "
            "Re-run [cyan]boswell run[/cyan] to verify."
        )

    return applied
