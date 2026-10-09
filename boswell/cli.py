"""Boswell CLI — universal repo auditor."""

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from .analyzer import analyze_repo
from .cost import estimate_cost
from .fixer import offer_fixes
from .scanner import scan_repo
from .strix_run import StrixRunError, run_strix
from .writer import (
    extract_fate,
    extract_top_risk,
    extract_verdict,
    write_portfolio,
    write_repo_output,
)
from . import db as _db

console = Console()


def _get_api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        console.print("[red]Error:[/red] OPENROUTER_API_KEY environment variable not set.")
        sys.exit(1)
    return key


def _prompt_personal_context(repo_name: str) -> str | None:
    console.print(f"\n[yellow]No BOSWELL_CONTEXT.md found in {repo_name}.[/yellow]")
    want = Confirm.ask("Would you like to add personal context? (Why did you build this?)")
    if not want:
        return None
    console.print("[dim]Type your answer. Press Enter twice when done.[/dim]")
    lines = []
    try:
        while True:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    text = "\n".join(lines).strip()
    return text if text else None


def _run_single_repo(
    repo_path: Path,
    api_key: str,
    skip_confirm: bool,
    prompt_context: bool,
) -> dict:
    """Run Boswell on one repo. Returns a result dict for portfolio aggregation."""
    name = repo_path.resolve().name

    if not repo_path.is_dir():
        return {"name": name, "error": "path is not a directory"}

    console.print(Panel(f"[bold cyan]Boswell[/bold cyan] — {name}", expand=False))

    # Scan
    console.print("  [cyan]Scanning repo...[/cyan]")
    scan = scan_repo(repo_path)

    console.print(f"  Files: {len(scan.all_files)} | Stack: {', '.join(scan.stack) or 'unknown'}")
    console.print(f"  Env vars found: {len(scan.env_var_keys)}")

    # Cost estimate
    est = estimate_cost(scan)
    console.print(f"\n[yellow]Cost estimate:[/yellow]\n{est.summary()}")

    if not skip_confirm:
        if not Confirm.ask("\nProceed with analysis?"):
            console.print("[red]Skipped.[/red]")
            return {"name": name, "error": "skipped by user"}

    # Personal context (single-repo mode only)
    personal_context: str | None = None
    if prompt_context and not scan.boswell_context:
        personal_context = _prompt_personal_context(name)

    # Analyze
    try:
        results = analyze_repo(
            scan=scan,
            api_key=api_key,
            prompt_context=personal_context,
            rich_console=console,
        )
    except Exception as e:
        console.print(f"  [red]Analysis failed: {e}[/red]")
        return {"name": name, "error": str(e)}

    # Write output
    out_dir = write_repo_output(
        repo_path=repo_path,
        results=results,
        scan=scan,
        cost_usd=est.total_usd,
    )
    console.print(f"\n  [green]Done.[/green] Output: {out_dir}/")
    console.print(f"    audit.md | audit-simple.md | handoff.md | handoff-simple.md | lessons.md")

    # Persist to Neon if configured
    db_url = _db.get_url()
    run_id: int | None = None
    finding_ids: list[int] = []
    if db_url:
        try:
            _db.init_db(db_url)
            run_id = _db.save_run(
                db_url,
                repo_name=name,
                repo_path=str(repo_path),
                cost_usd=est.total_usd,
                stack=list(scan.stack),
                env_vars=list(scan.env_var_keys),
            )
            finding_ids = _db.save_findings(db_url, run_id, results.get("leak_findings", []))
            _db.save_docs(db_url, run_id, {
                k: results[k] for k in
                ("audit", "handoff", "audit_simple", "handoff_simple", "lessons")
                if k in results
            })
            # Auto-import all LLM audit findings (full report, every run)
            audit_text = results.get("audit", "")
            n_imported = _db.import_audit_findings(db_url, run_id, audit_text)
            console.print(f"  [dim]Saved to Neon (run #{run_id}, {n_imported} findings imported)[/dim]")
        except Exception as db_err:
            console.print(f"  [yellow]Neon save failed (continuing):[/yellow] {db_err}")

    # Offer to fix all findings — always
    from .secret_check import LeakFinding
    raw_findings = results.get("leak_findings", [])
    findings = [
        LeakFinding(
            severity=f["severity"],
            category=f["category"],
            description=f["description"],
            location=f.get("location", ""),
            fix=f.get("fix", ""),
            action=f.get("action"),
        )
        for f in raw_findings
    ]
    if findings:
        console.print(f"\n[bold]Security findings ({len(findings)}):[/bold]")
        offer_fixes(
            findings=findings,
            repo_path=repo_path,
            console=console,
            db_url=db_url,
            finding_ids=finding_ids if finding_ids else None,
        )
    else:
        console.print("\n  [green]No security findings.[/green]")

    return {
        "name": name,
        "stack": scan.stack,
        "deploy_verdict": extract_verdict(results["audit"]),
        "top_risk": extract_top_risk(results["audit"]),
        "fate": extract_fate(results["handoff"]),
        "cost_usd": est.total_usd,
    }


@click.group()
def main():
    """Boswell — universal repo auditor. Turns any codebase into a legible handoff doc."""
    pass


@main.command()
@click.argument("repo", default=".", type=click.Path(exists=True))
@click.option("--context", is_flag=True, default=False,
              help="Prompt for personal context (why you built this).")
@click.option("--skip-confirm", is_flag=True, default=False,
              help="Skip the cost confirmation prompt.")
def run(repo: str, context: bool, skip_confirm: bool):
    """Analyze a single repository and write boswell/ docs."""
    api_key = _get_api_key()
    repo_path = Path(repo).resolve()
    _run_single_repo(repo_path, api_key, skip_confirm=skip_confirm, prompt_context=context)


@main.command(name="strix")
@click.argument("repo")
@click.option(
    "--scan-mode",
    type=click.Choice(["quick", "standard", "deep"]),
    default="quick",
    show_default=True,
    help="How deep Strix should test.",
)
def strix_cmd(repo: str, scan_mode: str) -> None:
    """Run Strix against a local repository you own."""
    try:
        code = run_strix(repo, scan_mode)
    except StrixRunError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)
    sys.exit(code)


@main.command()
@click.argument("root", default=".", type=click.Path(exists=True))
@click.option("--port", default=7474, show_default=True, help="Port to serve on.")
@click.option("--open/--no-open", default=True, help="Open browser automatically.")
def serve(root: str, port: int, open: bool):
    """Start the Boswell web interface at localhost:PORT."""
    import webbrowser
    import uvicorn
    from .server import app, set_repos_root

    root_path = Path(root).resolve()
    set_repos_root(root_path)

    url = f"http://localhost:{port}"
    console.print(f"[bold cyan]Boswell[/bold cyan] UI → [underline]{url}[/underline]")
    console.print(f"[dim]Scanning repos under: {root_path}[/dim]")
    console.print("[dim]The page only answers to localhost. Its API token stays in ~/.boswell/api.token.[/dim]")

    if open:
        import threading
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


@main.command()
@click.argument("repo", default=".", type=click.Path(exists=True))
@click.option("--skip-confirm", is_flag=True, default=False,
              help="Skip confirmation prompt and fix immediately.")
def fix(repo: str, skip_confirm: bool):
    """Apply LLM-generated security fixes to a repo on a new branch."""
    from .fix_code import fix_repo, _extract_findings, _also_extract_leak_findings

    api_key = _get_api_key()
    repo_path = Path(repo).resolve()

    audit_path = repo_path / ".boswell" / "audit.md"
    if not audit_path.exists():
        console.print(f"[red]Error:[/red] No .boswell/audit.md in {repo_path}. Run 'boswell run' first.")
        return

    audit_text = audit_path.read_text(encoding="utf-8")
    metadata_path = repo_path / ".boswell" / "metadata.json"

    findings = _extract_findings(audit_text)
    findings += _also_extract_leak_findings(metadata_path)

    actionable = [f for f in findings if f.get("file_path")]

    console.print(Panel(f"[bold cyan]Boswell Fix[/bold cyan] — {repo_path.name}", expand=False))
    console.print(f"\n  HIGH/CRITICAL findings: [bold]{len(findings)}[/bold]")
    console.print(f"  With file locations:    [bold]{len(actionable)}[/bold]")

    if not actionable:
        console.print("\n[yellow]No actionable findings with file paths to fix.[/yellow]")
        return

    console.print("\n[bold]Findings to patch:[/bold]")
    for f in actionable:
        sev_color = "red" if f["severity"] == "CRITICAL" else "yellow"
        console.print(
            f"  [{sev_color}]{f['severity']}[/{sev_color}] "
            f"[dim]{f['file_path']}[/dim] — {f['description'][:70]}…"
        )

    console.print(
        f"\n[dim]A new branch 'boswell/security-fixes-YYYYMMDD' will be created."
        f"\nFiles are patched by Gemini 2.5 Flash via OpenRouter."
        f"\nIf all findings are fixed, the branch is merged to main and pushed."
        f"\nIf any cannot be fixed, the deployment is taken offline and the partial branch is pushed for review.[/dim]"
    )

    if not skip_confirm:
        from rich.prompt import Confirm
        if not Confirm.ask(f"\nProceed with fixing {len(actionable)} finding(s)?"):
            console.print("[red]Cancelled.[/red]")
            return

    db_url = _db.get_url()
    result = fix_repo(
        repo_path=repo_path,
        api_key=api_key,
        rich_console=console,
        db_url=db_url,
        ship=True,
    )

    if "error" in result:
        console.print(f"\n[red]Error:[/red] {result['error']}")
        return

    console.print(f"\n[bold]Done.[/bold]")
    console.print(f"  Fixed:   {result['fixed']}")
    console.print(f"  Skipped: {result['skipped']}")

    status = result.get("status", "fix_only")

    if result.get("changes"):
        console.print("\n[bold]Changes:[/bold]")
        for c in result["changes"]:
            console.print(f"  [green]✓[/green] {c}")

    if status == "shipped":
        console.print("\n[bold green]✅ Shipped[/bold green] — fixes merged to main and pushed.")
    elif status == "disabled":
        console.print(
            f"\n[bold yellow]⚠ Taken offline[/bold yellow] — "
            f"{result['skipped']} finding(s) could not be fixed automatically.\n"
            f"  Branch [cyan]{result['branch']}[/cyan] has partial fixes — review before re-enabling."
        )
    elif status == "fix_only":
        branch = result.get("branch")
        push_error = result.get("push_error")
        if push_error:
            console.print(f"\n[yellow]Push failed:[/yellow] {push_error}")
            console.print(f"  Branch [cyan]{branch}[/cyan] has fixes — push manually when ready.")
        elif branch:
            console.print(f"\n  Branch:  [cyan]{branch}[/cyan]")
            console.print("[dim]Review the branch before merging to main.[/dim]")
    else:
        console.print(f"\n  [yellow]{result.get('note', 'Nothing was changed.')}[/yellow]")


@main.command()
@click.argument("folder", default=".", type=click.Path(exists=True))
@click.option("--skip-confirm", is_flag=True, default=False,
              help="Skip per-repo cost confirmation.")
@click.option("--since-days", default=0, type=int,
              help="Skip repos whose boswell/metadata.json is newer than N days.")
def batch(folder: str, skip_confirm: bool, since_days: int):
    """
    Analyze all repos in FOLDER (all immediate subdirectories that are git repos).
    Writes per-repo boswell/ docs and a PORTFOLIO.md at the batch root.
    """
    import json
    from datetime import datetime, timedelta

    api_key = _get_api_key()
    batch_root = Path(folder).resolve()

    subdirs = sorted(
        [d for d in batch_root.iterdir() if d.is_dir() and (d / ".git").exists()]
    )

    if not subdirs:
        console.print(f"[yellow]No git repositories found in {batch_root}[/yellow]")
        return

    console.print(f"[bold]Found {len(subdirs)} git repos in {batch_root}[/bold]\n")

    # Show total cost estimate upfront
    if not skip_confirm:
        total_est = 0.0
        for d in subdirs:
            s = scan_repo(d)
            total_est += estimate_cost(s).total_usd
        console.print(f"[yellow]Estimated total batch cost: ${total_est:.2f}[/yellow]")
        if not Confirm.ask(f"Proceed with all {len(subdirs)} repos?"):
            console.print("[red]Batch cancelled.[/red]")
            return

    all_results = []
    for d in subdirs:
        # --since-days: skip repos with a fresh boswell run
        if since_days > 0:
            meta_path = d / "boswell" / "metadata.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                    run_at = datetime.strptime(meta["run_at"], "%Y-%m-%d %H:%M")
                    if datetime.now() - run_at < timedelta(days=since_days):
                        console.print(f"[dim]Skipping {d.name} (boswell run < {since_days}d ago)[/dim]")
                        continue
                except Exception:
                    pass

        result = _run_single_repo(
            repo_path=d,
            api_key=api_key,
            skip_confirm=True,  # already confirmed above
            prompt_context=False,  # no interactive prompts in batch
        )
        all_results.append(result)
        console.print()

    # Write portfolio
    portfolio_path = write_portfolio(batch_root, all_results)
    console.print(f"\n[bold green]Portfolio summary:[/bold green] {portfolio_path}")
    total_cost = sum(r.get("cost_usd", 0) for r in all_results if not r.get("error"))
    console.print(f"Total cost: ${total_cost:.3f}")
