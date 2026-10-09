"""LLM analysis pipeline — Haiku for classification/summaries, Sonnet for writing."""

import json
from pathlib import Path

from openai import OpenAI

from .prompts import (
    AUDIT_SYSTEM,
    FILE_CLASSIFIER_SYSTEM,
    FOLDER_SUMMARY_SYSTEM,
    HANDOFF_SYSTEM,
    LESSONS_SYSTEM,
    SIMPLE_AUDIT_SYSTEM,
    SIMPLE_HANDOFF_SYSTEM,
    audit_prompt,
    file_classifier_prompt,
    folder_summary_prompt,
    handoff_prompt,
    lessons_prompt,
    simple_audit_prompt,
    simple_handoff_prompt,
)
from .scanner import FileInfo, RepoScan
from .secret_check import full_leak_scan

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
HAIKU  = "anthropic/claude-haiku-4-5"
SONNET = "anthropic/claude-sonnet-4-6"

MAX_FILE_READ_BYTES = 150_000  # per file, for folder summarization
MAX_FOLDER_CHUNK_CHARS = 80_000  # max chars sent to Haiku per folder


def _read_safe(path: Path, max_bytes: int = MAX_FILE_READ_BYTES) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _call(client: OpenAI, model: str, system: str, user: str, max_tokens: int = 2048) -> str:
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    )
    return resp.choices[0].message.content or ""


def _classify_important_files(client: OpenAI, scan: RepoScan) -> list[str]:
    """Ask Haiku which files matter most. Returns list of relative paths."""
    file_list = "\n".join(
        f"{f.rel} ({f.size} bytes)" for f in scan.all_files[:2000]
    )
    try:
        result = _call(client, HAIKU, FILE_CLASSIFIER_SYSTEM, file_classifier_prompt(file_list), max_tokens=1024)
        parsed = json.loads(result.strip())
        if isinstance(parsed, list):
            return [str(p) for p in parsed[:25]]
    except Exception:
        pass
    # Fallback: return key files we already have
    return list(scan.key_file_contents.keys())[:25]


def _summarize_folders(client: OpenAI, scan: RepoScan, rich_console=None) -> dict[str, str]:
    """
    For each folder, read its files and ask Haiku for a compact summary.
    Skips folders that are already covered by key_file_contents alone.
    """
    summaries: dict[str, str] = {}
    key_paths = set(scan.key_file_contents.keys())

    for dir_name, files in scan.folder_files.items():
        # Build a chunk of file contents for this folder
        chunk_parts = []
        chunk_chars = 0

        for fi in files:
            if fi.rel in key_paths:
                continue  # already read in full — don't duplicate
            if fi.size > 50_000:
                continue  # skip very large individual files
            content = _read_safe(fi.path, max_bytes=10_000)
            if not content.strip():
                continue
            entry = f"// {fi.rel}\n{content}\n"
            if chunk_chars + len(entry) > MAX_FOLDER_CHUNK_CHARS:
                break
            chunk_parts.append(entry)
            chunk_chars += len(entry)

        if not chunk_parts:
            continue

        if rich_console:
            rich_console.print(f"  [dim]Summarizing {dir_name}/[/dim]")

        try:
            summary = _call(
                client, HAIKU, FOLDER_SUMMARY_SYSTEM,
                folder_summary_prompt(dir_name, "\n".join(chunk_parts)),
                max_tokens=300,
            )
            summaries[dir_name] = summary.strip()
        except Exception as e:
            summaries[dir_name] = f"[summary failed: {e}]"

    return summaries


def analyze_repo(
    scan: RepoScan,
    api_key: str,
    prompt_context: str | None = None,
    rich_console=None,
) -> dict[str, str]:
    """
    Run the full analysis pipeline. Returns a dict with keys:
    audit, handoff, audit_simple, handoff_simple
    """
    client = OpenAI(api_key=api_key, base_url=OPENROUTER_BASE)

    def log(msg: str):
        if rich_console:
            rich_console.print(msg)

    # Full leak scan: .gitignore gaps + working tree + git history
    log("  [cyan]Running leak scan (gitignore, working tree, history)...[/cyan]")
    leak_findings = full_leak_scan(scan.repo_path)
    secret_warnings = [f.description for f in leak_findings]
    leak_fixes = {f.location: f.fix for f in leak_findings}

    # Phase 1: Classify important files and read them
    log("  [cyan]Classifying important files (Haiku)...[/cyan]")
    important_paths = _classify_important_files(client, scan)

    # Read any important files not already in key_file_contents
    augmented_key_files = dict(scan.key_file_contents)
    for rel_path in important_paths:
        if rel_path not in augmented_key_files:
            full_path = scan.repo_path / rel_path
            if full_path.exists():
                content = _read_safe(full_path)
                if content:
                    augmented_key_files[rel_path] = content

    # Phase 2: Folder summaries
    log("  [cyan]Summarizing folders (Haiku)...[/cyan]")
    folder_summaries = _summarize_folders(client, scan, rich_console)

    # Apply personal context
    boswell_context = prompt_context or scan.boswell_context

    # Phase 3: Technical audit
    log("  [cyan]Writing technical audit (Sonnet)...[/cyan]")
    audit_text = _call(
        client, SONNET, AUDIT_SYSTEM,
        audit_prompt(
            repo_name=scan.name,
            stack=scan.stack,
            env_vars=scan.env_var_keys,
            key_files=augmented_key_files,
            folder_summaries=folder_summaries,
            npm_audit=scan.npm_audit_json,
            pip_audit=scan.pip_audit_json,
            secret_warnings=secret_warnings,
            git_log=scan.git_log_summary,
        ),
        max_tokens=4096,
    )

    # Phase 4: Technical handoff
    log("  [cyan]Writing technical handoff (Sonnet)...[/cyan]")
    handoff_text = _call(
        client, SONNET, HANDOFF_SYSTEM,
        handoff_prompt(
            repo_name=scan.name,
            stack=scan.stack,
            env_vars=scan.env_var_keys,
            key_files=augmented_key_files,
            folder_summaries=folder_summaries,
            secret_warnings=secret_warnings,
            git_log=scan.git_log_summary,
            boswell_context=boswell_context,
        ),
        max_tokens=4096,
    )

    # Phase 5: Plain-English rewrites
    log("  [cyan]Writing plain-English versions (Sonnet)...[/cyan]")
    audit_simple = _call(
        client, SONNET, SIMPLE_AUDIT_SYSTEM,
        simple_audit_prompt(scan.name, audit_text),
        max_tokens=3000,
    )
    handoff_simple = _call(
        client, SONNET, SIMPLE_HANDOFF_SYSTEM,
        simple_handoff_prompt(scan.name, handoff_text),
        max_tokens=3000,
    )

    # Phase 6: Lessons for next time
    log("  [cyan]Writing lessons for next time (Sonnet)...[/cyan]")
    lessons_text = _call(
        client, SONNET, LESSONS_SYSTEM,
        lessons_prompt(scan.name, audit_text, handoff_text, scan.stack),
        max_tokens=3000,
    )

    return {
        "audit": audit_text,
        "handoff": handoff_text,
        "audit_simple": audit_simple,
        "handoff_simple": handoff_simple,
        "lessons": lessons_text,
        "secret_warnings": secret_warnings,
        "leak_findings": [
            {"severity": f.severity, "category": f.category,
             "description": f.description, "location": f.location, "fix": f.fix,
             "action": f.action}
            for f in leak_findings
        ],
    }
