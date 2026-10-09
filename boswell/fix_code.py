"""LLM-powered code security fixer."""

import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime
from pathlib import Path

from openai import OpenAI

from .safety import contained_path

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
GEMINI_FLASH = "google/gemini-2.5-flash"

MAX_FILE_LINES = 500
CONTEXT_WINDOW = 50  # lines around the finding line when file is too large

_FENCE_RE = re.compile(r"^```[^\n]*\n([\s\S]*?)```\s*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"\*\*\[(CRITICAL|HIGH)\]\*\*|\*\*(CRITICAL|HIGH)\*\*")
_PATH_RE = re.compile(
    r"`([^`\s]+\.[a-zA-Z0-9]{1,8}(?::\d+)?)`"  # `path/to/file.ts:42`
)
_LINE_RE = re.compile(r":(\d+)$")


def _strip_fences(text: str) -> str:
    """Remove markdown code fences from LLM output."""
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1)
    # Also handle triple-backtick without language tag at very start
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        end = next((i for i in range(len(lines) - 1, 0, -1) if lines[i].strip() == "```"), None)
        if end:
            return "\n".join(lines[1:end]) + "\n"
    return text


def _read_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _extract_findings(audit_md: str) -> list[dict]:
    """
    Parse HIGH/CRITICAL findings from audit.md.
    Returns list of {"severity", "description", "file_path", "line_no"}.
    """
    findings: list[dict] = []
    current: dict | None = None

    for line in audit_md.splitlines():
        stripped = line.strip().lstrip("- ").strip()

        sev_match = _SEVERITY_RE.search(stripped)
        if not sev_match:
            # If we have an active finding, look for path continuation lines
            if current is not None and current["file_path"] is None:
                path_m = _PATH_RE.search(stripped)
                if path_m:
                    raw = path_m.group(1)
                    line_m = _LINE_RE.search(raw)
                    current["file_path"] = raw.split(":")[0] if line_m else raw
                    current["line_no"] = int(line_m.group(1)) if line_m else None
            continue

        # Save previous finding
        if current is not None:
            findings.append(current)

        # Group 1 = **[HIGH]** pattern, Group 2 = **HIGH** pattern
        sev = sev_match.group(1) or sev_match.group(2)
        path_m = _PATH_RE.search(stripped)
        file_path: str | None = None
        line_no: int | None = None
        if path_m:
            raw = path_m.group(1)
            line_m = _LINE_RE.search(raw)
            file_path = raw.split(":")[0] if line_m else raw
            line_no = int(line_m.group(1)) if line_m else None

        current = {
            "severity": sev,
            "description": stripped,
            "file_path": file_path,
            "line_no": line_no,
        }

    if current is not None:
        findings.append(current)

    return findings


def _also_extract_leak_findings(metadata_path: Path) -> list[dict]:
    """Pull HIGH/CRITICAL findings from metadata.json leak_findings."""
    try:
        meta = json.loads(metadata_path.read_text())
    except Exception:
        return []
    out = []
    for f in meta.get("leak_findings", []):
        if f.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        loc = f.get("location", "") or ""
        # location may be "path/to/file.ts:42" or just a path
        line_m = _LINE_RE.search(loc)
        file_path = loc.split(":")[0] if line_m else loc or None
        out.append({
            "severity": f["severity"],
            "description": f.get("description", ""),
            "file_path": file_path or None,
            "line_no": int(line_m.group(1)) if line_m else None,
        })
    return out


def _build_file_snippet(content: str, line_no: int | None) -> str:
    """If file is large, return only ±CONTEXT_WINDOW lines around line_no."""
    lines = content.splitlines(keepends=True)
    if len(lines) <= MAX_FILE_LINES or line_no is None:
        return content
    start = max(0, line_no - 1 - CONTEXT_WINDOW)
    end = min(len(lines), line_no + CONTEXT_WINDOW)
    snippet_lines = lines[start:end]
    header = f"# [Boswell: showing lines {start+1}–{end} of {len(lines)} total]\n\n"
    return header + "".join(snippet_lines)


def _call_llm(client: OpenAI, finding: dict, file_path: str, snippet: str) -> str:
    system = (
        "You are a security engineer. You fix security vulnerabilities in source code. "
        "Return ONLY the complete fixed file content with no explanation and no markdown fences. "
        "If the snippet is partial (lines X–Y of N total), return only that same partial section fixed."
    )
    user = (
        f"FINDING ({finding['severity']}): {finding['description']}\n\n"
        f"FILE: {file_path}\n\n"
        f"{snippet}"
    )
    resp = client.chat.completions.create(
        model=GEMINI_FLASH,
        max_tokens=8192,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return resp.choices[0].message.content or ""


def _git_stash(repo_path: Path) -> bool:
    """Stash if working tree is dirty. Returns True if stash was applied."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path, capture_output=True, text=True,
    )
    if result.stdout.strip():
        subprocess.run(
            ["git", "stash", "push", "-m", "boswell-fix-stash"],
            cwd=repo_path, capture_output=True,
        )
        return True
    return False


def _git_unstash(repo_path: Path) -> None:
    subprocess.run(
        ["git", "stash", "pop"],
        cwd=repo_path, capture_output=True,
    )


def _git_create_branch(repo_path: Path, branch: str) -> None:
    subprocess.run(
        ["git", "checkout", "-b", branch],
        cwd=repo_path, capture_output=True,
    )


def _git_commit(repo_path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo_path, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_path, capture_output=True,
    )


def _detect_platform(repo_path: Path) -> tuple[str, str]:
    for wt in list(repo_path.rglob("wrangler.toml"))[:1]:
        try:
            import tomllib
            data = tomllib.loads(wt.read_text())
            return "cloudflare", data.get("name") or repo_path.name
        except Exception:
            return "cloudflare", repo_path.name
    vp = repo_path / ".vercel" / "project.json"
    if vp.exists():
        try:
            data = json.loads(vp.read_text())
            return "vercel", data.get("projectId") or repo_path.name
        except Exception:
            pass
    if (repo_path / "vercel.json").exists():
        return "vercel", repo_path.name
    return "unknown", repo_path.name


def _disable_deployment(repo_path: Path) -> dict:
    platform, project_id = _detect_platform(repo_path)
    if platform == "vercel":
        token = os.environ.get("VERCEL_TOKEN", "")
        if not token:
            return {"error": "VERCEL_TOKEN not set"}
        body = json.dumps({"paused": True}).encode()
        req = urllib.request.Request(
            f"https://api.vercel.com/v9/projects/{project_id}",
            data=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="PATCH",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return {"platform": "vercel", "project": project_id, **json.loads(r.read())}
        except Exception as e:
            return {"error": str(e)}
    elif platform == "cloudflare":
        token = os.environ.get("CF_API_TOKEN", "")
        account = os.environ.get("CF_ACCOUNT_ID", "")
        if not token or not account:
            return {"error": "CF_API_TOKEN and CF_ACCOUNT_ID not set"}
        body = json.dumps({
            "deployment_configs": {
                "production": {"deployments_enabled": False},
                "preview": {"deployments_enabled": False},
            }
        }).encode()
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project_id}",
            data=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return {"platform": "cloudflare", "project": project_id, **json.loads(r.read())}
        except Exception as e:
            return {"error": str(e)}
    return {"error": f"unknown platform for {repo_path.name}"}


def fix_repo(
    repo_path: Path,
    api_key: str,
    rich_console=None,
    db_url: str | None = None,
    run_id: int | None = None,
    ship: bool = True,
) -> dict:
    """
    Read .boswell/audit.md, fix HIGH/CRITICAL findings with LLM assistance,
    commit fixes to a new branch.

    Returns: {"fixed": int, "skipped": int, "branch": str | None, "changes": list[str]}
    """
    def log(msg: str) -> None:
        if rich_console:
            rich_console.print(msg)

    boswell_dir = repo_path / ".boswell"
    audit_path = boswell_dir / "audit.md"
    metadata_path = boswell_dir / "metadata.json"

    if not audit_path.exists():
        return {
            "error": "run boswell audit first — .boswell/audit.md not found",
            "fixed": 0,
            "skipped": 0,
            "branch": None,
            "changes": [],
        }

    audit_text = audit_path.read_text(encoding="utf-8")

    # Collect findings from both sources
    findings = _extract_findings(audit_text)
    findings += _also_extract_leak_findings(metadata_path)

    # Deduplicate by (file_path, description)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in findings:
        key = (f.get("file_path"), f["description"][:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    actionable = [f for f in findings if f.get("file_path")]
    log(f"  [cyan]Found {len(findings)} HIGH/CRITICAL findings ({len(actionable)} with file locations)[/cyan]")

    if not actionable:
        return {
            "fixed": 0,
            "skipped": len(findings),
            "branch": None,
            "changes": [],
            "note": "No actionable findings with file paths — nothing to patch",
        }

    client = OpenAI(api_key=api_key, base_url=OPENROUTER_BASE)

    stashed = _git_stash(repo_path)

    fixed = 0
    skipped = 0
    changes: list[str] = []

    for finding in actionable:
        rel_path = finding["file_path"]
        full_path = contained_path(repo_path, rel_path) if isinstance(rel_path, str) else None
        if full_path is None:
            log(f"  [yellow]Skip (path escapes repo):[/yellow] {rel_path}")
            skipped += 1
            continue

        if not full_path.exists():
            log(f"  [yellow]Skip (not found):[/yellow] {rel_path}")
            skipped += 1
            continue

        content = _read_safe(full_path)
        if not content:
            log(f"  [yellow]Skip (empty/unreadable):[/yellow] {rel_path}")
            skipped += 1
            continue

        snippet = _build_file_snippet(content, finding.get("line_no"))
        is_partial = len(content.splitlines()) > MAX_FILE_LINES and finding.get("line_no")

        log(f"  [cyan]Fixing ({finding['severity']}):[/cyan] {rel_path}")

        try:
            raw_fixed = _call_llm(client, finding, rel_path, snippet)
        except Exception as e:
            log(f"  [red]LLM error for {rel_path}:[/red] {e}")
            skipped += 1
            continue

        fixed_content = _strip_fences(raw_fixed)

        if not fixed_content.strip():
            log(f"  [yellow]Skip (LLM returned empty):[/yellow] {rel_path}")
            skipped += 1
            continue

        # If snippet was partial, reconstruct full file
        if is_partial and fixed_content.startswith("# [Boswell:"):
            # Strip header line from LLM response and splice back in
            fixed_lines = fixed_content.splitlines(keepends=True)
            fixed_lines = [l for l in fixed_lines if not l.startswith("# [Boswell:")]
            orig_lines = content.splitlines(keepends=True)
            line_no = finding["line_no"]
            start = max(0, line_no - 1 - CONTEXT_WINDOW)
            end = min(len(orig_lines), line_no + CONTEXT_WINDOW)
            full_fixed = "".join(orig_lines[:start]) + "".join(fixed_lines) + "".join(orig_lines[end:])
        else:
            full_fixed = fixed_content

        try:
            full_path.write_text(full_fixed, encoding="utf-8")
        except Exception as e:
            log(f"  [red]Write error for {rel_path}:[/red] {e}")
            skipped += 1
            continue

        changes.append(f"{rel_path} — {finding['severity']}: {finding['description'][:80]}")
        fixed += 1
        log(f"  [green]Fixed:[/green] {rel_path}")

    if not changes:
        if stashed:
            _git_unstash(repo_path)
        return {
            "fixed": 0,
            "skipped": skipped,
            "branch": None,
            "changes": [],
            "note": "No files could be patched",
        }

    # Create branch and commit
    branch = f"boswell/security-fixes-{datetime.now().strftime('%Y%m%d')}"
    log(f"  [cyan]Creating branch:[/cyan] {branch}")
    _git_create_branch(repo_path, branch)

    commit_body = "\n".join(f"- {c}" for c in changes)
    commit_msg = f"fix: security issues identified by Boswell audit\n\n{commit_body}"
    _git_commit(repo_path, commit_msg)

    log(f"  [green]Committed {fixed} fix(es) to {branch}[/green]")

    # Optionally mark findings resolved in Neon
    if db_url and run_id:
        try:
            from . import db as _db
            with _db._conn(db_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, description FROM boswell_findings WHERE run_id=%s AND severity IN ('CRITICAL','HIGH')",
                        (run_id,),
                    )
                    rows = cur.fetchall()
                    for fid, desc in rows:
                        if any(c.split(" — ", 1)[1][:60] in (desc or "") for c in changes):
                            cur.execute(
                                "UPDATE boswell_findings SET resolved=TRUE, resolved_at=NOW() WHERE id=%s",
                                (fid,),
                            )
                conn.commit()
        except Exception:
            pass  # Neon is optional

    if not ship:
        log("  [dim]Branch NOT pushed — review before merging.[/dim]")
        return {
            "fixed": fixed,
            "skipped": skipped,
            "branch": branch,
            "changes": changes,
            "status": "fix_only",
        }

    if skipped == 0:
        # Merge fix branch into main and push
        log("  [cyan]All findings fixed — merging to main and pushing…[/cyan]")
        subprocess.run(["git", "checkout", "main"], cwd=repo_path, capture_output=True)
        subprocess.run(
            ["git", "merge", branch, "--no-edit"],
            cwd=repo_path, capture_output=True,
        )
        push_result = subprocess.run(
            ["git", "push", "origin", "main"],
            cwd=repo_path, capture_output=True, text=True,
        )
        if push_result.returncode != 0:
            log(f"  [yellow]Push failed — leaving fix branch in place.[/yellow]")
            log(f"  [dim]{push_result.stderr.strip()}[/dim]")
            return {
                "fixed": fixed,
                "skipped": skipped,
                "branch": branch,
                "changes": changes,
                "status": "fix_only",
                "push_error": push_result.stderr.strip(),
            }
        log("  [green]Shipped to main.[/green]")
        return {
            "fixed": fixed,
            "skipped": skipped,
            "branch": "main",
            "changes": changes,
            "status": "shipped",
        }
    else:
        # Push fix branch and take the deployment offline
        log(f"  [yellow]{skipped} finding(s) could not be fixed — pushing branch and disabling deployment…[/yellow]")
        subprocess.run(
            ["git", "push", "origin", branch],
            cwd=repo_path, capture_output=True,
        )
        disable_result = _disable_deployment(repo_path)
        log(f"  [yellow]Deployment disabled: {disable_result}[/yellow]")
        return {
            "fixed": fixed,
            "skipped": skipped,
            "branch": branch,
            "changes": changes,
            "status": "disabled",
            "reason": "unfixable findings remain",
            "disable_result": disable_result,
        }
