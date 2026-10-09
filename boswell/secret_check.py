"""
Secret leakage detection — four layers:
0. gitleaks (primary, deterministic, 300+ rules) — if installed
1. Git history scan (last 6 months / 500 commits)
2. Working-tree scan (tracked files right now)
3. .gitignore coverage check (will the next commit leak?)

gitleaks is the authoritative source of truth for commit-history leaks.
Layers 1-3 supplement it and cover gitignore gaps gitleaks doesn't check.

Never prints or returns actual secret values — only file:line location.
"""

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .safety import contained_path

# (label, regex matching the secret token shape — not a variable name)
SECRET_PATTERNS = [
    ("Anthropic API key",      re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}")),
    ("OpenAI API key",         re.compile(r"sk-[a-zA-Z0-9]{20,}(?!ant)")),
    ("Stripe live secret",     re.compile(r"sk_live_[a-zA-Z0-9]{24,}")),
    ("Stripe test secret",     re.compile(r"sk_test_[a-zA-Z0-9]{24,}")),
    ("AWS access key",         re.compile(r"AKIA[A-Z0-9]{16}")),
    ("GitHub token (ghp)",     re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("GitHub token (gho)",     re.compile(r"gho_[a-zA-Z0-9]{36}")),
    ("Slack token",            re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,}")),
    ("Google API key",         re.compile(r"AIza[a-zA-Z0-9\-_]{35}")),
    ("Twilio Account SID",     re.compile(r"AC[a-f0-9]{32}")),
    ("SendGrid API key",       re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}")),
    ("Supabase anon key (JWT)",re.compile(r"eyJ[a-zA-Z0-9\-_]{50,}\.[a-zA-Z0-9\-_]{30,}")),
    ("Bearer token in header", re.compile(r"[Bb]earer\s+[a-zA-Z0-9\-_\.]{20,}")),
    # Cloudflare tokens appear in assignments/env context — bare 37-char strings are too noisy
    ("Cloudflare API token",   re.compile(r"(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cf_api_token)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{30,}")),
]

SKIP_FILE_RE = re.compile(
    r"\.(lock|min\.js|min\.css|tsbuildinfo|map|png|jpg|jpeg|gif|svg|woff|ttf|pdf|zip)$"
    r"|node_modules/|\.next/|dist/|build/|\.git/|boswell/|\.wrangler/"
)

# .env filenames that should never be git-tracked
DOTENV_RE = re.compile(r"^\.env(\..+)?$")

# Directories that should always be in .gitignore — (dir_name, gitignore_pattern, reason)
SHOULD_BE_IGNORED = [
    (".wrangler",   re.compile(r"^\.wrangler", re.MULTILINE),    "Cloudflare Workers build cache — may contain OAuth tokens"),
    (".next",       re.compile(r"^\.next",      re.MULTILINE),    "Next.js build output"),
    ("dist",        re.compile(r"^/?dist/?$",   re.MULTILINE),    "build output"),
    (".turbo",      re.compile(r"^\.turbo",     re.MULTILINE),    "Turborepo cache"),
    (".vercel",     re.compile(r"^\.vercel",    re.MULTILINE),    "Vercel build output"),
]


@dataclass
class LeakFinding:
    severity: str       # CRITICAL | HIGH | MEDIUM | INFO
    category: str       # "tracked-env-file" | "hardcoded-secret" | "history-leak" | "gitignore-gap"
    description: str    # human-readable, no secret value
    location: str       # file path, commit ref, or "no .gitignore"
    fix: str            # what the operator should do, shown in the UI
    action: dict | None = None  # structured fix; never a shell string


def _run(cmd: list[str], cwd: Path, timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.stdout
    except Exception:
        return ""


def _skip(filename: str) -> bool:
    return bool(SKIP_FILE_RE.search(filename))


# ── Layer 0: gitleaks (primary deterministic scanner) ────────────────────────

_GITLEAKS_BIN = shutil.which("gitleaks")

_GITLEAKS_SEVERITY: dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "CRITICAL",   # gitleaks HIGH → our CRITICAL (token in git history)
    "medium":   "HIGH",
    "low":      "HIGH",
    "info":     "MEDIUM",
}


def run_gitleaks(repo_path: Path) -> list[LeakFinding]:
    """
    Run gitleaks against the full git history and return findings.
    Returns empty list if gitleaks is not installed or the repo has no .git.
    """
    if not _GITLEAKS_BIN:
        return []
    if not (repo_path / ".git").exists():
        return []

    findings: list[LeakFinding] = []
    seen: set[str] = set()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        subprocess.run(
            [
                _GITLEAKS_BIN, "git",
                str(repo_path),
                "--report-format", "json",
                "--report-path", report_path,
                "--exit-code", "0",   # don't fail with non-zero on findings
                "--log-level", "error",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        raw = Path(report_path).read_text(encoding="utf-8", errors="replace").strip()
        if not raw or raw == "null":
            return []

        items = json.loads(raw)
        if not isinstance(items, list):
            return []

        for item in items:
            rule_id  = item.get("RuleID", "unknown")
            desc     = item.get("Description", rule_id)
            file_    = item.get("File", "")
            line     = item.get("StartLine", 0)
            commit   = item.get("Commit", "")[:8] if item.get("Commit") else ""
            gl_sev   = (item.get("Tags") or ["medium"])[0].lower() if item.get("Tags") else "high"
            severity = _GITLEAKS_SEVERITY.get(gl_sev, "CRITICAL")
            fingerprint = item.get("Fingerprint", f"{rule_id}:{file_}:{line}:{commit}")

            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            if commit:
                location = f"commit {commit} / {file_}:{line}"
                fix = (
                    f"Rotate this credential immediately. "
                    f"Then purge from history: git filter-repo --path {file_} --invert-paths"
                )
            else:
                location = f"{file_}:{line}"
                fix = f"Move the value to an environment variable and remove from source."

            findings.append(LeakFinding(
                severity=severity,
                category="history-leak" if commit else "hardcoded-secret",
                description=f"[gitleaks] {desc} — {file_}:{line}" + (f" (commit {commit})" if commit else ""),
                location=location,
                fix=fix,
            ))

    except Exception:
        pass
    finally:
        try:
            Path(report_path).unlink(missing_ok=True)
        except Exception:
            pass

    return findings


# ── Layer 1: Git history ─────────────────────────────────────────────────────

def scan_git_history(repo_path: Path) -> list[str]:
    """Legacy interface — returns plain warning strings for backward compat."""
    return [f.description for f in scan_history_findings(repo_path)]


def scan_history_findings(repo_path: Path) -> list[LeakFinding]:
    if not (repo_path / ".git").exists():
        return []

    findings: list[LeakFinding] = []
    seen: set[str] = set()

    diff = _run(
        ["git", "log", "-p", "--since=6.months", "--diff-filter=A",
         "--no-merges", "--format=COMMIT:%h %s", "-500"],
        repo_path,
    )

    current_commit = "unknown"
    current_file = ""

    for line in diff.splitlines():
        if line.startswith("COMMIT:"):
            current_commit = line[7:].strip()
            current_file = ""
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if _skip(current_file):
            continue

        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line[1:]):
                key = f"{current_commit}:{label}:{current_file}"
                if key not in seen:
                    seen.add(key)
                    findings.append(LeakFinding(
                        severity="CRITICAL",
                        category="history-leak",
                        description=f"Possible {label} committed in {current_commit} — file: {current_file}",
                        location=f"commit {current_commit} / {current_file}",
                        fix=f"Rotate this credential immediately. Then: git filter-repo --path {current_file} --invert-paths  (or BFG repo cleaner)",
                    ))

    return findings


# ── Layer 2: Working-tree scan ───────────────────────────────────────────────

def scan_working_tree(repo_path: Path) -> list[LeakFinding]:
    """
    Scan files currently tracked by git for hardcoded secret patterns.
    Also flags any .env files that are tracked (they should never be).
    """
    if not (repo_path / ".git").exists():
        return []

    findings: list[LeakFinding] = []

    # Get list of all tracked files
    tracked_raw = _run(["git", "ls-files"], repo_path)
    tracked_files = [f.strip() for f in tracked_raw.splitlines() if f.strip()]

    for rel_path in tracked_files:
        if _skip(rel_path):
            continue

        fname = Path(rel_path).name

        # Flag tracked .env files — these should never be in git
        if DOTENV_RE.match(fname) and fname not in {".env.example", ".env.sample", ".env.local.example"}:
            findings.append(LeakFinding(
                severity="CRITICAL",
                category="tracked-env-file",
                description=f".env file is tracked by git: {rel_path}",
                location=rel_path,
                fix=f"Stop tracking {rel_path} and add it to .gitignore.",
                action={"type": "untrack", "path": rel_path},
            ))
            continue  # no need to also scan its contents — just remove it

        # Scan file contents for hardcoded secret patterns
        full_path = repo_path / rel_path
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for lineno, line in enumerate(content.splitlines(), 1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(LeakFinding(
                        severity="CRITICAL",
                        category="hardcoded-secret",
                        description=f"Possible hardcoded {label} in source file: {rel_path}:{lineno}",
                        location=f"{rel_path}:{lineno}",
                        fix=f"Move the value to an environment variable. Remove from source. Run: git rm --cached {rel_path} if it was ever committed with the secret.",
                    ))
                    break  # one finding per line is enough

    return findings


# ── Layer 3: .gitignore coverage ─────────────────────────────────────────────

def scan_gitignore(repo_path: Path) -> list[LeakFinding]:
    """Check that .gitignore properly excludes .env files."""
    findings: list[LeakFinding] = []

    gitignore_path = repo_path / ".gitignore"
    if not gitignore_path.exists():
        findings.append(LeakFinding(
            severity="HIGH",
            category="gitignore-gap",
            description="No .gitignore file found — .env files are unprotected",
            location=".gitignore (missing)",
            fix="Add .env rules to a new .gitignore.",
            action={
                "type": "gitignore_lines",
                "lines": [".env", ".env.*", "!.env.example", "!.env.sample"],
                "stage": True,
            },
        ))
        return findings

    content = gitignore_path.read_text(encoding="utf-8", errors="replace")

    # Check for .env coverage
    has_env_coverage = bool(
        re.search(r"^\.env(\b|\*|$)", content, re.MULTILINE) or
        re.search(r"^\*\.env", content, re.MULTILINE)
    )
    if not has_env_coverage:
        findings.append(LeakFinding(
            severity="HIGH",
            category="gitignore-gap",
            description=".gitignore exists but does not exclude .env files",
            location=".gitignore",
            fix="Add .env rules to .gitignore.",
            action={
                "type": "gitignore_lines",
                "lines": [".env", ".env.*", "!.env.example", "!.env.sample"],
                "stage": False,
            },
        ))

    # Collect all .gitignore content across the repo (root + subdirs, skip worktrees)
    all_gitignore_content = content
    for gi_path in repo_path.rglob(".gitignore"):
        if ".claude/worktrees" in str(gi_path) or "node_modules" in str(gi_path):
            continue
        try:
            all_gitignore_content += "\n" + gi_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Check build artifact dirs that should be ignored — use git ls-files to find tracked ones
    for dir_name, pattern, reason in SHOULD_BE_IGNORED:
        # Any tracked file under this dir name anywhere in the repo
        tracked = _run(["git", "ls-files", f"*{dir_name}/*", "--", f"**/{dir_name}/**"],
                       repo_path).strip()
        # Simpler: just grep git ls-files output
        all_tracked = _run(["git", "ls-files"], repo_path)
        dir_tracked = [l for l in all_tracked.splitlines() if f"/{dir_name}/" in l or l.startswith(f"{dir_name}/")]
        if dir_tracked and not pattern.search(all_gitignore_content):
            example = dir_tracked[0]
            findings.append(LeakFinding(
                severity="HIGH",
                category="gitignore-gap",
                description=f"{dir_name}/ files are tracked by git and not excluded — {reason} (e.g. {example})",
                location=f"{dir_name}/ (e.g. {example})",
                fix=f"Stop tracking {dir_name}/ and add it to .gitignore.",
                action={"type": "untrack_dir", "dir": dir_name},
            ))

    # Check for any .env* files on disk that ARE tracked despite .gitignore
    # Exclude intentionally-tracked templates (.env.example, .env.sample, etc.)
    _SAFE_ENV_NAMES = {".env.example", ".env.sample", ".env.local.example", ".env.template"}
    for item in repo_path.iterdir():
        if DOTENV_RE.match(item.name) and item.is_file() and item.name not in _SAFE_ENV_NAMES:
            check = _run(["git", "ls-files", item.name], repo_path).strip()
            if check:
                findings.append(LeakFinding(
                    severity="CRITICAL",
                    category="tracked-env-file",
                    description=f"{item.name} is in .gitignore but still tracked by git (was force-added)",
                    location=item.name,
                    fix=f"Stop tracking {item.name} and add it to .gitignore.",
                    action={"type": "untrack", "path": item.name},
                ))

    return findings


_ENV_GITIGNORE_LINES = [".env", ".env.*", "!.env.example", "!.env.sample"]


def _git(repo_path: Path, args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
            errors="replace",
        )
    except Exception as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "git failed").strip()
    return True, (result.stdout or result.stderr).strip()


def _append_gitignore_line(repo_path: Path, line: str) -> None:
    path = repo_path / ".gitignore"
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    if line in existing.splitlines():
        return
    prefix = "" if (not existing or existing.endswith("\n")) else "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{prefix}{line}\n")


def _tracked_under(repo_path: Path, dir_name: str) -> list[str]:
    raw = _run(["git", "ls-files"], repo_path)
    tracked = []
    for line in raw.splitlines():
        if f"/{dir_name}/" in line or line.startswith(f"{dir_name}/"):
            tracked.append(line)
    return tracked


def _infer_action(finding: LeakFinding) -> dict | None:
    if finding.category == "tracked-env-file" and finding.location:
        return {"type": "untrack", "path": finding.location}
    if finding.category != "gitignore-gap":
        return None
    description = finding.description
    if description.startswith("No .gitignore"):
        return {"type": "gitignore_lines", "lines": list(_ENV_GITIGNORE_LINES), "stage": True}
    if "does not exclude .env" in description:
        return {"type": "gitignore_lines", "lines": list(_ENV_GITIGNORE_LINES), "stage": False}
    for dir_name, _pattern, _reason in SHOULD_BE_IGNORED:
        if description.startswith(f"{dir_name}/"):
            return {"type": "untrack_dir", "dir": dir_name}
    return None


def apply_auto_fix(finding: LeakFinding, repo_path: Path) -> tuple[bool, str]:
    """Apply a leak fix with argument lists. Repo names are never sent to a shell."""
    repo = repo_path.resolve()
    action = finding.action if isinstance(finding.action, dict) else _infer_action(finding)
    if not action:
        return False, "This finding is instructions only."
    kind = action.get("type")
    if kind == "untrack":
        rel = action.get("path")
        if not isinstance(rel, str) or contained_path(repo, rel) is None:
            return False, "Path is outside the repository."
        _append_gitignore_line(repo, rel)
        ok, out = _git(repo, ["git", "rm", "--cached", "--", rel])
        if not ok:
            return False, out
        return _git(repo, ["git", "commit", "-m", "stop tracking env file"])
    if kind == "gitignore_lines":
        lines = action.get("lines")
        if not isinstance(lines, list) or not lines:
            return False, "No gitignore lines to write."
        for line in lines:
            if not isinstance(line, str) or any(ch in line for ch in ("\n", "\r", "\x00")):
                return False, "Refusing to write gitignore lines."
            _append_gitignore_line(repo, line)
        if action.get("stage"):
            return _git(repo, ["git", "add", "--", ".gitignore"])
        return True, "Updated .gitignore"
    if kind == "untrack_dir":
        dir_name = action.get("dir")
        allowed = {name for name, _pattern, _reason in SHOULD_BE_IGNORED}
        if dir_name not in allowed:
            return False, "Unknown directory."
        _append_gitignore_line(repo, f"{dir_name}/")
        tracked = _tracked_under(repo, dir_name)
        if not tracked:
            return True, "Updated .gitignore"
        for rel in tracked:
            if contained_path(repo, rel) is None:
                return False, "Path is outside the repository."
        ok, out = _git(repo, ["git", "rm", "-r", "--cached", "--", *tracked])
        if not ok:
            return False, out
        return _git(repo, ["git", "commit", "-m", "untrack build artifacts"])
    return False, "This finding is instructions only."


# ── Combined entry point ──────────────────────────────────────────────────────

def full_leak_scan(repo_path: Path) -> list[LeakFinding]:
    """
    Run all layers and return deduplicated findings, sorted by severity.

    Layer 0 (gitleaks) is the authoritative history scanner when installed.
    When gitleaks is present, Layer 1 (regex history) is skipped to avoid
    duplicate findings — gitleaks has a superset of our patterns.
    Layers 2-3 (working tree + gitignore) always run; gitleaks doesn't cover them.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

    gl_findings = run_gitleaks(repo_path)
    has_gitleaks = bool(_GITLEAKS_BIN and (repo_path / ".git").exists())

    findings: list[LeakFinding] = []
    findings += scan_gitignore(repo_path)
    findings += scan_working_tree(repo_path)

    if has_gitleaks:
        # gitleaks already covered history; skip our regex history scan
        findings += gl_findings
    else:
        # No gitleaks — fall back to regex history scan
        findings += scan_history_findings(repo_path)

    # Deduplicate by location
    seen_locs: set[str] = set()
    unique = []
    for f in findings:
        if f.location not in seen_locs:
            seen_locs.add(f.location)
            unique.append(f)

    return sorted(unique, key=lambda f: severity_order.get(f.severity, 9))
