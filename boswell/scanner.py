"""Static repo collection — no LLM calls, no secret values ever logged."""

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

IGNORE_DIRS = {
    ".git", "node_modules", ".next", "__pycache__", "dist", "build",
    ".vercel", ".cache", "coverage", ".nyc_output", "venv", ".venv",
    "env", "target", "vendor", ".turbo", "out", ".output", "boswell",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "eggs", ".eggs",
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".tsbuildinfo", ".map", ".pyc", ".pyo", ".DS_Store",
}

# Files always read in full regardless of size
ALWAYS_READ = {
    "package.json", "pyproject.toml", "requirements.txt", "setup.py",
    "setup.cfg", "Cargo.toml", "go.mod", "Dockerfile", "docker-compose.yml",
    "wrangler.toml", "vercel.json", "vercel.ts", "next.config.js",
    "next.config.ts", "next.config.mjs", "tailwind.config.ts",
    "tailwind.config.js", "tsconfig.json", "vite.config.ts", "vite.config.js",
    ".eslintrc", ".eslintrc.json", ".eslintrc.js", "README.md", "CLAUDE.md",
    ".env.example", ".env.local.example", ".env.sample",
}

# Stack detection: import/require/sdk patterns → label
STACK_PATTERNS = [
    (r"next[\"']|from [\"']next/", "Next.js"),
    (r"from [\"']react", "React"),
    (r"from [\"']vue", "Vue"),
    (r"svelte", "Svelte"),
    (r"cloudflare|wrangler|pages\.dev", "Cloudflare Pages"),
    (r"vercel", "Vercel"),
    (r"supabase", "Supabase"),
    (r"prisma", "Prisma"),
    (r"drizzle-orm", "Drizzle ORM"),
    (r"stripe", "Stripe"),
    (r"openai", "OpenAI"),
    (r"anthropic", "Anthropic"),
    (r"@google-ai|gemini", "Google AI"),
    (r"twilio", "Twilio"),
    (r"sendgrid|nodemailer", "Email (SendGrid/Nodemailer)"),
    (r"aws-sdk|@aws-sdk", "AWS"),
    (r"firebase", "Firebase"),
    (r"mongodb|mongoose", "MongoDB"),
    (r"pg\b|postgres|postgresql", "PostgreSQL"),
    (r"redis", "Redis"),
    (r"langchain|langgraph", "LangChain"),
    (r"fastapi", "FastAPI"),
    (r"flask", "Flask"),
    (r"django", "Django"),
    (r"express", "Express"),
    (r"hono", "Hono"),
]

# Env var key patterns (to inventory, never log values)
ENV_KEY_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*=", re.MULTILINE)
DOTENV_FILE_RE = re.compile(r"^\.env(\..+)?$")


@dataclass
class FileInfo:
    path: Path
    rel: str
    size: int
    ext: str


@dataclass
class RepoScan:
    repo_path: Path
    name: str
    all_files: list[FileInfo] = field(default_factory=list)
    key_file_contents: dict[str, str] = field(default_factory=dict)
    folder_files: dict[str, list[FileInfo]] = field(default_factory=dict)
    stack: list[str] = field(default_factory=list)
    env_var_keys: list[str] = field(default_factory=list)
    npm_audit_json: Optional[str] = None
    pip_audit_json: Optional[str] = None
    git_log_summary: str = ""
    is_git_repo: bool = False
    boswell_context: Optional[str] = None
    total_size_bytes: int = 0


def _run(cmd: list[str], cwd: Path, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _read_safe(path: Path, max_bytes: int = 200_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _strip_secret_values(content: str) -> str:
    """Replace env var values with [REDACTED] so we never log secrets."""
    return re.sub(
        r"^([A-Z][A-Z0-9_]{2,}\s*=\s*)(.+)$",
        r"\1[REDACTED]",
        content,
        flags=re.MULTILINE,
    )


def extract_secret_values(repo_path: Path) -> dict[str, str]:
    """
    Read actual secret values from .env files for vault storage.
    Returns {KEY: value} — only called when the user explicitly opts in.
    Never called during a normal scan.
    """
    secrets: dict[str, str] = {}
    for fname in repo_path.iterdir() if repo_path.is_dir() else []:
        if DOTENV_FILE_RE.match(fname.name) and fname.is_file():
            try:
                raw = fname.read_text(encoding="utf-8", errors="replace")
                for line in raw.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$", line)
                    if m:
                        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
                        if val and val != "[REDACTED]":
                            secrets[key] = val
            except Exception:
                pass
    return secrets


def scan_repo(repo_path: Path) -> RepoScan:
    scan = RepoScan(repo_path=repo_path, name=repo_path.resolve().name)

    # Is it a git repo?
    scan.is_git_repo = (repo_path / ".git").exists()

    # Walk the file tree
    folder_map: dict[str, list[FileInfo]] = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        root_path = Path(root)
        rel_dir = str(root_path.relative_to(repo_path)) if root_path != repo_path else "."
        file_infos = []
        for fname in files:
            fpath = root_path / fname
            ext = fpath.suffix.lower()
            if ext in IGNORE_EXTENSIONS:
                continue
            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            fi = FileInfo(path=fpath, rel=str(fpath.relative_to(repo_path)), size=size, ext=ext)
            file_infos.append(fi)
            scan.all_files.append(fi)
            scan.total_size_bytes += size
        if file_infos:
            folder_map[rel_dir] = file_infos
    scan.folder_files = folder_map

    # Read always-read files and scan for env vars / stack signals
    stack_signals: set[str] = set()
    env_keys: set[str] = set()

    for fi in scan.all_files:
        fname = fi.path.name
        is_dotenv = bool(DOTENV_FILE_RE.match(fname))
        should_read_full = fname in ALWAYS_READ or is_dotenv

        if should_read_full:
            raw = _read_safe(fi.path)
            # Strip values from .env* files before storing
            content = _strip_secret_values(raw) if is_dotenv else raw
            scan.key_file_contents[fi.rel] = content

            # Extract env var keys from .env files
            if is_dotenv:
                env_keys.update(ENV_KEY_RE.findall(raw))

        # Stack detection: scan package.json, imports, and config files
        if fi.ext in {".json", ".ts", ".tsx", ".js", ".jsx", ".py", ".toml"}:
            sample = _read_safe(fi.path, max_bytes=8_000)
            for pattern, label in STACK_PATTERNS:
                if label not in stack_signals and re.search(pattern, sample, re.IGNORECASE):
                    stack_signals.add(label)
            # Also collect env var keys from source imports/references
            env_keys.update(re.findall(r'process\.env\.([A-Z][A-Z0-9_]{2,})', sample))
            env_keys.update(re.findall(r'os\.environ\.get\(["\']([A-Z][A-Z0-9_]{2,})', sample))
            env_keys.update(re.findall(r'os\.getenv\(["\']([A-Z][A-Z0-9_]{2,})', sample))

    scan.stack = sorted(stack_signals)
    scan.env_var_keys = sorted(env_keys)

    # npm audit
    if (repo_path / "package-lock.json").exists() or (repo_path / "package.json").exists():
        out = _run(["npm", "audit", "--json"], repo_path, timeout=60)
        if out:
            scan.npm_audit_json = out[:20_000]  # cap size

    # pip-audit
    if (repo_path / "requirements.txt").exists() or (repo_path / "pyproject.toml").exists():
        out = _run(["pip-audit", "--format=json"], repo_path, timeout=60)
        if out:
            scan.pip_audit_json = out[:10_000]

    # Git log summary
    if scan.is_git_repo:
        log = _run(
            ["git", "log", "--oneline", "--since=6.months", "-500",
             "--pretty=format:%h %s (%ad)", "--date=short"],
            repo_path,
        )
        scan.git_log_summary = log[:8_000]

    # BOSWELL_CONTEXT.md
    ctx_path = repo_path / "BOSWELL_CONTEXT.md"
    if ctx_path.exists():
        scan.boswell_context = _read_safe(ctx_path)

    return scan
