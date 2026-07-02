"""
Constitution engine — per-repo governance rules enforced statically.
Rules are checked and violations feed into the entropy score.
"""

import json
import re
from pathlib import Path

try:
    import yaml as _yaml
    def _dump(obj) -> str:
        return _yaml.dump(obj, default_flow_style=False, sort_keys=True)
    def _load(text: str) -> dict:
        return _yaml.safe_load(text) or {}
except ImportError:
    import json as _json_fallback
    def _dump(obj) -> str:  # type: ignore[misc]
        return _json_fallback.dumps(obj, indent=2)
    def _load(text: str) -> dict:  # type: ignore[misc]
        return _json_fallback.loads(text)


RULE_DEFINITIONS: dict[str, dict] = {
    "typescript_strict": {
        "description": "tsconfig.json must have 'strict': true",
        "default_severity": "HIGH",
    },
    "edge_runtime": {
        "description": "All app/api/**/route.ts files must export const runtime = 'edge' on line 1",
        "default_severity": "HIGH",
    },
    "no_supabase": {
        "description": "No @supabase imports anywhere in source",
        "default_severity": "CRITICAL",
    },
    "neon_only": {
        "description": "Database access must use @neondatabase/serverless",
        "default_severity": "HIGH",
    },
    "custom_jwt_auth": {
        "description": "No NextAuth, Clerk, Auth0, or Firebase auth imports",
        "default_severity": "HIGH",
    },
    "max_file_lines": {
        "description": "No source file exceeds the line limit (default 300)",
        "default_severity": "MEDIUM",
        "param": "limit",
        "default_param": 300,
    },
    "no_console_log": {
        "description": "No console.log statements in source files",
        "default_severity": "LOW",
    },
    "no_env_fallback": {
        "description": "No process.env.X ?? 'fallback' patterns — missing env vars must throw",
        "default_severity": "HIGH",
    },
    "has_gitignore_env": {
        "description": ".gitignore must include .env* entries",
        "default_severity": "CRITICAL",
    },
    "no_inline_styles": {
        "description": "No inline style={{ }} in JSX/TSX files",
        "default_severity": "LOW",
    },
    "parameterized_queries": {
        "description": "No string-interpolated SQL queries (template literals with ${} in query calls)",
        "default_severity": "CRITICAL",
    },
}

_DEFAULT_ENABLED: dict[str, bool] = {
    "typescript_strict": True,
    "edge_runtime": False,   # only for Next.js/Cloudflare repos
    "no_supabase": True,
    "neon_only": False,      # only if repo uses a database
    "custom_jwt_auth": False,
    "max_file_lines": True,
    "no_console_log": True,
    "no_env_fallback": True,
    "has_gitignore_env": True,
    "no_inline_styles": False,
    "parameterized_queries": True,
}

_SKIP_DIRS = {
    "node_modules", ".next", "dist", "out", ".vercel", ".wrangler",
    "build", ".turbo", "coverage", ".boswell", "__pycache__",
}
_SOURCE_EXTS = {".ts", ".tsx", ".js", ".jsx"}


def _source_files(repo_path: Path) -> list[Path]:
    files = []
    for f in repo_path.rglob("*"):
        if any(p in _SKIP_DIRS for p in f.parts):
            continue
        if f.suffix in _SOURCE_EXTS and f.is_file():
            files.append(f)
    return files


# ── default / load / save ──────────────────────────────────────────────────

def default_constitution() -> dict:
    rules: dict = {}
    for rule_id, defn in RULE_DEFINITIONS.items():
        r: dict = {
            "enabled": _DEFAULT_ENABLED.get(rule_id, True),
            "severity": defn["default_severity"],
        }
        if "param" in defn:
            r[defn["param"]] = defn["default_param"]
        rules[rule_id] = r
    return {"version": 1, "rules": rules}


def load_constitution(repo_path: Path) -> dict:
    path = repo_path / ".boswell" / "constitution.yaml"
    if path.exists():
        try:
            loaded = _load(path.read_text())
            if loaded and isinstance(loaded, dict):
                # Merge with defaults so new rules are always present
                defaults = default_constitution()
                for rule_id, rule_default in defaults["rules"].items():
                    if rule_id not in loaded.get("rules", {}):
                        loaded.setdefault("rules", {})[rule_id] = rule_default
                return loaded
        except Exception:
            pass
    return default_constitution()


def save_constitution(repo_path: Path, constitution: dict) -> None:
    boswell_dir = repo_path / ".boswell"
    boswell_dir.mkdir(exist_ok=True)
    path = boswell_dir / "constitution.yaml"
    path.write_text(_dump(constitution))


# ── rule checkers ──────────────────────────────────────────────────────────

def _v(rule: str, file: str, line: int | None, detail: str) -> dict:
    return {"rule": rule, "file": file, "line": line, "detail": detail}


def _check_typescript_strict(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    for name in ("tsconfig.json", "tsconfig.app.json"):
        p = repo_path / name
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
            if not data.get("compilerOptions", {}).get("strict", False):
                violations.append(_v("typescript_strict", name, None,
                                     f"{name} missing 'strict': true in compilerOptions"))
        except Exception:
            pass
    return violations


def _check_edge_runtime(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    for api_dir in (repo_path / "app" / "api", repo_path / "src" / "app" / "api"):
        if not api_dir.exists():
            continue
        for f in api_dir.rglob("route.ts"):
            if any(p in _SKIP_DIRS for p in f.parts):
                continue
            try:
                lines = f.read_text(errors="replace").splitlines()
                first = lines[0].strip() if lines else ""
                if 'runtime' not in first or '"edge"' not in first and "'edge'" not in first:
                    violations.append(_v("edge_runtime",
                                         str(f.relative_to(repo_path)), 1,
                                         "Missing export const runtime = 'edge' on line 1"))
            except Exception:
                pass
    return violations


def _check_no_supabase(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'(?:from|require)\s*[\'"]@supabase/')
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("no_supabase", str(f.relative_to(repo_path)),
                                     line_no, f"Supabase import: {m.group(0).strip()}"))
        except Exception:
            pass
    return violations


def _check_neon_only(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'(?:from|require)\s*[\'"](?:pg|postgres|pg-promise)[\'"]')
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("neon_only", str(f.relative_to(repo_path)),
                                     line_no, f"Non-Neon DB import: {m.group(0).strip()}"))
        except Exception:
            pass
    return violations


def _check_custom_jwt_auth(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'(?:from|require)\s*[\'"](?:next-auth|@auth0/|@clerk/|firebase/auth|@firebase/auth)[\'"]')
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("custom_jwt_auth", str(f.relative_to(repo_path)),
                                     line_no, f"Third-party auth import: {m.group(0).strip()}"))
        except Exception:
            pass
    return violations


def _check_max_file_lines(repo_path: Path, config: dict) -> list[dict]:
    limit = int(config.get("limit", 300))
    violations = []
    for f in _source_files(repo_path):
        try:
            lines = f.read_text(errors="replace").count("\n")
            if lines > limit:
                violations.append(_v("max_file_lines", str(f.relative_to(repo_path)),
                                     None, f"{lines} lines exceeds limit of {limit}"))
        except Exception:
            pass
    violations.sort(key=lambda x: -int(x["detail"].split()[0]))
    return violations[:10]


def _check_no_console_log(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'\bconsole\.log\s*\(')
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("no_console_log", str(f.relative_to(repo_path)),
                                     line_no, "console.log found"))
        except Exception:
            pass
    return violations[:10]


def _check_no_env_fallback(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'process\.env\.\w+\s*(?:\?\?|\|\|)\s*["\'][^"\']*["\']')
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                snippet = m.group(0)[:70]
                violations.append(_v("no_env_fallback", str(f.relative_to(repo_path)),
                                     line_no, f"Env var fallback: {snippet}"))
        except Exception:
            pass
    return violations[:10]


def _check_has_gitignore_env(repo_path: Path, config: dict) -> list[dict]:
    gi = repo_path / ".gitignore"
    if not gi.exists():
        return [_v("has_gitignore_env", ".gitignore", None, ".gitignore file not found")]
    content = gi.read_text(errors="replace")
    if ".env" not in content:
        return [_v("has_gitignore_env", ".gitignore", None,
                   ".gitignore does not include .env* entries")]
    return []


def _check_no_inline_styles(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    pattern = re.compile(r'\bstyle=\{\{')
    for f in _source_files(repo_path):
        if f.suffix not in (".tsx", ".jsx"):
            continue
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("no_inline_styles", str(f.relative_to(repo_path)),
                                     line_no, "Inline style={{}} found"))
        except Exception:
            pass
    return violations[:10]


def _check_parameterized_queries(repo_path: Path, config: dict) -> list[dict]:
    violations = []
    # Template literal with ${} inside a sql/query/execute/run call
    pattern = re.compile(
        r'(?:sql|query|execute|run|db\.query)\s*\(\s*`[^`]*\$\{',
        re.IGNORECASE,
    )
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            m = pattern.search(content)
            if m:
                line_no = content[: m.start()].count("\n") + 1
                violations.append(_v("parameterized_queries", str(f.relative_to(repo_path)),
                                     line_no, "SQL string interpolation detected"))
        except Exception:
            pass
    return violations[:5]


_CHECKERS = {
    "typescript_strict": _check_typescript_strict,
    "edge_runtime": _check_edge_runtime,
    "no_supabase": _check_no_supabase,
    "neon_only": _check_neon_only,
    "custom_jwt_auth": _check_custom_jwt_auth,
    "max_file_lines": _check_max_file_lines,
    "no_console_log": _check_no_console_log,
    "no_env_fallback": _check_no_env_fallback,
    "has_gitignore_env": _check_has_gitignore_env,
    "no_inline_styles": _check_no_inline_styles,
    "parameterized_queries": _check_parameterized_queries,
}

_SEV_PENALTY = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}


# ── main entry point ───────────────────────────────────────────────────────

def check_constitution(repo_path: Path) -> dict:
    """Run all enabled constitution checks. Returns violations and per-rule summaries."""
    constitution = load_constitution(repo_path)
    rules = constitution.get("rules", {})

    all_violations: list[dict] = []
    rule_summaries: list[dict] = []

    for rule_id, checker in _CHECKERS.items():
        rule_config = rules.get(rule_id, {})
        enabled = rule_config.get("enabled", _DEFAULT_ENABLED.get(rule_id, True))
        severity = rule_config.get(
            "severity", RULE_DEFINITIONS[rule_id]["default_severity"]
        )

        if not enabled:
            rule_summaries.append({
                "rule": rule_id,
                "status": "skipped",
                "severity": severity,
                "violations": 0,
                "description": RULE_DEFINITIONS[rule_id]["description"],
                "details": [],
            })
            continue

        try:
            violations = checker(repo_path, rule_config)
        except Exception:
            violations = []

        all_violations.extend(violations)
        rule_summaries.append({
            "rule": rule_id,
            "status": "pass" if not violations else "fail",
            "severity": severity,
            "violations": len(violations),
            "description": RULE_DEFINITIONS[rule_id]["description"],
            "details": violations[:3],
        })

    score = 0
    for v in all_violations:
        rule_id = v["rule"]
        sev = rules.get(rule_id, {}).get(
            "severity", RULE_DEFINITIONS.get(rule_id, {}).get("default_severity", "MEDIUM")
        )
        score += _SEV_PENALTY.get(sev, 4)

    return {
        "violations": all_violations,
        "rule_summaries": rule_summaries,
        "total_violations": len(all_violations),
        "constitution_score": min(100, score),
        "passed": sum(1 for r in rule_summaries if r["status"] == "pass"),
        "failed": sum(1 for r in rule_summaries if r["status"] == "fail"),
        "skipped": sum(1 for r in rule_summaries if r["status"] == "skipped"),
    }


def constitution_penalty(repo_path: Path) -> int:
    """Quick constitution penalty (0-100) for entropy integration."""
    try:
        result = check_constitution(repo_path)
        return result["constitution_score"]
    except Exception:
        return 0
