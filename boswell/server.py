"""
Boswell web interface — FastAPI server at localhost:7474.
Run with: boswell serve
"""

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import vault as v
from .safety import (
    api_token,
    assert_public_http_url,
    bearer_ok,
    clear_unlock_failures,
    contained_path,
    host_allowed,
    record_unlock_failure,
    unlock_blocked,
)

app = FastAPI(title="Boswell", docs_url=None, redoc_url=None)


class _LocalGuard(BaseHTTPMiddleware):
    """Accept only localhost, and require the local API token on /api routes."""

    async def dispatch(self, request, call_next):
        if not host_allowed(request.headers.get("host", "")):
            return JSONResponse({"detail": "This server only accepts localhost."}, status_code=403)
        path = request.url.path
        if path == "/api" or path.startswith("/api/"):
            if not bearer_ok(request.headers.get("authorization")):
                return JSONResponse({"detail": "Missing or invalid API token."}, status_code=401)
        return await call_next(request)


app.add_middleware(_LocalGuard)


@app.on_event("startup")
def _startup_init_db():
    """Ensure Neon schema (including boswell_repo_meta) is up to date on server start."""
    try:
        v.tighten_vault_files()
    except Exception:
        pass
    try:
        from . import db as _db
        db_url = _db.get_url()
        if db_url:
            _db.init_db(db_url)
    except Exception:
        pass


# The root folder to scan for repos — set at startup
_repos_root: Path = Path.home()


def set_repos_root(path: Path):
    global _repos_root
    _repos_root = path


def _find_boswell_repos(root: Path) -> list[dict]:
    """Find all directories up to 2 levels under root that are git repos.
    If a .boswell/metadata.json exists, use it. Otherwise auto-create minimal metadata."""
    repos = []
    seen: set[str] = set()

    def _check(candidate: Path) -> None:
        key = str(candidate.resolve())
        if key in seen:
            return
        seen.add(key)
        boswell_dir = candidate / ".boswell"
        meta_path = boswell_dir / "metadata.json"

        # Auto-bootstrap .boswell/ for plain git repos that haven't been scanned yet
        if (candidate / ".git").is_dir() and not meta_path.exists():
            try:
                boswell_dir.mkdir(exist_ok=True)
                meta_path.write_text(json.dumps({
                    "name": candidate.name,
                    "stack": [],
                    "platforms": [],
                }, indent=2))
            except Exception:
                pass

        if boswell_dir.is_dir() and meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                repos.append({
                    "name": candidate.name,
                    "path": str(candidate),
                    "meta": meta,
                    "has_audit": (boswell_dir / "audit.md").exists(),
                    "has_handoff": (boswell_dir / "handoff.md").exists(),
                    "has_lessons": (boswell_dir / "lessons.md").exists(),
                    "has_vault_secrets": candidate.name in (v.list_repos() if v.is_unlocked() else []),
                })
            except Exception:
                pass

    # depth-0: root itself; depth-1: direct children; depth-2: grandchildren
    try:
        level1 = [root] + [d for d in root.iterdir() if d.is_dir()]
    except PermissionError:
        return []

    for d1 in level1:
        _check(d1)
        try:
            for d2 in d1.iterdir():
                if d2.is_dir():
                    _check(d2)
        except PermissionError:
            pass

    # Merge in Neon metadata (deployed_url, run_at, last_score, stack, platforms).
    # A single batch SELECT; Neon values win when both local and remote exist.
    if repos:
        try:
            from . import db as _db
            db_url = _db.get_url()
            if db_url:
                neon_meta = _db.fetch_repo_meta_batch(db_url, [r["name"] for r in repos])
                for r in repos:
                    nm = neon_meta.get(r["name"])
                    if not nm:
                        continue
                    meta = r.setdefault("meta", {})
                    for field in ("deployed_url", "stack", "platforms", "last_score"):
                        nv = nm.get(field)
                        if nv not in (None, "", [], {}):
                            meta[field] = nv
                    if nm.get("run_at"):
                        # run_at comes back as a datetime from psycopg2 — normalise to string
                        ra = nm["run_at"]
                        meta["run_at"] = ra.strftime("%Y-%m-%d %H:%M") if hasattr(ra, "strftime") else str(ra)
        except Exception:
            pass  # Neon unavailable — local file data is used as-is

    return sorted(repos, key=lambda r: r["name"])


def _read_doc(repo_path: str, doc: str) -> str:
    path = Path(repo_path) / ".boswell" / f"{doc}.md"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


# ── API routes ──────────────────────────────────────────────────────────────

@app.get("/api/repos")
def api_repos():
    return _find_boswell_repos(_repos_root)


@app.get("/api/repo/{name}/doc/{doc}")
def api_doc(name: str, doc: str):
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")
    allowed = {"audit", "handoff", "audit-simple", "handoff-simple", "lessons", "improvements", "optimal-prompt"}
    if doc not in allowed:
        raise HTTPException(400, "Invalid doc name")
    content = _read_doc(repo["path"], doc)
    return {"content": content}


@app.get("/api/leaks")
def api_leaks():
    """Return all leak findings. Uses Neon if BOSWELL_DATABASE_URL is set, else local metadata."""
    from . import db as _db
    db_url = _db.get_url()
    if db_url:
        try:
            rows = _db.list_findings(db_url)
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
            rows.sort(key=lambda x: order.get(x.get("severity", "INFO"), 9))
            return rows
        except Exception:
            pass  # fall through to local metadata

    repos = _find_boswell_repos(_repos_root)
    all_leaks = []
    for r in repos:
        meta = r.get("meta", {})
        for f in meta.get("leak_findings", []):
            all_leaks.append({**f, "repo": r["name"]})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    all_leaks.sort(key=lambda x: order.get(x.get("severity", "INFO"), 9))
    return all_leaks


@app.get("/api/runs")
def api_runs():
    """Return all Boswell scan runs from Neon (requires BOSWELL_DATABASE_URL)."""
    from . import db as _db
    db_url = _db.get_url()
    if not db_url:
        return []
    try:
        return _db.list_runs(db_url)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/repo/{name}/findings")
def api_repo_findings(name: str):
    """Parse audit.md for structured findings (CRITICAL/HIGH/MEDIUM/LOW/INFO lines)."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")
    content = _read_doc(repo["path"], "audit")
    findings = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for line in content.splitlines():
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{sev}]" in line:
                findings.append({
                    "severity": sev,
                    "text": line.strip().lstrip("- "),
                })
                break
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return findings


@app.get("/api/repo/{name}/fixed-summary")
def api_fixed_summary(name: str):
    """Return resolved findings for a repo (from Neon or parsed audit.md)."""
    from . import db as _db
    db_url = _db.get_url()
    if db_url:
        try:
            rows = _db.list_findings(db_url, repo_name=name)
            resolved = [r for r in rows if r.get("resolved")]
            if resolved:
                return resolved
        except Exception:
            pass
    # Fallback: no resolved tracking without Neon
    return []


@app.get("/api/repo/{name}/open-summary")
def api_open_summary(name: str):
    """Return open findings for a repo (from Neon if available, else audit.md)."""
    from . import db as _db
    db_url = _db.get_url()
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    if db_url:
        try:
            rows = _db.list_findings(db_url, repo_name=name)
            open_rows = [r for r in rows if not r.get("resolved")]
            if open_rows:
                return open_rows
        except Exception:
            pass

    # Fallback: parse audit.md
    content = _read_doc(repo["path"], "audit")
    findings = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for line in content.splitlines():
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{sev}]" in line:
                findings.append({"severity": sev, "description": line.strip().lstrip("- "), "resolved": False})
                break
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return findings


@app.post("/api/repo/{name}/generate-improvements")
async def generate_improvements(name: str):
    """Generate a improvements.md doc via LLM and cache in .boswell/."""
    import os as _os
    api_key = _os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "OPENROUTER_API_KEY not set")

    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    meta = repo.get("meta", {})
    stack = ", ".join(meta.get("stack") or []) or "unknown"
    handoff = _read_doc(repo["path"], "handoff-simple") or _read_doc(repo["path"], "handoff") or ""
    audit = _read_doc(repo["path"], "audit-simple") or _read_doc(repo["path"], "audit") or ""

    # Pull MEDIUM/LOW/INFO findings for context
    medium_low = [l.strip() for l in audit.splitlines()
                  if any(f"[{s}]" in l for s in ("MEDIUM", "LOW", "INFO"))][:20]

    standards_path = Path.home() / "Documents" / "EDDIE_BUILD_STANDARDS.md"
    standards = standards_path.read_text(encoding="utf-8") if standards_path.exists() else ""

    prompt = f"""You are a senior software architect reviewing a codebase.

Repo: {name}
Stack: {stack}

Handoff notes:
{handoff[:3000]}

Medium/Low findings (not yet security-critical but worth addressing):
{chr(10).join(medium_low) if medium_low else 'None'}

Build standards in use:
{standards[:2000]}

Generate a structured improvement plan for this repo covering areas BEYOND security fixes.
Focus on concrete, actionable suggestions only. No generic advice.

Format as markdown with these sections:
## Performance
## Code Quality
## Architecture
## Developer Experience
## Testing Gaps
## Quick Wins (under 30 mins each)

Keep each suggestion to 1-2 sentences. Be specific to this repo's stack and context."""

    import urllib.request as _urllib
    body = json.dumps({
        "model": "anthropic/claude-sonnet-4-6",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1500,
    }).encode()
    req = _urllib.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urllib.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        content = data["choices"][0]["message"]["content"]
    except Exception as e:
        raise HTTPException(500, f"LLM error: {e}")

    out_path = Path(repo["path"]) / ".boswell" / "improvements.md"
    out_path.write_text(content, encoding="utf-8")
    return {"ok": True, "content": content}


@app.post("/api/repo/{name}/generate-optimal-prompt")
async def generate_optimal_prompt(name: str):
    """Generate a copy-paste ready Claude Code session prompt and cache in .boswell/."""
    import os as _os
    api_key = _os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "OPENROUTER_API_KEY not set")

    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    meta = repo.get("meta", {})
    stack = ", ".join(meta.get("stack") or []) or "unknown"
    handoff = _read_doc(repo["path"], "handoff-simple") or _read_doc(repo["path"], "handoff") or ""
    audit = _read_doc(repo["path"], "audit") or ""

    open_findings = [l.strip() for l in audit.splitlines()
                     if any(f"[{s}]" in l for s in ("CRITICAL", "HIGH"))][:15]

    from . import db as _db
    db_url = _db.get_url()
    resolved_descriptions = []
    if db_url:
        try:
            rows = _db.list_findings(db_url, repo_name=name)
            resolved_descriptions = [r.get("description", "") for r in rows if r.get("resolved")][:10]
        except Exception:
            pass

    standards_path = Path.home() / "Documents" / "EDDIE_BUILD_STANDARDS.md"
    standards_summary = ""
    if standards_path.exists():
        # Just grab the headers for brevity
        lines = standards_path.read_text(encoding="utf-8").splitlines()
        standards_summary = "\n".join(l for l in lines if l.startswith("#"))[:500]

    prompt = f"""Generate an optimal Claude Code session prompt for a developer about to work on this repo.

Repo: {name}
Stack: {stack}

What this repo does (from handoff):
{handoff[:1500]}

Already fixed — DO NOT re-address:
{chr(10).join(f'- {d}' for d in resolved_descriptions) if resolved_descriptions else '- Nothing tracked yet (Neon not connected)'}

Still open — must address (CRITICAL/HIGH):
{chr(10).join(open_findings) if open_findings else '- None found'}

Governance standards headers:
{standards_summary}

Generate a concise, copy-paste ready prompt (200-400 words) that:
1. Briefly explains what this codebase does and its stack
2. Lists what was already fixed (so Claude doesn't re-do it)
3. Prioritizes what needs fixing next with specific file/function context where known
4. States the key standards to enforce
5. Ends with: "Work through each issue methodically. Fix, test, commit."

Write the prompt in second person addressed to Claude. Make it specific, not generic."""

    import urllib.request as _urllib
    body = json.dumps({
        "model": "anthropic/claude-sonnet-4-6",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1000,
    }).encode()
    req = _urllib.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urllib.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        content = data["choices"][0]["message"]["content"]
    except Exception as e:
        raise HTTPException(500, f"LLM error: {e}")

    out_path = Path(repo["path"]) / ".boswell" / "optimal-prompt.md"
    out_path.write_text(content, encoding="utf-8")
    return {"ok": True, "content": content}


@app.post("/api/repo/{name}/import-findings")
def api_import_findings(name: str):
    """Parse audit.md and bulk-import all findings into Neon under a synthetic run."""
    from . import db as _db
    import json as _json
    db_url = _db.get_url()
    if not db_url:
        raise HTTPException(503, "BOSWELL_DATABASE_URL not set")
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    content = _read_doc(repo["path"], "audit")
    if not content:
        raise HTTPException(404, "audit.md not found")

    # Find or create an llm-audit synthetic run for this repo
    with _db._conn(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM boswell_runs WHERE repo_name=%s AND stack @> '[\"llm-audit\"]' ORDER BY run_at DESC LIMIT 1",
                (name,),
            )
            row = cur.fetchone()
            if row:
                run_id = row[0]
            else:
                meta = repo.get("meta", {})
                stack = (meta.get("stack") or []) + ["llm-audit"]
                cur.execute(
                    """INSERT INTO boswell_runs (repo_name, repo_path, cost_usd, stack, env_vars)
                       VALUES (%s,%s,%s,%s::jsonb,%s::jsonb) RETURNING id""",
                    (name, repo["path"], 0, _json.dumps(stack), _json.dumps([])),
                )
                run_id = cur.fetchone()[0]
        conn.commit()

    n = _db.import_audit_findings(db_url, run_id, content)
    return {"imported": n, "run_id": run_id}


@app.post("/api/import-all")
def api_import_all():
    """Bulk-import all repos that have audit.md in parallel. Returns per-repo results."""
    from . import db as _db
    import json as _json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    db_url = _db.get_url()
    if not db_url:
        raise HTTPException(503, "BOSWELL_DATABASE_URL not set")

    repos = _find_boswell_repos(_repos_root)

    def _import_one(repo: dict) -> dict:
        name = repo["name"]
        content = _read_doc(repo["path"], "audit")
        if not content:
            return {"name": name, "status": "no_audit_md"}
        try:
            with _db._conn(db_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id FROM boswell_runs WHERE repo_name=%s AND stack @> '[\"llm-audit\"]' ORDER BY run_at DESC LIMIT 1",
                        (name,),
                    )
                    row = cur.fetchone()
                    if row:
                        run_id = row[0]
                    else:
                        meta = repo.get("meta", {})
                        stack = (meta.get("stack") or []) + ["llm-audit"]
                        cur.execute(
                            """INSERT INTO boswell_runs (repo_name, repo_path, cost_usd, stack, env_vars)
                               VALUES (%s,%s,%s,%s::jsonb,%s::jsonb) RETURNING id""",
                            (name, repo["path"], 0, _json.dumps(stack), _json.dumps([])),
                        )
                        run_id = cur.fetchone()[0]
                conn.commit()
            n = _db.import_audit_findings(db_url, run_id, content)
            return {"name": name, "status": "ok", "imported": n}
        except Exception as e:
            return {"name": name, "status": "error", "error": str(e)[:200]}

    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_import_one, r): r["name"] for r in repos}
        for fut in as_completed(futures):
            results.append(fut.result())

    ok = [r for r in results if r["status"] == "ok"]
    skipped = [r for r in results if r["status"] == "no_audit_md"]
    errors = [r for r in results if r["status"] == "error"]
    total_findings = sum(r.get("imported", 0) for r in ok)

    return {
        "imported_repos": len(ok),
        "total_findings": total_findings,
        "skipped": len(skipped),
        "errors": errors,
    }


class FixSelectedRequest(BaseModel):
    finding_ids: list[int]


@app.post("/api/fix-selected")
def api_fix_selected(req: FixSelectedRequest):
    """Auto-fix selected findings using Claude via OpenRouter. Applies patches and commits."""
    import json as _json
    import re as _re
    import subprocess as _sp
    from . import db as _db

    db_url = _db.get_url()
    if not db_url:
        raise HTTPException(503, "BOSWELL_DATABASE_URL not set")

    or_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not or_key:
        raise HTTPException(503, "OPENROUTER_API_KEY not set")

    # Fetch findings from Neon
    with _db._conn(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT f.id, f.severity, f.category, f.description, f.location, r.repo_name, r.repo_path
                   FROM boswell_findings f
                   JOIN boswell_runs r ON r.id = f.run_id
                   WHERE f.id = ANY(%s) AND f.resolved = FALSE""",
                (req.finding_ids,),
            )
            rows = cur.fetchall()

    if not rows:
        return {"fixed_count": 0, "errors": ["No unresolved findings found for given IDs"]}

    # Group by repo
    by_repo: dict[str, dict] = {}
    for fid, sev, cat, desc, loc, repo_name, repo_path in rows:
        if repo_name not in by_repo:
            by_repo[repo_name] = {"path": repo_path, "findings": []}
        by_repo[repo_name]["findings"].append({
            "id": fid, "severity": sev, "category": cat or "Security",
            "description": desc, "location": loc or "",
        })

    fixed_ids: list[int] = []
    errors: list[str] = []

    for repo_name, data in by_repo.items():
        repo_path = data["path"]
        findings = data["findings"]

        # Read relevant source files (from location field, fall back to key files)
        file_contents: dict[str, str] = {}
        for f in findings:
            if f["location"]:
                # Extract file path from location (e.g. "app/api/auth/route.ts:42")
                fpath = f["location"].split(":")[0].strip()
                full = Path(repo_path) / fpath
                if full.exists() and full.stat().st_size < 50_000:
                    try:
                        file_contents[fpath] = full.read_text(errors="replace")
                    except Exception:
                        pass

        # Build prompt
        findings_text = "\n".join(
            f"{i+1}. [{f['severity']}] {f['category']}\n   {f['description']}"
            + (f"\n   Location: {f['location']}" if f['location'] else "")
            for i, f in enumerate(findings)
        )

        files_text = ""
        for fpath, content in file_contents.items():
            files_text += f"\n\n--- {fpath} ---\n{content}"

        system = (
            "You are a security engineer fixing code vulnerabilities. "
            "Return ONLY the fixed files in this exact format — nothing else:\n\n"
            "<fix path=\"relative/path/to/file\">\n"
            "complete fixed file content here\n"
            "</fix>\n\n"
            "One <fix> block per file changed. Do not add explanations outside the blocks."
        )
        user = (
            f"Fix these security findings in the {repo_name} repo:\n\n{findings_text}"
            + (f"\n\nRelevant source files:{files_text}" if files_text else "")
        )

        try:
            resp = httpx.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {or_key}", "Content-Type": "application/json"},
                json={
                    "model": "anthropic/claude-sonnet-4-6",
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "max_tokens": 8000,
                },
                timeout=120,
            )
            resp.raise_for_status()
            reply = resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            errors.append(f"{repo_name}: Claude call failed — {str(e)[:150]}")
            continue

        # Parse <fix path="...">...</fix> blocks
        patches = _re.findall(r'<fix\s+path="([^"]+)">(.*?)</fix>', reply, _re.DOTALL)
        if not patches:
            errors.append(f"{repo_name}: Claude returned no fix blocks")
            continue

        # Apply patches
        patched_files = []
        for rel_path, content in patches:
            full_path = contained_path(Path(repo_path), rel_path)
            if full_path is None:
                errors.append(f"{repo_name}: path escapes repo — {rel_path}")
                continue
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content.strip("\n"))
            patched_files.append(str(full_path.relative_to(Path(repo_path).resolve())))

        if not patched_files:
            errors.append(f"{repo_name}: no files written")
            continue

        # Git commit
        try:
            _sp.run(["git", "add"] + patched_files, cwd=repo_path, capture_output=True, timeout=15)
            msg = f"fix: resolve {len(findings)} Boswell finding(s)\n\nFixed by Boswell auto-fix"
            result = _sp.run(
                ["git", "commit", "-m", msg],
                cwd=repo_path, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0 and "nothing to commit" not in result.stdout:
                errors.append(f"{repo_name}: git commit failed — {result.stderr[:100]}")
                continue
        except Exception as e:
            errors.append(f"{repo_name}: git error — {str(e)[:100]}")
            continue

        # Mark findings resolved in Neon
        with _db._conn(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE boswell_findings SET resolved=TRUE, resolved_at=NOW() WHERE id = ANY(%s)",
                    ([f["id"] for f in findings],),
                )
            conn.commit()
        fixed_ids.extend(f["id"] for f in findings)

    return {"fixed_count": len(fixed_ids), "fixed_ids": fixed_ids, "errors": errors}


@app.post("/api/findings/{finding_id}/resolve")
def api_resolve_finding(finding_id: int):
    """Mark a single finding resolved in Neon."""
    from . import db as _db
    db_url = _db.get_url()
    if not db_url:
        raise HTTPException(503, "BOSWELL_DATABASE_URL not set")
    _db.mark_resolved(db_url, finding_id)
    return {"ok": True, "id": finding_id}


@app.post("/api/findings/{finding_id}/reopen")
def api_reopen_finding(finding_id: int):
    """Reopen a resolved finding."""
    from . import db as _db
    db_url = _db.get_url()
    if not db_url:
        raise HTTPException(503, "BOSWELL_DATABASE_URL not set")
    with _db._conn(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE boswell_findings SET resolved=FALSE, resolved_at=NULL WHERE id=%s",
                (finding_id,),
            )
        conn.commit()
    return {"ok": True, "id": finding_id}


@app.get("/api/repo/{name}/neon-findings")
def api_neon_findings(name: str):
    """Return all Neon-stored findings for a repo (with IDs for resolve actions)."""
    from . import db as _db
    db_url = _db.get_url()
    if not db_url:
        return []
    try:
        return _db.list_findings(db_url, repo_name=name)
    except Exception:
        return []


@app.get("/api/fixes")
def api_fixes():
    """Return all resolved findings from Neon."""
    from . import db as _db
    db_url = _db.get_url()
    if not db_url:
        return []
    try:
        rows = _db.list_findings(db_url)
        rows = [r for r in rows if r.get("resolved")]
        return rows
    except Exception:
        return []


@app.get("/api/standards")
def api_standards():
    """Return the EDDIE_BUILD_STANDARDS.md content."""
    candidates = [
        Path.home() / "Documents" / "EDDIE_BUILD_STANDARDS.md",
        Path.home() / "EDDIE_BUILD_STANDARDS.md",
        _repos_root / "EDDIE_BUILD_STANDARDS.md",
    ]
    for p in candidates:
        if p.exists():
            return {"content": p.read_text(encoding="utf-8"), "path": str(p)}
    return {"content": "", "path": ""}


@app.post("/api/leaks/scan/{repo}")
def api_live_leak_scan(repo: str):
    """Run a fresh leak scan on a repo right now (no LLM)."""
    repos = _find_boswell_repos(_repos_root)
    r = next((x for x in repos if x["name"] == repo), None)
    if not r:
        raise HTTPException(404, "Repo not found")
    from .secret_check import full_leak_scan
    findings = full_leak_scan(Path(r["path"]))
    return [
        {"severity": f.severity, "category": f.category,
         "description": f.description, "location": f.location, "fix": f.fix}
        for f in findings
    ]


@app.post("/api/repo/{name}/fix-code")
async def fix_repo_endpoint(name: str):
    """Run LLM-powered security fixes. Ships to main if all fixed, disables deployment if not."""
    import os as _os
    from .fix_code import fix_repo as _fix_repo

    api_key = _os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "OPENROUTER_API_KEY not set")

    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    from . import db as _db
    db_url = _db.get_url()

    result = _fix_repo(
        repo_path=Path(repo["path"]),
        api_key=api_key,
        db_url=db_url,
        ship=True,
    )

    if "error" in result:
        raise HTTPException(400, result["error"])

    status = result.get("status", "fix_only")
    branch = result.get("branch")

    if status == "shipped":
        alert = "✅ Fixed and shipped to main"
    elif status == "disabled":
        alert = f"⚠ Could not fully fix — app taken offline. Branch {branch} has partial fixes."
    elif branch:
        alert = f"Branch {branch} created — review before merging."
    else:
        note = result.get("note", "")
        alert = f"⚠ No patchable files found — findings may be history-only leaks requiring manual rotation. {note}".strip()

    return {
        "ok": True,
        "status": status,
        "fixed": result["fixed"],
        "skipped": result["skipped"],
        "branch": branch,
        "changes": result.get("changes", []),
        "alert": alert,
    }


@app.post("/api/run/{name}")
def api_run_repo(name: str):
    """Trigger a full Boswell audit on a repo (background process)."""
    import subprocess
    repos = _find_boswell_repos(_repos_root)
    r = next((x for x in repos if x["name"] == name), None)
    if not r:
        raise HTTPException(404, "Repo not found")
    subprocess.Popen(
        ["boswell", "run", r["path"], "--skip-confirm"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return {"ok": True, "repo": name, "path": r["path"]}


@app.post("/api/run-all")
def api_run_all(request: Request):
    """Trigger a full Boswell audit on deployed repos only (unless ?all=1)."""
    import subprocess
    all_repos = str(request.query_params.get("all", "0")) == "1"
    repos = _find_boswell_repos(_repos_root)
    triggered = []
    skipped_undeployed = []
    for r in repos:
        deployed_url = (r.get("meta") or {}).get("deployed_url", "")
        if not all_repos and not deployed_url:
            skipped_undeployed.append(r["name"])
            continue
        subprocess.Popen(
            ["boswell", "run", r["path"], "--skip-confirm"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        triggered.append(r["name"])
    return {"ok": True, "triggered": triggered, "skipped_undeployed": skipped_undeployed}


@app.post("/api/repo/{name}/set-deployed-url")
async def api_set_deployed_url(name: str, request: Request):
    """Set the deployed_url for a repo in both local metadata.json and Neon."""
    body = await request.json()
    url_value = body.get("url", "").strip()
    if url_value:
        try:
            assert_public_http_url(url_value)
        except ValueError:
            raise HTTPException(400, "Deployed URL must be a public http or https address")
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")
    # Write to local metadata.json
    meta_path = Path(repo["path"]) / ".boswell" / "metadata.json"
    try:
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        meta["deployed_url"] = url_value
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception as exc:
        raise HTTPException(500, f"Could not update metadata.json: {exc}")
    # Best-effort write to Neon
    try:
        from . import db as _db
        db_url = _db.get_url()
        if db_url:
            _db.upsert_repo_meta(db_url, repo_name=name, deployed_url=url_value)
    except Exception:
        pass
    return {"ok": True, "repo": name, "deployed_url": url_value}


@app.get("/api/vault/status")
def vault_status():
    return {
        "exists": v.vault_exists(),
        "unlocked": v.is_unlocked(),
    }


@app.post("/api/vault/create")
async def vault_create(request: Request):
    body = await request.json()
    password = body.get("password", "")
    if not password or len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if v.vault_exists():
        raise HTTPException(400, "Vault already exists — use /unlock")
    v.create_vault(password)
    return {"ok": True}


@app.post("/api/vault/unlock")
async def vault_unlock(request: Request):
    if unlock_blocked():
        raise HTTPException(429, "Too many unlock attempts. Wait and try again.")
    body = await request.json()
    password = body.get("password", "")
    ok = v.unlock_vault(password)
    if not ok:
        record_unlock_failure()
        raise HTTPException(401, "Wrong password")
    clear_unlock_failures()
    return {"ok": True}


@app.post("/api/vault/lock")
def vault_lock():
    v.lock_vault()
    return {"ok": True}


@app.get("/api/vault/secrets")
def vault_secrets():
    if not v.is_unlocked():
        raise HTTPException(403, "Vault is locked")
    return v.all_secrets_masked()


@app.post("/api/vault/secret/{repo}/{key}")
async def vault_get_secret(repo: str, key: str, request: Request):
    """Return one secret only after the master password is checked again."""
    if unlock_blocked():
        raise HTTPException(429, "Too many unlock attempts. Wait and try again.")
    body = await request.json()
    password = body.get("password", "")
    data = v.open_vault(password)
    if data is None:
        record_unlock_failure()
        raise HTTPException(401, "Wrong password")
    clear_unlock_failures()
    entry = data.get(repo, {}).get(key)
    if not entry:
        raise HTTPException(404, "Secret not found")
    return {"value": entry["value"]}


@app.post("/api/vault/ingest/{repo}")
def vault_ingest(repo: str):
    """Read .env files from repo and store actual values in vault."""
    if not v.is_unlocked():
        raise HTTPException(403, "Vault is locked")
    repos = _find_boswell_repos(_repos_root)
    r = next((x for x in repos if x["name"] == repo), None)
    if not r:
        raise HTTPException(404, "Repo not found")
    from .scanner import extract_secret_values
    secrets = extract_secret_values(Path(r["path"]))
    if secrets:
        v.store_repo_secrets(repo, secrets)
    return {"stored": len(secrets), "keys": list(secrets.keys())}


@app.delete("/api/vault/repo/{repo}")
def vault_delete_repo(repo: str):
    if not v.is_unlocked():
        raise HTTPException(403, "Vault is locked")
    v.delete_repo_secrets(repo)
    return {"ok": True}


# ── Deployment disable / enable ──────────────────────────────────────────────

def _detect_platform(repo_path: Path) -> tuple[str, str]:
    """Returns (platform, project_name). platform is 'vercel', 'cloudflare', or 'unknown'."""
    # Cloudflare: look for wrangler.toml up to 3 levels deep
    for wt in list(repo_path.rglob("wrangler.toml"))[:1]:
        import tomllib
        try:
            data = tomllib.loads(wt.read_text())
            name = data.get("name") or repo_path.name
            return "cloudflare", name
        except Exception:
            return "cloudflare", repo_path.name
    # Vercel: look for vercel.json or .vercel/project.json
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


async def _vercel_set_paused(project_id: str, paused: bool) -> dict:
    import urllib.request
    token = os.environ.get("VERCEL_TOKEN", "")
    if not token:
        return {"error": "VERCEL_TOKEN not set"}
    body = json.dumps({"paused": paused}).encode()
    req = urllib.request.Request(
        f"https://api.vercel.com/v9/projects/{project_id}",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


async def _cf_set_paused(project_name: str, paused: bool) -> dict:
    import urllib.request
    token = os.environ.get("CF_API_TOKEN", "")
    account = os.environ.get("CF_ACCOUNT_ID", "")
    if not token or not account:
        return {"error": "CF_API_TOKEN and CF_ACCOUNT_ID not set"}
    # Cloudflare Pages: update deployment_configs to disable/enable production deployments
    body = json.dumps({
        "deployment_configs": {
            "production": {"deployments_enabled": not paused},
            "preview": {"deployments_enabled": not paused},
        }
    }).encode()
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project_name}",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/repo/{name}/disable")
async def disable_repo_deployment(name: str):
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")
    path = Path(repo["path"])
    platform, project_id = _detect_platform(path)
    if platform == "vercel":
        result = await _vercel_set_paused(project_id, True)
    elif platform == "cloudflare":
        result = await _cf_set_paused(project_id, True)
    else:
        return JSONResponse({"error": f"Unknown platform for {name} — add vercel.json or wrangler.toml"}, 400)
    if "error" in result:
        return JSONResponse({"error": result["error"]}, 500)
    return {"ok": True, "platform": platform, "project": project_id, "status": "disabled"}


@app.post("/api/repo/{name}/enable")
async def enable_repo_deployment(name: str):
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")
    path = Path(repo["path"])
    platform, project_id = _detect_platform(path)
    if platform == "vercel":
        result = await _vercel_set_paused(project_id, False)
    elif platform == "cloudflare":
        result = await _cf_set_paused(project_id, False)
    else:
        return JSONResponse({"error": f"Unknown platform for {name}"}, 400)
    if "error" in result:
        return JSONResponse({"error": result["error"]}, 500)
    return {"ok": True, "platform": platform, "project": project_id, "status": "enabled"}


def _find_cron_jobs(repo_path: Path) -> list[dict]:
    """Parse vercel.json, wrangler.toml, and source for cron/scheduler definitions."""
    jobs = []

    # vercel.json crons
    vj = repo_path / "vercel.json"
    if vj.exists():
        try:
            data = json.loads(vj.read_text())
            for c in data.get("crons", []):
                jobs.append({"source": "vercel.json", "schedule": c.get("schedule"), "path": c.get("path")})
        except Exception:
            pass

    # wrangler.toml [triggers]
    for wt in list(repo_path.rglob("wrangler.toml"))[:1]:
        try:
            import tomllib
            data = tomllib.loads(wt.read_text())
            for cron in data.get("triggers", {}).get("crons", []):
                jobs.append({"source": "wrangler.toml", "schedule": cron, "path": None})
        except Exception:
            pass

    # package.json scripts with "cron" in them
    pj = repo_path / "package.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text())
            for name, cmd in data.get("scripts", {}).items():
                if "cron" in name.lower() or "scheduler" in name.lower() or "worker" in name.lower():
                    jobs.append({"source": f"package.json#scripts.{name}", "schedule": "manual/custom", "path": cmd})
        except Exception:
            pass

    # grep source for common patterns
    for pattern in ["setInterval", "cron(", "schedule(", "pg-boss", "BullMQ", "node-cron"]:
        result = subprocess.run(
            ["grep", "-r", "--include=*.ts", "--include=*.js", "-l", pattern, str(repo_path)],
            capture_output=True, text=True,
        )
        for f in result.stdout.strip().splitlines()[:3]:
            rel = os.path.relpath(f, repo_path)
            if "node_modules" not in rel:
                jobs.append({"source": rel, "schedule": pattern, "path": None})

    # deduplicate by source+schedule
    seen = set()
    unique = []
    for j in jobs:
        key = (j["source"], j["schedule"])
        if key not in seen:
            seen.add(key)
            unique.append(j)
    return unique


async def _vercel_recent_executions(project_id: str) -> list[dict]:
    """Try to get recent cron/function executions from Vercel runtime logs."""
    token = os.environ.get("VERCEL_TOKEN", "")
    if not token:
        return []
    import urllib.request, urllib.error
    # Get latest deployment
    req = urllib.request.Request(
        f"https://api.vercel.com/v9/projects/{project_id}/deployments?limit=1&target=production",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        deployments = data.get("deployments", [])
        if not deployments:
            return []
        dep_id = deployments[0]["uid"]
        # Get function execution events
        req2 = urllib.request.Request(
            f"https://api.vercel.com/v2/deployments/{dep_id}/events?limit=50",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req2, timeout=10) as r:
            events = json.loads(r.read())
        cron_events = [e for e in (events if isinstance(events, list) else [])
                       if "cron" in str(e).lower() or "schedule" in str(e).lower()]
        return cron_events[:5]
    except Exception:
        return []


@app.get("/api/repo/{name}/job-health")
async def repo_job_health(name: str):
    """Assess whether background/cron jobs are defined and have evidence of execution."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    path = Path(repo["path"])
    platform, project_id = _detect_platform(path)
    jobs = _find_cron_jobs(path)
    recent = []

    if platform == "vercel" and jobs:
        recent = await _vercel_recent_executions(project_id)

    has_token = bool(os.environ.get("VERCEL_TOKEN") or os.environ.get("CF_API_TOKEN"))

    return {
        "name": name,
        "platform": platform,
        "jobs_defined": jobs,
        "jobs_found": len(jobs),
        "recent_executions": recent,
        "execution_evidence": len(recent) > 0,
        "note": (
            "No cron/background jobs found in this repo."
            if not jobs else
            f"Found {len(jobs)} job definition(s). " + (
                f"{len(recent)} recent execution event(s) found in Vercel logs."
                if recent else
                ("No runtime logs available — add VERCEL_TOKEN or CF_API_TOKEN to ~/.boswell/.env for live verification."
                 if not has_token else
                 "No recent execution evidence found in logs — jobs may not be running.")
            )
        ),
    }


@app.get("/api/repo/{name}/entropy")
async def repo_entropy(name: str, snapshot: bool = False):
    """Compute entropy score for a repo. Pass ?snapshot=true to persist to Neon."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    from .entropy import compute_entropy, save_snapshot
    from .constitution import constitution_penalty
    meta = repo.get("meta", {})
    leak_findings = meta.get("leak_findings", [])
    result = compute_entropy(Path(repo["path"]), leak_findings)

    # Blend in constitution violations (weight 0.15, replaces nothing — additive penalty capped)
    try:
        const_score = constitution_penalty(Path(repo["path"]))
        result["constitution_score"] = const_score
        # Add up to 10 points to overall entropy from constitution violations
        bonus = min(10, int(const_score * 0.10))
        result["overall_entropy"] = min(100, result["overall_entropy"] + bonus)
        from .entropy import _label as _ent_label
        result["label"] = _ent_label(result["overall_entropy"])
    except Exception:
        result["constitution_score"] = 0

    if snapshot:
        from . import db as _db
        db_url = _db.get_url()
        if db_url:
            try:
                save_snapshot(db_url, name, result)
            except Exception:
                pass

    return result


@app.get("/api/repo/{name}/entropy/history")
def repo_entropy_history(name: str):
    """Return entropy snapshot history from Neon."""
    from . import db as _db
    from .entropy import load_history
    db_url = _db.get_url()
    if not db_url:
        return []
    try:
        return load_history(db_url, name)
    except Exception:
        return []


@app.get("/api/briefing")
def api_briefing():
    """
    Weekly portfolio briefing:
    - Repos whose entropy degraded since last scan
    - Repos with CRITICAL findings
    - Repos never scanned or stale (30+ days)
    - Smart-scan candidates (new commits since last scan)
    - Total portfolio audit cost estimate
    """
    import subprocess
    from datetime import datetime, timezone, timedelta
    from .entropy import compute_entropy, load_history
    from . import db as _db

    db_url = _db.get_url()
    repos = _find_boswell_repos(_repos_root)
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=30)

    degraded = []
    critical_repos = []
    never_scanned = []
    stale = []
    smart_scan_candidates = []
    total_cost = 0.0

    for r in repos:
        meta = r.get("meta", {}) or {}
        name = r["name"]
        path = Path(r["path"])
        run_at_str = meta.get("run_at")
        files_scanned = meta.get("files_scanned") or 50
        total_cost += files_scanned * 0.002

        # Never scanned
        if not run_at_str:
            never_scanned.append(name)
        else:
            try:
                run_at = datetime.fromisoformat(run_at_str.replace("Z", "+00:00"))
                if run_at.tzinfo is None:
                    run_at = run_at.replace(tzinfo=timezone.utc)
                if run_at < stale_cutoff:
                    stale.append({"name": name, "last_scan": run_at_str})
            except Exception:
                pass

        # CRITICAL findings
        leaks = meta.get("leak_findings") or []
        crit = [f for f in leaks if f.get("severity") == "CRITICAL"]
        if crit:
            critical_repos.append({"name": name, "count": len(crit)})

        # Entropy degraded (compare last two Neon snapshots)
        if db_url:
            try:
                history = load_history(db_url, name, limit=2)
                if len(history) >= 2:
                    latest = history[0]["entropy_score"]
                    prev = history[1]["entropy_score"]
                    delta = int(latest) - int(prev)
                    if delta >= 5:
                        degraded.append({"name": name, "delta": delta, "current": latest, "prev": prev})
            except Exception:
                pass

        # Smart scan: has new commits since last scan?
        if path.exists() and (path / ".git").exists():
            try:
                last_commit_raw = subprocess.run(
                    ["git", "log", "-1", "--format=%cI"],
                    cwd=path, capture_output=True, text=True, timeout=5
                ).stdout.strip()
                if last_commit_raw:
                    last_commit = datetime.fromisoformat(last_commit_raw.replace("Z", "+00:00"))
                    if last_commit.tzinfo is None:
                        last_commit = last_commit.replace(tzinfo=timezone.utc)
                    if run_at_str:
                        try:
                            run_at = datetime.fromisoformat(run_at_str.replace("Z", "+00:00"))
                            if run_at.tzinfo is None:
                                run_at = run_at.replace(tzinfo=timezone.utc)
                            if last_commit > run_at:
                                smart_scan_candidates.append({
                                    "name": name,
                                    "last_commit": last_commit_raw,
                                    "last_scan": run_at_str,
                                    "estimated_cost": round(files_scanned * 0.002, 2),
                                })
                        except Exception:
                            pass
                    else:
                        smart_scan_candidates.append({
                            "name": name,
                            "last_commit": last_commit_raw,
                            "last_scan": None,
                            "estimated_cost": round(files_scanned * 0.002, 2),
                        })
            except Exception:
                pass

    return {
        "generated_at": now.isoformat(),
        "total_repos": len(repos),
        "degraded": sorted(degraded, key=lambda x: -x["delta"]),
        "critical_repos": sorted(critical_repos, key=lambda x: -x["count"]),
        "never_scanned": never_scanned,
        "stale": stale,
        "smart_scan_candidates": smart_scan_candidates,
        "full_portfolio_cost": round(total_cost, 2),
        "smart_scan_cost": round(sum(c["estimated_cost"] for c in smart_scan_candidates), 2),
    }


@app.post("/api/smart-scan")
async def api_smart_scan():
    """
    Trigger audits only for repos with new commits since their last scan.
    This is the weekly scan — cost-efficient because unchanged repos are skipped.
    """
    import subprocess
    from datetime import datetime, timezone

    repos = _find_boswell_repos(_repos_root)
    triggered = []
    skipped = []

    for r in repos:
        meta = r.get("meta", {}) or {}
        # Only smart-scan deployed apps unless specifically overridden
        if not meta.get("deployed_url", ""):
            skipped.append({"name": r["name"], "reason": "not deployed"})
            continue

        path = Path(r["path"])
        run_at_str = meta.get("run_at")

        needs_scan = False
        if not run_at_str:
            needs_scan = True
        elif path.exists() and (path / ".git").exists():
            try:
                last_commit_raw = subprocess.run(
                    ["git", "log", "-1", "--format=%cI"],
                    cwd=path, capture_output=True, text=True, timeout=5
                ).stdout.strip()
                if last_commit_raw:
                    last_commit = datetime.fromisoformat(last_commit_raw.replace("Z", "+00:00"))
                    run_at = datetime.fromisoformat(run_at_str.replace("Z", "+00:00"))
                    if last_commit.tzinfo is None:
                        last_commit = last_commit.replace(tzinfo=__import__("datetime").timezone.utc)
                    if run_at.tzinfo is None:
                        run_at = run_at.replace(tzinfo=__import__("datetime").timezone.utc)
                    if last_commit > run_at:
                        needs_scan = True
            except Exception:
                needs_scan = True

        if needs_scan:
            try:
                subprocess.Popen(
                    ["boswell", "run", r["path"], "--skip-confirm"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                triggered.append(r["name"])
            except Exception as e:
                skipped.append({"name": r["name"], "error": str(e)})
        else:
            skipped.append({"name": r["name"], "reason": "no new commits"})

    return {"triggered": triggered, "skipped": skipped, "total_triggered": len(triggered)}


@app.post("/api/entropy/snapshot-all")
async def entropy_snapshot_all():
    """Compute and snapshot entropy for every known repo."""
    from .entropy import compute_entropy, save_snapshot
    from . import db as _db
    db_url = _db.get_url()
    repos = _find_boswell_repos(_repos_root)
    results = []
    for r in repos:
        try:
            meta = r.get("meta", {})
            result = compute_entropy(Path(r["path"]), meta.get("leak_findings", []))
            if db_url:
                save_snapshot(db_url, r["name"], result)
            results.append({"name": r["name"], "entropy": result["overall_entropy"], "label": result["label"]})
        except Exception as e:
            results.append({"name": r["name"], "error": str(e)})
    return sorted(results, key=lambda x: -(x.get("entropy") or 0))


@app.post("/api/portfolio/assess")
async def portfolio_assess():
    """Generate portfolio-level assessment: shutdown/merge candidates + developer profile."""
    import os as _os
    api_key = _os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "OPENROUTER_API_KEY not set")

    repos = _find_boswell_repos(_repos_root)
    if not repos:
        raise HTTPException(404, "No repos found")

    # Build repo summaries
    repo_summaries = []
    for r in repos:
        meta = r.get("meta", {})
        findings = meta.get("leak_findings", [])
        crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        stack = ", ".join(meta.get("stack") or []) or "unknown"
        run_at = meta.get("run_at", "unknown")
        repo_summaries.append(f"- {r['name']}: stack={stack}, CRITICAL={crit}, HIGH={high}, last_scan={run_at}")

    # Gather all findings patterns across repos
    all_categories: dict[str, int] = {}
    all_finding_descriptions = []
    for r in repos:
        meta = r.get("meta", {})
        for f in meta.get("leak_findings", []):
            cat = f.get("category", "unknown")
            all_categories[cat] = all_categories.get(cat, 0) + 1
            if f.get("severity") in ("CRITICAL", "HIGH"):
                all_finding_descriptions.append(f"[{r['name']}] {f.get('severity')} {f.get('category')}: {f.get('description','')[:100]}")

    category_summary = "\n".join(f"  {k}: {v} occurrences" for k, v in sorted(all_categories.items(), key=lambda x: -x[1]))
    findings_sample = "\n".join(all_finding_descriptions[:30])

    standards_path = Path.home() / "Documents" / "EDDIE_BUILD_STANDARDS.md"
    standards = standards_path.read_text(encoding="utf-8")[:2000] if standards_path.exists() else ""

    prompt = f"""You are a senior engineering advisor doing a portfolio review of a solo developer's deployed applications.

Here are all {len(repos)} repos with their security findings:

{chr(10).join(repo_summaries)}

Finding patterns across the portfolio (category: count):
{category_summary}

Sample of CRITICAL/HIGH findings:
{findings_sample}

Developer's stated build standards:
{standards[:1500]}

Produce a JSON response with exactly this structure:
{{
  "shutdown_candidates": [
    {{"name": "repo-name", "reason": "1-2 sentence specific reason", "confidence": "high|medium|low"}}
  ],
  "merge_candidates": [
    {{"repos": ["repo-a", "repo-b"], "reason": "1-2 sentence specific reason", "combined_name": "suggested-name"}}
  ],
  "developer_assessment": {{
    "summary": "2-3 sentence honest overall assessment of this developer's patterns",
    "strengths": ["specific strength 1", "specific strength 2", "specific strength 3"],
    "recurring_mistakes": ["specific mistake 1", "specific mistake 2", "specific mistake 3"],
    "learn_next": ["specific thing to learn 1", "specific thing to learn 2", "specific thing to learn 3"],
    "vibe_score": 1-10,
    "vibe_label": "one punchy label like 'Prolific but scattered' or 'Security-naive builder'"
  }}
}}

Rules:
- Only recommend shutdown if the repo is clearly abandoned, redundant, or dangerously broken with no path forward
- Only recommend merge if repos have genuine overlap in purpose AND stack compatibility
- The developer assessment must be brutally honest, specific to what you see in the data, not generic advice
- Respond with valid JSON only, no markdown fences"""

    import urllib.request as _urllib
    body = json.dumps({
        "model": "google/gemini-2.5-flash",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},
    }).encode()
    req = _urllib.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urllib.urlopen(req, timeout=90) as r:
            data = json.loads(r.read())
        content = data["choices"][0]["message"]["content"]
        result = json.loads(content)
    except Exception as e:
        raise HTTPException(500, f"LLM error: {e}")

    # Cache result
    cache_path = Path.home() / ".boswell" / "portfolio-assessment.json"
    cache_path.parent.mkdir(exist_ok=True)
    cache_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result


@app.get("/api/portfolio/assess")
def portfolio_assess_cached():
    """Return cached portfolio assessment."""
    cache_path = Path.home() / ".boswell" / "portfolio-assessment.json"
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text())
    except Exception:
        return {}


@app.get("/api/repo/{name}/ship-check")
async def repo_ship_check(name: str):
    """Run Ship Readiness checks — live ping, deployment health, env vars, auth, security."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    path = Path(repo["path"])
    platform, project_id = _detect_platform(path)

    from .ship_check import run_ship_checks
    checks = run_ship_checks(path, platform=platform, project_id=project_id)

    passed = sum(1 for c in checks if c["status"] == "pass")
    failed = sum(1 for c in checks if c["status"] == "fail")
    warned = sum(1 for c in checks if c["status"] == "warn")

    if failed > 0:
        overall = "fail"
    elif warned > 0:
        overall = "warn"
    else:
        overall = "pass"

    return {
        "name": name,
        "platform": platform,
        "overall": overall,
        "passed": passed,
        "failed": failed,
        "warned": warned,
        "checks": checks,
    }


# ── GitHub Sync endpoints ────────────────────────────────────────────────────

@app.get("/api/github/status")
async def github_status():
    """Check GitHub connection and show which repos are missing locally."""
    from .github_sync import get_credentials, get_sync_status
    token, username = get_credentials()
    if not token or not username:
        return {
            "connected": False,
            "error": "Set GITHUB_TOKEN and GITHUB_USERNAME in ~/.boswell/.env",
        }
    try:
        status = get_sync_status(_repos_root, token, username)
        status["connected"] = True
        return status
    except Exception as e:
        return {"connected": False, "error": str(e)}


@app.post("/api/github/sync")
async def github_sync_all():
    """Clone all repos from GitHub that aren't already present locally."""
    from .github_sync import get_credentials, get_sync_status, clone_repos
    token, username = get_credentials()
    if not token or not username:
        raise HTTPException(400, "Set GITHUB_TOKEN and GITHUB_USERNAME in ~/.boswell/.env")

    status = get_sync_status(_repos_root, token, username)
    if "error" in status:
        raise HTTPException(500, status["error"])

    missing = status.get("missing", [])
    if not missing:
        return {"cloned": [], "failed": [], "message": "Already up to date."}

    result = clone_repos(_repos_root, missing)
    return {
        "cloned": result["cloned"],
        "failed": result["failed"],
        "message": f"Cloned {len(result['cloned'])} repo(s). {len(result['failed'])} failed.",
    }


@app.post("/api/github/sync-one")
async def github_sync_one(request: Request):
    """Clone a single repo by name."""
    from .github_sync import get_credentials, get_sync_status, clone_repos
    body = await request.json()
    name = body.get("name")
    if not name:
        raise HTTPException(400, "Missing name")

    token, username = get_credentials()
    if not token or not username:
        raise HTTPException(400, "Set GITHUB_TOKEN and GITHUB_USERNAME in ~/.boswell/.env")

    status = get_sync_status(_repos_root, token, username)
    repo = next((r for r in status.get("missing", []) if r["name"] == name), None)
    if not repo:
        return {"cloned": [], "failed": [], "message": f"{name} already present or not found on GitHub."}

    result = clone_repos(_repos_root, [repo])
    return result


# ── AI Slop Detection endpoints ─────────────────────────────────────────────

@app.get("/api/repo/{name}/slop")
async def repo_slop(name: str):
    """Detect AI slop patterns in a repo."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    from .slop import compute_slop
    return compute_slop(Path(repo["path"]))


@app.post("/api/repo/{name}/slop/diagnose")
async def repo_slop_diagnose(name: str):
    """Generate an LLM diagnosis of slop findings."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(500, "OPENROUTER_API_KEY not set")

    from .slop import compute_slop
    result = compute_slop(Path(repo["path"]))

    prompt = f"""You are a brutally honest senior engineer reviewing AI-generated code slop.

Repo: {name}
Slop Score: {result['slop_score']}/100 ({result['label']})

Findings:
- Utility sprawl: {result['utility_sprawl']['verdict']}
- Single-call wrappers: {result['single_call_wrappers']['verdict']}
- Duplicate helpers: {result['duplicate_helpers']['verdict']}
- Cargo-cult patterns: {result['cargo_cult']['verdict']}
- Re-export chains: {result['reexport_chains']['verdict']}
- Generic types: {result['generic_types']['verdict']}

Write 3-4 sentences. Be specific and punchy. Name the worst pattern. Explain what it means for the codebase's future. Do not hedge. Do not be polite. Sound like a senior engineer who has seen this before."""

    import httpx
    resp = httpx.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": "anthropic/claude-sonnet-4-6",
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=30,
    )
    resp.raise_for_status()
    diagnosis = resp.json()["choices"][0]["message"]["content"].strip()

    return {"diagnosis": diagnosis, "slop_score": result["slop_score"], "label": result["label"]}


# ── Constitution endpoints ───────────────────────────────────────────────────

@app.get("/api/repo/{name}/constitution")
async def repo_get_constitution(name: str):
    """Return the constitution YAML and last check results."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    path = Path(repo["path"])
    from .constitution import load_constitution, RULE_DEFINITIONS, check_constitution
    constitution = load_constitution(path)
    result = check_constitution(path)

    # Attach rule metadata for the UI
    for rs in result["rule_summaries"]:
        rs["meta"] = RULE_DEFINITIONS.get(rs["rule"], {})

    return {
        "name": name,
        "constitution": constitution,
        "check": result,
        "rule_definitions": RULE_DEFINITIONS,
    }


@app.put("/api/repo/{name}/constitution")
async def repo_put_constitution(name: str, request: Request):
    """Save updated constitution YAML for a repo."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    body = await request.json()
    constitution = body.get("constitution")
    if not constitution:
        raise HTTPException(400, "Missing constitution payload")

    path = Path(repo["path"])
    from .constitution import save_constitution
    save_constitution(path, constitution)
    return {"ok": True}


@app.post("/api/repo/{name}/constitution/check")
async def repo_constitution_check(name: str):
    """Re-run constitution checks and return fresh results."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    path = Path(repo["path"])
    from .constitution import check_constitution, RULE_DEFINITIONS
    result = check_constitution(path)

    for rs in result["rule_summaries"]:
        rs["meta"] = RULE_DEFINITIONS.get(rs["rule"], {})

    return {"name": name, "check": result}


@app.post("/api/repo/{name}/constitution/generate")
async def repo_constitution_generate(name: str):
    """Use Claude to generate a tailored constitution YAML based on the repo's audit."""
    repos = _find_boswell_repos(_repos_root)
    repo = next((r for r in repos if r["name"] == name), None)
    if not repo:
        raise HTTPException(404, "Repo not found")

    path = Path(repo["path"])
    boswell_dir = path / ".boswell"

    # Gather context
    audit_text = ""
    for doc in ("audit.md", "audit-simple.md"):
        p = boswell_dir / doc
        if p.exists():
            audit_text = p.read_text(errors="replace")[:3000]
            break

    meta = {}
    meta_path = boswell_dir / "metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            pass

    from .constitution import default_constitution, save_constitution
    default = default_constitution()

    prompt = f"""You are a senior software architect. Based on the repository audit below, generate a tailored constitution for this repo's governance rules.

Repository: {name}
Stack: {meta.get('stack', 'unknown')}
Audit summary (first 3000 chars):
{audit_text or '[no audit found]'}

The constitution is a YAML document. Return ONLY valid YAML — no markdown fences, no explanation.
Use this exact structure, adjusting 'enabled' and 'severity' based on what matters for this specific repo:

{chr(10).join([
    f"{rule_id}:" + chr(10) +
    f"  enabled: {'true' if rule_id in ('no_supabase','has_gitignore_env','parameterized_queries') else 'false'}" + chr(10) +
    f"  severity: {defn['default_severity']}"
    + (chr(10) + f"  limit: 300" if defn.get('param') == 'limit' else '')
    for rule_id, defn in [
        ('typescript_strict', {'default_severity': 'HIGH'}),
        ('edge_runtime', {'default_severity': 'HIGH'}),
        ('no_supabase', {'default_severity': 'CRITICAL'}),
        ('neon_only', {'default_severity': 'HIGH'}),
        ('custom_jwt_auth', {'default_severity': 'HIGH'}),
        ('max_file_lines', {'default_severity': 'MEDIUM', 'param': 'limit'}),
        ('no_console_log', {'default_severity': 'LOW'}),
        ('no_env_fallback', {'default_severity': 'HIGH'}),
        ('has_gitignore_env', {'default_severity': 'CRITICAL'}),
        ('no_inline_styles', {'default_severity': 'LOW'}),
        ('parameterized_queries', {'default_severity': 'CRITICAL'}),
    ]
])}

Wrap everything under a top-level 'rules:' key with 'version: 1' at the top.
Enable edge_runtime only if the repo is a Next.js/Cloudflare Pages app.
Enable neon_only and custom_jwt_auth only if the repo has a database or auth layer.
Enable no_console_log if the repo is production code.
Respond with YAML only."""

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(500, "OPENROUTER_API_KEY not set")

    import httpx
    resp = httpx.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": "anthropic/claude-sonnet-4-6",
            "max_tokens": 800,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=45,
    )
    resp.raise_for_status()
    raw_yaml = resp.json()["choices"][0]["message"]["content"].strip()

    # Strip markdown fences if model added them
    if raw_yaml.startswith("```"):
        raw_yaml = re.sub(r"^```[a-z]*\n?", "", raw_yaml).rstrip("`").strip()

    try:
        import yaml as _yaml
        parsed = _yaml.safe_load(raw_yaml)
        if not isinstance(parsed, dict) or "rules" not in parsed:
            raise ValueError("Invalid constitution structure")
        parsed["version"] = 1
        save_constitution(path, parsed)
        return {"ok": True, "constitution": parsed, "yaml": raw_yaml}
    except Exception as e:
        # Save raw YAML anyway
        from .constitution import save_constitution as sc
        default["_raw"] = raw_yaml
        return {"ok": False, "error": str(e), "yaml": raw_yaml}


# ── HTML shell — served for all non-API routes ───────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Boswell</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0d0f12; --surface: #151820; --border: #1e2330;
    --text: #cdd6f4; --muted: #6c7086; --accent: #89b4fa;
    --green: #a6e3a1; --red: #f38ba8; --yellow: #f9e2af;
    --purple: #cba6f7; --teal: #94e2d5;
    --font: 'SF Mono', 'Fira Code', monospace;
  }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; height: 100vh; display: flex; flex-direction: column; }
  nav { display: flex; align-items: center; gap: 2px; padding: 0 16px; background: var(--surface); border-bottom: 1px solid var(--border); height: 44px; flex-shrink: 0; overflow-x: auto; }
  nav .brand { font-size: 15px; font-weight: 700; color: var(--accent); margin-right: 16px; white-space: nowrap; }
  nav button { background: none; border: none; color: var(--muted); cursor: pointer; padding: 6px 10px; border-radius: 6px; font-family: var(--font); font-size: 12px; white-space: nowrap; transition: color .15s, background .15s; }
  nav button:hover { color: var(--text); background: var(--border); }
  nav button.active { color: var(--accent); background: rgba(137,180,250,.1); }
  nav .spacer { flex: 1; }
  nav .vault-badge { font-size: 11px; padding: 3px 8px; border-radius: 99px; border: 1px solid; }
  nav .vault-badge.locked { color: var(--yellow); border-color: var(--yellow); }
  nav .vault-badge.unlocked { color: var(--green); border-color: var(--green); }
  nav .db-dot { width: 7px; height: 7px; border-radius: 50%; margin-left: 8px; }
  nav .db-dot.on { background: var(--green); }
  nav .db-dot.off { background: var(--muted); }
  .layout { display: flex; flex: 1; overflow: hidden; }
  .sidebar { width: 220px; flex-shrink: 0; background: var(--surface); border-right: 1px solid var(--border); overflow-y: auto; padding: 12px 0; }
  .sidebar h3 { font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); padding: 0 14px 6px; }
  .repo-item { padding: 8px 14px; cursor: pointer; border-left: 2px solid transparent; transition: all .15s; }
  .repo-item:hover { background: rgba(255,255,255,.03); }
  .repo-item.active { border-left-color: var(--accent); background: rgba(137,180,250,.07); }
  .repo-item .rname { color: var(--text); font-size: 12px; }
  .repo-item .rmeta { color: var(--muted); font-size: 10px; margin-top: 2px; }
  .repo-item .badge { display: inline-block; font-size: 9px; padding: 1px 5px; border-radius: 3px; margin-top: 3px; }
  .badge-green { background: rgba(166,227,161,.15); color: var(--green); }
  .badge-red { background: rgba(243,139,168,.15); color: var(--red); }
  .badge-yellow { background: rgba(249,226,175,.15); color: var(--yellow); }
  main { flex: 1; overflow-y: auto; padding: 24px; }
  .page { display: none; }
  .page.active { display: block; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 14px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card h4 { font-size: 13px; color: var(--accent); margin-bottom: 6px; }
  .card .stack { font-size: 11px; color: var(--muted); margin-bottom: 8px; }
  .card .verdict { font-size: 11px; margin-bottom: 4px; }
  .card .cost { font-size: 10px; color: var(--muted); margin-top: 8px; }
  .card button { margin-top: 10px; font-family: var(--font); font-size: 11px; padding: 5px 10px; border-radius: 5px; border: 1px solid var(--border); background: none; color: var(--accent); cursor: pointer; }
  .card button:hover { background: rgba(137,180,250,.1); }
  .doc-tabs { display: flex; gap: 2px; margin-bottom: 16px; flex-wrap: wrap; }
  .doc-tabs button { font-family: var(--font); font-size: 11px; padding: 5px 12px; border-radius: 5px; border: 1px solid var(--border); background: none; color: var(--muted); cursor: pointer; }
  .doc-tabs button.active { color: var(--accent); border-color: var(--accent); background: rgba(137,180,250,.08); }
  .doc-content { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; line-height: 1.7; white-space: pre-wrap; font-size: 12px; min-height: 300px; overflow-x: auto; }
  .doc-content h1, .doc-content h2 { color: var(--accent); margin: 16px 0 8px; }
  .doc-content h3 { color: var(--purple); margin: 12px 0 6px; }
  .doc-content strong { color: var(--yellow); }
  .doc-content code { background: var(--border); padding: 1px 4px; border-radius: 3px; }
  .vault-lock-form { max-width: 340px; }
  .vault-lock-form input { width: 100%; background: var(--surface); border: 1px solid var(--border); color: var(--text); font-family: var(--font); font-size: 13px; padding: 8px 12px; border-radius: 6px; margin: 8px 0; outline: none; }
  .vault-lock-form input:focus { border-color: var(--accent); }
  .vault-lock-form button { padding: 8px 18px; border-radius: 6px; border: none; background: var(--accent); color: var(--bg); font-family: var(--font); font-size: 13px; cursor: pointer; font-weight: 600; }
  .vault-section { margin-bottom: 24px; }
  .vault-section h3 { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-bottom: 10px; }
  .secret-row { display: flex; align-items: center; gap: 10px; padding: 7px 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; }
  .secret-key { color: var(--teal); font-size: 12px; flex: 1; }
  .secret-val { color: var(--muted); font-size: 12px; font-family: var(--font); }
  .secret-val.revealed { color: var(--yellow); }
  .secret-btn { font-size: 10px; padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border); background: none; color: var(--muted); cursor: pointer; }
  .secret-btn:hover { color: var(--text); border-color: var(--text); }
  .ingest-btn { font-size: 11px; padding: 5px 12px; border-radius: 5px; border: 1px solid var(--border); background: none; color: var(--green); cursor: pointer; margin-top: 6px; font-family: var(--font); }
  .ingest-btn:hover { background: rgba(166,227,161,.1); }
  .run-btn { background: none; border: 1px solid var(--border); color: var(--teal); cursor: pointer; border-radius: 4px; font-size: 11px; padding: 2px 6px; font-family: var(--font); line-height: 1; flex-shrink: 0; }
  .run-btn:hover { background: rgba(148,226,213,.1); }
  .run-btn:disabled { opacity: .5; cursor: default; }
  #run-all-btn { font-family: var(--font); font-size: 11px; padding: 4px 10px; border-radius: 5px; border: 1px solid var(--teal); background: none; color: var(--teal); cursor: pointer; }
  #run-all-btn:hover { background: rgba(148,226,213,.1); }
  #run-all-btn:disabled { opacity: .5; cursor: default; }
  .empty { color: var(--muted); font-size: 12px; padding: 40px 0; text-align: center; }
  .err { color: var(--red); font-size: 12px; margin-top: 6px; }
  .ok { color: var(--green); font-size: 12px; margin-top: 6px; }
  h2.page-title { font-size: 16px; margin-bottom: 18px; color: var(--text); }
  .stat-row { display: flex; gap: 14px; margin-bottom: 20px; flex-wrap: wrap; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; min-width: 120px; }
  .stat .val { font-size: 22px; color: var(--accent); font-weight: 700; }
  .stat .lbl { font-size: 10px; color: var(--muted); margin-top: 2px; }
  .loading { color: var(--muted); font-size: 12px; }
  .back-btn { font-family: var(--font); font-size: 11px; color: var(--muted); background: none; border: none; cursor: pointer; margin-bottom: 14px; padding: 0; }
  .back-btn:hover { color: var(--text); }
  /* History table */
  .run-table { width: 100%; border-collapse: collapse; }
  .run-table th { font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); text-align: left; padding: 6px 12px; border-bottom: 1px solid var(--border); }
  .run-table td { font-size: 12px; padding: 9px 12px; border-bottom: 1px solid rgba(30,35,48,.6); vertical-align: top; }
  .run-table tr:hover td { background: rgba(255,255,255,.02); }
  .pill { display: inline-block; font-size: 9px; padding: 2px 6px; border-radius: 99px; font-weight: 700; }
  .pill-red { background: rgba(243,139,168,.15); color: var(--red); }
  .pill-green { background: rgba(166,227,161,.15); color: var(--green); }
  .pill-muted { background: rgba(108,112,134,.15); color: var(--muted); }
  /* Leak cards */
  .leak-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; transition: opacity .2s; }
  .leak-card.resolved { opacity: .45; }
  .leak-card.resolved .lc-desc { text-decoration: line-through; color: var(--muted); }
  /* Severity colors */
  .sev-CRITICAL { color: var(--red); font-weight: 700; }
  .sev-HIGH { color: var(--red); }
  .sev-MEDIUM { color: var(--yellow); }
  .sev-LOW { color: var(--muted); }
  .sev-INFO { color: var(--muted); font-style: italic; }
  /* Finding rows */
  .finding-row { padding: 9px 14px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: flex-start; font-size: 12px; }
  .finding-row:last-child { border-bottom: none; }
  .finding-sev { font-size: 10px; font-weight: 700; min-width: 64px; padding-top: 1px; }
  .finding-text { flex: 1; line-height: 1.5; }
  .finding-resolved { opacity: .5; text-decoration: line-through; }
  /* Standards page */
  .standards-content { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 28px 32px; line-height: 1.75; max-width: 900px; }
  .standards-content h1 { font-size: 18px; color: var(--accent); margin: 0 0 18px; }
  .standards-content h2 { font-size: 14px; color: var(--accent); margin: 24px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  .standards-content h3 { font-size: 12px; color: var(--purple); margin: 14px 0 6px; }
  .standards-content pre { background: rgba(0,0,0,.4); border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; margin: 8px 0; }
  .standards-content code { background: var(--border); padding: 1px 4px; border-radius: 3px; font-size: 11px; }
  .standards-content pre code { background: none; padding: 0; }
  .standards-content table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 11px; }
  .standards-content th { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .06em; }
  .standards-content td { padding: 7px 10px; border-bottom: 1px solid rgba(30,35,48,.5); }
  .standards-content strong { color: var(--yellow); }
  .standards-content blockquote { border-left: 3px solid var(--accent); padding-left: 12px; color: var(--muted); margin: 8px 0; }
  .standards-content hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
</style>
</head>
<body>

<nav>
  <span class="brand">◎ Boswell</span>
  <button onclick="showPage('overview')" id="nav-overview" class="active">Overview</button>
  <button onclick="showPage('history')" id="nav-history">History</button>
  <button onclick="showPage('leaks')" id="nav-leaks">Leaks</button>
  <button onclick="showPage('vault')" id="nav-vault">Vault</button>
  <button onclick="showPage('fixes')" id="nav-fixes">Fixes</button>
  <button onclick="showPage('standards')" id="nav-standards">Standards</button>
  <button onclick="showPage('portfolio')" id="nav-portfolio">Portfolio</button>
  <button onclick="showPage('briefing')" id="nav-briefing">Briefing</button>
  <span class="spacer"></span>
  <button id="run-all-btn" onclick="runAll()">⟳ run all</button>
  <span id="db-label" style="font-size:10px;color:var(--muted)"></span>
  <div class="db-dot off" id="db-dot" title="Neon DB"></div>
  <span class="vault-badge locked" id="vault-badge">⚿ locked</span>
</nav>

<div class="layout">
  <div class="sidebar" id="sidebar">
    <h3>Repos</h3>
    <div id="repo-list"><div class="empty">loading…</div></div>
  </div>

  <main>
    <!-- OVERVIEW -->
    <div class="page active" id="page-overview">
      <h2 class="page-title">Portfolio Overview</h2>
      <div class="stat-row" id="stats"></div>
      <div id="github-sync-panel" style="margin-bottom:20px"></div>
      <div class="cards" id="cards"><div class="loading">loading repos…</div></div>
    </div>

    <!-- REPO DETAIL -->
    <div class="page" id="page-repo">
      <button class="back-btn" onclick="showPage('overview')">← back to overview</button>
      <h2 class="page-title" id="repo-detail-title"></h2>
      <div class="doc-tabs" id="doc-tabs"></div>
      <div class="doc-content" id="doc-content">Select a document above.</div>
    </div>

    <!-- HISTORY -->
    <div class="page" id="page-history">
      <h2 class="page-title">Scan History</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:16px">Every <code>boswell run</code> stored in Neon — findings tracked over time.</div>
      <div style="display:flex;gap:8px;margin-bottom:16px;align-items:center;flex-wrap:wrap">
        <select id="entropy-chart-repo" onchange="loadEntropyChart()" style="padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:12px">
          <option value="">— select repo for entropy chart —</option>
        </select>
        <button onclick="loadEntropyChart()" style="padding:4px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--accent);cursor:pointer;font-size:12px">Load chart</button>
      </div>
      <div id="entropy-chart-container" style="display:none;margin-bottom:24px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px">
        <canvas id="entropy-chart" height="120"></canvas>
      </div>
      <div id="history-content"><div class="loading">loading…</div></div>
    </div>

    <!-- BRIEFING -->
    <div class="page" id="page-briefing">
      <h2 class="page-title">Weekly Briefing</h2>
      <div style="display:flex;gap:8px;margin-bottom:16px;align-items:center">
        <button onclick="loadBriefing()" style="padding:5px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--accent);cursor:pointer;font-size:12px">⟳ Refresh</button>
        <button id="smart-scan-btn" onclick="triggerSmartScan()" style="padding:5px 14px;border-radius:6px;border:1px solid var(--accent);background:rgba(137,180,250,0.1);color:var(--accent);cursor:pointer;font-size:12px">⚡ Smart Scan</button>
        <span id="briefing-cost" style="font-size:11px;color:var(--muted)"></span>
      </div>
      <div id="briefing-content"><div class="loading">loading…</div></div>
    </div>

    <!-- LEAKS -->
    <div class="page" id="page-leaks">
      <h2 class="page-title">Leaks & Exposure</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:16px">Three-layer scan: .gitignore gaps · tracked .env files · hardcoded secrets in source · git history</div>
      <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
        <select id="leak-repo-filter" onchange="filterLeaks()" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:5px 10px;border-radius:5px">
          <option value="">All repos</option>
        </select>
        <select id="leak-status-filter" onchange="filterLeaks()" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:5px 10px;border-radius:5px">
          <option value="">All findings</option>
          <option value="open">Open only</option>
          <option value="resolved">Resolved only</option>
        </select>
        <button onclick="runLiveScan()" style="font-family:var(--font);font-size:11px;padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--teal);cursor:pointer;">⟳ Live scan selected repo</button>
        <span id="scan-status" style="font-size:11px;color:var(--muted);padding:5px 0"></span>
        <span id="leak-count" style="font-size:11px;color:var(--muted);margin-left:auto"></span>
      </div>
      <div id="leaks-list"><div class="loading">loading…</div></div>
    </div>

    <!-- VAULT -->
    <div class="page" id="page-vault">
      <h2 class="page-title">Vault</h2>
      <div id="vault-content"></div>
    </div>

    <!-- FIXES -->
    <div class="page" id="page-fixes">
      <h2 class="page-title">What Was Found &amp; Fixed</h2>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <div style="font-size:11px;color:var(--muted)">Full audit findings from each repo · resolved findings tracked in Neon</div>
        <button id="import-all-btn" onclick="importAll()" style="font-family:var(--font);font-size:11px;padding:4px 10px;border-radius:5px;border:1px solid var(--teal);background:none;color:var(--teal);cursor:pointer;margin-left:auto">⟳ import all</button>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
        <select id="fixes-repo-filter" onchange="filterFindings()" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:5px 10px;border-radius:5px">
          <option value="">All repos</option>
        </select>
        <select id="fixes-sev-filter" onchange="filterFindings()" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:5px 10px;border-radius:5px">
          <option value="">All severities</option>
          <option value="CRITICAL">Critical only</option>
          <option value="HIGH">High only</option>
          <option value="MEDIUM">Medium only</option>
        </select>
        <select id="fixes-status-filter" onchange="filterFindings()" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:5px 10px;border-radius:5px">
          <option value="">Open + Resolved</option>
          <option value="open">Open only</option>
          <option value="resolved">Resolved only</option>
        </select>
        <span id="findings-count" style="font-size:11px;color:var(--muted);margin-left:auto"></span>
      </div>
      <div id="fixes-stats" class="stat-row"></div>
      <!-- Selection action bar (shown when findings are checked) -->
      <div id="selection-bar" style="display:none;position:sticky;top:8px;z-index:20;background:var(--bg-card);border:1px solid var(--teal);border-radius:8px;padding:10px 14px;margin-bottom:12px;align-items:center;gap:12px;box-shadow:0 4px 16px rgba(0,0,0,0.3)">
        <span style="font-size:12px;color:var(--text);font-weight:600"><span id="sel-count">0</span> selected</span>
        <button id="copy-prompt-btn" onclick="copyFixPrompt()" style="font-family:var(--font);font-size:11px;padding:4px 12px;border-radius:5px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer">📋 copy prompt</button>
        <button id="auto-fix-btn" onclick="autoFix()" style="font-family:var(--font);font-size:11px;padding:4px 12px;border-radius:5px;border:none;background:var(--teal);color:#000;cursor:pointer;font-weight:600">⚡ auto-fix</button>
        <button onclick="clearSelection()" style="font-family:var(--font);font-size:11px;padding:4px 10px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;margin-left:auto">✕ clear</button>
      </div>
      <div id="fixes-list"><div class="loading">loading…</div></div>
    </div>

    <!-- PORTFOLIO -->
    <div class="page" id="page-portfolio">
      <h2 class="page-title">Portfolio Assessment</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:20px">AI-generated portfolio review — shutdown candidates, merge opportunities, and developer profile.</div>
      <div id="portfolio-content"><div class="loading">loading…</div></div>
    </div>

    <!-- STANDARDS -->
    <div class="page" id="page-standards">
      <h2 class="page-title">Build Standards</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:20px" id="standards-path"></div>
      <div class="standards-content" id="standards-content"><div class="loading">loading…</div></div>
    </div>
  </main>
</div>

<script>
const BOSWELL_TOKEN = "__BOSWELL_TOKEN__";
const _boswellFetch = window.fetch.bind(window);
window.fetch = function (input, init) {
  const next = init ? Object.assign({}, init) : {};
  const headers = new Headers(next.headers || {});
  if (!headers.has("Authorization")) {
    headers.set("Authorization", "Bearer " + BOSWELL_TOKEN);
  }
  next.headers = headers;
  return _boswellFetch(input, next);
};
const BOSWELL_BASE = window.location.pathname.replace(/\/[^/]*$/, '').replace(/\/$/, '') || '';
let repos = [];
let currentRepo = null;
let allLeaks = [];
let vaultUnlocked = false;
let neonConnected = false;

// ── Nav ──────────────────────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav button[id^="nav-"]').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  const nb = document.getElementById('nav-' + name);
  if (nb) nb.classList.add('active');
  if (name === 'vault') renderVaultPage();
  if (name === 'leaks') loadLeaks();
  if (name === 'history') loadHistory();
  if (name === 'fixes') loadFixes();
  if (name === 'standards') loadStandards();
  if (name === 'portfolio') loadPortfolio();
  if (name === 'briefing') loadBriefing();
  if (name === 'history') populateEntropyRepoSelect();
}

// ── DB status ────────────────────────────────────────────────────────────────
async function checkDbStatus() {
  try {
    const res = await fetch(BOSWELL_BASE+'/api/runs');
    neonConnected = res.ok;
  } catch { neonConnected = false; }
  const dot = document.getElementById('db-dot');
  const lbl = document.getElementById('db-label');
  dot.className = 'db-dot ' + (neonConnected ? 'on' : 'off');
  lbl.textContent = neonConnected ? 'neon' : '';
  lbl.style.color = neonConnected ? 'var(--green)' : 'var(--muted)';
}

// ── Repos ────────────────────────────────────────────────────────────────────
async function loadRepos() {
  const res = await fetch(BOSWELL_BASE+'/api/repos');
  repos = await res.json();
  renderSidebar();
  renderOverview();
  const sel = document.getElementById('leak-repo-filter');
  repos.forEach(r => {
    const o = document.createElement('option');
    o.value = r.name; o.textContent = r.name;
    sel.appendChild(o);
  });
}

function renderSidebar() {
  const el = document.getElementById('repo-list');
  if (!repos.length) { el.innerHTML = '<div class="empty">no repos found</div>'; return; }
  el.innerHTML = repos.map(r => {
    const leakCount = r.meta?.leak_findings?.length || 0;
    return `<div class="repo-item" onclick="openRepo('${r.name}')">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:4px">
        <div class="rname">${r.name}</div>
        <button class="run-btn" onclick="event.stopPropagation();runAudit('${r.name}')" title="Re-run audit">⟳</button>
      </div>
      <div class="rmeta">${(r.meta?.stack || []).slice(0,3).join(', ') || 'unknown'}</div>
      ${leakCount ? `<span class="badge badge-red">${leakCount} finding${leakCount!==1?'s':''}</span>` : '<span class="badge badge-green">clean</span>'}
    </div>`;
  }).join('');
}

async function runAudit(name) {
  const btn = [...document.querySelectorAll('.run-btn')].find(b => b.closest('.repo-item')?.querySelector('.rname')?.textContent === name);
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const res = await fetch(`/api/run/${encodeURIComponent(name)}`, { method: 'POST' });
    if (!res.ok) throw new Error(await res.text());
    if (btn) { btn.textContent = '✓'; setTimeout(() => { btn.textContent = '⟳'; btn.disabled = false; }, 3000); }
  } catch (e) {
    if (btn) { btn.textContent = '!'; btn.disabled = false; }
    alert('Run failed: ' + e.message);
  }
}

async function runAll() {
  const btn = document.getElementById('run-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'running…'; }
  try {
    const res = await fetch(BOSWELL_BASE+'/api/run-all', { method: 'POST' });
    const data = await res.json();
    if (btn) { btn.textContent = `✓ ${data.triggered?.length || 0} queued`; setTimeout(() => { btn.textContent = 'run all'; btn.disabled = false; }, 4000); }
  } catch (e) {
    if (btn) { btn.textContent = 'run all'; btn.disabled = false; }
    alert('Run all failed: ' + e.message);
  }
}

function renderOverview() {
  const total = repos.length;
  const totalCost = repos.reduce((s, r) => s + (r.meta?.cost_usd || 0), 0);
  const openFindings = repos.reduce((s, r) => s + (r.meta?.leak_findings?.length || 0), 0);
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="val">${total}</div><div class="lbl">repos audited</div></div>
    <div class="stat"><div class="val">$${totalCost.toFixed(2)}</div><div class="lbl">total cost</div></div>
    <div class="stat"><div class="val" style="color:${openFindings?'var(--red)':'var(--green)'}">${openFindings}</div><div class="lbl">open findings</div></div>
    <div class="stat" style="cursor:pointer" onclick="scanAllEntropy(this)" title="Compute entropy for all repos">
      <div class="val" id="avg-entropy-val" style="color:var(--muted)">—</div>
      <div class="lbl">avg entropy · click to scan</div>
    </div>
  `;
  // GitHub sync panel
  loadGithubStatus();

  document.getElementById('cards').innerHTML = repos.map(r => {
    const leaks = r.meta?.leak_findings || [];
    const crit = leaks.filter(f => f.severity === 'CRITICAL').length;
    return `<div class="card" id="card-${r.name}">
      <div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:4px">
        <h4 style="margin:0;flex:1">${r.name}</h4>
        <div id="entropy-badge-${r.name}" style="font-size:10px;padding:2px 7px;border-radius:99px;background:var(--border);color:var(--muted);flex-shrink:0;cursor:pointer" onclick="loadEntropy('${r.name}')" title="Click to compute entropy">entropy</div>
      </div>
      <div class="stack">${(r.meta?.stack || []).slice(0,4).join(' · ') || 'unknown stack'}</div>
      ${crit ? `<div style="font-size:11px;color:var(--red);margin-bottom:4px">⚠ ${crit} CRITICAL finding${crit!==1?'s':''}</div>` : '<div style="font-size:11px;color:var(--green);margin-bottom:4px">✓ No critical findings</div>'}
      <div id="entropy-detail-${r.name}" style="display:none;font-size:10px;color:var(--muted);margin-bottom:6px"></div>
      <div class="cost">$${(r.meta?.cost_usd || 0).toFixed(3)} · ${r.meta?.files_scanned || 0} files · ${r.meta?.run_at || ''}</div>
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">
        <button onclick="openRepo('${r.name}')">View docs →</button>
        <button id="deploy-btn-${r.name}" onclick="toggleDeploy('${r.name}',this)" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-size:11px;padding:4px 10px;border-radius:5px;cursor:pointer">⏸ Disable</button>
        <button onclick="checkJobs('${r.name}',this)" style="background:var(--surface);border:1px solid var(--teal);color:var(--teal);font-size:11px;padding:4px 10px;border-radius:5px;cursor:pointer">⏱ Jobs</button>
        <button id="ship-btn-${r.name}" onclick="shipCheck('${r.name}',this)" style="background:var(--surface);border:1px solid var(--purple);color:var(--purple);font-size:11px;padding:4px 10px;border-radius:5px;cursor:pointer">🚀 Ship Check</button>
        ${crit ? `<button id="fix-btn-${r.name}" onclick="fixCode('${r.name}',this)" style="background:var(--surface);border:1px solid var(--red);color:var(--red);font-size:11px;padding:4px 10px;border-radius:5px;cursor:pointer">🔧 Fix &amp; Ship</button>` : ''}
      </div>
    </div>`;
  }).join('') || '<div class="empty">no repos found — run boswell in a repo first</div>';
}

async function loadGithubStatus() {
  const panel = document.getElementById('github-sync-panel');
  if (!panel) return;
  try {
    const res = await fetch(BOSWELL_BASE+'/api/github/status');
    const data = await res.json();

    if (!data.connected) {
      panel.innerHTML = `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
        <span style="font-size:13px">⎊</span>
        <span style="font-size:12px;color:var(--muted)">GitHub not connected — add <code>GITHUB_TOKEN</code> and <code>GITHUB_USERNAME</code> to <code>~/.boswell/.env</code></span>
      </div>`;
      return;
    }

    const missing = data.missing || [];
    if (missing.length === 0) {
      panel.innerHTML = `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:12px">
        <span style="font-size:13px;color:var(--green)">✓</span>
        <span style="font-size:12px;color:var(--muted)">GitHub synced — all ${data.total_github} repos present locally</span>
      </div>`;
      return;
    }

    panel.innerHTML = `<div style="background:var(--surface);border:1px solid rgba(249,226,175,.3);border-radius:8px;padding:14px 16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <span style="font-size:13px">⎊</span>
        <span style="font-size:12px;color:var(--yellow);font-weight:600">${missing.length} GitHub repo${missing.length!==1?'s':''} not cloned locally</span>
        <button onclick="syncAllGithub(this)" style="margin-left:auto;font-family:var(--font);font-size:11px;padding:4px 14px;border-radius:5px;border:1px solid var(--yellow);background:none;color:var(--yellow);cursor:pointer">Clone All</button>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${missing.slice(0,12).map(r => `
          <div style="display:flex;align-items:center;gap:6px;background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:4px 10px">
            <span style="font-size:11px;color:var(--text)">${r.name}</span>
            ${r.private ? '<span style="font-size:9px;color:var(--muted)">🔒</span>' : ''}
            <button onclick="syncOneGithub('${r.name}',this)" style="font-family:var(--font);font-size:10px;padding:2px 8px;border-radius:4px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer">Clone</button>
          </div>`).join('')}
        ${missing.length > 12 ? `<div style="font-size:11px;color:var(--muted);padding:4px 10px;align-self:center">+${missing.length-12} more</div>` : ''}
      </div>
      <div id="github-sync-status" style="font-size:11px;color:var(--muted);margin-top:8px"></div>
    </div>`;
  } catch (e) {
    // silently fail — GitHub is optional
  }
}

async function syncAllGithub(btn) {
  const status = document.getElementById('github-sync-status');
  btn.disabled = true;
  btn.textContent = '⏳ Cloning…';
  try {
    const res = await fetch(BOSWELL_BASE+'/api/github/sync', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'unknown');
    if (status) {
      const msg = `✓ Cloned: ${data.cloned.join(', ') || 'none'}` +
        (data.failed.length ? ` · Failed: ${data.failed.map(f=>f.name).join(', ')}` : '');
      status.textContent = msg;
      status.style.color = data.failed.length ? 'var(--yellow)' : 'var(--green)';
    }
    // Refresh status after a short delay
    setTimeout(loadGithubStatus, 1500);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = 'Clone All';
    if (status) { status.textContent = 'Error: ' + e.message; status.style.color = 'var(--red)'; }
  }
}

async function syncOneGithub(name, btn) {
  btn.disabled = true;
  btn.textContent = '⏳';
  const status = document.getElementById('github-sync-status');
  try {
    const res = await fetch(BOSWELL_BASE+'/api/github/sync-one', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'unknown');
    btn.textContent = '✓';
    btn.style.color = 'var(--green)';
    btn.style.borderColor = 'var(--green)';
    if (status) { status.textContent = `✓ ${name} cloned — run Boswell on it to audit.`; status.style.color = 'var(--green)'; }
  } catch (e) {
    btn.disabled = false;
    btn.textContent = 'Clone';
    if (status) { status.textContent = 'Error: ' + e.message; status.style.color = 'var(--red)'; }
  }
}

async function openRepo(name) {
  currentRepo = repos.find(r => r.name === name);
  if (!currentRepo) return;
  document.querySelectorAll('.repo-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.repo-item').forEach(el => {
    if (el.querySelector('.rname')?.textContent === name) el.classList.add('active');
  });
  document.getElementById('repo-detail-title').textContent = name;
  const docs = [
    { key: 'audit', label: 'Audit' },
    { key: 'audit-simple', label: 'Audit (plain)' },
    { key: 'handoff', label: 'Handoff' },
    { key: 'handoff-simple', label: 'Handoff (plain)' },
    ...(currentRepo.has_lessons ? [{ key: 'lessons', label: 'Lessons' }] : []),
    { key: 'fixed', label: '✓ Fixed', special: 'fixed' },
    { key: 'not-fixed', label: '✗ Not Fixed', special: 'not-fixed' },
    { key: 'improvements', label: '⟳ Improvements', special: 'improvements' },
    { key: 'optimal-prompt', label: '⚡ Optimal Prompt', special: 'optimal-prompt' },
    { key: 'constitution', label: '⚖ Constitution', special: 'constitution' },
    { key: 'slop', label: '🤖 AI Slop', special: 'slop' },
  ];
  document.getElementById('doc-tabs').innerHTML = docs.map(d =>
    `<button onclick="${d.special ? `loadSpecialTab('${d.special}')` : `loadDoc('${d.key}')`}" id="tab-${d.key}">${d.label}</button>`
  ).join('');
  showPage('repo');
  await loadDoc('audit');
}

async function loadDoc(docKey) {
  document.querySelectorAll('.doc-tabs button').forEach(b => b.classList.remove('active'));
  const tab = document.getElementById('tab-' + docKey);
  if (tab) tab.classList.add('active');
  document.getElementById('doc-content').textContent = 'loading…';
  const res = await fetch(`/api/repo/${currentRepo.name}/doc/${docKey}`);
  if (!res.ok) { document.getElementById('doc-content').textContent = '[not available]'; return; }
  const data = await res.json();
  renderMarkdown(data.content);
}

async function loadSpecialTab(tab) {
  document.querySelectorAll('.doc-tabs button').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById('tab-' + tab);
  if (btn) btn.classList.add('active');
  const el = document.getElementById('doc-content');
  el.style.whiteSpace = 'normal';

  if (tab === 'fixed') {
    el.innerHTML = '<div class="loading">loading…</div>';
    const res = await fetch(`/api/repo/${currentRepo.name}/fixed-summary`);
    const findings = await res.json();
    if (!findings.length) {
      el.innerHTML = '<div class="empty" style="color:var(--muted)">No resolved findings tracked yet.<br/>Connect Neon and import findings to track resolutions.</div>';
      return;
    }
    const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--red)', MEDIUM: 'var(--yellow)', LOW: 'var(--muted)', INFO: 'var(--muted)' };
    el.innerHTML = `<div style="color:var(--green);font-size:12px;margin-bottom:14px">✓ ${findings.length} finding${findings.length!==1?'s':''} resolved</div>` +
      findings.map(f => `<div style="display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--border);align-items:flex-start">
        <span style="font-size:10px;font-weight:700;color:${sevColor[f.severity]||'var(--muted)'};min-width:64px;flex-shrink:0">${f.severity||'?'}</span>
        <span style="font-size:12px;color:var(--muted);text-decoration:line-through;flex:1">${(f.description||'').replace(/\*\*/g,'')}</span>
        <span style="font-size:10px;color:var(--green);flex-shrink:0">✓ fixed</span>
      </div>`).join('');
    return;
  }

  if (tab === 'not-fixed') {
    el.innerHTML = '<div class="loading">loading…</div>';
    const res = await fetch(`/api/repo/${currentRepo.name}/open-summary`);
    const findings = await res.json();
    if (!findings.length) {
      el.innerHTML = '<div class="empty" style="color:var(--green)">✓ No open findings.</div>';
      return;
    }
    const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--red)', MEDIUM: 'var(--yellow)', LOW: 'var(--muted)', INFO: 'var(--muted)' };
    const groups = {};
    findings.forEach(f => { if (!groups[f.severity]) groups[f.severity] = []; groups[f.severity].push(f); });
    el.innerHTML = `<div style="color:var(--red);font-size:12px;margin-bottom:14px">✗ ${findings.length} open finding${findings.length!==1?'s':''}</div>` +
      ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].filter(s => groups[s]).map(sev =>
        `<div style="margin-bottom:18px">
          <div style="font-size:10px;font-weight:700;color:${sevColor[sev]};margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">${sev} (${groups[sev].length})</div>
          ${groups[sev].map(f => `<div style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;font-size:12px;line-height:1.5">${(f.description||'').replace(/\*\*/g,'')}</div>`).join('')}
        </div>`
      ).join('');
    return;
  }

  if (tab === 'improvements') {
    el.innerHTML = '<div class="loading">checking…</div>';
    const check = await fetch(`/api/repo/${currentRepo.name}/doc/improvements`);
    const data = await check.json();
    if (data.content) {
      renderMarkdown(data.content);
      return;
    }
    el.innerHTML = `<div style="text-align:center;padding:40px 0">
      <div style="color:var(--muted);font-size:12px;margin-bottom:16px">No improvements doc yet — generate one via Gemini 2.5 Flash.</div>
      <button onclick="generateDoc('improvements',this)" style="font-family:var(--font);font-size:12px;padding:8px 18px;border-radius:6px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer">Generate Improvements</button>
      <div id="gen-status" style="font-size:11px;color:var(--muted);margin-top:10px"></div>
    </div>`;
    return;
  }

  if (tab === 'optimal-prompt') {
    el.innerHTML = '<div class="loading">checking…</div>';
    const check = await fetch(`/api/repo/${currentRepo.name}/doc/optimal-prompt`);
    const data = await check.json();
    if (data.content) {
      renderOptimalPrompt(data.content);
      return;
    }
    el.innerHTML = `<div style="text-align:center;padding:40px 0">
      <div style="color:var(--muted);font-size:12px;margin-bottom:16px">No prompt generated yet — create a copy-paste ready Claude Code session prompt.</div>
      <button onclick="generateDoc('optimal-prompt',this)" style="font-family:var(--font);font-size:12px;padding:8px 18px;border-radius:6px;border:1px solid var(--purple);background:none;color:var(--purple);cursor:pointer">⚡ Generate Optimal Prompt</button>
      <div id="gen-status" style="font-size:11px;color:var(--muted);margin-top:10px"></div>
    </div>`;
    return;
  }

  if (tab === 'constitution') {
    el.innerHTML = '<div class="loading">loading constitution…</div>';
    const res = await fetch(`/api/repo/${currentRepo.name}/constitution`);
    if (!res.ok) { el.innerHTML = '<div class="empty">Error loading constitution.</div>'; return; }
    const data = await res.json();
    renderConstitution(data);
    return;
  }

  if (tab === 'slop') {
    el.innerHTML = '<div class="loading">scanning for AI slop…</div>';
    const res = await fetch(`/api/repo/${currentRepo.name}/slop`);
    if (!res.ok) { el.innerHTML = '<div class="empty">Error scanning for slop.</div>'; return; }
    const data = await res.json();
    renderSlop(data);
    return;
  }
}

function renderConstitution(data) {
  const el = document.getElementById('doc-content');
  el.style.whiteSpace = 'normal';
  const check = data.check;
  const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--red)', MEDIUM: 'var(--yellow)', LOW: 'var(--muted)', INFO: 'var(--muted)' };
  const statusIcon = { pass: '✓', fail: '✗', skipped: '–' };
  const statusColor = { pass: 'var(--green)', fail: 'var(--red)', skipped: 'var(--muted)' };

  const scoreColor = check.constitution_score <= 10 ? 'var(--green)'
    : check.constitution_score <= 30 ? 'var(--yellow)' : 'var(--red)';

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap">
      <div style="font-size:28px;font-weight:700;color:${scoreColor}">${check.constitution_score}</div>
      <div>
        <div style="font-size:12px;color:var(--text);font-weight:600">Constitution Score</div>
        <div style="font-size:11px;color:var(--muted)">${check.passed} passed · ${check.failed} failed · ${check.skipped} skipped</div>
      </div>
      <div style="margin-left:auto;display:flex;gap:8px">
        <button onclick="recheckConstitution()" style="font-family:var(--font);font-size:11px;padding:5px 14px;border-radius:5px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer">⟳ Re-check</button>
        <button onclick="generateConstitution(this)" style="font-family:var(--font);font-size:11px;padding:5px 14px;border-radius:5px;border:1px solid var(--purple);background:none;color:var(--purple);cursor:pointer">✦ Generate</button>
      </div>
    </div>
    <div style="font-size:10px;color:var(--muted);margin-bottom:14px;text-transform:uppercase;letter-spacing:.06em">Rules</div>
    ${check.rule_summaries.map(r => `
      <div style="display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);align-items:flex-start">
        <span style="font-size:13px;color:${statusColor[r.status]||'var(--muted)'};min-width:16px;flex-shrink:0;margin-top:1px">${statusIcon[r.status]||'?'}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;color:${r.status==='fail'?'var(--text)':'var(--muted)'};font-weight:${r.status==='fail'?'600':'400'}">${r.rule.replace(/_/g,' ')}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">${r.description}</div>
          ${r.details && r.details.length ? `<div style="margin-top:6px">${r.details.map(d =>
            `<div style="font-size:10px;color:var(--red);background:rgba(243,139,168,.08);border:1px solid rgba(243,139,168,.2);border-radius:4px;padding:4px 8px;margin-bottom:3px;font-family:monospace">${d.file}${d.line ? ':' + d.line : ''} — ${d.detail}</div>`
          ).join('')}</div>` : ''}
        </div>
        <span style="font-size:9px;font-weight:700;color:${sevColor[r.severity]||'var(--muted)'};flex-shrink:0;margin-top:2px">${r.severity}</span>
      </div>`
    ).join('')}
    <div id="constitution-status" style="font-size:11px;color:var(--muted);margin-top:12px"></div>
  `;
}

function renderSlop(data) {
  const el = document.getElementById('doc-content');
  el.style.whiteSpace = 'normal';

  const scoreColor = data.slop_score <= 10 ? 'var(--green)'
    : data.slop_score <= 25 ? 'var(--accent)'
    : data.slop_score <= 45 ? 'var(--yellow)'
    : 'var(--red)';

  const sections = [
    { key: 'utility_sprawl',       icon: '📁', label: 'Utility Sprawl' },
    { key: 'single_call_wrappers', icon: '🪆', label: 'Single-Call Wrappers' },
    { key: 'duplicate_helpers',    icon: '♊', label: 'Duplicate Helpers' },
    { key: 'cargo_cult',           icon: '🙈', label: 'Cargo-Cult Patterns' },
    { key: 'reexport_chains',      icon: '📦', label: 'Barrel Re-exports' },
    { key: 'generic_types',        icon: '🔤', label: 'Generic Type Names' },
  ];

  function slopBar(score, max) {
    const pct = Math.round(score / max * 100);
    const col = pct === 0 ? 'var(--green)' : pct < 40 ? 'var(--yellow)' : 'var(--red)';
    return `<div style="height:4px;background:var(--border);border-radius:2px;margin-top:4px">
      <div style="width:${pct}%;height:100%;background:${col};border-radius:2px;transition:width .3s"></div>
    </div>`;
  }

  const maxScores = { utility_sprawl: 40, single_call_wrappers: 30, duplicate_helpers: 25, cargo_cult: 35, reexport_chains: 10, generic_types: 10 };

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap">
      <div style="font-size:28px;font-weight:700;color:${scoreColor}">${data.slop_score}</div>
      <div>
        <div style="font-size:12px;color:var(--text);font-weight:600">${data.label}</div>
        <div style="font-size:11px;color:var(--muted)">AI slop score out of 100</div>
      </div>
      <button onclick="diagnoseSlopWithAI(this)" style="margin-left:auto;font-family:var(--font);font-size:11px;padding:5px 14px;border-radius:5px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer">✦ AI Diagnosis</button>
    </div>
    <div id="slop-diagnosis" style="margin-bottom:16px"></div>
    ${sections.map(s => {
      const d = data[s.key];
      const score = d.score || 0;
      const max = maxScores[s.key] || 40;
      return `<div style="padding:12px 0;border-bottom:1px solid var(--border)">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <span style="font-size:13px">${s.icon}</span>
          <span style="font-size:12px;color:var(--text);font-weight:600;flex:1">${s.label}</span>
          <span style="font-size:11px;color:${score===0?'var(--green)':score<max*.4?'var(--yellow)':'var(--red)'};font-weight:700">${score}/${max}</span>
        </div>
        ${slopBar(score, max)}
        <div style="font-size:11px;color:var(--muted);margin-top:6px">${d.verdict || ''}</div>
        ${renderSlopExamples(s.key, d)}
      </div>`;
    }).join('')}
  `;
}

function renderSlopExamples(key, d) {
  const style = 'font-size:10px;color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:4px 8px;margin-top:4px;font-family:monospace';
  if (key === 'utility_sprawl' && d.files && d.files.length) {
    return d.files.slice(0,4).map(f => `<div style="${style}">${f}</div>`).join('');
  }
  if (key === 'single_call_wrappers' && d.examples && d.examples.length) {
    return d.examples.slice(0,4).map(e => `<div style="${style}">${e.file}:${e.line} — ${e.name}()</div>`).join('');
  }
  if (key === 'duplicate_helpers' && d.examples) {
    return Object.entries(d.examples).slice(0,4).map(([name, files]) =>
      `<div style="${style}">${name} — in ${files.length} files</div>`
    ).join('');
  }
  if (key === 'cargo_cult' && d.empty_catch_examples && d.empty_catch_examples.length) {
    return d.empty_catch_examples.slice(0,3).map(e => `<div style="${style}">${e.file}:${e.line} — empty catch</div>`).join('');
  }
  if (key === 'reexport_chains' && d.files && d.files.length) {
    return d.files.slice(0,4).map(f => `<div style="${style}">${f.file} (${f.reexport_lines} re-exports)</div>`).join('');
  }
  if (key === 'generic_types' && d.examples && d.examples.length) {
    return d.examples.slice(0,4).map(e => `<div style="${style}">${e.file}:${e.line} — ${e.name}</div>`).join('');
  }
  return '';
}

async function diagnoseSlopWithAI(btn) {
  const diag = document.getElementById('slop-diagnosis');
  btn.disabled = true;
  btn.textContent = '⏳ Diagnosing…';
  try {
    const res = await fetch(`/api/repo/${currentRepo.name}/slop/diagnose`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'unknown');
    if (diag) {
      diag.innerHTML = `<div style="background:rgba(137,180,250,.06);border:1px solid rgba(137,180,250,.2);border-radius:8px;padding:14px 16px;font-size:12px;line-height:1.7;color:var(--text)">${data.diagnosis}</div>`;
    }
    btn.textContent = '✦ Regenerate';
    btn.disabled = false;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '✦ AI Diagnosis';
    if (diag) diag.innerHTML = `<div style="color:var(--red);font-size:11px">Error: ${e.message}</div>`;
  }
}

async function recheckConstitution() {
  const el = document.getElementById('doc-content');
  const status = document.getElementById('constitution-status');
  if (status) status.textContent = 'Checking…';
  const res = await fetch(`/api/repo/${currentRepo.name}/constitution/check`, { method: 'POST' });
  if (!res.ok) { if (status) status.textContent = 'Error.'; return; }
  const data = await res.json();
  renderConstitution({ check: data.check });
}

async function generateConstitution(btn) {
  const status = document.getElementById('constitution-status');
  btn.disabled = true;
  btn.textContent = '⏳ Generating…';
  if (status) status.textContent = 'Asking Claude Sonnet to tailor rules for this repo…';
  try {
    const res = await fetch(`/api/repo/${currentRepo.name}/constitution/generate`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'unknown error');
    // Reload the full tab with new rules
    const res2 = await fetch(`/api/repo/${currentRepo.name}/constitution`);
    const data2 = await res2.json();
    renderConstitution(data2);
    if (status) { status.textContent = '✓ Constitution generated and saved.'; status.style.color = 'var(--green)'; }
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '✦ Generate';
    if (status) { status.textContent = 'Error: ' + e.message; status.style.color = 'var(--red)'; }
  }
}

async function generateDoc(type, btn) {
  const status = document.getElementById('gen-status');
  btn.disabled = true;
  btn.textContent = '⏳ Generating…';
  if (status) status.textContent = 'Calling Gemini 2.5 Flash…';
  try {
    const endpoint = type === 'improvements' ? 'generate-improvements' : 'generate-optimal-prompt';
    const res = await fetch(`/api/repo/${currentRepo.name}/${endpoint}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'unknown error');
    if (type === 'optimal-prompt') renderOptimalPrompt(data.content);
    else renderMarkdown(data.content);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = type === 'improvements' ? 'Generate Improvements' : '⚡ Generate Optimal Prompt';
    if (status) { status.textContent = 'Error: ' + e.message; status.style.color = 'var(--red)'; }
  }
}

function renderOptimalPrompt(content) {
  const el = document.getElementById('doc-content');
  el.style.whiteSpace = 'pre-wrap';
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
      <span style="font-size:12px;color:var(--muted)">Copy and paste this into Claude Code or Cursor to start a focused session.</span>
      <button onclick="copyPrompt()" style="font-family:var(--font);font-size:11px;padding:4px 12px;border-radius:5px;border:1px solid var(--purple);background:none;color:var(--purple);cursor:pointer;margin-left:auto">Copy</button>
      <button onclick="generateDoc('optimal-prompt',this)" style="font-family:var(--font);font-size:11px;padding:4px 12px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer">Regenerate</button>
    </div>
    <div id="prompt-text" style="background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:8px;padding:20px;font-size:12px;line-height:1.7;white-space:pre-wrap">${content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`;
}

function copyPrompt() {
  const el = document.getElementById('prompt-text');
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    const btns = document.querySelectorAll('button');
    btns.forEach(b => { if (b.textContent === 'Copy') { b.textContent = '✓ Copied'; setTimeout(() => b.textContent = 'Copy', 2000); }});
  });
}

function renderMarkdown(md) {
  let html = md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^### (.+)$/gm,'<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/`([^`]+)`/g,'<code>$1</code>');
  const el = document.getElementById('doc-content');
  el.innerHTML = html;
  el.style.whiteSpace = 'pre-wrap';
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const el = document.getElementById('history-content');
  el.innerHTML = '<div class="loading">loading from Neon…</div>';
  const res = await fetch(BOSWELL_BASE+'/api/runs');
  const runs = await res.json();
  if (!runs.length) {
    el.innerHTML = '<div class="empty">No runs stored yet.<br/>Run <code>boswell run &lt;repo&gt;</code> to start tracking.</div>';
    return;
  }
  el.innerHTML = `
    <div class="stat-row">
      <div class="stat"><div class="val">${runs.length}</div><div class="lbl">total runs</div></div>
      <div class="stat"><div class="val" style="color:var(--red)">${runs.reduce((s,r)=>s+parseInt(r.open_findings||0),0)}</div><div class="lbl">open findings</div></div>
      <div class="stat"><div class="val" style="color:var(--green)">${runs.reduce((s,r)=>s+parseInt(r.resolved_findings||0),0)}</div><div class="lbl">resolved</div></div>
      <div class="stat"><div class="val">$${runs.reduce((s,r)=>s+parseFloat(r.cost_usd||0),0).toFixed(2)}</div><div class="lbl">total spend</div></div>
    </div>
    <table class="run-table">
      <thead><tr>
        <th>Repo</th><th>Run at</th><th>Stack</th><th>Open</th><th>Resolved</th><th>Cost</th>
      </tr></thead>
      <tbody>
        ${runs.map(r => {
          const open = parseInt(r.open_findings||0);
          const resolved = parseInt(r.resolved_findings||0);
          const stack = Array.isArray(r.stack) ? r.stack.slice(0,3).join(', ') : (r.stack ? JSON.parse(r.stack||'[]').slice(0,3).join(', ') : '—');
          const runAt = r.run_at ? new Date(r.run_at).toLocaleString() : '—';
          return `<tr>
            <td style="color:var(--accent);font-weight:600">${r.repo_name}</td>
            <td style="color:var(--muted)">${runAt}</td>
            <td style="color:var(--muted);font-size:11px">${stack||'—'}</td>
            <td>${open ? `<span class="pill pill-red">${open}</span>` : `<span class="pill pill-green">0</span>`}</td>
            <td>${resolved ? `<span class="pill pill-green">${resolved}</span>` : `<span class="pill pill-muted">0</span>`}</td>
            <td style="color:var(--muted)">$${parseFloat(r.cost_usd||0).toFixed(3)}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;
}

// ── Entropy timeline chart ────────────────────────────────────────────────────
let _entropyChart = null;

async function populateEntropyRepoSelect() {
  const sel = document.getElementById('entropy-chart-repo');
  if (!sel || sel.options.length > 1) return;
  try {
    const repos = await fetch(BOSWELL_BASE+'/api/repos').then(r => r.json());
    repos.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.name; opt.textContent = r.name;
      sel.appendChild(opt);
    });
  } catch {}
}

async function loadEntropyChart() {
  const sel = document.getElementById('entropy-chart-repo');
  const name = sel?.value;
  if (!name) return;
  const container = document.getElementById('entropy-chart-container');
  container.style.display = 'block';
  try {
    const history = await fetch(`/api/repo/${encodeURIComponent(name)}/entropy/history`).then(r => r.json());
    if (!history.length) {
      container.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:8px">No snapshots yet — scan this repo with ?snapshot=true first.</div>';
      return;
    }
    // history is newest-first; reverse for chronological display
    const pts = [...history].reverse();
    const labels = pts.map(p => new Date(p.snapshot_at).toLocaleDateString());
    const makeDS = (key, label, color) => ({
      label, data: pts.map(p => p[key]),
      borderColor: color, backgroundColor: color + '22',
      tension: 0.3, pointRadius: 3, fill: false,
    });
    if (_entropyChart) _entropyChart.destroy();
    container.innerHTML = '<canvas id="entropy-chart" height="120"></canvas>';
    const ctx = document.getElementById('entropy-chart').getContext('2d');
    _entropyChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          makeDS('entropy_score',        'Overall',         '#89b4fa'),
          makeDS('security_score',       'Security',        '#f38ba8'),
          makeDS('architecture_score',   'Architecture',    '#f9e2af'),
          makeDS('maintainability_score','Maintainability', '#a6e3a1'),
          makeDS('dependency_score',     'Dependency',      '#cba6f7'),
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: '#cdd6f4', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#6c7086', font: { size: 10 } }, grid: { color: '#1e2330' } },
          y: { min: 0, max: 100, ticks: { color: '#6c7086', font: { size: 10 } }, grid: { color: '#1e2330' } },
        },
      },
    });
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-size:12px;padding:8px">Failed to load history: ${e.message}</div>`;
  }
}

// ── Briefing ─────────────────────────────────────────────────────────────────
async function loadBriefing() {
  const el = document.getElementById('briefing-content');
  const costEl = document.getElementById('briefing-cost');
  el.innerHTML = '<div class="loading">Generating briefing…</div>';
  try {
    const b = await fetch(BOSWELL_BASE+'/api/briefing').then(r => r.json());
    if (costEl) costEl.textContent = `Smart scan: ~$${b.smart_scan_cost} · Full portfolio: ~$${b.full_portfolio_cost}`;

    const section = (title, color, items, render) => {
      if (!items.length) return '';
      return `<div style="margin-bottom:20px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:${color};margin-bottom:8px">${title} (${items.length})</div>
        ${items.map(render).join('')}
      </div>`;
    };

    const pill = (label, color) => `<span style="font-size:10px;padding:1px 7px;border-radius:20px;background:${color}22;color:${color};border:1px solid ${color}44">${label}</span>`;

    el.innerHTML = `
      <div class="stat-row" style="margin-bottom:20px">
        <div class="stat"><div class="val">${b.total_repos}</div><div class="lbl">repos tracked</div></div>
        <div class="stat"><div class="val" style="color:var(--red)">${b.critical_repos.length}</div><div class="lbl">have CRITICAL leaks</div></div>
        <div class="stat"><div class="val" style="color:var(--yellow)">${b.degraded.length}</div><div class="lbl">degraded entropy</div></div>
        <div class="stat"><div class="val" style="color:var(--accent)">${b.smart_scan_candidates.length}</div><div class="lbl">need re-scan</div></div>
      </div>

      ${section('Entropy degraded', '#f9e2af', b.degraded, d =>
        `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:4px;border-radius:6px;background:var(--surface);border:1px solid var(--border)">
          <span style="color:var(--text);font-weight:600;font-size:12px">${d.name}</span>
          <span style="font-size:11px;color:var(--muted)">${d.prev} → <span style="color:var(--red)">${d.current}</span> (+${d.delta})</span>
        </div>`
      )}

      ${section('CRITICAL findings', '#f38ba8', b.critical_repos, r =>
        `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:4px;border-radius:6px;background:var(--surface);border:1px solid var(--border)">
          <span style="color:var(--text);font-weight:600;font-size:12px">${r.name}</span>
          ${pill(r.count + ' CRITICAL', '#f38ba8')}
        </div>`
      )}

      ${section('Need re-scan (new commits)', '#89b4fa', b.smart_scan_candidates, c =>
        `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:4px;border-radius:6px;background:var(--surface);border:1px solid var(--border)">
          <span style="color:var(--text);font-weight:600;font-size:12px">${c.name}</span>
          <span style="font-size:11px;color:var(--muted)">~$${c.estimated_cost}</span>
        </div>`
      )}

      ${section('Never scanned', '#cba6f7', b.never_scanned, name =>
        `<div style="padding:8px 10px;margin-bottom:4px;border-radius:6px;background:var(--surface);border:1px solid var(--border);font-size:12px">${name}</div>`
      )}

      ${section('Stale (&gt;30 days)', '#6c7086', b.stale, r =>
        `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:4px;border-radius:6px;background:var(--surface);border:1px solid var(--border)">
          <span style="color:var(--text);font-size:12px">${r.name}</span>
          <span style="font-size:11px;color:var(--muted)">last: ${r.last_scan ? new Date(r.last_scan).toLocaleDateString() : '—'}</span>
        </div>`
      )}

      ${!b.degraded.length && !b.critical_repos.length && !b.never_scanned.length
        ? '<div style="color:var(--green);font-size:13px;padding:16px 0">Portfolio is clean. No action needed.</div>'
        : ''
      }
    `;
  } catch (e) {
    el.innerHTML = `<div style="color:var(--red)">Failed to load briefing: ${e.message}</div>`;
  }
}

async function triggerSmartScan() {
  const btn = document.getElementById('smart-scan-btn');
  btn.textContent = '⏳ scanning…';
  btn.disabled = true;
  try {
    const res = await fetch(BOSWELL_BASE+'/api/smart-scan', { method: 'POST' });
    const data = await res.json();
    btn.textContent = `✓ ${data.total_triggered} queued`;
    setTimeout(() => { btn.textContent = '⚡ Smart Scan'; btn.disabled = false; }, 4000);
  } catch {
    btn.textContent = '✗ error'; btn.disabled = false;
  }
}

// ── Leaks ─────────────────────────────────────────────────────────────────────
async function loadLeaks() {
  const res = await fetch(BOSWELL_BASE+'/api/leaks');
  allLeaks = await res.json();
  filterLeaks();
}

function filterLeaks() {
  const repoFilter = document.getElementById('leak-repo-filter').value;
  const statusFilter = document.getElementById('leak-status-filter').value;
  let filtered = allLeaks;
  if (repoFilter) filtered = filtered.filter(f => (f.repo_name || f.repo) === repoFilter);
  if (statusFilter === 'open') filtered = filtered.filter(f => !f.resolved);
  if (statusFilter === 'resolved') filtered = filtered.filter(f => f.resolved);
  document.getElementById('leak-count').textContent = `${filtered.length} of ${allLeaks.length}`;
  renderLeaks(filtered);
}

function renderLeaks(findings) {
  const el = document.getElementById('leaks-list');
  if (!findings.length) {
    el.innerHTML = '<div class="empty" style="color:var(--green)">✓ No findings match current filters.</div>';
    return;
  }
  const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--red)', MEDIUM: 'var(--yellow)', INFO: 'var(--muted)' };
  el.innerHTML = findings.map(f => {
    const resolved = f.resolved;
    const repo = f.repo_name || f.repo || '';
    const runAt = f.run_at ? ` · ${new Date(f.run_at).toLocaleDateString()}` : '';
    return `<div class="leak-card ${resolved ? 'resolved' : ''}">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
        <span style="font-size:10px;font-weight:700;color:${sevColor[f.severity]}">${f.severity}</span>
        <span style="font-size:10px;color:var(--muted)">${f.category}</span>
        ${resolved ? '<span style="font-size:10px;color:var(--green);margin-left:4px">✓ resolved</span>' : ''}
        <span style="font-size:10px;color:var(--accent);margin-left:auto">${repo}${runAt}</span>
      </div>
      <div class="lc-desc" style="font-size:12px;color:var(--text);margin-bottom:6px">${f.description}</div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:6px">📍 ${f.location || '—'}</div>
      ${!resolved ? `<div style="background:rgba(0,0,0,.3);border-radius:4px;padding:6px 10px;font-size:11px;word-break:break-all">
        Fix: <code style="color:var(--yellow)">${f.fix || '—'}</code>
      </div>` : ''}
    </div>`;
  }).join('');
}

async function runLiveScan() {
  const repoSel = document.getElementById('leak-repo-filter').value;
  if (!repoSel) { document.getElementById('scan-status').textContent = 'Select a repo first'; return; }
  const status = document.getElementById('scan-status');
  status.textContent = `Scanning ${repoSel}…`;
  status.style.color = 'var(--muted)';
  const res = await fetch(`/api/leaks/scan/${repoSel}`, { method: 'POST' });
  const findings = await res.json();
  allLeaks = findings.map(f => ({ ...f, repo: repoSel }));
  status.textContent = `${findings.length} finding${findings.length!==1?'s':''} found`;
  status.style.color = findings.length ? 'var(--red)' : 'var(--green)';
  filterLeaks();
}

// ── Vault ────────────────────────────────────────────────────────────────────
async function checkVaultStatus() {
  const res = await fetch(BOSWELL_BASE+'/api/vault/status');
  const data = await res.json();
  vaultUnlocked = data.unlocked;
  updateVaultBadge();
}
function updateVaultBadge() {
  const badge = document.getElementById('vault-badge');
  badge.className = 'vault-badge ' + (vaultUnlocked ? 'unlocked' : 'locked');
  badge.textContent = vaultUnlocked ? '⚿ unlocked' : '⚿ locked';
}
async function renderVaultPage() {
  await checkVaultStatus();
  const el = document.getElementById('vault-content');
  if (!vaultUnlocked) {
    const statusRes = await fetch(BOSWELL_BASE+'/api/vault/status');
    const status = await statusRes.json();
    const isNew = !status.exists;
    el.innerHTML = `<div class="vault-lock-form">
      <p style="color:var(--muted);font-size:12px;margin-bottom:12px">${isNew ? 'Create a master password to initialize your vault.' : 'Enter your master password to unlock the vault.'}</p>
      <input type="password" id="vault-pw" placeholder="master password" autocomplete="off"/>
      <br/><button onclick="${isNew ? 'createVault' : 'unlockVault'}()">${isNew ? 'Create Vault' : 'Unlock'}</button>
      <div id="vault-err" class="err"></div>
    </div>`;
    return;
  }
  const res = await fetch(BOSWELL_BASE+'/api/vault/secrets');
  const secrets = await res.json();
  const repoNames = Object.keys(secrets);
  if (!repoNames.length) {
    el.innerHTML = `<p style="color:var(--muted);font-size:12px">No secrets stored yet.</p>
      <button onclick="lockVault()" style="margin-top:16px;font-family:var(--font);font-size:11px;padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--red);cursor:pointer;">Lock vault</button>`;
    return;
  }
  el.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <span style="font-size:11px;color:var(--muted)">${repoNames.length} repo${repoNames.length!==1?'s':''} · vault unlocked</span>
      <button onclick="lockVault()" style="font-family:var(--font);font-size:11px;padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--red);cursor:pointer;">Lock vault</button>
    </div>
    ${repoNames.map(repo => `<div class="vault-section"><h3>${repo}</h3>${secrets[repo].map(s => `
      <div class="secret-row">
        <span class="secret-key">${s.key}</span>
        <span class="secret-val" id="sv-${repo}-${s.key}">••••••••</span>
        <button class="secret-btn" onclick="revealSecret('${repo}','${s.key}')">reveal</button>
      </div>`).join('')}</div>`).join('')}
    <hr style="border-color:var(--border);margin:20px 0"/>
    <select id="ingest-repo" style="background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font);font-size:12px;padding:6px 10px;border-radius:5px;margin-right:8px">
      ${repos.map(r => `<option value="${r.name}">${r.name}</option>`).join('')}
    </select>
    <button class="ingest-btn" onclick="ingestSecrets()">+ Ingest from .env</button>
    <div id="ingest-msg" style="font-size:11px;margin-top:6px"></div>`;
}
async function createVault() {
  const pw = document.getElementById('vault-pw').value;
  const res = await fetch(BOSWELL_BASE+'/api/vault/create', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
  if (res.ok) { vaultUnlocked = true; updateVaultBadge(); renderVaultPage(); }
  else { const e = await res.json(); document.getElementById('vault-err').textContent = e.detail; }
}
async function unlockVault() {
  const pw = document.getElementById('vault-pw').value;
  const res = await fetch(BOSWELL_BASE+'/api/vault/unlock', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
  if (res.ok) { vaultUnlocked = true; updateVaultBadge(); renderVaultPage(); }
  else { document.getElementById('vault-err').textContent = 'Wrong password'; }
}
async function lockVault() {
  await fetch(BOSWELL_BASE+'/api/vault/lock', { method: 'POST' });
  vaultUnlocked = false; updateVaultBadge(); renderVaultPage();
}
async function revealSecret(repo, key) {
  const password = window.prompt("Vault password to reveal this secret");
  if (!password) return;
  const res = await fetch(`/api/vault/secret/${repo}/${key}`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({password}),
  });
  if (!res.ok) { alert("Wrong vault password"); return; }
  const data = await res.json();
  const el = document.getElementById(`sv-${repo}-${key}`);
  if (el) { el.textContent = data.value; el.classList.add('revealed'); }
}
async function ingestSecrets() {
  const repo = document.getElementById('ingest-repo').value;
  const msg = document.getElementById('ingest-msg');
  msg.textContent = 'Reading .env files…'; msg.style.color = 'var(--muted)';
  const res = await fetch(`/api/vault/ingest/${repo}`, { method: 'POST' });
  const data = await res.json();
  if (res.ok) {
    msg.textContent = `Stored ${data.stored} secret${data.stored!==1?'s':''}: ${data.keys.join(', ')}`;
    msg.style.color = 'var(--green)';
    setTimeout(() => renderVaultPage(), 1000);
  } else { msg.textContent = 'Failed'; msg.style.color = 'var(--red)'; }
}

// ── Fixes / Findings ──────────────────────────────────────────────────────────
let allFindings = [];
let resolvedFindings = [];

async function importFindings(name) {
  const btn = document.getElementById(`import-btn-${name}`);
  if (btn) { btn.disabled = true; btn.textContent = 'importing…'; }
  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/import-findings`, { method: 'POST' });
    const data = await res.json();
    if (btn) { btn.textContent = `✓ ${data.imported} imported`; setTimeout(() => { btn.textContent = 'reimport'; btn.disabled = false; }, 3000); }
    await loadFixes();
  } catch (e) {
    if (btn) { btn.textContent = 'import'; btn.disabled = false; }
    alert('Import failed: ' + e.message);
  }
}

async function toggleResolve(id, currentlyResolved) {
  const btn = document.getElementById(`resolve-btn-${id}`);
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  const endpoint = currentlyResolved ? `/api/findings/${id}/reopen` : `/api/findings/${id}/resolve`;
  try {
    await fetch(endpoint, { method: 'POST' });
    await loadFixes();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = currentlyResolved ? 'reopen' : 'resolve'; }
  }
}

async function importAll() {
  const btn = document.getElementById('import-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'importing…'; }
  try {
    const res = await fetch(BOSWELL_BASE + '/api/import-all', { method: 'POST' });
    const data = await res.json();
    if (btn) {
      btn.textContent = `✓ ${data.imported_repos} repos · ${data.total_findings} findings`;
      if (data.errors && data.errors.length) {
        btn.title = 'Errors: ' + data.errors.map(e => e.name + ': ' + e.error).join('; ');
      }
      setTimeout(() => { btn.textContent = '⟳ import all'; btn.disabled = false; btn.title = ''; }, 4000);
    }
  } catch (e) {
    if (btn) { btn.textContent = 'error — retry'; btn.disabled = false; }
  }
  await loadFixes();
}

// ── Selection & Fix ──────────────────────────────────────────────────────────
let selectedFindings = new Set();

function toggleFindingSelect(id, checked) {
  if (checked) selectedFindings.add(id); else selectedFindings.delete(id);
  updateSelectionBar();
}

function updateSelectionBar() {
  const bar = document.getElementById('selection-bar');
  const count = document.getElementById('sel-count');
  if (selectedFindings.size === 0) { bar.style.display = 'none'; return; }
  bar.style.display = 'flex';
  count.textContent = selectedFindings.size;
}

function clearSelection() {
  selectedFindings.clear();
  document.querySelectorAll('.finding-checkbox').forEach(cb => cb.checked = false);
  updateSelectionBar();
}

async function copyFixPrompt() {
  const findings = allFindings.filter(f => selectedFindings.has(f.id));
  const byRepo = {};
  findings.forEach(f => { if (!byRepo[f.repo]) byRepo[f.repo] = []; byRepo[f.repo].push(f); });

  let prompt = '';
  for (const [repo, repoFindings] of Object.entries(byRepo)) {
    prompt += `Fix the following security findings in the ${repo} repo:\n\n`;
    repoFindings.forEach((f, i) => {
      prompt += `${i+1}. [${f.severity}] ${f.category || 'Security'}\n   ${f.description}`;
      if (f.location) prompt += `\n   Location: ${f.location}`;
      prompt += '\n\n';
    });
  }

  await navigator.clipboard.writeText(prompt.trim());
  const btn = document.getElementById('copy-prompt-btn');
  btn.textContent = '✓ copied';
  setTimeout(() => btn.textContent = '📋 copy prompt', 2500);
}

async function autoFix() {
  const btn = document.getElementById('auto-fix-btn');
  btn.disabled = true; btn.textContent = 'fixing…';
  try {
    const res = await fetch(BOSWELL_BASE + '/api/fix-selected', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_ids: [...selectedFindings] })
    });
    const data = await res.json();
    if (data.error) { btn.textContent = 'error'; btn.title = data.error; btn.disabled = false; return; }
    btn.textContent = `✓ ${data.fixed_count} fixed`;
    if (data.errors && data.errors.length) btn.title = data.errors.join('; ');
    setTimeout(() => { btn.textContent = '⚡ auto-fix'; btn.disabled = false; btn.title = ''; }, 4000);
    clearSelection();
    await loadFixes();
  } catch (e) {
    btn.textContent = 'error'; btn.disabled = false;
  }
}

async function loadFixes() {
  document.getElementById('fixes-list').innerHTML = '<div class="loading">loading…</div>';

  // Load findings from Neon for all repos (has real IDs)
  allFindings = [];
  for (const repo of repos) {
    try {
      const res = await fetch(`/api/repo/${repo.name}/neon-findings`);
      if (res.ok) {
        const found = await res.json();
        found.forEach(f => allFindings.push({ ...f, repo: f.repo_name || repo.name }));
      }
    } catch {}
  }

  // Populate repo filter
  const sel = document.getElementById('fixes-repo-filter');
  const prev = sel.value;
  sel.innerHTML = '<option value="">All repos</option>';
  [...new Set(allFindings.map(f => f.repo))].forEach(r => {
    const o = document.createElement('option');
    o.value = r; o.textContent = r;
    sel.appendChild(o);
  });
  sel.value = prev;

  renderFindingsStats();
  filterFindings();
}

function renderFindingsStats() {
  const total = allFindings.length;
  const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const high = allFindings.filter(f => f.severity === 'HIGH').length;
  const resolved = allFindings.filter(f => f.resolved).length;
  document.getElementById('fixes-stats').innerHTML = `
    <div class="stat"><div class="val">${total}</div><div class="lbl">total findings</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">${critical}</div><div class="lbl">critical</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">${high}</div><div class="lbl">high</div></div>
    <div class="stat"><div class="val" style="color:var(--green)">${resolved}</div><div class="lbl">resolved</div></div>
    <div class="stat"><div class="val" style="color:${total-resolved?'var(--red)':'var(--green)'}">${total-resolved}</div><div class="lbl">open</div></div>
  `;
}

function filterFindings() {
  const repoFilter = document.getElementById('fixes-repo-filter').value;
  const sevFilter = document.getElementById('fixes-sev-filter').value;
  const statusFilter = document.getElementById('fixes-status-filter').value;
  let filtered = allFindings;
  if (repoFilter) filtered = filtered.filter(f => f.repo === repoFilter);
  if (sevFilter) filtered = filtered.filter(f => f.severity === sevFilter);
  if (statusFilter === 'open') filtered = filtered.filter(f => !f.resolved);
  if (statusFilter === 'resolved') filtered = filtered.filter(f => f.resolved);
  document.getElementById('findings-count').textContent = `${filtered.length} of ${allFindings.length}`;

  const el = document.getElementById('fixes-list');

  // Show import buttons for repos with no Neon findings
  const reposWithFindings = new Set(allFindings.map(f => f.repo));
  const noFindings = repos.filter(r => !reposWithFindings.has(r.name));
  let importHtml = '';
  if (noFindings.length) {
    importHtml = `<div style="margin-bottom:16px;padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px">
      <div style="color:var(--muted);font-size:11px;margin-bottom:8px">These repos have audit.md but no findings imported yet:</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${noFindings.map(r => `<button id="import-btn-${r.name}" onclick="importFindings('${r.name}')" style="font-family:var(--font);font-size:11px;padding:4px 10px;border-radius:5px;border:1px solid var(--teal);background:none;color:var(--teal);cursor:pointer">${r.name} → import</button>`).join('')}
      </div>
    </div>`;
  }

  if (!filtered.length) {
    el.innerHTML = importHtml + '<div class="empty" style="color:var(--green)">✓ No findings match current filters.</div>';
    return;
  }

  // Group by repo
  const byRepo = {};
  filtered.forEach(f => { if (!byRepo[f.repo]) byRepo[f.repo] = []; byRepo[f.repo].push(f); });

  const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--red)', MEDIUM: 'var(--yellow)', LOW: 'var(--muted)', INFO: 'var(--muted)' };

  el.innerHTML = importHtml + Object.entries(byRepo).map(([repo, findings]) => {
    const open = findings.filter(f => !f.resolved).length;
    const res = findings.filter(f => f.resolved).length;
    return `<div style="margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-size:13px;color:var(--accent);font-weight:600">${repo}</span>
        ${open ? `<span class="pill pill-red">${open} open</span>` : ''}
        ${res ? `<span class="pill pill-green">${res} resolved</span>` : ''}
        <button id="import-btn-${repo}" onclick="importFindings('${repo}')" style="font-family:var(--font);font-size:10px;padding:2px 7px;border-radius:4px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;margin-left:auto">reimport</button>
      </div>
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden">
        ${findings.map(f => {
          const desc = (f.description || '').replace(/\*\*/g,'').replace(/`/g,'');
          const shortDesc = desc.length > 120 ? desc.slice(0,120)+'…' : desc;
          return `<div class="finding-row ${f.resolved ? 'finding-resolved' : ''}" style="display:flex;align-items:flex-start;gap:10px">
            <input type="checkbox" class="finding-checkbox" data-id="${f.id}" onchange="toggleFindingSelect(${f.id}, this.checked)"
              style="margin-top:3px;flex-shrink:0;cursor:pointer;accent-color:var(--teal)" ${f.resolved ? 'disabled' : ''}>
            <span class="finding-sev" style="color:${sevColor[f.severity]};white-space:nowrap;flex-shrink:0">${f.severity}</span>
            <span class="finding-text" style="flex:1" title="${desc.replace(/"/g,'&quot;')}">${shortDesc}</span>
            <button id="resolve-btn-${f.id}" onclick="toggleResolve(${f.id}, ${!!f.resolved})"
              style="font-family:var(--font);font-size:10px;padding:2px 7px;border-radius:4px;border:1px solid var(--border);background:none;cursor:pointer;flex-shrink:0;color:${f.resolved ? 'var(--muted)' : 'var(--green)'}"
            >${f.resolved ? 'reopen' : 'resolve'}</button>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }).join('');
}

// ── Standards ────────────────────────────────────────────────────────────────
async function loadStandards() {
  const el = document.getElementById('standards-content');
  const pathEl = document.getElementById('standards-path');
  el.innerHTML = '<div class="loading">loading…</div>';
  try {
    const res = await fetch(BOSWELL_BASE+'/api/standards');
    const data = await res.json();
    if (!data.content) {
      el.innerHTML = '<div class="empty">EDDIE_BUILD_STANDARDS.md not found.<br/>Expected at ~/Documents/EDDIE_BUILD_STANDARDS.md</div>';
      return;
    }
    pathEl.textContent = data.path;
    el.innerHTML = renderStandardsMarkdown(data.content);
  } catch {
    el.innerHTML = '<div class="empty">Failed to load standards.</div>';
  }
}

function renderStandardsMarkdown(md) {
  // Escape HTML
  let s = md.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Fenced code blocks
  s = s.replace(/```[\w]*\n([\s\S]*?)```/gm, (_, code) =>
    `<pre><code>${code.trimEnd()}</code></pre>`);

  // Tables
  s = s.replace(/^\|(.+)\|$/gm, line => {
    if (/^[\|\-\s]+$/.test(line.replace(/[|]/g, ''))) return '<tr class="sep"></tr>';
    const cells = line.split('|').slice(1,-1).map(c => c.trim());
    return '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
  });
  s = s.replace(/(<tr.*<\/tr>\n*)+/g, match => {
    const rows = match.trim().split('\n').filter(r => !r.includes('class="sep"'));
    if (!rows.length) return '';
    const [head, ...body] = rows;
    const headerCells = head.replace(/<\/?t[dr]>/g,'|').split('|').filter(Boolean);
    const theadRow = '<tr>' + headerCells.map(c=>`<th>${c}</th>`).join('') + '</tr>';
    return `<table><thead>${theadRow}</thead><tbody>${body.join('\n')}</tbody></table>`;
  });

  // Headings
  s = s.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  s = s.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  s = s.replace(/^### (.+)$/gm, '<h3>$1</h3>');

  // HR
  s = s.replace(/^---$/gm, '<hr>');

  // Inline
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Blockquote
  s = s.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');

  // Line breaks for non-block content
  s = s.replace(/\n(?!<)/g, '\n');

  return s;
}

// ── Init ─────────────────────────────────────────────────────────────────────
checkVaultStatus();
checkDbStatus();
loadRepos();

// ── Disable / Enable deployment ──────────────────────────────────────────────
const _deployState = {};
async function toggleDeploy(name, btn) {
  const disabled = _deployState[name];
  const action = disabled ? 'enable' : 'disable';
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/${action}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok || data.error) {
      alert(`Failed to ${action} ${name}: ${data.error || 'unknown error'}`);
      btn.textContent = disabled ? '▶ Enable' : '⏸ Disable';
    } else {
      _deployState[name] = !disabled;
      btn.textContent = _deployState[name] ? '▶ Enable' : '⏸ Disable';
      btn.style.color = _deployState[name] ? 'var(--red)' : 'var(--text)';
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
    btn.textContent = disabled ? '▶ Enable' : '⏸ Disable';
  }
  btn.disabled = false;
}

// ── Fix issues ───────────────────────────────────────────────────────────────
async function fixCode(name, btn) {
  if (!confirm(`Run Boswell Fix & Ship on "${name}"?\n\nThis will:\n• Send HIGH/CRITICAL findings + files to Gemini 2.5 Flash\n• Write patched files back to disk\n• If ALL fixed: merge to main and push (CI/CD auto-deploys)\n• If ANY unfixable: take the deployment offline and push the partial branch for review`)) return;
  btn.disabled = true;
  btn.textContent = '⏳ Fixing…';
  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/fix-code`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      alert(`Fix failed: ${data.detail || 'unknown error'}`);
      btn.textContent = '🔧 Fix & Ship';
      btn.disabled = false;
      return;
    }
    alert(data.alert || (data.fixed > 0 ? `Fixed ${data.fixed} issue(s).` : `Nothing fixed (${data.skipped} skipped).`));
    if (data.status === 'shipped') {
      btn.textContent = '✅ Shipped';
    } else if (data.status === 'disabled') {
      btn.textContent = '⚠ Taken offline';
      btn.style.borderColor = 'var(--yellow)';
      btn.style.color = 'var(--yellow)';
    } else {
      btn.textContent = data.fixed > 0 ? `✓ ${data.fixed} fixed` : '🔧 Fix & Ship';
    }
    btn.disabled = false;
  } catch (e) {
    alert('Fix request failed: ' + e.message);
    btn.textContent = '🔧 Fix & Ship';
    btn.disabled = false;
  }
}

async function checkJobs(name, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Checking…';
  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/job-health`);
    const data = await res.json();
    if (!res.ok) { alert('Error: ' + (data.detail || 'unknown')); return; }
    const jobs = data.jobs_defined || [];
    let msg = `📋 Job Health: ${name}\n\n${data.note}\n`;
    if (jobs.length) {
      msg += '\nDefined jobs:\n' + jobs.map(j =>
        `  • ${j.source}${j.schedule ? ' @ ' + j.schedule : ''}${j.path ? ' → ' + j.path : ''}`
      ).join('\n');
    }
    if (data.recent_executions?.length) {
      msg += `\n\nRecent executions: ${data.recent_executions.length} event(s) found in logs`;
    }
    if (!data.execution_evidence && jobs.length) {
      msg += '\n\n⚠ Add VERCEL_TOKEN or CF_API_TOKEN to ~/.boswell/.env for live execution verification.';
    }
    alert(msg);
  } catch (e) {
    alert('Job health check failed: ' + e.message);
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
}

// ── Entropy ───────────────────────────────────────────────────────────────────
const _entropyColor = score =>
  score <= 15 ? 'var(--green)' :
  score <= 30 ? 'var(--teal)' :
  score <= 50 ? 'var(--yellow)' :
  score <= 70 ? 'var(--red)' : 'var(--red)';

async function loadEntropy(name) {
  const badge = document.getElementById(`entropy-badge-${name}`);
  const detail = document.getElementById(`entropy-detail-${name}`);
  if (!badge) return;
  badge.textContent = '…';
  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/entropy?snapshot=true`);
    const d = await res.json();
    if (!res.ok) { badge.textContent = 'err'; return; }
    const score = d.overall_entropy;
    const color = _entropyColor(score);
    badge.textContent = `${score} ${d.label}`;
    badge.style.background = `rgba(0,0,0,0.3)`;
    badge.style.color = color;
    badge.style.border = `1px solid ${color}`;
    if (detail) {
      detail.style.display = 'block';
      detail.innerHTML = `
        <span style="color:var(--red)">sec ${d.security_score}</span> ·
        <span style="color:var(--yellow)">arch ${d.architecture_score}</span> ·
        <span style="color:var(--muted)">maint ${d.maintainability_score}</span> ·
        <span style="color:var(--muted)">deps ${d.dependency_score}</span>`;
    }
  } catch (e) {
    badge.textContent = 'err';
  }
}

async function scanAllEntropy(statEl) {
  const valEl = document.getElementById('avg-entropy-val');
  if (valEl) valEl.textContent = '…';
  try {
    const res = await fetch(BOSWELL_BASE+'/api/entropy/snapshot-all', { method: 'POST' });
    const results = await res.json();
    results.forEach(r => {
      if (!r.error) {
        const badge = document.getElementById(`entropy-badge-${r.name}`);
        const detail = document.getElementById(`entropy-detail-${r.name}`);
        if (badge) {
          const color = _entropyColor(r.entropy);
          badge.textContent = `${r.entropy} ${r.label}`;
          badge.style.color = color;
          badge.style.border = `1px solid ${color}`;
        }
      }
    });
    const scores = results.filter(r => r.entropy != null).map(r => r.entropy);
    const avg = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0;
    if (valEl) { valEl.textContent = avg; valEl.style.color = _entropyColor(avg); }
  } catch (e) {
    if (valEl) valEl.textContent = 'err';
  }
}

// ── Portfolio Assessment ──────────────────────────────────────────────────────
async function loadPortfolio() {
  const el = document.getElementById('portfolio-content');
  el.innerHTML = '<div class="loading">loading cached assessment…</div>';
  const res = await fetch(BOSWELL_BASE+'/api/portfolio/assess');
  const data = await res.json();
  renderPortfolio(el, data);
}

async function generatePortfolio() {
  const el = document.getElementById('portfolio-content');
  el.innerHTML = '<div class="loading">Analysing ' + repos.length + ' repos via Gemini 2.5 Flash… (30-60s)</div>';
  try {
    const res = await fetch(BOSWELL_BASE+'/api/portfolio/assess', { method: 'POST' });
    if (!res.ok) { const e = await res.json(); el.innerHTML = `<div class="err">Error: ${e.detail}</div>`; return; }
    const data = await res.json();
    renderPortfolio(el, data);
  } catch (e) {
    el.innerHTML = `<div class="err">Failed: ${e.message}</div>`;
  }
}

function renderPortfolio(el, data) {
  const confColor = { high: 'var(--red)', medium: 'var(--yellow)', low: 'var(--muted)' };

  if (!data || !data.developer_assessment) {
    el.innerHTML = `<div style="text-align:center;padding:40px 0">
      <div style="color:var(--muted);font-size:12px;margin-bottom:16px">No assessment yet. Generate one to get shutdown candidates, merge opportunities, and a developer profile.</div>
      <button onclick="generatePortfolio()" style="font-family:var(--font);font-size:12px;padding:8px 20px;border-radius:6px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer">Generate Portfolio Assessment</button>
    </div>`;
    return;
  }

  const dev = data.developer_assessment;
  const shutdowns = data.shutdown_candidates || [];
  const merges = data.merge_candidates || [];

  el.innerHTML = `
    <div style="display:flex;gap:10px;margin-bottom:24px;align-items:center">
      <button onclick="generatePortfolio()" style="font-family:var(--font);font-size:11px;padding:5px 14px;border-radius:5px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer">↺ Regenerate</button>
    </div>

    <!-- Developer Profile -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px 24px;margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px">
        <div>
          <div style="font-size:15px;font-weight:700;color:var(--accent)">${dev.vibe_label || 'Developer'}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">Vibe Score: ${dev.vibe_score}/10</div>
        </div>
        <div style="margin-left:auto;width:48px;height:48px;border-radius:50%;background:conic-gradient(var(--accent) ${(dev.vibe_score||5)*36}deg, var(--border) 0deg);display:flex;align-items:center;justify-content:center">
          <div style="width:36px;height:36px;border-radius:50%;background:var(--surface);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:var(--accent)">${dev.vibe_score}</div>
        </div>
      </div>
      <p style="font-size:12px;line-height:1.7;color:var(--text);margin-bottom:16px">${dev.summary || ''}</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px">
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--green);margin-bottom:8px">Strengths</div>
          ${(dev.strengths||[]).map(s => `<div style="font-size:11px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--border)">✓ ${s}</div>`).join('')}
        </div>
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--red);margin-bottom:8px">Recurring Mistakes</div>
          ${(dev.recurring_mistakes||[]).map(s => `<div style="font-size:11px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--border)">✗ ${s}</div>`).join('')}
        </div>
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--yellow);margin-bottom:8px">Learn Next</div>
          ${(dev.learn_next||[]).map(s => `<div style="font-size:11px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--border)">→ ${s}</div>`).join('')}
        </div>
      </div>
    </div>

    <!-- Shutdown Candidates -->
    <div style="margin-bottom:20px">
      <h3 style="font-size:13px;color:var(--red);margin-bottom:12px">⛔ Shutdown Candidates (${shutdowns.length})</h3>
      ${!shutdowns.length ? '<div style="color:var(--muted);font-size:12px">No shutdown candidates identified.</div>' :
        shutdowns.map(s => `<div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:6px;padding:12px 16px;margin-bottom:8px;display:flex;align-items:flex-start;gap:12px">
          <div style="flex:1">
            <div style="font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px">${s.name}</div>
            <div style="font-size:12px;color:var(--text);line-height:1.5">${s.reason}</div>
          </div>
          <span style="font-size:10px;font-weight:700;color:${confColor[s.confidence]||'var(--muted)'};flex-shrink:0;padding-top:2px">${(s.confidence||'').toUpperCase()}</span>
        </div>`).join('')}
    </div>

    <!-- Merge Candidates -->
    <div>
      <h3 style="font-size:13px;color:var(--yellow);margin-bottom:12px">⇢ Merge Candidates (${merges.length})</h3>
      ${!merges.length ? '<div style="color:var(--muted);font-size:12px">No merge candidates identified.</div>' :
        merges.map(m => `<div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--yellow);border-radius:6px;padding:12px 16px;margin-bottom:8px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
            ${(m.repos||[]).map(r => `<span style="font-size:11px;background:rgba(249,226,175,.1);color:var(--yellow);padding:2px 8px;border-radius:4px;font-weight:600">${r}</span>`).join('<span style="color:var(--muted);font-size:11px">+</span>')}
            ${m.combined_name ? `<span style="font-size:10px;color:var(--muted);margin-left:4px">→ ${m.combined_name}</span>` : ''}
          </div>
          <div style="font-size:12px;color:var(--text);line-height:1.5">${m.reason}</div>
        </div>`).join('')}
    </div>`;
}

// ── Ship Readiness check ──────────────────────────────────────────────────────
async function shipCheck(name, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Checking…';

  const CHECK_LABELS = {
    build: 'Build',
    live: 'Live ping',
    deployment: 'Deployment health',
    env_vars: 'Env vars',
    health_endpoint: 'Health endpoint',
    auth_endpoint: 'Auth endpoint',
    security: 'Security findings',
  };
  const STATUS_ICON = { pass: '✅', fail: '❌', warn: '⚠️', skip: '⏭' };

  try {
    const res = await fetch(`/api/repo/${encodeURIComponent(name)}/ship-check`);
    const data = await res.json();
    if (!res.ok) { alert('Error: ' + (data.detail || 'unknown')); return; }

    let msg = `🚀 Ship Readiness: ${name} [${data.platform || 'unknown'}]\n`;
    if (data.overall === 'pass') msg += `✅ CERTIFIED READY — ${data.passed} check(s) passed\n`;
    else if (data.overall === 'fail') msg += `❌ NOT READY — ${data.failed} check(s) failed\n`;
    else msg += `⚠️ CAUTION — ${data.warned} warning(s), ${data.passed} passed\n`;
    msg += '\n';

    for (const check of data.checks) {
      const icon = STATUS_ICON[check.status] || '?';
      const label = CHECK_LABELS[check.name] || check.name;
      msg += `${icon} ${label}`;
      if (check.status !== 'pass') msg += `\n   ${check.detail}`;
      msg += '\n';
    }

    if (data.overall !== 'pass') {
      msg += '\n(Build check skipped — run npm run build locally to verify)';
    }

    alert(msg);

    if (data.overall === 'pass') {
      btn.textContent = '✅ Ready';
      btn.style.borderColor = 'var(--green)';
      btn.style.color = 'var(--green)';
    } else if (data.overall === 'fail') {
      btn.textContent = '❌ Not ready';
      btn.style.borderColor = 'var(--red)';
      btn.style.color = 'var(--red)';
    } else {
      btn.textContent = '⚠ Caution';
      btn.style.borderColor = 'var(--yellow)';
      btn.style.color = 'var(--yellow)';
    }
  } catch (e) {
    alert('Ship check failed: ' + e.message);
    btn.textContent = orig;
    btn.style.borderColor = '';
    btn.style.color = '';
  }
  btn.disabled = false;
}

// ── Live refresh — polls every 15s while a batch is running ──────────────────
async function pollIfRunning() {
  try {
    const res = await fetch(BOSWELL_BASE+'/api/repos');
    if (!res.ok) return;
    const fresh = await res.json();
    const audited = fresh.filter(r => r.meta).length;
    const prev = repos.filter(r => r.meta).length;
    if (audited !== prev) {
      repos = fresh;
      renderSidebar();
      if (document.getElementById('page-overview').classList.contains('active')) renderOverview();
    }
  } catch { /* ignore */ }
}
setInterval(pollIfRunning, 15000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
@app.get("/{path:path}", response_class=HTMLResponse)
def shell(path: str = ""):
    if path.startswith("api/"):
        raise HTTPException(404)
    return HTML.replace("__BOSWELL_TOKEN__", api_token(), 1)
