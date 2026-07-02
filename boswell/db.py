"""Neon Postgres persistence for Boswell scan results.

Set BOSWELL_DATABASE_URL to a Neon connection string to enable.
If the env var is absent, every function is a silent no-op.
"""

import json
import os
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS boswell_runs (
    id          SERIAL PRIMARY KEY,
    repo_name   TEXT NOT NULL,
    repo_path   TEXT,
    run_at      TIMESTAMPTZ DEFAULT NOW(),
    cost_usd    NUMERIC(10,4),
    stack       JSONB,
    env_vars    JSONB
);

CREATE TABLE IF NOT EXISTS boswell_findings (
    id          SERIAL PRIMARY KEY,
    run_id      INTEGER REFERENCES boswell_runs(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL,
    location    TEXT,
    fix         TEXT,
    resolved    BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS boswell_docs (
    id          SERIAL PRIMARY KEY,
    run_id      INTEGER REFERENCES boswell_runs(id) ON DELETE CASCADE,
    doc_type    TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repo_entropy_snapshots (
    id                   SERIAL PRIMARY KEY,
    repo_name            TEXT NOT NULL,
    snapshot_at          TIMESTAMPTZ DEFAULT NOW(),
    entropy_score        INTEGER,
    security_score       INTEGER,
    architecture_score   INTEGER,
    maintainability_score INTEGER,
    dependency_score     INTEGER,
    details              JSONB
);

CREATE INDEX IF NOT EXISTS idx_entropy_repo_name ON repo_entropy_snapshots(repo_name);
CREATE INDEX IF NOT EXISTS idx_entropy_snapshot_at ON repo_entropy_snapshots(snapshot_at DESC);

CREATE TABLE IF NOT EXISTS boswell_repo_meta (
    repo_name   TEXT PRIMARY KEY,
    deployed_url TEXT DEFAULT '',
    stack       JSONB DEFAULT '[]',
    platforms   JSONB DEFAULT '[]',
    run_at      TIMESTAMPTZ,
    last_score  NUMERIC,
    updated_at  TIMESTAMPTZ DEFAULT now()
);
"""


def get_url() -> str | None:
    return os.environ.get("BOSWELL_DATABASE_URL")


def _conn(url: str):
    import psycopg2
    return psycopg2.connect(url)


def init_db(url: str) -> None:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
        conn.commit()


def save_run(
    url: str,
    repo_name: str,
    repo_path: str,
    cost_usd: float,
    stack: list[str],
    env_vars: list[str],
) -> int:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO boswell_runs (repo_name, repo_path, cost_usd, stack, env_vars)
                   VALUES (%s, %s, %s, %s::jsonb, %s::jsonb) RETURNING id""",
                (repo_name, repo_path, cost_usd,
                 json.dumps(stack), json.dumps(env_vars)),
            )
            run_id = cur.fetchone()[0]
        conn.commit()
    return run_id


def save_findings(url: str, run_id: int, findings: list[dict]) -> list[int]:
    if not findings:
        return []
    ids: list[int] = []
    with _conn(url) as conn:
        with conn.cursor() as cur:
            for f in findings:
                cur.execute(
                    """INSERT INTO boswell_findings
                       (run_id, severity, category, description, location, fix)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                    (run_id, f["severity"], f["category"],
                     f["description"], f.get("location"), f.get("fix")),
                )
                ids.append(cur.fetchone()[0])
        conn.commit()
    return ids


def save_docs(url: str, run_id: int, docs: dict[str, str]) -> None:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            for doc_type, content in docs.items():
                cur.execute(
                    "INSERT INTO boswell_docs (run_id, doc_type, content) VALUES (%s, %s, %s)",
                    (run_id, doc_type, content),
                )
        conn.commit()


def import_audit_findings(url: str, run_id: int, audit_text: str) -> int:
    """Parse all [SEVERITY] findings from audit.md and insert into boswell_findings.
    Skips descriptions that already exist under this run_id (idempotent).
    Returns the number of new rows inserted.
    """
    import re as _re

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    raw: list[dict] = []
    for line in audit_text.splitlines():
        stripped = line.strip().lstrip("- ").strip()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{sev}]" not in stripped:
                continue
            title_m = _re.search(r'\*\*\[' + sev + r'\]\s*([^\*]+)\*\*', stripped)
            title = title_m.group(1).strip(" —") if title_m else sev
            tl = title.lower()
            if any(k in tl for k in ("secret","credential","hardcoded","token","key","password","committed")):
                cat = "secrets"
            elif any(k in tl for k in ("inject","sql","xss","csrf")):
                cat = "injection"
            elif any(k in tl for k in ("auth","unauthenticated","access control","session")):
                cat = "auth"
            elif any(k in tl for k in ("cors","config","runtime","env")):
                cat = "config"
            elif any(k in tl for k in ("supabase","migration","database","neon")):
                cat = "database"
            else:
                cat = "audit"
            loc_m = _re.search(r'`([^`]*(?:app|api|lib|src|route|page|worker)[^`]*)`', stripped)
            raw.append({
                "severity": sev,
                "category": cat,
                "description": stripped,
                "location": loc_m.group(1) if loc_m else None,
            })
            break

    if not raw:
        return 0

    raw.sort(key=lambda x: severity_order.get(x["severity"], 9))

    inserted = 0
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT description FROM boswell_findings WHERE run_id=%s", (run_id,))
            existing = {r[0] for r in cur.fetchall()}
            for f in raw:
                if f["description"] in existing:
                    continue
                cur.execute(
                    """INSERT INTO boswell_findings (run_id, severity, category, description, location)
                       VALUES (%s,%s,%s,%s,%s)""",
                    (run_id, f["severity"], f["category"], f["description"], f["location"]),
                )
                inserted += 1
        conn.commit()
    return inserted


def mark_resolved(url: str, finding_id: int) -> None:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE boswell_findings SET resolved=TRUE, resolved_at=NOW() WHERE id=%s",
                (finding_id,),
            )
        conn.commit()


def list_findings(url: str, repo_name: str | None = None) -> list[dict[str, Any]]:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            if repo_name:
                cur.execute(
                    """SELECT f.id, f.severity, f.category, f.description,
                              f.location, f.fix, f.resolved, r.repo_name, r.run_at
                       FROM boswell_findings f
                       JOIN boswell_runs r ON r.id = f.run_id
                       WHERE r.repo_name = %s
                       ORDER BY f.created_at DESC""",
                    (repo_name,),
                )
            else:
                cur.execute(
                    """SELECT f.id, f.severity, f.category, f.description,
                              f.location, f.fix, f.resolved, r.repo_name, r.run_at
                       FROM boswell_findings f
                       JOIN boswell_runs r ON r.id = f.run_id
                       ORDER BY f.created_at DESC""",
                )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def list_runs(url: str) -> list[dict[str, Any]]:
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT r.id, r.repo_name, r.run_at, r.cost_usd, r.stack,
                          COUNT(f.id) FILTER (WHERE NOT f.resolved) AS open_findings,
                          COUNT(f.id) FILTER (WHERE f.resolved) AS resolved_findings
                   FROM boswell_runs r
                   LEFT JOIN boswell_findings f ON f.run_id = r.id
                   GROUP BY r.id ORDER BY r.run_at DESC"""
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def upsert_repo_meta(
    url: str,
    repo_name: str,
    *,
    deployed_url: str | None = None,
    stack: list | None = None,
    platforms: list | None = None,
    run_at: str | None = None,
    last_score: float | None = None,
) -> None:
    """Upsert repo metadata into boswell_repo_meta. Only provided (non-None) fields are written."""
    fields: list[str] = ["repo_name"]
    values: list[Any] = [repo_name]
    updates: list[str] = ["updated_at = now()"]

    if deployed_url is not None:
        fields.append("deployed_url")
        values.append(deployed_url)
        updates.append("deployed_url = EXCLUDED.deployed_url")
    if stack is not None:
        fields.append("stack")
        values.append(json.dumps(stack))
        updates.append("stack = EXCLUDED.stack")
    if platforms is not None:
        fields.append("platforms")
        values.append(json.dumps(platforms))
        updates.append("platforms = EXCLUDED.platforms")
    if run_at is not None:
        fields.append("run_at")
        values.append(run_at)
        updates.append("run_at = EXCLUDED.run_at")
    if last_score is not None:
        fields.append("last_score")
        values.append(last_score)
        updates.append("last_score = EXCLUDED.last_score")

    placeholders = ", ".join(
        f"%s::jsonb" if f in ("stack", "platforms") else "%s"
        for f in fields
    )
    col_list = ", ".join(fields)
    update_clause = ", ".join(updates)

    sql = f"""
        INSERT INTO boswell_repo_meta ({col_list})
        VALUES ({placeholders})
        ON CONFLICT (repo_name) DO UPDATE SET {update_clause}
    """
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)
        conn.commit()


def fetch_repo_meta_batch(url: str, repo_names: list[str]) -> dict[str, dict[str, Any]]:
    """Return a dict of repo_name -> meta dict for the given repo names."""
    if not repo_names:
        return {}
    with _conn(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT repo_name, deployed_url, stack, platforms, run_at, last_score "
                "FROM boswell_repo_meta WHERE repo_name = ANY(%s)",
                (repo_names,),
            )
            cols = [d[0] for d in cur.description]
            return {row[0]: dict(zip(cols, row)) for row in cur.fetchall()}
