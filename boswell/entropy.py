"""
Entropy score — weighted composite of security, architecture, maintainability, dependency health.
Score: 0-100, higher = more entropic (worse).
"""

from pathlib import Path


# Category weights (must sum to 1.0)
WEIGHTS = {
    "security": 0.30,
    "architecture": 0.35,
    "maintainability": 0.20,
    "dependency": 0.15,
}


def _security_score(leak_findings: list[dict]) -> int:
    """0-100 based on CRITICAL and HIGH finding counts."""
    crit = sum(1 for f in leak_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in leak_findings if f.get("severity") == "HIGH")
    raw = crit * 20 + high * 8
    return min(100, raw)


def compute_entropy(
    repo_path: Path,
    leak_findings: list[dict],
) -> dict:
    """
    Run architecture checks and combine with security findings into an entropy score.
    Returns full breakdown dict.
    """
    from .architecture import run_architecture_checks

    arch = run_architecture_checks(repo_path)

    security_score = _security_score(leak_findings)
    architecture_score = arch["architecture_score"]
    maintainability_score = arch["maintainability"]["score"]
    dependency_score = arch["dependency_sprawl"]["score"]

    # Normalise sub-scores to 0-100 where needed
    # architecture_score and dependency_score are already 0-100
    # maintainability_score is 0-40 raw — scale to 0-100
    maint_norm = min(100, int(maintainability_score * 2.5))
    dep_norm = min(100, int(dependency_score * 2.5))

    overall = int(
        security_score * WEIGHTS["security"]
        + architecture_score * WEIGHTS["architecture"]
        + maint_norm * WEIGHTS["maintainability"]
        + dep_norm * WEIGHTS["dependency"]
    )

    return {
        "overall_entropy": overall,
        "security_score": security_score,
        "architecture_score": architecture_score,
        "maintainability_score": maint_norm,
        "dependency_score": dep_norm,
        "details": arch,
        "label": _label(overall),
    }


def _label(score: int) -> str:
    if score <= 15:
        return "Healthy"
    if score <= 30:
        return "Stable"
    if score <= 50:
        return "Drifting"
    if score <= 70:
        return "Degraded"
    return "Critical"


def save_snapshot(db_url: str, repo_name: str, entropy: dict) -> None:
    """Persist entropy snapshot to Neon."""
    import json
    import psycopg2

    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO repo_entropy_snapshots
                    (repo_name, entropy_score, security_score, architecture_score,
                     maintainability_score, dependency_score, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            """, (
                repo_name,
                entropy["overall_entropy"],
                entropy["security_score"],
                entropy["architecture_score"],
                entropy["maintainability_score"],
                entropy["dependency_score"],
                json.dumps(entropy.get("details", {})),
            ))
        conn.commit()


def load_history(db_url: str, repo_name: str, limit: int = 30) -> list[dict]:
    """Load entropy snapshot history for a repo."""
    import psycopg2
    import psycopg2.extras

    with psycopg2.connect(db_url) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT snapshot_at, entropy_score, security_score,
                       architecture_score, maintainability_score, dependency_score
                FROM repo_entropy_snapshots
                WHERE repo_name = %s
                ORDER BY snapshot_at DESC
                LIMIT %s
            """, (repo_name, limit))
            return [dict(r) for r in cur.fetchall()]
