"""
GitHub sync — discover and clone repos that aren't yet in the local repos root.

Reads GITHUB_TOKEN and GITHUB_USERNAME from env (or ~/.boswell/.env).
Clones any repos not already present in the root directory.
Does NOT auto-audit — that's on-demand via the UI to control cost.
"""

import os
import subprocess
from pathlib import Path

import httpx


def _load_boswell_env() -> None:
    """Load ~/.boswell/.env into os.environ if present."""
    env_path = Path.home() / ".boswell" / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def get_credentials() -> tuple[str | None, str | None]:
    _load_boswell_env()
    return os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_USERNAME")


def list_github_repos(token: str, username: str) -> list[dict]:
    """Return all repos owned by username (not forks, not archived)."""
    repos: list[dict] = []
    page = 1
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    while True:
        resp = httpx.get(
            "https://api.github.com/user/repos",
            headers=headers,
            params={"per_page": 100, "page": page, "type": "owner", "sort": "updated"},
            timeout=20,
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return repos


def get_sync_status(root: Path, token: str, username: str) -> dict:
    """Compare GitHub repos against local clones. Returns status without cloning."""
    try:
        github_repos = list_github_repos(token, username)
    except Exception as e:
        return {"error": str(e), "github_repos": [], "missing": [], "present": []}

    existing_names = {
        d.name for d in root.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    } if root.exists() else set()

    missing = []
    present = []
    for repo in github_repos:
        name = repo["name"]
        entry = {
            "name": name,
            "full_name": repo["full_name"],
            "clone_url": repo["clone_url"],
            "updated_at": repo.get("updated_at", ""),
            "private": repo.get("private", False),
            "description": repo.get("description") or "",
            "archived": repo.get("archived", False),
        }
        if name in existing_names:
            present.append(entry)
        else:
            missing.append(entry)

    return {
        "total_github": len(github_repos),
        "present": len(present),
        "missing": missing,
        "present_list": present,
        "username": username,
    }


def clone_repos(root: Path, repos: list[dict]) -> dict:
    """Clone missing repos and pull updates on existing ones."""
    _load_boswell_env()
    root.mkdir(parents=True, exist_ok=True)
    cloned: list[str] = []
    pulled: list[str] = []
    failed: list[dict] = []

    token = os.environ.get("GITHUB_TOKEN", "")

    def _authed_url(url: str) -> str:
        if token and url.startswith("https://github.com/"):
            return url.replace("https://github.com/", f"https://{token}@github.com/")
        return url

    for repo in repos:
        name = repo["name"]
        target = root / name

        if (target / ".git").exists():
            # Repo already cloned — pull latest commits
            try:
                # Update the remote URL in case token changed
                authed = _authed_url(repo["clone_url"])
                subprocess.run(
                    ["git", "remote", "set-url", "origin", authed],
                    cwd=target, capture_output=True, timeout=10,
                )
                result = subprocess.run(
                    ["git", "pull", "--ff-only", "--depth", "1"],
                    cwd=target, capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    pulled.append(name)
                else:
                    # Already up to date or unrelated history — not a failure
                    pulled.append(name)
            except Exception as e:
                failed.append({"name": name, "error": f"pull failed: {str(e)[:150]}"})
            continue

        # Fresh clone
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", _authed_url(repo["clone_url"]), str(target)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                cloned.append(name)
            else:
                failed.append({"name": name, "error": result.stderr.strip()[:200]})
        except Exception as e:
            failed.append({"name": name, "error": str(e)[:200]})

    return {"cloned": cloned, "pulled": pulled, "failed": failed}
