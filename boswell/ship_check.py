"""
Ship Readiness checks — run before declaring a repo ready to ship.
Each check returns: {name, status, detail}
  status: "pass" | "fail" | "warn" | "skip"
"""

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from .safety import assert_public_http_url, guarded_urlopen


def _deployed_url(repo_path: Path, platform: str, project_name: str) -> Optional[str]:
    meta_path = repo_path / ".boswell" / "metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            if meta.get("deployed_url"):
                return meta["deployed_url"]
        except Exception:
            pass

    if platform == "cloudflare":
        return f"https://{project_name}.pages.dev"

    if platform == "vercel":
        # project_id from .vercel/project.json is NOT the URL slug — use folder name or vercel.json name
        vj = repo_path / "vercel.json"
        slug = repo_path.name  # default: folder name is typically the Vercel slug
        if vj.exists():
            try:
                data = json.loads(vj.read_text())
                slug = data.get("name") or slug
            except Exception:
                pass
        return f"https://{slug}.vercel.app"

    return None


def check_build(repo_path: Path) -> dict:
    """Report whether a build script exists. Never execute it.

    A repository's npm build script can run any command as the operator.
    """
    pkg = repo_path / "package.json"
    if not pkg.exists():
        return {"name": "build", "status": "skip", "detail": "No package.json"}

    try:
        scripts = json.loads(pkg.read_text()).get("scripts", {})
    except Exception:
        return {"name": "build", "status": "skip", "detail": "Could not parse package.json"}
    if "build" not in scripts:
        return {"name": "build", "status": "skip", "detail": "No build script in package.json"}
    return {
        "name": "build",
        "status": "skip",
        "detail": "Boswell does not run npm build. A repository build script can run any command. Run the build yourself if you trust this repo.",
    }


def check_live(url: Optional[str]) -> dict:
    if not url:
        return {"name": "live", "status": "skip", "detail": "No deployed URL found"}

    try:
        assert_public_http_url(url)
        with guarded_urlopen(url, timeout=10, headers={"User-Agent": "Boswell/1.0 ship-check"}) as r:
            code = r.status
    except ValueError:
        return {
            "name": "live",
            "status": "fail",
            "detail": "Deployed URL must be a public http or https address",
        }
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        return {"name": "live", "status": "fail", "detail": "Could not reach the deployed URL"}

    if code < 400:
        return {"name": "live", "status": "pass", "detail": f"HTTP {code} from {url}"}
    if code < 500:
        return {"name": "live", "status": "warn", "detail": f"HTTP {code} from {url} (check deployed URL is correct)"}
    return {"name": "live", "status": "fail", "detail": f"HTTP {code} from {url}"}


def check_deployment_health(platform: str, project_id: str) -> dict:
    token = os.environ.get("VERCEL_TOKEN", "")
    cf_token = os.environ.get("CF_API_TOKEN", "")
    cf_account = os.environ.get("CF_ACCOUNT_ID", "")

    if platform == "vercel":
        if not token:
            return {"name": "deployment", "status": "skip", "detail": "VERCEL_TOKEN not set"}
        try:
            req = urllib.request.Request(
                f"https://api.vercel.com/v9/projects/{project_id}/deployments?limit=1&target=production",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            deps = data.get("deployments", [])
            if not deps:
                return {"name": "deployment", "status": "warn", "detail": "No production deployments found"}
            dep = deps[0]
            state = dep.get("state", "unknown").upper()
            dep_url = dep.get("url", "")
            if state == "READY":
                return {"name": "deployment", "status": "pass", "detail": f"Latest deployment READY ({dep_url})"}
            elif state in ("ERROR", "CANCELED"):
                return {"name": "deployment", "status": "fail", "detail": f"Latest deployment state: {state}"}
            return {"name": "deployment", "status": "warn", "detail": f"Latest deployment state: {state}"}
        except Exception as e:
            return {"name": "deployment", "status": "skip", "detail": f"Vercel API error: {e}"}

    elif platform == "cloudflare":
        if not cf_token or not cf_account:
            return {"name": "deployment", "status": "skip", "detail": "CF_API_TOKEN / CF_ACCOUNT_ID not set"}
        try:
            req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/accounts/{cf_account}/pages/projects/{project_id}/deployments?per_page=1",
                headers={"Authorization": f"Bearer {cf_token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            deps = data.get("result", [])
            if not deps:
                return {"name": "deployment", "status": "warn", "detail": "No deployments found"}
            dep = deps[0]
            stage = dep.get("latest_stage", {}).get("name", "unknown")
            status = dep.get("latest_stage", {}).get("status", "unknown")
            if status == "success":
                return {"name": "deployment", "status": "pass", "detail": f"Latest deployment succeeded ({stage})"}
            elif status == "failure":
                return {"name": "deployment", "status": "fail", "detail": f"Latest deployment failed at {stage}"}
            return {"name": "deployment", "status": "warn", "detail": f"Latest deployment: {stage}/{status}"}
        except Exception as e:
            return {"name": "deployment", "status": "skip", "detail": f"Cloudflare API error: {e}"}

    return {"name": "deployment", "status": "skip", "detail": f"Unknown platform: {platform}"}


def check_env_vars(repo_path: Path, platform: str, project_id: str) -> dict:
    example_path = repo_path / ".env.example"
    if not example_path.exists():
        for candidate in repo_path.rglob(".env.example"):
            example_path = candidate
            break
        else:
            return {"name": "env_vars", "status": "skip", "detail": "No .env.example found"}

    required_keys = set()
    for line in example_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key = line.split("=")[0].strip()
            if key:
                required_keys.add(key)

    if not required_keys:
        return {"name": "env_vars", "status": "skip", "detail": ".env.example has no keys"}

    token = os.environ.get("VERCEL_TOKEN", "")
    if platform == "vercel" and token:
        try:
            req = urllib.request.Request(
                f"https://api.vercel.com/v9/projects/{project_id}/env",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            configured = {e["key"] for e in data.get("envs", [])}
            missing = required_keys - configured
            if missing:
                return {
                    "name": "env_vars",
                    "status": "fail",
                    "detail": f"Missing in Vercel: {', '.join(sorted(missing))}",
                }
            return {"name": "env_vars", "status": "pass", "detail": f"All {len(required_keys)} env vars set in Vercel"}
        except Exception as e:
            return {"name": "env_vars", "status": "skip", "detail": f"Vercel API error: {e}"}

    keys_str = ", ".join(sorted(required_keys))
    return {
        "name": "env_vars",
        "status": "skip",
        "detail": f"VERCEL_TOKEN not set — cannot verify ({len(required_keys)} keys expected: {keys_str})",
    }


def check_health_endpoint(url: Optional[str]) -> dict:
    if not url:
        return {"name": "health_endpoint", "status": "skip", "detail": "No deployed URL"}

    try:
        assert_public_http_url(url)
    except ValueError:
        return {
            "name": "health_endpoint",
            "status": "fail",
            "detail": "Deployed URL must be a public http or https address",
        }

    base = url.rstrip("/")
    for path in ["/api/health", "/api/ping", "/health", "/ping", "/_health"]:
        try:
            with guarded_urlopen(
                base + path,
                timeout=8,
                headers={"User-Agent": "Boswell/1.0 ship-check"},
            ) as r:
                # 200/204 = healthy; other 2xx/3xx = present but unusual
                return {"name": "health_endpoint", "status": "pass", "detail": f"{path} → HTTP {r.status}"}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # endpoint not present, try next path
            if e.code >= 500:
                return {"name": "health_endpoint", "status": "fail", "detail": f"{path} → HTTP {e.code} (server error)"}
            # 401/403/405 means the endpoint exists
            return {"name": "health_endpoint", "status": "pass", "detail": f"{path} → HTTP {e.code}"}
        except Exception:
            continue

    return {"name": "health_endpoint", "status": "skip", "detail": "No health endpoint found at standard paths"}


def check_auth_endpoint(url: Optional[str]) -> dict:
    if not url:
        return {"name": "auth_endpoint", "status": "skip", "detail": "No deployed URL"}

    try:
        assert_public_http_url(url)
    except ValueError:
        return {
            "name": "auth_endpoint",
            "status": "fail",
            "detail": "Deployed URL must be a public http or https address",
        }

    base = url.rstrip("/")
    body = json.dumps({"email": "boswell-check@example.com", "password": "bogus"}).encode()

    for path in ["/api/auth/login", "/api/login", "/auth/login", "/login"]:
        try:
            with guarded_urlopen(
                base + path,
                timeout=8,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Boswell/1.0 ship-check"},
                method="POST",
            ) as r:
                # 200 with bogus creds is unusual but not a server error
                return {"name": "auth_endpoint", "status": "pass", "detail": f"{path} → HTTP {r.status} (auth responding)"}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # endpoint not present, try next path
            if e.code >= 500:
                return {
                    "name": "auth_endpoint",
                    "status": "fail",
                    "detail": f"{path} → HTTP {e.code} (server error — auth may be broken)",
                }
            # 400/401/403/422 = auth endpoint exists and correctly rejected bogus creds
            return {"name": "auth_endpoint", "status": "pass", "detail": f"{path} → HTTP {e.code} (auth responding)"}
        except Exception:
            continue

    return {"name": "auth_endpoint", "status": "skip", "detail": "No auth endpoint at standard paths"}


def check_security(repo_path: Path) -> dict:
    audit_path = repo_path / ".boswell" / "audit.md"
    if not audit_path.exists():
        return {"name": "security", "status": "skip", "detail": "No audit.md — run boswell audit first"}

    content = audit_path.read_text(encoding="utf-8")
    critical = [l.strip() for l in content.splitlines() if "[CRITICAL]" in l]
    high = [l.strip() for l in content.splitlines() if "[HIGH]" in l]

    if critical:
        previews = "\n".join(f"  • {l}" for l in critical[:3])
        return {
            "name": "security",
            "status": "fail",
            "detail": f"{len(critical)} CRITICAL finding(s) — must fix before shipping:\n{previews}",
        }
    if high:
        return {
            "name": "security",
            "status": "warn",
            "detail": f"No CRITICAL, but {len(high)} HIGH finding(s) still open",
        }
    return {"name": "security", "status": "pass", "detail": "No CRITICAL or HIGH findings"}


def run_ship_checks(
    repo_path: Path,
    platform: str,
    project_id: str,
) -> list[dict]:
    url = _deployed_url(repo_path, platform, project_id)

    checks = []
    checks.append(check_build(repo_path))

    checks.append(check_live(url))
    checks.append(check_deployment_health(platform, project_id))
    checks.append(check_env_vars(repo_path, platform, project_id))
    checks.append(check_health_endpoint(url))
    checks.append(check_auth_endpoint(url))
    checks.append(check_security(repo_path))

    return checks
