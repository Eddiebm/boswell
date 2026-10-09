"""Regression checks for the local-repo safety guards."""

import json
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from boswell import fixer, secret_check, ship_check, vault
from boswell.safety import (
    api_token,
    assert_public_http_url,
    bearer_ok,
    clear_unlock_failures,
    contained_path,
    host_allowed,
    record_unlock_failure,
    token_path,
    unlock_blocked,
)
from boswell.secret_check import LeakFinding


def test_contained_path_stays_inside_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    inside = repo / "src" / "app.py"
    inside.parent.mkdir()
    inside.write_text("ok\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("original\n", encoding="utf-8")

    assert contained_path(repo, "src/app.py") == inside.resolve()
    assert contained_path(repo, "../outside.txt") is None
    assert contained_path(repo, str(outside)) is None
    assert contained_path(repo, "src/../../outside.txt") is None
    assert outside.read_text(encoding="utf-8") == "original\n"


def test_fix_repo_skips_paths_outside_the_repo(tmp_path: Path, monkeypatch):
    from boswell import fix_code

    repo = tmp_path / "repo"
    (repo / ".boswell").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("original\n", encoding="utf-8")
    (repo / ".boswell" / "audit.md").write_text(
        "**[HIGH]** bad write `../outside.txt`\n",
        encoding="utf-8",
    )
    called = {"llm": False}

    def _boom(*_args, **_kwargs):
        called["llm"] = True
        return "overwritten\n"

    monkeypatch.setattr(fix_code, "OpenAI", lambda **_kwargs: object())
    monkeypatch.setattr(fix_code, "_call_llm", _boom)
    monkeypatch.setattr(fix_code, "_git_stash", lambda _path: False)

    result = fix_code.fix_repo(repo, api_key="test", ship=False)

    assert called["llm"] is False
    assert result["fixed"] == 0
    assert outside.read_text(encoding="utf-8") == "original\n"


def test_auto_fix_does_not_pass_filenames_through_a_shell(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    weird = ".env.;touch /tmp/boswell-not-a-command"
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr(secret_check.subprocess, "run", fake_run)
    finding = LeakFinding(
        severity="CRITICAL",
        category="tracked-env-file",
        description="tracked env",
        location=weird,
        fix=f"echo hi; touch {tmp_path / 'marker'}",
        action={"type": "untrack", "path": weird},
    )

    ok, _out = secret_check.apply_auto_fix(finding, repo)

    assert ok is True
    assert calls
    assert all(kwargs.get("shell") is not True for _args, kwargs in calls)
    assert calls[0][0] == ["git", "rm", "--cached", "--", weird]
    assert not (tmp_path / "marker").exists()


def test_offer_fixes_uses_the_safe_applier(tmp_path: Path, monkeypatch):
    seen = {}

    def fake_apply(finding, repo_path):
        seen["fix"] = finding.fix
        seen["repo"] = repo_path
        return True, "applied"

    class Yes:
        @staticmethod
        def ask(*_args, **_kwargs):
            return True

    monkeypatch.setattr(fixer, "apply_auto_fix", fake_apply)
    monkeypatch.setattr(fixer, "Confirm", Yes)
    finding = LeakFinding(
        severity="HIGH",
        category="gitignore-gap",
        description="No .gitignore file found",
        location=".gitignore (missing)",
        fix="instructions",
        action={"type": "gitignore_lines", "lines": [".env"], "stage": False},
    )

    class Console:
        def print(self, *_args, **_kwargs):
            return None

    applied = fixer.offer_fixes([finding], tmp_path, Console())
    assert applied == 1
    assert seen["repo"] == tmp_path


def test_build_check_does_not_run_package_scripts(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "build-ran"
    (repo / "package.json").write_text(
        json.dumps({"scripts": {"build": f"touch {marker}"}}),
        encoding="utf-8",
    )

    result = ship_check.check_build(repo)

    assert result["status"] == "skip"
    assert "does not run" in result["detail"]
    assert not marker.exists()


def test_ship_check_rejects_local_and_file_urls():
    with pytest.raises(ValueError):
        assert_public_http_url("file:///etc/passwd")
    with pytest.raises(ValueError):
        assert_public_http_url("http://127.0.0.1/latest")
    with pytest.raises(ValueError):
        assert_public_http_url("http://169.254.169.254/latest/meta-data")
    with pytest.raises(ValueError):
        assert_public_http_url("http://10.1.2.3/")

    live = ship_check.check_live("file:///etc/passwd")
    assert live["status"] == "fail"
    assert "passwd" not in live["detail"]
    assert "file:" not in live["detail"].lower()


def test_host_and_token(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BOSWELL_HOME", str(tmp_path))
    token = api_token()
    mode = stat.S_IMODE(token_path().stat().st_mode)
    assert mode == 0o600
    assert host_allowed("localhost:7474")
    assert host_allowed("127.0.0.1")
    assert not host_allowed("evil.example")
    assert bearer_ok(f"Bearer {token}")
    assert not bearer_ok("Bearer nope")
    assert not bearer_ok(None)


def test_unlock_rate_limit():
    clear_unlock_failures()
    assert unlock_blocked(now=1000) is False
    for offset in range(5):
        record_unlock_failure(now=1000 + offset)
    assert unlock_blocked(now=1005) is True
    assert unlock_blocked(now=1000 + 15 * 60 + 1) is False
    clear_unlock_failures()


def test_vault_files_are_private(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(vault, "VAULT_DIR", tmp_path)
    monkeypatch.setattr(vault, "VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(vault, "SALT_PATH", tmp_path / "vault.salt")
    vault.create_vault("correct-horse")
    vault.store_secret("demo", "TOKEN", "secret-value")
    for path in (tmp_path / "vault.enc", tmp_path / "vault.salt"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert vault.read_secret("demo", "TOKEN", "correct-horse") == "secret-value"
    assert vault.read_secret("demo", "TOKEN", "wrong-password") is None
    vault.lock_vault()


def test_api_requires_localhost_and_token(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BOSWELL_HOME", str(tmp_path))
    from boswell.server import app

    client = TestClient(app)
    open_response = client.get("/api/vault/status")
    assert open_response.status_code == 403

    token = api_token()
    missing = client.get("/api/vault/status", headers={"Host": "localhost"})
    assert missing.status_code == 401

    foreign = client.get(
        "/api/vault/status",
        headers={"Host": "evil.example", "Authorization": f"Bearer {token}"},
    )
    assert foreign.status_code == 403

    ok = client.get(
        "/api/vault/status",
        headers={"Host": "localhost", "Authorization": f"Bearer {token}"},
    )
    assert ok.status_code == 200

    page = client.get("/", headers={"Host": "localhost"})
    assert page.status_code == 200
    assert token in page.text
    assert "__BOSWELL_TOKEN__" not in page.text

    stolen = client.get("/", headers={"Host": "evil.example"})
    assert stolen.status_code == 403
    assert token not in stolen.text


def test_deployed_url_route_rejects_local_targets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BOSWELL_HOME", str(tmp_path / "home"))
    repo = tmp_path / "demo"
    (repo / ".boswell").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".boswell" / "metadata.json").write_text("{}", encoding="utf-8")
    (repo / "package.json").write_text(
        json.dumps({"scripts": {"build": "touch /tmp/boswell-build-should-not-run"}}),
        encoding="utf-8",
    )

    from boswell.server import app, set_repos_root

    set_repos_root(tmp_path)
    client = TestClient(app)
    headers = {
        "Host": "localhost",
        "Authorization": f"Bearer {api_token()}",
    }
    saved = client.post(
        "/api/repo/demo/set-deployed-url",
        headers=headers,
        json={"url": "file:///etc/passwd"},
    )
    assert saved.status_code == 400
    meta = json.loads((repo / ".boswell" / "metadata.json").read_text(encoding="utf-8"))
    assert meta.get("deployed_url") != "file:///etc/passwd"

    checked = client.get(
        "/api/repo/demo/ship-check",
        headers=headers,
        params={"skip_build": "false"},
    )
    assert checked.status_code == 200
    build = next(item for item in checked.json()["checks"] if item["name"] == "build")
    assert build["status"] == "skip"
    assert not Path("/tmp/boswell-build-should-not-run").exists()
