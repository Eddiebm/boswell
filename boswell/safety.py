"""Guards for untrusted repositories and the local Boswell server."""

import ipaddress
import os
import secrets
import socket
import time
import urllib.parse
import urllib.request
from pathlib import Path

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_UNLOCK_LIMIT = 5
_UNLOCK_WINDOW_SECONDS = 15 * 60
_unlock_failures: list[float] = []


def contained_path(repo_path: Path, rel_path: str) -> Path | None:
    """Return a path inside the repo, or None when it would escape."""
    if not isinstance(rel_path, str):
        return None
    text = rel_path.strip()
    if not text or any(ch in text for ch in ("\x00", "\n", "\r")):
        return None
    root = repo_path.resolve()
    candidate = (root / text).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate == root:
        return None
    return candidate


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    site_local = getattr(ip, "is_site_local", False)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or site_local
    )


def assert_public_http_url(url: str) -> str:
    """Accept only http(s) URLs whose host resolves to public addresses."""
    parsed = urllib.parse.urlsplit((url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https")
    if parsed.username or parsed.password:
        raise ValueError("credentials in url")
    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    host_name = host.lower().rstrip(".")
    if host_name == "localhost" or host_name.endswith(".localhost"):
        raise ValueError("local host")
    try:
        literal = ipaddress.ip_address(host_name)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public(literal):
            raise ValueError("not a public address")
        return url.strip()
    try:
        infos = socket.getaddrinfo(host_name, None)
    except socket.gaierror as exc:
        raise ValueError("could not resolve host") from exc
    if not infos:
        raise ValueError("could not resolve host")
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not _is_public(address):
            raise ValueError("not a public address")
    return url.strip()


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        assert_public_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def guarded_urlopen(url: str, timeout: int, data: bytes | None = None, headers: dict | None = None, method: str | None = None):
    """Fetch a public http(s) URL. Redirects are checked again before they are followed."""
    assert_public_http_url(url)
    opener = urllib.request.build_opener(_GuardedRedirect)
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method=method,
    )
    return opener.open(request, timeout=timeout)


def token_path() -> Path:
    home = os.environ.get("BOSWELL_HOME")
    base = Path(home) if home else Path.home() / ".boswell"
    return base / "api.token"


def api_token() -> str:
    """Return the local API token, creating a 0600 file on first use."""
    path = token_path()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            os.chmod(path, 0o600)
            return token
    token = secrets.token_urlsafe(32)
    path.write_text(token + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return token


def host_allowed(host_header: str) -> bool:
    if not host_header:
        return False
    host = host_header.split(",")[0].strip().lower()
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return False
        name = host[1:end]
    elif host.count(":") == 1:
        name = host.rsplit(":", 1)[0]
    else:
        name = host
    return name in _ALLOWED_HOSTS


def bearer_ok(authorization: str | None) -> bool:
    if not authorization:
        return False
    prefix = "bearer "
    if not authorization.lower().startswith(prefix):
        return False
    token = authorization[len(prefix):].strip()
    expected = api_token()
    if len(token) != len(expected):
        return False
    return secrets.compare_digest(token, expected)


def unlock_blocked(now: float | None = None) -> bool:
    moment = time.monotonic() if now is None else now
    recent = [stamp for stamp in _unlock_failures if moment - stamp < _UNLOCK_WINDOW_SECONDS]
    _unlock_failures[:] = recent
    return len(recent) >= _UNLOCK_LIMIT


def record_unlock_failure(now: float | None = None) -> None:
    _unlock_failures.append(time.monotonic() if now is None else now)


def clear_unlock_failures() -> None:
    _unlock_failures.clear()
