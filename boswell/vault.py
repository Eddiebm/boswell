"""
Local encrypted vault for storing repo secrets.
Vault lives at ~/.boswell/vault.enc (Fernet / AES-128-CBC + HMAC-SHA256).
Master password is set once; key is derived via PBKDF2HMAC.
"""

import base64
import json
import os
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_DIR = Path.home() / ".boswell"
VAULT_PATH = VAULT_DIR / "vault.enc"
SALT_PATH = VAULT_DIR / "vault.salt"

# In-memory session: once unlocked, keep the Fernet instance for the server's lifetime
_session_fernet: Fernet | None = None


def _ensure_dir():
    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)


def _restrict_file(path: Path) -> None:
    if path.exists():
        os.chmod(path, 0o600)


def tighten_vault_files() -> None:
    """Keep the vault and its salt readable only by this user."""
    _ensure_dir()
    _restrict_file(VAULT_PATH)
    _restrict_file(SALT_PATH)


def _derive_key(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


def vault_exists() -> bool:
    return VAULT_PATH.exists()


def create_vault(password: str) -> None:
    """Initialize a new empty vault with the given master password."""
    _ensure_dir()
    salt = os.urandom(16)
    SALT_PATH.write_bytes(salt)
    _restrict_file(SALT_PATH)
    f = _derive_key(password, salt)
    _save({}, f)
    global _session_fernet
    _session_fernet = f


def unlock_vault(password: str) -> bool:
    """Attempt to unlock the vault. Returns True on success."""
    global _session_fernet
    if not VAULT_PATH.exists() or not SALT_PATH.exists():
        return False
    salt = SALT_PATH.read_bytes()
    f = _derive_key(password, salt)
    try:
        _load(f)  # will raise InvalidToken if wrong password
        _session_fernet = f
        return True
    except (InvalidToken, Exception):
        return False


def is_unlocked() -> bool:
    return _session_fernet is not None


def lock_vault() -> None:
    global _session_fernet
    _session_fernet = None


def _load(f: Fernet | None = None) -> dict:
    fernet = f or _session_fernet
    if fernet is None:
        raise RuntimeError("Vault is locked")
    raw = VAULT_PATH.read_bytes()
    return json.loads(fernet.decrypt(raw).decode())


def _save(data: dict, f: Fernet | None = None) -> None:
    fernet = f or _session_fernet
    if fernet is None:
        raise RuntimeError("Vault is locked")
    _ensure_dir()
    VAULT_PATH.write_bytes(fernet.encrypt(json.dumps(data).encode()))
    _restrict_file(VAULT_PATH)


def store_secret(repo: str, key: str, value: str) -> None:
    """Store or update a secret value for a repo."""
    data = _load()
    if repo not in data:
        data[repo] = {}
    data[repo][key] = {
        "value": value,
        "stored_at": datetime.now().isoformat(),
    }
    _save(data)


def store_repo_secrets(repo: str, secrets: dict[str, str]) -> None:
    """Store multiple secrets for a repo at once."""
    data = _load()
    if repo not in data:
        data[repo] = {}
    for key, value in secrets.items():
        data[repo][key] = {
            "value": value,
            "stored_at": datetime.now().isoformat(),
        }
    _save(data)


def list_repos() -> list[str]:
    """List all repos that have secrets in the vault."""
    if not is_unlocked():
        return []
    return list(_load().keys())


def list_secrets(repo: str) -> list[dict]:
    """List secrets for a repo — values masked by default."""
    if not is_unlocked():
        return []
    data = _load()
    entries = data.get(repo, {})
    return [
        {"key": k, "masked": "••••••••", "stored_at": v["stored_at"]}
        for k, v in entries.items()
    ]


def get_secret(repo: str, key: str) -> str | None:
    """Get a plaintext secret value. Vault must be unlocked."""
    if not is_unlocked():
        return None
    data = _load()
    entry = data.get(repo, {}).get(key)
    return entry["value"] if entry else None


def open_vault(password: str) -> dict | None:
    """Decrypt the vault with a password. Does not leave it unlocked."""
    if not password or not VAULT_PATH.exists() or not SALT_PATH.exists():
        return None
    fernet = _derive_key(password, SALT_PATH.read_bytes())
    try:
        return _load(fernet)
    except Exception:
        return None


def read_secret(repo: str, key: str, password: str) -> str | None:
    """Return one secret after checking the master password again."""
    data = open_vault(password)
    if data is None:
        return None
    entry = data.get(repo, {}).get(key)
    return entry["value"] if entry else None


def all_secrets_masked() -> dict[str, list[dict]]:
    """Return all repos and their masked secret keys (for the vault overview page)."""
    if not is_unlocked():
        return {}
    data = _load()
    result = {}
    for repo, secrets in data.items():
        result[repo] = [
            {"key": k, "stored_at": v["stored_at"]}
            for k, v in secrets.items()
        ]
    return result


def delete_repo_secrets(repo: str) -> None:
    data = _load()
    data.pop(repo, None)
    _save(data)
