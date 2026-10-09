"""Run the installed Strix CLI against a local repository."""

import os
import shutil
import subprocess
from pathlib import Path

SCAN_MODES = ("quick", "standard", "deep")


class StrixRunError(Exception):
    """The Strix run cannot start."""


def local_repo(repo: str) -> Path:
    """Return a local directory. URLs are rejected."""
    text = repo.strip()
    if "://" in text or text.startswith("git@"):
        raise StrixRunError(
            "This command only accepts a local directory. It does not scan a URL."
        )
    path = Path(text).expanduser().resolve()
    if not path.is_dir():
        raise StrixRunError(f"{path} is not a directory.")
    return path


def strix_command(repo: Path, scan_mode: str) -> list[str]:
    """Build the Strix invocation for one local repository."""
    if scan_mode not in SCAN_MODES:
        raise StrixRunError(
            f"Unknown scan mode {scan_mode!r}. Use quick, standard, or deep."
        )
    binary = shutil.which("strix")
    if binary is None:
        raise StrixRunError(
            "strix is not installed. Install it from https://strix.ai/install and try again."
        )
    if not os.environ.get("STRIX_LLM", "").strip():
        raise StrixRunError(
            "STRIX_LLM is not set. Set STRIX_LLM and LLM_API_KEY, then try again."
        )
    return [
        binary,
        "-n",
        "--target",
        str(repo),
        "--scan-mode",
        scan_mode,
        "--scope-mode",
        "full",
    ]


def run_strix(repo: str, scan_mode: str = "quick") -> int:
    """Run Strix and return its exit code."""
    path = local_repo(repo)
    command = strix_command(path, scan_mode)
    completed = subprocess.run(command, check=False)
    return completed.returncode
