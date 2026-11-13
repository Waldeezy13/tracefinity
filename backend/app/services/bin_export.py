"""Export the current generated files for a saved bin to an rclone remote."""

import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


class BinExportError(RuntimeError):
    """A remote export could not be completed."""


def _safe_name(name: str) -> str:
    # A single portable path component, not a remote path or an rclone option.
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-_")[:80]
    return safe or "bin"


def export_bin(remote: str, user_id: str, name: str, bin_id: str, outputs: Path) -> None:
    """Copy generated files without deleting other files in the remote directory."""
    name = _safe_name(name or "")
    identity = json.dumps([user_id, bin_id], ensure_ascii=True).encode("ascii")
    stem = f"{name}-{hashlib.sha256(identity).hexdigest()[:16]}"
    destination = f"{remote.rstrip('/')}/{name}"
    files = (
        (outputs / f"{bin_id}.stl", f"{stem}.stl", True),
        (outputs / f"{bin_id}.3mf", f"{stem}.3mf", False),
        (outputs / f"{bin_id}_parts.zip", f"{stem}-parts.zip", False),
        (outputs / f"{bin_id}_insert.stl", f"{stem}-insert.stl", False),
    )
    deadline = time.monotonic() + 90
    try:
        for source, filename, required in files:
            if not required and not source.exists():
                continue
            if not source.is_file():
                raise BinExportError("local generated STL is missing")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BinExportError("rclone timed out after 90 seconds")
            result = subprocess.run(
                ["rclone", "copyto", "--", str(source), f"{destination}/{filename}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=remaining,
                check=False,
            )
            if result.returncode:
                raise BinExportError(f"rclone exited with status {result.returncode}")
    except subprocess.TimeoutExpired as exc:
        raise BinExportError("rclone timed out after 90 seconds") from exc
    except OSError as exc:
        raise BinExportError(f"could not run rclone: {exc.strerror}") from exc
