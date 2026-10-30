"""Ephemeral isolated workspace for examining one untrusted repository.

Every remote scan gets a fresh, private working directory under the scan root.
The tarball, the extracted tree and every scratch file live inside it, and the
whole directory is deleted once the examination finishes — only the persisted
findings/report survive.

Isolation here is *static*: the workspace is a plain directory and nothing in it
is ever executed. This module only owns the lifecycle (create → use → purge) and
proves the purge; execution containment is not claimed.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

DEFAULT_WORKSPACE_ROOT = ".agentpoi_scan"


@dataclass
class PurgeResult:
    """Outcome of deleting a workspace and every byte it held."""

    workspace: str
    removed: bool
    removed_files: int = 0
    removed_bytes: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "workspace": self.workspace,
            "status": "deleted" if self.removed else "delete-failed",
            "removed_files": self.removed_files,
            "removed_bytes": self.removed_bytes,
            "error": self.error,
        }


def _on_remove_error(func, path, exc_info) -> None:  # pragma: no cover - OS-specific
    """Retries a failed unlink after restoring write permission (Windows)."""
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        pass


class IsolatedWorkspace:
    """Create-on-enter, delete-on-exit scratch directory for one repository."""

    def __init__(self, root: str | Path | None = None, prefix: str = "ws_") -> None:
        self.root = Path(root or DEFAULT_WORKSPACE_ROOT)
        self.root.mkdir(parents=True, exist_ok=True)
        self._path = Path(tempfile.mkdtemp(prefix=prefix, dir=self.root))
        # Best-effort private permissions on POSIX; no effect on Windows.
        try:
            os.chmod(self._path, 0o700)
        except OSError:  # pragma: no cover - platform dependent
            pass
        self._purge_result: PurgeResult | None = None

    @property
    def path(self) -> Path:
        return self._path

    def snapshot_dir(self, commit_sha: str) -> Path:
        """Deterministic extraction directory inside the workspace."""
        return self._path / f"snap_{commit_sha[:12]}"

    def stats(self) -> tuple[int, int]:
        """Returns (file_count, total_bytes) for everything currently on disk."""
        files = 0
        total = 0
        for root, _dirs, names in os.walk(self._path):
            for name in names:
                candidate = Path(root) / name
                try:
                    total += candidate.stat().st_size
                    files += 1
                except OSError:  # pragma: no cover - raced/unreadable
                    continue
        return files, total

    def purge(self) -> PurgeResult:
        """Deletes the workspace completely; safe to call more than once."""
        if self._purge_result is not None:
            return self._purge_result
        files, total = self.stats()
        error = ""
        if self._path.exists():
            try:
                shutil.rmtree(self._path, onerror=_on_remove_error)
            except OSError as exc:  # pragma: no cover - defensive
                error = str(exc)
        removed = not self._path.exists()
        self._purge_result = PurgeResult(
            workspace=str(self._path),
            removed=removed,
            removed_files=files if removed else 0,
            removed_bytes=total if removed else 0,
            error=error,
        )
        return self._purge_result

    def __enter__(self) -> "IsolatedWorkspace":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.purge()
