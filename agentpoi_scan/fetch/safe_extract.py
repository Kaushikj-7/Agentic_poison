"""Safe snapshot extraction — the no-execution core of Zone 1.

The tarball of an attacker-controlled repository is extracted with hard
structural defenses: regular files only (no symlinks, no devices), path
traversal blocked, depth/file-count/total-size caps enforced, ``.git`` dropped,
and exec bits stripped. Violations raise :class:`ExtractionError` instead of
attempting a best-effort extraction.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Tuple

DEFAULT_MAX_FILES = 20000
DEFAULT_MAX_TOTAL_MB = 500
DEFAULT_MAX_DEPTH = 20
MAX_SINGLE_FILE_MB = 100
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".rs", ".java", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".cs", ".php", ".sh", ".bash", ".zsh", ".yml", ".yaml",
    ".json", ".toml", ".cfg", ".ini", ".md", ".txt", ".lock", ".sql", ".vue",
    ".svelte", ".html", ".css", ".scss", ".xml", ".gradle", ".kt", ".swift",
    ".dockerfile", ".env", ".example", ".ps1", ".bat", ".pl", ".lua",
}
BINARY_HINT_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyd",
    ".class", ".jar", ".deb", ".rpm", ".msi", ".app", ".wasm", ".sys",
}


class ExtractionError(Exception):
    """Raised when the tarball violates a structural safety cap."""


@dataclass
class Manifest:
    """Structural record of an extracted snapshot."""

    snapshot_dir: str = ""
    commit_sha: str = ""
    files: Dict[str, int] = field(default_factory=dict)  # relpath -> size
    sha256: Dict[str, str] = field(default_factory=dict)
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (member, reason)

    @property
    def text_files(self) -> List[str]:
        return sorted(p for p in self.files if PurePosixPath(p).suffix in TEXT_EXTENSIONS)

    @property
    def binary_candidates(self) -> List[str]:
        candidates = [
            p for p in self.files if PurePosixPath(p).suffix in BINARY_HINT_EXTENSIONS
        ]
        # Anything without a known text extension but that fails a text sniff is
        # treated as a binary candidate by the scanners; the manifest only
        # pre-labels obvious binary extensions.
        return sorted(candidates)

    def to_dict(self) -> Dict[str, object]:
        return {
            "snapshot_dir": self.snapshot_dir,
            "commit_sha": self.commit_sha,
            "file_count": len(self.files),
            "total_bytes": sum(self.files.values()),
            "sha256": self.sha256,
            "skipped": [list(s) for s in self.skipped],
        }


def _check_member_name(name: str, max_depth: int) -> str:
    """Validates a member path; returns the normalized relative path or raises."""
    pure = PurePosixPath(name)
    parts = [p for p in pure.parts if p not in (".",)]
    if not parts:
        raise ExtractionError(f"empty member path: {name!r}")
    if pure.is_absolute() or name.startswith(("/", "\\")) or ":" in name.split("/")[0]:
        raise ExtractionError(f"absolute member path: {name!r}")
    if ".." in parts:
        raise ExtractionError(f"path traversal in member: {name!r}")
    depth = len(parts)
    if depth > max_depth:
        raise ExtractionError(
            f"member depth {depth} exceeds cap {max_depth}: {name!r}"
        )
    return "/".join(parts)


def extract_snapshot(
    tar_bytes: bytes,
    dest: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_mb: int = DEFAULT_MAX_TOTAL_MB,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Manifest:
    """Extracts a repository tarball into ``dest`` with hard structural caps.

    Only regular files are written. Symlinks, hardlinks, devices and
    directories from the tarball are recorded as skipped, never created.
    """
    manifest = Manifest()
    total_limit = max_total_mb * 1024 * 1024
    single_limit = MAX_SINGLE_FILE_MB * 1024 * 1024
    dest = Path(dest)
    total_bytes = 0
    file_count = 0

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if PurePosixPath(name).is_absolute() or name.startswith(("/", "\\")):
                raise ExtractionError(f"absolute member path: {name!r}")
            if name.startswith("./"):
                name = name[2:]
            parts = PurePosixPath(name).parts
            if not parts:
                continue
            stripped = "/".join(parts[1:]) if len(parts) > 1 else ""
            if not stripped:
                # Top-level directory entry of a GitHub tarball (repo-sha/).
                continue
            rel = _check_member_name(stripped, max_depth=max_depth)
            pure_rel = PurePosixPath(rel)
            if pure_rel.name == ".gitmodules" or any(
                p == ".git" or (p.startswith(".git") and p != ".github") for p in pure_rel.parts
            ):
                manifest.skipped.append((rel, "prohibited git metadata entry"))
                continue
            if not member.isfile():
                reason = {tarfile.SYMTYPE: "symlink"}.get(
                    member.type, "non-regular file"
                )
                manifest.skipped.append((rel, reason))
                continue
            if member.size > single_limit:
                manifest.skipped.append((rel, "exceeds per-file size cap"))
                continue
            if file_count + 1 > max_files:
                raise ExtractionError("file count cap exceeded")
            if total_bytes + member.size > total_limit:
                raise ExtractionError("total size cap exceeded")

            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                manifest.skipped.append((rel, "unreadable member"))
                continue
            data = src.read()
            target.write_bytes(data)
            os.chmod(target, 0o644)

            digest = hashlib.sha256(data).hexdigest()
            manifest.files[rel] = len(data)
            manifest.sha256[rel] = digest
            file_count += 1
            total_bytes += len(data)

    return manifest
