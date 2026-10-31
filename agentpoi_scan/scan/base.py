"""Scanner protocol and shared Zone 2 plumbing.

Every scanner is *parse-only*: it receives the extracted snapshot path (never a
checkout, never a shell) and returns canonical Findings. Any tool that needs to
install, build or run target code may not exist here — external scanners are
invoked only if their binary is present, with fixed arguments, and they degrade
to ``skipped`` otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Protocol, runtime_checkable

from agentpoi_scan.fetch.safe_extract import BINARY_HINT_EXTENSIONS, TEXT_EXTENSIONS
from agentpoi_scan.findings.model import Finding


class LoadError(Exception):
    """A snapshot could not be loaded from disk."""


@dataclass
class ScanContext:
    """Read-only view over an extracted snapshot plus its manifest."""

    snapshot_dir: Path
    repo: str
    commit_sha: str
    file_index: List[str] = field(default_factory=list)
    binary_candidates: List[str] = field(default_factory=list)
    redact_secrets: bool = True

    @classmethod
    def from_manifest(
        cls, snapshot_dir: Path, repo: str, commit_sha: str, manifest, redact_secrets: bool = True
    ) -> "ScanContext":
        return cls(
            snapshot_dir=Path(snapshot_dir),
            repo=repo,
            commit_sha=commit_sha,
            file_index=sorted(manifest.files),
            binary_candidates=list(manifest.binary_candidates),
            redact_secrets=redact_secrets,
        )

    # -- helpers ----------------------------------------------------------------
    def read_text(self, relpath: str, max_bytes: int = 512_000) -> Optional[str]:
        """Reads one snapshot file as text (never executes anything)."""
        suffix = Path(relpath).suffix
        if suffix not in TEXT_EXTENSIONS and suffix in BINARY_HINT_EXTENSIONS:
            return None
        path = self.snapshot_dir / relpath
        if not path.is_file():
            raise LoadError(f"missing snapshot file: {relpath}")
        try:
            data = path.read_bytes()[:max_bytes]
        except OSError as exc:
            raise LoadError(f"unreadable snapshot file {relpath}: {exc}") from exc
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def files_with_suffix(self, suffixes) -> List[str]:
        wanted = {s if s.startswith(".") else f".{s}" for s in suffixes}
        return [p for p in self.file_index if Path(p).suffix in wanted]


@runtime_checkable
class Scanner(Protocol):
    name: str

    def run(self, context: ScanContext) -> "ScanResult":  # pragma: no cover - protocol
        ...


@dataclass
class ScanResult:
    """Outcome of one scanner over one snapshot."""

    scanner: str
    findings: List[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    isolation: str = "in-process"


def external_available(binary: str, which: Callable[[str], Optional[str]] = None) -> bool:
    """Checks for the external scanner binary without ever invoking it."""
    import shutil

    which = which or shutil.which
    return which(binary) is not None
