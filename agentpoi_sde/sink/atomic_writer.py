"""Atomic, guarded filesystem mutation writer with transactional rollback.

Provides crash-safe, atomic disk writes for approved code mutations:
- Writes to shadow temp files in target directory, fsyncs, and uses atomic os.replace.
- Comprehensive transactional rollback: records pre-mutation state of touched files
  and restores them automatically if any step fails.
- Strict path containment checks preventing repository root escapes.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence

from agentpoi_sde.domain import CodeMutation, MutationOp


def _validate_contained_path(repo_root: str, rel_path: str) -> Path:
    """Validate that rel_path resolves strictly within repo_root."""
    norm = rel_path.replace("\\", "/").strip()
    if norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":"):
        raise ValueError(f"Security error: absolute path rejected: {rel_path}")
    resolved_root = Path(repo_root).resolve()
    target = (resolved_root / norm).resolve()
    try:
        if not target.is_relative_to(resolved_root):
            raise ValueError(f"Security error: path traversal escape rejected: {rel_path}")
    except AttributeError:
        # Python < 3.9 fallback
        if os.path.commonpath([str(resolved_root), str(target)]) != str(resolved_root):
            raise ValueError(f"Security error: path traversal escape rejected: {rel_path}")
    return target


class AtomicDiskWriter:
    """Atomic filesystem writer for code mutations with rollback capabilities."""

    def __init__(self, repo_root: str) -> None:
        self.repo_root = os.path.abspath(repo_root)
        if not os.path.isdir(self.repo_root):
            raise ValueError(f"Repository root directory does not exist: {self.repo_root}")

    def write_file_atomic(self, rel_path: str, content: str) -> str:
        """Write content to rel_path atomically using a temp file and os.replace."""
        target_path = _validate_contained_path(self.repo_root, rel_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to temporary file in the same directory for atomic replace
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=str(target_path.parent),
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name

        try:
            os.replace(tmp_name, str(target_path))
        except Exception:
            if os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass
            raise

        return str(target_path)

    def delete_file_atomic(self, rel_path: str) -> bool:
        """Delete rel_path safely."""
        target_path = _validate_contained_path(self.repo_root, rel_path)
        if target_path.exists():
            if target_path.is_file():
                target_path.unlink()
                return True
            elif target_path.is_dir():
                shutil.rmtree(str(target_path))
                return True
        return False

    def apply_mutation(self, mutation: CodeMutation) -> str:
        """Apply a single mutation atomically to disk."""
        if mutation.op == MutationOp.DELETE:
            self.delete_file_atomic(mutation.path)
            return f"deleted:{mutation.path}"
        else:
            self.write_file_atomic(mutation.path, mutation.new_content)
            return f"written:{mutation.path}"

    @contextmanager
    def transaction(self) -> Iterator["AtomicDiskTransaction"]:
        """Context manager for a transaction with automatic rollback on error."""
        tx = AtomicDiskTransaction(self)
        try:
            yield tx
        except Exception:
            tx.rollback()
            raise


class AtomicDiskTransaction:
    """Transactional container tracking mutations with rollback capability."""

    def __init__(self, writer: AtomicDiskWriter) -> None:
        self.writer = writer
        self._backups: Dict[str, Optional[str]] = {}  # rel_path -> original content or None
        self._applied_mutations: List[CodeMutation] = []
        self._rolled_back: bool = False

    def apply(self, mutation: CodeMutation) -> None:
        """Record pre-state backup and apply mutation to disk."""
        if self._rolled_back:
            raise RuntimeError("Cannot apply mutations on a rolled back transaction")

        target_path = _validate_contained_path(self.writer.repo_root, mutation.path)
        # Record original state if not already recorded
        if mutation.path not in self._backups:
            if target_path.exists() and target_path.is_file():
                try:
                    with open(str(target_path), "r", encoding="utf-8", errors="replace") as f:
                        self._backups[mutation.path] = f.read()
                except Exception:
                    self._backups[mutation.path] = None
            else:
                self._backups[mutation.path] = None

        self.writer.apply_mutation(mutation)
        self._applied_mutations.append(mutation)

    def rollback(self) -> None:
        """Roll back all applied mutations to their original state."""
        if self._rolled_back:
            return
        self._rolled_back = True

        for rel_path, original_content in reversed(list(self._backups.items())):
            try:
                target_path = _validate_contained_path(self.writer.repo_root, rel_path)
                if original_content is None:
                    # File was newly created in transaction; remove it
                    if target_path.exists():
                        if target_path.is_file():
                            target_path.unlink()
                else:
                    # File previously existed; restore original content
                    self.writer.write_file_atomic(rel_path, original_content)
            except Exception:
                pass
