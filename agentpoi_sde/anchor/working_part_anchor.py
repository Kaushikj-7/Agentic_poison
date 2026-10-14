"""Immutable registry of verified working code components and regression tests (Invariant I9)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from agentpoi_sde.capability.capability_scope import CapabilityScope


@dataclass(frozen=True)
class WorkingPartRecord:
    """Cryptographic record of an immutable working software component."""

    file_path: str
    content_hash: str
    description: str
    registered_at: float = field(default_factory=time.time)


class WorkingPartAnchor:
    """Protects verified working components from accidental agent mutation or regression."""

    def __init__(self) -> None:
        self._working_files: Dict[str, WorkingPartRecord] = {}
        self._regression_tests: Set[str] = set()

    @property
    def working_file_count(self) -> int:
        return len(self._working_files)

    def register_working_file(self, file_path: str, content_hash: str, description: str = "") -> None:
        """Registers a file as a verified working part of the application."""
        norm_path = file_path.replace("\\", "/")
        self._working_files[norm_path] = WorkingPartRecord(
            file_path=norm_path,
            content_hash=content_hash,
            description=description,
        )

    def is_working_file(self, file_path: str) -> bool:
        """Checks if a file is registered as a protected working part."""
        norm_path = file_path.replace("\\", "/")
        return norm_path in self._working_files

    def register_regression_test(self, test_path: str) -> None:
        """Registers a test file as an immutable regression check."""
        norm_path = test_path.replace("\\", "/")
        self._regression_tests.add(norm_path)

    def get_regression_tests(self) -> List[str]:
        """Returns all registered regression test paths."""
        return sorted(self._regression_tests)

    def can_mutate_file(self, file_path: str, scope: Optional[CapabilityScope] = None) -> bool:
        """Evaluates whether an agent's capability scope permits mutating file_path.

        Fail-closed invariant:
        If file_path is a protected working file, it CANNOT be mutated unless
        it is explicitly granted in scope.allowed_paths.
        """
        norm_path = file_path.replace("\\", "/")
        is_working = norm_path in self._working_files

        if scope is None:
            # Without capability scope, working files are strictly immutable
            return not is_working

        # Check if scope explicitly allows this path
        allows_path = any(
            norm_path == p.replace("\\", "/") or norm_path.startswith(p.replace("\\", "/") + "/")
            for p in scope.allowed_paths
        )

        if is_working and not allows_path:
            return False

        return allows_path
