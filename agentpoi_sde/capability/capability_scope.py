"""Capability Scope (K): deterministic least-privilege grants and replay protection.

A capability grant bounds exactly which paths, operations and egress an agent may touch for
one intent, plus a file budget. It is enforced outside the model, so model compliance is
never required (unlike prompt-level least-privilege, arXiv:2605.14859). The same structure
provides the freshness (non-replay) nonce store used by the sink.
"""

from fnmatch import fnmatch
from typing import Iterable, List, Optional, Set

from agentpoi_sde.domain import InvariantViolation, MutationDelta, MutationOp


class CapabilityScope:
    """A scoped, non-bypassable capability grant for a single intent."""

    def __init__(
        self,
        scope_id: str,
        allowed_paths: Iterable[str],
        allowed_ops: Optional[Iterable[MutationOp]] = None,
        egress_allowlist: Optional[Iterable[str]] = None,
        max_files: int = 1,
    ) -> None:
        self.scope_id = scope_id
        self.allowed_paths: List[str] = [p.replace("\\", "/") for p in allowed_paths]
        self.allowed_ops: Set[MutationOp] = set(allowed_ops or list(MutationOp))
        self.egress_allowlist: List[str] = list(egress_allowlist or [])
        self.max_files = max_files
        self._consumed_nonces: Set[str] = set()

    def _path_permitted(self, path: str) -> bool:
        """Return True when a path falls inside this grant's patterns."""
        norm = path.replace("\\", "/")
        for pattern in self.allowed_paths:
            pat = pattern + "*" if pattern.endswith("/") else pattern
            if fnmatch(norm, pat):
                return True
        return False

    def validate(self, delta: MutationDelta) -> List[InvariantViolation]:
        """Return capability-scope violations for a mutation delta."""
        violations: List[InvariantViolation] = []
        if not self._path_permitted(delta.path):
            violations.append(
                InvariantViolation("K1", f"path '{delta.path}' is outside capability grant '{self.scope_id}'.")
            )
        if delta.op not in self.allowed_ops:
            violations.append(
                InvariantViolation("K2", f"operation '{delta.op.value}' is not granted by '{self.scope_id}'.")
            )
        for url in delta.introduced_urls:
            if not any(url.startswith(prefix) for prefix in self.egress_allowlist):
                violations.append(
                    InvariantViolation("K3", f"egress endpoint '{url}' is not allow-listed by '{self.scope_id}'.")
                )
        return violations

    # -- freshness / non-replay ---------------------------------------------------
    def is_consumed(self, nonce: str) -> bool:
        """Return True when a nonce has already been consumed (a replay)."""
        return nonce in self._consumed_nonces

    def consume(self, nonce: str) -> bool:
        """Consume a nonce exactly once; return False when it was a replay."""
        if nonce in self._consumed_nonces:
            return False
        self._consumed_nonces.add(nonce)
        return True

    def consumed_count(self) -> int:
        """Return the number of consumed nonces (telemetry / tests)."""
        return len(self._consumed_nonces)
