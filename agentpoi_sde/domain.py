"""Core domain model for the AgentPOI-SDE fail-closed software engineering platform.

Defines the trust tiering, mutation algebra, intent contracts, architecture policy
and verification result types shared across the invariant pipeline. This module has
no dependencies on the anchor, verifier, or agent layers so it can be imported by all.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class TrustTier(str, Enum):
    """Epistemic trust tier of a context artefact (see docs/SDE_ARCHITECTURE.md §2)."""

    T0_AUTHENTICATED_INTENT = "t0_authenticated_intent"
    T1_REPOSITORY_GROUND_TRUTH = "t1_repository_ground_truth"
    T2_UNTRUSTED_CONTEXT = "t2_untrusted_context"


class MutationOp(str, Enum):
    """Normalised operation of a proposed code mutation."""

    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class GuardPolicy(str, Enum):
    """Operational policy for the fail-closed mutation sink."""

    STRICT = "strict"          # all invariants, provenance, capability and freshness enforced
    MONITORING = "monitoring"  # invariants evaluated and logged; nothing is applied
    PERMISSIVE = "permissive"  # baseline: mutation applied unconditionally (evaluation only)


@dataclass(frozen=True)
class CodeMutation:
    """A single proposed code mutation, authored by the agent.

    Content is carried explicitly so the delta extractor never has to guess what the
    agent intended from natural-language prose (anti-defect F1: no prose-shaped oracle).
    """

    path: str
    op: MutationOp
    new_content: str = ""
    old_content: str = ""
    symbol: Optional[str] = None


@dataclass(frozen=True)
class MutationDelta:
    """Normalised, typed description of a mutation  Delta(edit)."""

    path: str
    op: MutationOp
    symbol: Optional[str]
    patch_hash: str
    imports_added: Tuple[str, ...] = ()
    added_lines: int = 0
    removed_lines: int = 0
    introduced_secrets: Tuple[str, ...] = ()
    introduced_urls: Tuple[str, ...] = ()
    removed_assertions: int = 0
    added_skips: int = 0
    deletes_test_file: bool = False
    is_policy_file: bool = False
    is_test_file: bool = False
    syntax_error: bool = False
    provenance_node_id: str = ""
    old_content: str = ""
    new_content: str = ""


@dataclass(frozen=True)
class IntentContract:
    """The authenticated task contract  Intent anchor.  Paths are glob patterns."""

    intent_id: str
    goal: str
    allowed_paths: Tuple[str, ...]
    obligations: Tuple[str, ...] = ()
    auth_token: str = ""

    def permits(self, path: str) -> bool:
        """Return True when ``path`` falls inside any declared intent scope pattern."""
        from fnmatch import fnmatch

        norm = path.replace("\\", "/")
        for pattern in self.allowed_paths:
            pat = pattern.replace("\\", "/")
            if pat.endswith("/"):
                pat = pat + "*"
            if fnmatch(norm, pat):
                return True
        return False

    def permits_policy_file(self, path: str) -> bool:
        """Return True only when allowed_paths explicitly targets the policy file or directory."""
        from fnmatch import fnmatch

        norm = path.replace("\\", "/").lstrip("./")
        for pattern in self.allowed_paths:
            pat = pattern.replace("\\", "/").lstrip("./")
            if pat in ("*", "**", "*.*", "./*", "./**"):
                continue
            if pat.startswith("*") or pat.startswith("?"):
                continue
            if pat.endswith("/"):
                pat = pat + "*"
            if fnmatch(norm, pat) or norm == pat:
                return True
        return False


@dataclass(frozen=True)
class DesignDecision:
    """An Architecture Decision Record synthesised by the design plane.

    A decision becomes *executable* through ``enforced_paths`` (the scope it governs) and
    ``forbidden_imports`` (import prefixes that would contradict the decision).
    """

    decision_id: str
    title: str
    statement: str
    enforced_paths: Tuple[str, ...] = ()
    forbidden_imports: Tuple[str, ...] = ()

    def applies_to(self, path: str) -> bool:
        from fnmatch import fnmatch

        norm = path.replace("\\", "/")
        return any(fnmatch(norm, p.replace("\\", "/")) for p in self.enforced_paths)


@dataclass(frozen=True)
class ArchitecturePolicy:
    """Declared architecture invariants for a repository.

    ``layer_roots`` maps a human layer name to a path prefix (e.g. ``core`` -> ``svc/core``).
    ``forbidden_edges`` lists ``(importer_layer, imported_layer)`` pairs that must never
    be created (e.g. ``("core", "api")`` means core must not import api).
    """

    layer_roots: Dict[str, str]
    forbidden_edges: Tuple[Tuple[str, str], ...] = ()
    protected_paths: Tuple[str, ...] = ()
    test_markers: Tuple[str, ...] = ()

    def layer_of(self, path: str) -> Optional[str]:
        """Resolve the architecture layer of a path by longest matching prefix."""
        norm = path.replace("\\", "/")
        best_layer: Optional[str] = None
        best_len = -1
        for layer, prefix in self.layer_roots.items():
            pre = prefix.replace("\\", "/").rstrip("/")
            if norm == pre or norm.startswith(pre + "/"):
                if len(pre) > best_len:
                    best_layer = layer
                    best_len = len(pre)
        return best_layer


@dataclass(frozen=True)
class InvariantViolation:
    """A single, machine-readable invariant breach."""

    code: str
    message: str


@dataclass
class VerificationResult:
    """Outcome of the invariant verification pipeline for one mutation."""

    is_admitted: bool
    is_executable: bool
    decision: str  # "ALLOWED" | "QUARANTINED" | "BLOCKED" | "MONITORED"
    violations: List[InvariantViolation] = field(default_factory=list)
    delta: Optional[MutationDelta] = None
    provenance_hash: Optional[str] = None

    @property
    def violation_codes(self) -> List[str]:
        """Distinct invariant codes breached, for compact telemetry."""
        seen: List[str] = []
        for v in self.violations:
            if v.code not in seen:
                seen.append(v.code)
        return seen
