"""Repository State Anchor (R0): immutable, content-addressed repository ground truth.

R0 is the software-engineering analogue of the financial Immutable State Anchor S0. It is
derived exclusively from committed artefacts (file contents, the derived AST symbol/import
graph, the declared architecture policy and the lockfile-derived dependency allowlist).
Untrusted context can never mutate R0: a mutation is judged *against* it and only promoted
into a new R0 at an explicit, ledgered commit.
"""

import hashlib
from typing import Dict, Iterable, List, Optional, Set

from agentpoi_sde.anchor.policy_registry import default_policy, is_policy_file, is_test_file
from agentpoi_sde.anchor.symbol_index import SymbolIndex, find_cycles
from agentpoi_sde.domain import ArchitecturePolicy, DesignDecision


def content_hash(text: str) -> str:
    """Return the SHA-256 hex digest of ``text`` (deterministic, encoding-stable)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RepositoryStateAnchor:
    """Deterministic snapshot of repository ground truth."""

    def __init__(
        self,
        files: Optional[Dict[str, str]] = None,
        policy: Optional[ArchitecturePolicy] = None,
        dependency_allowlist: Optional[Iterable[str]] = None,
        design_decisions: Optional[Iterable[DesignDecision]] = None,
    ) -> None:
        self.files: Dict[str, str] = {p: (c or "") for p, c in (files or {}).items()}
        self.policy: ArchitecturePolicy = policy or default_policy()
        self.declared_dependencies: Set[str] = set(dependency_allowlist or [])
        self.design_decisions: List[DesignDecision] = list(design_decisions or [])
        self.symbol_index = SymbolIndex().build(self.files)
        self.import_graph: Dict[str, Set[str]] = self.symbol_index.internal_edges()

    # -- identity -----------------------------------------------------------------
    def file_hash(self, path: str) -> str:
        """Return the content hash of a committed file (empty string hash if absent)."""
        return content_hash(self.files.get(path, ""))

    def tree_oid(self) -> str:
        """Return a stable tree object id over all committed (path, content-hash) pairs."""
        manifest = "\n".join(
            f"{path}:{self.file_hash(path)}" for path in sorted(self.files)
        )
        return content_hash(manifest)

    # -- structural queries -------------------------------------------------------
    def exists(self, path: str) -> bool:
        """Return True if the path exists in committed ground truth."""
        return path in self.files

    def committed_content(self, path: str) -> str:
        """Return the committed content of a path ("" if absent)."""
        return self.files.get(path, "")

    def is_protected(self, path: str) -> bool:
        """Return True when the path is a protected agent/CI/policy artefact."""
        return is_policy_file(path, self.policy)

    def is_test(self, path: str) -> bool:
        """Return True when the path belongs to the test oracle."""
        return is_test_file(path, self.policy)

    def layer_of(self, path: str) -> Optional[str]:
        """Return the declared architecture layer of a path."""
        return self.policy.layer_of(path)

    def external_dependencies(self) -> Set[str]:
        """Return the top-level external dependencies already present in R0."""
        return self.symbol_index.external_imports()

    def verified_dependencies(self) -> Set[str]:
        """Return the union of R0 external imports and declared (lockfile) dependencies."""
        return self.external_dependencies() | self.declared_dependencies

    def cycles(self) -> List[List[str]]:
        """Return the dependency cycles currently present in R0."""
        return find_cycles(self.import_graph)

    def design_decisions_for(self, path: str) -> List[DesignDecision]:
        """Return design decisions whose enforced scope covers ``path``."""
        return [d for d in self.design_decisions if d.applies_to(path)]

    # -- evolution ----------------------------------------------------------------
    def add_design_decision(self, decision: DesignDecision) -> None:
        """Register a new executable design decision (Phase 4 design plane)."""
        self.design_decisions.append(decision)

    def to_files(self) -> Dict[str, str]:
        """Return a defensive copy of the committed file map."""
        return dict(self.files)

    @classmethod
    def from_files(
        cls,
        files: Dict[str, str],
        policy: Optional[ArchitecturePolicy] = None,
        dependency_allowlist: Optional[Iterable[str]] = None,
        design_decisions: Optional[Iterable[DesignDecision]] = None,
    ) -> "RepositoryStateAnchor":
        """Construct an anchor snapshot from a file map."""
        return cls(
            files=files,
            policy=policy,
            dependency_allowlist=dependency_allowlist,
            design_decisions=design_decisions,
        )
