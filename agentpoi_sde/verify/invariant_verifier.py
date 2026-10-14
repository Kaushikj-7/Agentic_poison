"""Repository Invariant Verifier: the nine deterministic sink gates (I1-I9) plus design gates.

Each invariant maps to a documented, currently-unmitigated attack class (see
``docs/SDE_ARCHITECTURE.md`` §3). The verifier is pure: it takes the immutable repository
anchor R0, an authenticated intent contract I, and a mutation delta  Delta, and returns
machine-readable violations. It never consults the model's prose.
"""

from typing import Dict, List, Optional, Set

from agentpoi_sde.anchor.policy_registry import default_policy, forbidden_edge_reason
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.anchor.symbol_index import SymbolIndex, find_cycles
from agentpoi_sde.anchor.working_part_anchor import WorkingPartAnchor
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.config_loader import get_egress_allowlist, get_invariant_config
from agentpoi_sde.delta.mutation_delta import is_weakening
from agentpoi_sde.domain import (
    ArchitecturePolicy,
    IntentContract,
    InvariantViolation,
    MutationDelta,
    MutationOp,
)
from agentpoi_sde.schema.backend_extractor import BackendRouteExtractor
from agentpoi_sde.schema.contract_model import BackendRoute, FrontendCall
from agentpoi_sde.schema.cross_stack_verifier import CrossStackVerifier
from agentpoi_sde.schema.frontend_extractor import FrontendCallExtractor


class RepoInvariantVerifier:
    """Evaluates mutation deltas against the immutable repository anchor R0."""

    def __init__(
        self,
        anchor: RepositoryStateAnchor,
        egress_allowlist: Optional[List[str]] = None,
        invariant_config: Optional[Dict[str, bool]] = None,
        working_anchor: Optional[WorkingPartAnchor] = None,
    ) -> None:
        self.anchor = anchor
        self.policy: ArchitecturePolicy = anchor.policy or default_policy()
        self.egress_allowlist = list(egress_allowlist or get_egress_allowlist())
        self.enabled: Dict[str, bool] = dict(get_invariant_config())
        if invariant_config:
            self.enabled.update(invariant_config)
        self.working_anchor = working_anchor or getattr(anchor, "working_anchor", None)

    def _on(self, key: str) -> bool:
        """Return whether an invariant is enabled (defaults to enabled when unspecified)."""
        return bool(self.enabled.get(key, True))

    # -- projection ---------------------------------------------------------------
    def _projected_files(self, delta: MutationDelta) -> Dict[str, str]:
        """Return R0's files with the candidate mutation applied (hypothetical tree)."""
        projected = self.anchor.to_files()
        if delta.op == MutationOp.DELETE:
            projected.pop(delta.path, None)
        else:
            projected[delta.path] = delta.new_content
        return projected

    # -- I1 policy-file integrity -------------------------------------------------
    def check_policy_files(self, intent: IntentContract, delta: MutationDelta) -> List[InvariantViolation]:
        """A protected policy/CI artefact may only be mutated when explicitly in intent scope."""
        if delta.is_policy_file and not intent.permits(delta.path):
            return [
                InvariantViolation(
                    "I1",
                    f"protected policy path '{delta.path}' mutated without an authenticated "
                    f"intent grant (injection-driven policy/CI tampering).",
                )
            ]
        return []

    # -- I2 test integrity --------------------------------------------------------
    def check_test_integrity(self, delta: MutationDelta) -> List[InvariantViolation]:
        """A mutation may not weaken, skip or delete the test oracle it is meant to satisfy."""
        if is_weakening(delta):
            return [
                InvariantViolation(
                    "I2",
                    f"test oracle weakened at '{delta.path}' "
                    f"(removed_assertions={delta.removed_assertions}, "
                    f"added_skips={delta.added_skips}, deletes_test_file={delta.deletes_test_file}).",
                )
            ]
        return []

    # -- I3 secrets & egress ------------------------------------------------------
    def check_secrets_and_egress(self, delta: MutationDelta) -> List[InvariantViolation]:
        """No new credential material, and no new non-allow-listed egress endpoint."""
        violations: List[InvariantViolation] = []
        if delta.introduced_secrets:
            violations.append(
                InvariantViolation(
                    "I3",
                    f"mutation introduces credential material: {list(delta.introduced_secrets)}.",
                )
            )
        for url in delta.introduced_urls:
            if not any(url.startswith(prefix) for prefix in self.egress_allowlist):
                violations.append(
                    InvariantViolation("I3", f"mutation introduces non-allow-listed egress '{url}'.")
                )
        return violations

    # -- I4 architecture ----------------------------------------------------------
    def check_architecture(self, delta: MutationDelta) -> List[InvariantViolation]:
        """No forbidden layer edge, no newly-introduced dependency cycle."""
        violations: List[InvariantViolation] = []
        projected = self._projected_files(delta)
        new_edges: Dict[str, Set[str]] = SymbolIndex().build(projected).internal_edges()

        for target in sorted(new_edges.get(delta.path, set())):
            reason = forbidden_edge_reason(self.policy, delta.path, target)
            if reason:
                violations.append(InvariantViolation("I4", f"architecture violation: {reason}."))

        baseline_cycles = {tuple(sorted(c)) for c in self.anchor.cycles()}
        for cycle in find_cycles(new_edges):
            key = tuple(sorted(cycle))
            if key not in baseline_cycles:
                violations.append(
                    InvariantViolation(
                        "I4",
                        f"architecture violation: mutation introduces dependency cycle {cycle}.",
                    )
                )
                break
        return violations

    # -- I5 blast radius ----------------------------------------------------------
    def check_blast_radius(self, intent: IntentContract, delta: MutationDelta) -> List[InvariantViolation]:
        """Every mutated path must lie inside the declared intent scope."""
        if not intent.permits(delta.path):
            return [
                InvariantViolation(
                    "I5",
                    f"mutation path '{delta.path}' is outside intent '{intent.intent_id}' scope "
                    f"{list(intent.allowed_paths)}.",
                )
            ]
        return []

    # -- I6 dependency provenance -------------------------------------------------
    def check_dependency_provenance(self, delta: MutationDelta) -> List[InvariantViolation]:
        """Introduced imports must be internal or present in the verified dependency set."""
        verified = self.anchor.verified_dependencies()
        projected_index = SymbolIndex().build(self._projected_files(delta))
        violations: List[InvariantViolation] = []
        for dotted in delta.imports_added:
            if projected_index.resolve_import(dotted) is not None:
                continue
            top_level = dotted.split(".")[0]
            if top_level not in verified:
                violations.append(
                    InvariantViolation(
                        "I6",
                        f"dependency '{dotted}' has no verified provenance in R0 or the lockfile.",
                    )
                )
        return violations

    # -- I7 syntax integrity ------------------------------------------------------
    def check_syntax_integrity(self, delta: MutationDelta) -> List[InvariantViolation]:
        """A mutation must leave every touched Python file syntactically valid (fail-closed)."""
        if delta.syntax_error:
            return [
                InvariantViolation(
                    "I7",
                    f"mutation leaves '{delta.path}' unparsable; a mutation that cannot be "
                    f"parsed cannot be verified (fail-closed on malformed output).",
                )
            ]
        return []

    # -- I8 cross-stack schema consensus ------------------------------------------
    def check_cross_stack(self, delta: MutationDelta) -> List[InvariantViolation]:
        """A mutation must maintain contract consensus between frontend and backend."""
        projected = self._projected_files(delta)
        f_extractor = FrontendCallExtractor()
        b_extractor = BackendRouteExtractor()

        calls: List[FrontendCall] = []
        routes: List[BackendRoute] = []

        frontend_exts = (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html")
        for path, code in projected.items():
            if any(path.endswith(ext) for ext in frontend_exts):
                calls.extend(f_extractor.extract_calls(path, code))
            elif path.endswith(".py"):
                routes.extend(b_extractor.extract_routes(path, code))

        internal_calls = [
            c for c in calls
            if not (c.raw_path.startswith("http://") or c.raw_path.startswith("https://"))
        ]

        if not internal_calls:
            return []

        result = CrossStackVerifier().verify(internal_calls, routes)
        if not result.is_consistent:
            return [InvariantViolation("I8", f"{v.code}: {v.message}") for v in result.violations]
        return []

    # -- I9 working part immutability ---------------------------------------------
    def check_working_parts(
        self,
        delta: MutationDelta,
        capability: Optional[CapabilityScope] = None,
    ) -> List[InvariantViolation]:
        """A mutation may not touch protected working files without explicit capability."""
        if not self.working_anchor:
            return []

        if not self.working_anchor.can_mutate_file(delta.path, capability):
            return [
                InvariantViolation(
                    "I9",
                    f"mutation path '{delta.path}' touches protected working component without "
                    f"explicit capability scope grant (Invariant I9: Working Part Immutability).",
                )
            ]
        return []

    # -- design gates (D1) --------------------------------------------------------
    def check_design_decisions(self, delta: MutationDelta) -> List[InvariantViolation]:
        """A mutation must not contradict an executable design decision."""
        violations: List[InvariantViolation] = []
        for decision in self.anchor.design_decisions_for(delta.path):
            for dotted in delta.imports_added:
                for forbidden in decision.forbidden_imports:
                    if dotted == forbidden or dotted.startswith(forbidden + "."):
                        violations.append(
                            InvariantViolation(
                                "D1",
                                f"mutation contradicts design decision {decision.decision_id} "
                                f"('{decision.title}'): import '{dotted}' is forbidden.",
                            )
                        )
        return violations

    # -- aggregate ----------------------------------------------------------------
    def three_way_match(self, intent: IntentContract, delta: MutationDelta) -> List[InvariantViolation]:
        """The engineering three-way match: Intent I <-> Anchor R0 <-> Mutation  Delta."""
        violations: List[InvariantViolation] = []
        violations.extend(self.check_blast_radius(intent, delta))
        violations.extend(self.check_policy_files(intent, delta))
        return violations

    def verify(
        self,
        intent: IntentContract,
        delta: MutationDelta,
        capability: Optional[CapabilityScope] = None,
    ) -> List[InvariantViolation]:
        """Run every enabled invariant plus the design gates; return all violations found.

        Each invariant is individually governed by ``invariants.enforce_*`` configuration;
        an unspecified key defaults to enabled (fail-closed). Design decisions are always
        enforced. Disabling an invariant is an explicit operator choice, mirroring the
        ``GuardPolicy.MONITORING`` escape hatch rather than an implicit fail-open.
        """
        violations: List[InvariantViolation] = []
        if self._on("enforce_blast_radius"):
            violations.extend(self.check_blast_radius(intent, delta))
        if self._on("enforce_policy_files"):
            violations.extend(self.check_policy_files(intent, delta))
        if self._on("enforce_test_integrity"):
            violations.extend(self.check_test_integrity(delta))
        if self._on("enforce_secrets"):
            violations.extend(self.check_secrets_and_egress(delta))
        if self._on("enforce_architecture"):
            violations.extend(self.check_architecture(delta))
        if self._on("enforce_dependency_provenance"):
            violations.extend(self.check_dependency_provenance(delta))
        if self._on("enforce_syntax_integrity"):
            violations.extend(self.check_syntax_integrity(delta))
        if self._on("enforce_cross_stack"):
            violations.extend(self.check_cross_stack(delta))
        if self._on("enforce_working_parts"):
            violations.extend(self.check_working_parts(delta, capability=capability))
        violations.extend(self.check_design_decisions(delta))
        return violations
