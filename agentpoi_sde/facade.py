"""High-level public facade for the AgentPOI-SDE fail-closed coding-agent platform.

Exposes ``DevGuard``, ``GuardPolicy`` and ``MutationVerdict`` so developers can wrap an
autonomous coding or system-design agent with deterministic, fail-closed mutation
authorisation without wiring the anchor, delta algebra, provenance DAG or capability layer
by hand. Mirrors ``agent_poi.facade.FinancialGuard`` for cross-platform consistency.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agent_poi.memory.schema import SourceOrigin
from agentpoi_sde.anchor.policy_registry import injection_marker_hits
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.anchor.working_part_anchor import WorkingPartAnchor
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.config_loader import load_sde_config
from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor, screen_mutation_content
from agentpoi_sde.domain import (
    ArchitecturePolicy,
    CodeMutation,
    DesignDecision,
    GuardPolicy,
    IntentContract,
    InvariantViolation,
    MutationDelta,
    MutationOp,
    VerificationResult,
)
from agentpoi_sde.exceptions import (
    ArchitectureViolationError,
    BlastRadiusError,
    CapabilityScopeError,
    DependencyProvenanceError,
    PolicyFileIntegrityError,
    ReplayDetectedError,
    SDESecurityError,
    SecretProliferationError,
    SyntaxIntegrityError,
    TestIntegrityError,
    UntrustedProvenanceError,
)
from agentpoi_sde.graph.arch_ledger import ArchitecturalLedger
from agentpoi_sde.graph.merkle_graph import EdgeType, MerkleKnowledgeGraph, NodeType
from agentpoi_sde.harvester.component_harvester import (
    ComponentHarvester,
    HarvestedComponent,
)
from agentpoi_sde.provenance.code_provenance import ProvenanceDAG
from agentpoi_sde.sandbox.isolated_sandbox import (
    IsolatedConfigurationSandbox,
    SandboxExecutionResult,
)
from agentpoi_sde.sink.atomic_writer import AtomicDiskWriter
from agentpoi_sde.verify.invariant_verifier import RepoInvariantVerifier


class ViolationItem(str):
    """String representation of an invariant violation that also exposes .code and .message."""

    code: str
    message: str

    def __new__(cls, code: str, message: str) -> "ViolationItem":
        obj = super().__new__(cls, message)
        obj.code = code
        obj.message = message
        return obj

    def __repr__(self) -> str:
        return f"ViolationItem(code={self.code!r}, message={self.message!r})"


@dataclass
class MutationVerdict:
    """High-level verdict returned to callers for one proposed mutation."""

    is_applied: bool
    status: str  # "APPROVED" | "QUARANTINED" | "BLOCKED" | "MONITORED"
    intent_id: str
    mutation_path: str
    action_taken: str = "none"
    violations: List[Any] = field(default_factory=list)
    violation_codes: List[str] = field(default_factory=list)
    delta: Optional[MutationDelta] = None
    provenance_hash: Optional[str] = None

    @property
    def is_approved(self) -> bool:
        """Alias for ``is_applied`` for cross-platform API symmetry."""
        return self.is_applied


class DevGuard:
    """Fail-closed mutation guard for autonomous software-engineering agents.

    Example:
        >>> from agentpoi_sde import DevGuard, GuardPolicy, CodeMutation, MutationOp
        >>> guard = DevGuard(files={"svc/core/engine.py": "def f():\\n    return 1\\n"})
        >>> intent = guard.register_intent("T1", "add helper", ["svc/core/engine.py"])
        >>> verdict = guard.propose_mutation(
        ...     CodeMutation("svc/core/engine.py", MutationOp.MODIFY, "def f():\\n    return 2\\n"),
        ...     intent.intent_id,
        ... )
        >>> verdict.is_applied
        True
    """

    def __init__(
        self,
        policy: GuardPolicy = GuardPolicy.STRICT,
        files: Optional[Dict[str, str]] = None,
        architecture_policy: Optional[ArchitecturePolicy] = None,
        dependency_allowlist: Optional[Sequence[str]] = None,
        design_decisions: Optional[Sequence[DesignDecision]] = None,
        egress_allowlist: Optional[List[str]] = None,
        capability: Optional[CapabilityScope] = None,
        invariant_config: Optional[Dict[str, bool]] = None,
        working_anchor: Optional[WorkingPartAnchor] = None,
        raise_on_violation: bool = False,
        repo_dir: Optional[str] = None,
        apply_to_disk: bool = False,
        monitoring_applies_mutations: Optional[bool] = None,
    ) -> None:
        self.policy = GuardPolicy(policy)
        self.raise_on_violation = raise_on_violation
        self.repo_dir = repo_dir
        self.apply_to_disk = apply_to_disk
        if monitoring_applies_mutations is None:
            self.monitoring_applies_mutations = bool(
                load_sde_config().get("guard", {}).get("monitoring_applies_mutations", False)
            )
        else:
            self.monitoring_applies_mutations = bool(monitoring_applies_mutations)
        self.disk_writer = (
            AtomicDiskWriter(repo_dir) if (repo_dir and os.path.isdir(repo_dir)) else None
        )
        self._invariant_config = dict(invariant_config) if invariant_config else None
        self.anchor = RepositoryStateAnchor(
            files=dict(files or {}),
            policy=architecture_policy,
            dependency_allowlist=dependency_allowlist,
            design_decisions=design_decisions,
        )
        self.workspace: Dict[str, str] = self.anchor.to_files()
        self.working_anchor = working_anchor or WorkingPartAnchor()
        self.merkle_graph = MerkleKnowledgeGraph()
        self.arch_ledger = ArchitecturalLedger()
        self.sandbox = IsolatedConfigurationSandbox()
        self.harvester = ComponentHarvester()
        self.verifier = RepoInvariantVerifier(
            self.anchor,
            egress_allowlist=egress_allowlist,
            invariant_config=self._invariant_config,
            working_anchor=self.working_anchor,
        )
        self.delta_extractor = MutationDeltaExtractor(self.anchor.policy)
        self.provenance = ProvenanceDAG()
        self.capability = capability
        self.ledger: List[Dict[str, object]] = []
        self.audit_log: List[Dict[str, object]] = []
        self._intents: Dict[str, IntentContract] = {}
        self._intent_nodes: Dict[str, str] = {}
        self._context_nodes: List[str] = []
        self._consumed_nonces: set = set()

    # -- registration -------------------------------------------------------------
    def register_intent(
        self,
        intent_id: str,
        goal: str,
        allowed_paths: Sequence[str],
        obligations: Sequence[str] = (),
    ) -> IntentContract:
        """Register an authenticated intent contract as a T0 provenance root."""
        token = secrets.token_hex(16)
        contract = IntentContract(
            intent_id=intent_id,
            goal=goal,
            allowed_paths=tuple(allowed_paths),
            obligations=tuple(obligations),
            auth_token=token,
        )
        self._intents[intent_id] = contract
        node = self.provenance.add_node(
            content=f"intent:{intent_id}:{goal}",
            origin=SourceOrigin.VERIFIED_USER,
            node_id=f"intent::{intent_id}",
        )
        self._intent_nodes[intent_id] = node.node_id
        return contract

    def register_context(
        self,
        content: str,
        origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
        parent_ids: Optional[List[str]] = None,
        track: bool = True,
    ) -> str:
        """Register a context artefact (T1 repo ground truth or T2 untrusted) in the DAG."""
        node = self.provenance.add_node(
            content=str(content or ""),
            origin=origin,
            parent_ids=list(parent_ids or []),
        )
        if track:
            self._context_nodes.append(node.node_id)
        return node.node_id

    def reset_context(self) -> None:
        """Clear the active context node list (start of a new reasoning session)."""
        self._context_nodes = []

    def register_design_decision(self, decision: DesignDecision) -> None:
        """Register an executable design decision (ADR) that future mutations must respect."""
        self.anchor.add_design_decision(decision)

    # -- intent shield ------------------------------------------------------------
    def screen_context(self, text: str) -> List[str]:
        """Return injection markers detected in a context artefact (Intent Shield signal)."""
        return injection_marker_hits(str(text or ""))

    def screen_mutation_content(self, text: str) -> List[str]:
        """Return injection markers detected in mutation content (Intent Shield at sink)."""
        return screen_mutation_content(str(text or ""))

    # -- evaluation ---------------------------------------------------------------
    def _freshness_violations(self, nonce: Optional[str]) -> List[InvariantViolation]:
        """Return freshness (non-replay) violations for a nonce."""
        if nonce is None:
            return []
        if self.capability is not None:
            if not self.capability.consume(nonce):
                return [InvariantViolation("F", f"nonce '{nonce}' has already been consumed (replay).")]
            return []
        if nonce in self._consumed_nonces:
            return [InvariantViolation("F", f"nonce '{nonce}' has already been consumed (replay).")]
        self._consumed_nonces.add(nonce)
        return []

    def _apply(self, delta: MutationDelta) -> None:
        """Apply an authorised mutation to the working tree and optionally to disk."""
        if delta.op == MutationOp.DELETE:
            self.workspace.pop(delta.path, None)
        else:
            self.workspace[delta.path] = delta.new_content

        if self.apply_to_disk and self.disk_writer is not None:
            mutation = CodeMutation(
                path=delta.path,
                op=delta.op,
                new_content=delta.new_content,
                old_content=delta.old_content,
            )
            self.disk_writer.apply_mutation(mutation)

    def _build_result(
        self,
        intent: Optional[IntentContract],
        delta: MutationDelta,
        invariant_violations: List[InvariantViolation],
        provenance_violations: List[InvariantViolation],
        capability_violations: List[InvariantViolation],
        freshness_violations: List[InvariantViolation],
    ) -> VerificationResult:
        """Compose the aggregate verification result and the decision state."""
        all_violations = (
            list(invariant_violations)
            + list(provenance_violations)
            + list(capability_violations)
            + list(freshness_violations)
        )
        is_admitted = not all_violations
        is_executable = is_admitted
        decision = "ALLOWED" if is_admitted else "BLOCKED"
        return VerificationResult(
            is_admitted=is_admitted,
            is_executable=is_executable,
            decision=decision,
            violations=all_violations,
            delta=delta,
            provenance_hash=self.provenance.nodes[delta.provenance_node_id].sha256_hash
            if delta.provenance_node_id in self.provenance.nodes
            else None,
        )

    def _evaluate_mutation_gates(
        self,
        intent: IntentContract,
        delta: MutationDelta,
        nonce: Optional[str],
        mutation_node: Any,
    ) -> VerificationResult:
        """Evaluates provenance, capability, invariant, and freshness gates."""
        provenance_ok, provenance_msgs = self.provenance.verify_mutation_authority(mutation_node.node_id)
        provenance_violations = [self._split_provenance(msg) for msg in provenance_msgs]
        capability_violations = self.capability.validate(delta) if self.capability else []
        invariant_violations = list(self.verifier.verify(intent, delta, capability=self.capability))
        if self.verifier._on("enforce_policy_files"):
            injection_hits = self.screen_mutation_content(delta.new_content)
            if injection_hits:
                invariant_violations.append(
                    InvariantViolation(
                        "I1",
                        f"mutation content contains prompt injection directives: {injection_hits}.",
                    )
                )

        return self._build_result(
            intent=intent,
            delta=delta,
            invariant_violations=invariant_violations,
            provenance_violations=provenance_violations,
            capability_violations=capability_violations,
            freshness_violations=self._freshness_violations(nonce),
        )

    def _finalize_approved_mutation(
        self,
        delta: MutationDelta,
        intent_id: str,
        nonce: Optional[str],
        result: VerificationResult,
    ) -> MutationVerdict:
        """Applies delta, updates Merkle knowledge graph, logs decision, and returns approved verdict."""
        self._apply(delta)
        self._record(delta, intent_id, nonce, "approved")

        # Update runtime Merkle Knowledge Graph
        node_id = f"file:{delta.path}"
        payload = {
            "path": delta.path,
            "op": delta.op.value,
            "patch_hash": delta.patch_hash,
            "lines_added": delta.added_lines,
            "lines_removed": delta.removed_lines,
        }
        self.merkle_graph.add_node(node_id, NodeType.FILE, payload)
        if delta.symbol:
            sym_node_id = f"symbol:{delta.path}#{delta.symbol}"
            self.merkle_graph.add_node(
                sym_node_id, NodeType.SYMBOL, {"symbol": delta.symbol, "file": delta.path}
            )
            self.merkle_graph.add_edge(sym_node_id, node_id, EdgeType.EXTRACTED_FROM)

        live_graph_root = self.merkle_graph.compute_root_hash()
        self.arch_ledger.record_decision(
            feature=f"Mutation {delta.path} ({delta.op.value})",
            how=f"Applied delta to {delta.path}",
            why=f"Intent: {intent_id}",
            connections=[],
            elements_used=[delta.path],
            graph_root=live_graph_root,
        )

        if self.capability is not None:
            self.capability.record_touched_file(delta.path)

        return MutationVerdict(
            is_applied=True,
            status="APPROVED",
            intent_id=intent_id,
            mutation_path=delta.path,
            action_taken="applied",
            delta=delta,
            provenance_hash=result.provenance_hash,
        )

    def _finalize_blocked_mutation(
        self,
        delta: MutationDelta,
        intent_id: str,
        nonce: Optional[str],
        result: VerificationResult,
    ) -> MutationVerdict:
        """Audits quarantine event and returns blocked verdict."""
        self._audit(delta, intent_id, nonce, "blocked", result)
        verdict = MutationVerdict(
            is_applied=False,
            status="BLOCKED",
            intent_id=intent_id,
            mutation_path=delta.path,
            action_taken="quarantined",
            violations=[ViolationItem(v.code, v.message) for v in result.violations],
            violation_codes=result.violation_codes,
            delta=delta,
            provenance_hash=result.provenance_hash,
        )
        if self.raise_on_violation and not verdict.is_applied:
            self._raise(verdict)
        return verdict

    def _create_mutation_node_and_delta(
        self,
        mutation: CodeMutation,
        intent_id: str,
        mutation_origin: SourceOrigin,
        parent_node_ids: Optional[List[str]],
    ) -> Tuple[Any, MutationDelta]:
        """Creates provenance node for proposed mutation and extracts its AST delta."""
        parents = list(parent_node_ids or [])
        parents.append(self._intent_nodes[intent_id])
        parents.extend(self._context_nodes)
        node = self.provenance.add_node(
            content=f"mutation:{mutation.path}:{mutation.op.value}",
            origin=mutation_origin,
            parent_ids=parents,
        )
        delta = self.delta_extractor.extract(
            mutation,
            provenance_node_id=node.node_id,
            previous_content=self.workspace.get(mutation.path),
        )
        return node, delta

    def _handle_permissive(
        self, delta: MutationDelta, intent_id: str, nonce: Optional[str], mutation_node: Any
    ) -> MutationVerdict:
        """Applies mutation under PERMISSIVE policy bypass."""
        self._apply(delta)
        self._record(delta, intent_id, nonce, "approved_permissive")
        return MutationVerdict(
            is_applied=True,
            status="APPROVED",
            intent_id=intent_id,
            mutation_path=delta.path,
            action_taken="applied_permissive",
            delta=delta,
            provenance_hash=mutation_node.sha256_hash,
        )

    def _handle_monitoring(
        self, delta: MutationDelta, intent_id: str, nonce: Optional[str], result: VerificationResult
    ) -> MutationVerdict:
        """Audits mutation under MONITORING policy, applying only if monitoring_applies_mutations is enabled."""
        self._audit(delta, intent_id, nonce, "monitored", result)
        action_taken = "monitoring_logged"
        is_applied = False
        if self.monitoring_applies_mutations:
            self._apply(delta)
            action_taken = "monitoring_applied"
            is_applied = True

        return MutationVerdict(
            is_applied=is_applied,
            status="MONITORED",
            intent_id=intent_id,
            mutation_path=delta.path,
            action_taken=action_taken,
            violations=[ViolationItem(v.code, v.message) for v in result.violations],
            violation_codes=result.violation_codes,
            delta=delta,
            provenance_hash=result.provenance_hash,
        )

    def propose_mutation(
        self,
        mutation: CodeMutation,
        intent_id: str,
        nonce: Optional[str] = None,
        mutation_origin: Optional[SourceOrigin] = None,
        auth_token: Optional[str] = None,
        parent_node_ids: Optional[List[str]] = None,
    ) -> MutationVerdict:
        """Evaluate a proposed mutation through every gate and, if authorised, apply it."""
        intent = self._intents.get(intent_id)
        if intent is None:
            return MutationVerdict(
                is_applied=False,
                status="BLOCKED",
                intent_id=intent_id,
                mutation_path=mutation.path,
                action_taken="blocked_unknown_intent",
                violations=[f"I0: intent '{intent_id}' is not registered."],
                violation_codes=["I0"],
            )

        # Enforce provenance trust boundary:
        # A caller cannot self-assert VERIFIED_USER without supplying the authenticated intent auth_token.
        if mutation_origin == SourceOrigin.VERIFIED_USER:
            if not auth_token or auth_token != intent.auth_token:
                return MutationVerdict(
                    is_applied=False,
                    status="BLOCKED",
                    intent_id=intent_id,
                    mutation_path=mutation.path,
                    action_taken="blocked_unauthenticated_origin",
                    violations=[
                        ViolationItem(
                            "P1",
                            "P1: unauthenticated caller cannot self-assert VERIFIED_USER origin; valid intent auth_token required.",
                        )
                    ],
                    violation_codes=["P1"],
                )
            effective_origin = SourceOrigin.VERIFIED_USER
        elif mutation_origin is None:
            if auth_token and auth_token == intent.auth_token:
                effective_origin = SourceOrigin.VERIFIED_USER
            else:
                effective_origin = SourceOrigin.INTERNAL_TOOL
        else:
            effective_origin = mutation_origin

        mutation_node, delta = self._create_mutation_node_and_delta(
            mutation, intent_id, effective_origin, parent_node_ids
        )
        if self.policy == GuardPolicy.PERMISSIVE:
            return self._handle_permissive(delta, intent_id, nonce, mutation_node)

        result = self._evaluate_mutation_gates(intent, delta, nonce, mutation_node)
        if self.policy == GuardPolicy.MONITORING:
            return self._handle_monitoring(delta, intent_id, nonce, result)

        if result.is_executable:
            return self._finalize_approved_mutation(delta, intent_id, nonce, result)
        return self._finalize_blocked_mutation(delta, intent_id, nonce, result)

    # Backwards/forwards-compatible alias mirroring FinancialGuard.protect.
    def protect(self, mutation: CodeMutation, intent_id: str, **kwargs) -> MutationVerdict:
        """Alias for :meth:`propose_mutation`."""
        return self.propose_mutation(mutation, intent_id, **kwargs)

    # -- introspection ------------------------------------------------------------
    @staticmethod
    def _split_provenance(message: str) -> InvariantViolation:
        """Split a provenance violation string ('P2: ...') into a structured violation."""
        code = message.split(":", 1)[0] if ":" in message else "P"
        return InvariantViolation(code, message)

    def _record(self, delta: MutationDelta, intent_id: str, nonce: Optional[str], action: str) -> None:
        """Append an applied mutation to the ledger."""
        node = self.provenance.nodes.get(delta.provenance_node_id)
        self.ledger.append(
            {
                "path": delta.path,
                "op": delta.op.value,
                "patch_hash": delta.patch_hash,
                "provenance_hash": node.sha256_hash if node else None,
                "intent_id": intent_id,
                "nonce": nonce,
                "action": action,
            }
        )

    def _audit(
        self,
        delta: MutationDelta,
        intent_id: str,
        nonce: Optional[str],
        action: str,
        result: VerificationResult,
    ) -> None:
        """Append a blocked/monitored attempt to the audit log."""
        self.audit_log.append(
            {
                "path": delta.path,
                "op": delta.op.value,
                "intent_id": intent_id,
                "nonce": nonce,
                "action": action,
                "violation_codes": result.violation_codes,
                "violations": [v.message for v in result.violations],
            }
        )

    def _raise(self, verdict: MutationVerdict) -> None:
        """Raise a typed domain exception matching the primary violation code."""
        codes = set(verdict.violation_codes)
        details = {"violations": verdict.violations}
        if "I1" in codes:
            raise PolicyFileIntegrityError(verdict.mutation_path, details)
        if "I2" in codes:
            raise TestIntegrityError(verdict.mutation_path, details)
        if "I3" in codes:
            raise SecretProliferationError(verdict.violations, details)
        if "I4" in codes:
            raise ArchitectureViolationError("; ".join(verdict.violations), details)
        if "I5" in codes:
            raise BlastRadiusError(verdict.mutation_path, details)
        if "I6" in codes:
            raise DependencyProvenanceError("; ".join(verdict.violations), details)
        if "I7" in codes:
            raise SyntaxIntegrityError(verdict.mutation_path, details)
        if codes & {"P1", "P2", "P3", "P4"}:
            raise UntrustedProvenanceError(verdict.mutation_path, details)
        if "K1" in codes or "K2" in codes or "K3" in codes:
            raise CapabilityScopeError("; ".join(verdict.violations), details)
        if "F" in codes:
            raise ReplayDetectedError(verdict.mutation_path, details)
        raise SDESecurityError("; ".join(verdict.violations) or "mutation blocked", details)

    def get_workspace(self) -> Dict[str, str]:
        """Return a defensive copy of the current working tree."""
        return dict(self.workspace)

    def get_ledger(self) -> List[Dict[str, object]]:
        """Return the applied-mutation ledger."""
        return list(self.ledger)

    def get_audit_log(self) -> List[Dict[str, object]]:
        """Return the blocked/monitored attempt log."""
        return list(self.audit_log)

    def tree_oid(self) -> str:
        """Return the current working-tree object id."""
        return self.anchor.__class__(files=self.workspace, policy=self.anchor.policy).tree_oid()

    def commit(self) -> str:
        """Promote the working tree to a new immutable repository anchor R0."""
        self.anchor = RepositoryStateAnchor(
            files=dict(self.workspace),
            policy=self.anchor.policy,
            dependency_allowlist=self.anchor.declared_dependencies,
            design_decisions=self.anchor.design_decisions,
        )
        self.verifier = RepoInvariantVerifier(
            self.anchor,
            egress_allowlist=self.verifier.egress_allowlist,
            invariant_config=self._invariant_config,
            working_anchor=self.working_anchor,
        )
        self.delta_extractor = MutationDeltaExtractor(self.anchor.policy)
        return self.anchor.tree_oid()

    # -- working parts & sandbox --------------------------------------------------
    def register_working_file(self, file_path: str, content_hash: str = "", description: str = "") -> None:
        """Register a verified working file to protect it under Invariant I9."""
        actual_hash = content_hash or self.anchor.file_hash(file_path)
        self.working_anchor.register_working_file(file_path, actual_hash, description)

    def is_working_file(self, file_path: str) -> bool:
        """Check if file is protected as an immutable working part."""
        return self.working_anchor.is_working_file(file_path)

    def register_regression_test(self, test_path: str) -> None:
        """Register a test file as an immutable regression gate."""
        self.working_anchor.register_regression_test(test_path)

    def run_sandbox_tests(
        self,
        feature_name: str,
        test_files: Dict[str, str],
        source_files: Optional[Dict[str, str]] = None,
    ) -> SandboxExecutionResult:
        """Run tests in clean isolated configuration sandbox."""
        return self.sandbox.run_test_in_isolation(
            feature_name=feature_name,
            test_files=test_files,
            source_files=source_files or {},
        )

    # -- component harvesting -----------------------------------------------------
    def harvest_component(
        self,
        repo_name: str,
        file_path: str,
        target_symbol: str,
        source_code: Optional[str] = None,
    ) -> HarvestedComponent:
        """Safely slice and sanitize open-source component for project reuse."""
        return self.harvester.harvest(
            repo_name=repo_name,
            file_path=file_path,
            target_symbol=target_symbol,
            source_code=source_code,
        )
