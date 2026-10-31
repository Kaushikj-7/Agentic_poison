"""Autonomous agent execution loop and cryptographic state transition runner.

This module implements the multi-step autonomous execution loop for AgentPOI-SDE:
1. Anchors the initial repository state (R0) and computes the initial Merkle graph root (M0).
2. Formats authoritative user intent (T0) and untrusted context (T2) using epistemic envelopes.
3. Queries an advisory model provider (OpenRouter with graceful fallback).
4. Supports optional interactive step confirmation ([A]pprove / [R]eject / [Q]uit).
5. Routes all code mutations through DevGuard's fail-closed verification sink.
6. Updates workspace files, re-indexes AST in the Merkle knowledge graph, and commits state transitions.
7. Validates architectural ledger hash chain integrity and compiles an unforgeable verification report.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from agentpoi_sde.agent.armor import wrap_envelopes
from agentpoi_sde.agent.llm_provider import OpenRouterProvider
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor
from agentpoi_sde.domain import CodeMutation, MutationOp
from agentpoi_sde.facade import DevGuard
from agentpoi_sde.graph.arch_ledger import ArchitecturalLedger
from agentpoi_sde.graph.context_router import CryptographicContextRouter, RoutedContextBundle
from agentpoi_sde.graph.graph_indexer import GraphIndexer
from agentpoi_sde.graph.merkle_graph import MerkleKnowledgeGraph, NodeType
from agentpoi_sde.provenance.code_provenance import SourceOrigin
from agentpoi_sde.sink.atomic_writer import AtomicDiskWriter
from agentpoi_sde.verify.invariant_verifier import RepoInvariantVerifier


@dataclass
class StateTransitionRecord:
    """Cryptographic audit record for a single autonomous loop step transition."""

    step: int
    action: str
    target_path: str
    status: str
    violation_codes: List[str]
    pre_merkle_root: str
    post_merkle_root: str
    pre_tree_oid: str
    post_tree_oid: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state transition record to dictionary."""
        return {
            "step": self.step,
            "action": self.action,
            "target_path": self.target_path,
            "status": self.status,
            "violation_codes": list(self.violation_codes),
            "pre_merkle_root": self.pre_merkle_root,
            "post_merkle_root": self.post_merkle_root,
            "pre_tree_oid": self.pre_tree_oid,
            "post_tree_oid": self.post_tree_oid,
            "timestamp": self.timestamp,
        }


@dataclass
class UnforgeableVerificationReport:
    """Cryptographically verifiable execution summary report.

    Contains initial and final repository tree anchors (R0 -> Rt), Merkle knowledge
    graph roots (M0 -> Mt), complete step audit trails, and a deterministic SHA-256 digest.
    """

    task_id: str
    goal: str
    initial_tree_oid: str
    final_tree_oid: str
    initial_merkle_root: str
    final_merkle_root: str
    total_steps: int
    mutations_applied: int
    mutations_blocked: int
    transitions: List[StateTransitionRecord]
    ledger_chain_verified: bool
    status: str
    report_digest: str = ""

    def __post_init__(self) -> None:
        if not self.report_digest:
            self.report_digest = self.compute_digest()

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 digest of key report components."""
        payload = (
            f"{self.task_id}:{self.initial_tree_oid}:{self.final_tree_oid}:"
            f"{self.initial_merkle_root}:{self.final_merkle_root}:"
            f"{self.mutations_applied}:{self.mutations_blocked}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize verification report to dictionary."""
        return {
            "task_id": self.task_id,
            "goal": self.goal,
            "initial_tree_oid": self.initial_tree_oid,
            "final_tree_oid": self.final_tree_oid,
            "initial_merkle_root": self.initial_merkle_root,
            "final_merkle_root": self.final_merkle_root,
            "total_steps": self.total_steps,
            "mutations_applied": self.mutations_applied,
            "mutations_blocked": self.mutations_blocked,
            "transitions": [t.to_dict() for t in self.transitions],
            "ledger_chain_verified": self.ledger_chain_verified,
            "status": self.status,
            "report_digest": self.report_digest,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize verification report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        """Render report as human-readable Markdown summary."""
        lines = [
            "# AgentPOI-SDE Verification Report",
            "",
            "## Summary",
            f"- **Task ID**: `{self.task_id}`",
            f"- **Goal**: {self.goal}",
            f"- **Status**: `{self.status}`",
            f"- **Report Digest (SHA-256)**: `{self.report_digest}`",
            f"- **Ledger Chain Integrity**: `{'VERIFIED' if self.ledger_chain_verified else 'INVALID'}`",
            f"- **Initial Tree OID ($R_0$)**: `{self.initial_tree_oid}`",
            f"- **Final Tree OID ($R_t$)**: `{self.final_tree_oid}`",
            f"- **Initial Merkle Root ($M_0$)**: `{self.initial_merkle_root}`",
            f"- **Final Merkle Root ($M_t$)**: `{self.final_merkle_root}`",
            f"- **Total Steps**: {self.total_steps} (Applied: {self.mutations_applied}, Blocked: {self.mutations_blocked})",
            "",
            "## State Transitions",
            "| Step | Action | Target Path | Status | Violations | Pre-Merkle | Post-Merkle |",
            "|:---:|:---:|:---|:---:|:---|:---|:---|",
        ]
        for tr in self.transitions:
            v_codes = ",".join(tr.violation_codes) if tr.violation_codes else "-"
            pre_m = tr.pre_merkle_root[:8] if tr.pre_merkle_root else "-"
            post_m = tr.post_merkle_root[:8] if tr.post_merkle_root else "-"
            lines.append(
                f"| {tr.step} | {tr.action} | `{tr.target_path}` | {tr.status} | {v_codes} | `{pre_m}` | `{post_m}` |"
            )
        lines.append("")
        return "\n".join(lines)


class AutonomousAgentRunner:
    """Multi-step autonomous agent execution loop runner with fail-closed gating."""

    def __init__(
        self,
        repo_path: str = ".",
        guard: Optional[DevGuard] = None,
        provider: Optional[Any] = None,
        max_steps: int = 10,
        budget: Optional[float] = None,
        interactive: bool = False,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        rollback_on_failure: bool = False,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.max_steps = max_steps
        self.budget = budget
        self.interactive = interactive
        self.model = model
        self.api_key = api_key
        self.rollback_on_failure = rollback_on_failure
        self.guard = guard if guard is not None else self._init_default_guard()
        self.provider = provider if provider is not None else OpenRouterProvider(api_key=api_key, model=model)
        self.graph_indexer = GraphIndexer()

        # Unify Merkle Knowledge Graph with DevGuard
        if not hasattr(self.guard, "merkle_graph") or self.guard.merkle_graph is None:
            self.guard.merkle_graph = MerkleKnowledgeGraph()
        self.merkle_graph = self.guard.merkle_graph

        # Unify Architectural Ledger with DevGuard
        if not hasattr(self.guard, "arch_ledger") or self.guard.arch_ledger is None:
            self.guard.arch_ledger = ArchitecturalLedger()
        self.arch_ledger = self.guard.arch_ledger

        self.transitions: List[StateTransitionRecord] = []
        self._initial_workspace: Dict[str, str] = {}
        self._touched_files: Dict[str, Optional[str]] = {}
        self.last_routed_bundle: Optional[RoutedContextBundle] = None

    def _init_default_guard(self) -> DevGuard:
        """Initialize DevGuard from repo directory anchor with atomic disk writing enabled."""
        if self.repo_path.exists() and self.repo_path.is_dir():
            anchor = RepositoryStateAnchor.from_directory(str(self.repo_path))
            return DevGuard(
                files=dict(anchor.files),
                repo_dir=str(self.repo_path),
                apply_to_disk=True,
            )
        return DevGuard(files={})

    def _init_merkle_graph(self) -> None:
        """Index all workspace Python and general files into Merkle graph."""
        for path, content in sorted(self.guard.workspace.items()):
            if path.endswith(".py"):
                self.graph_indexer.index_source(self.merkle_graph, path, content)
            else:
                self.merkle_graph.add_node(
                    f"file:{path}",
                    NodeType.FILE,
                    {"path": path, "size": len(content)},
                )

    def _record_pre_mutation_state(self, rel_path: str) -> None:
        """Record pre-mutation content for a file path in touch journal if not already tracked."""
        norm_path = rel_path.replace("\\", "/").strip()
        if norm_path not in self._touched_files:
            target = self.repo_path / norm_path
            if target.exists() and target.is_file():
                try:
                    self._touched_files[norm_path] = target.read_text(encoding="utf-8")
                except Exception:
                    self._touched_files[norm_path] = self._initial_workspace.get(norm_path)
            elif norm_path in self._initial_workspace:
                self._touched_files[norm_path] = self._initial_workspace[norm_path]
            else:
                self._touched_files[norm_path] = None

    def _write_disk_mutation(self, mutation: CodeMutation) -> None:
        """Write approved mutation to disk atomically if not already applied by DevGuard."""
        if not self.guard.apply_to_disk and getattr(self.guard, "repo_dir", None) is None:
            return
        rel_path = mutation.path.replace("\\", "/").strip()
        if rel_path not in self._touched_files:
            self._record_pre_mutation_state(rel_path)

        if self.guard.apply_to_disk and self.guard.disk_writer is not None:
            return  # Already written atomically via DevGuard
        if not self.repo_path.is_dir():
            return
        AtomicDiskWriter(str(self.repo_path)).apply_mutation(mutation)

    def rollback(self) -> None:
        """Atomically revert workspace, repository anchor, disk state, and Merkle graph to R0/M0."""
        # 1. Revert guard workspace to snapshot
        self.guard.workspace = dict(self._initial_workspace)

        # 2. Re-anchor repository anchor back to R0
        self.guard.anchor = RepositoryStateAnchor(
            files=dict(self._initial_workspace),
            policy=self.guard.anchor.policy,
            dependency_allowlist=self.guard.anchor.declared_dependencies,
            design_decisions=self.guard.anchor.design_decisions,
        )
        if hasattr(self.guard, "verifier") and self.guard.verifier is not None:
            self.guard.verifier = RepoInvariantVerifier(
                self.guard.anchor,
                egress_allowlist=getattr(self.guard.verifier, "egress_allowlist", None),
                invariant_config=getattr(self.guard, "_invariant_config", None),
                working_anchor=getattr(self.guard, "working_anchor", None),
            )
        if hasattr(self.guard, "delta_extractor"):
            self.guard.delta_extractor = MutationDeltaExtractor(self.guard.anchor.policy)

        # 3. Revert touched disk files
        if self.repo_path.is_dir():
            for rel_path, orig_content in self._touched_files.items():
                target = self.repo_path / rel_path
                if orig_content is None:
                    if target.exists() and target.is_file():
                        target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(orig_content, encoding="utf-8")

        # 4. Synchronize Merkle graph back to M0
        fresh_graph = MerkleKnowledgeGraph()
        self.merkle_graph = fresh_graph
        self.guard.merkle_graph = fresh_graph
        self._init_merkle_graph()

        # 5. Restore architectural ledger and mutation audit ledger lengths
        if hasattr(self.guard, "arch_ledger") and hasattr(self.guard.arch_ledger, "_blocks"):
            self.guard.arch_ledger._blocks = self.guard.arch_ledger._blocks[: self._initial_arch_blocks_len]
        if hasattr(self.guard, "ledger"):
            self.guard.ledger = self.guard.ledger[: self._initial_ledger_len]

    def _update_merkle_graph(self, mutation: CodeMutation) -> None:
        """Update Merkle knowledge graph following an approved mutation."""
        if mutation.op == MutationOp.DELETE:
            return
        if mutation.path.endswith(".py"):
            self.graph_indexer.index_source(self.merkle_graph, mutation.path, mutation.new_content)

    def _prompt_interactive(self, step: int, mutation: CodeMutation) -> str:
        """Prompt user for confirmation in interactive mode on stderr. Returns 'A', 'R', or 'Q'."""
        op_str = mutation.op.value if isinstance(mutation.op, MutationOp) else str(mutation.op)
        sys.stderr.write(f"\n[Step {step}] Proposed mutation: {op_str} -> {mutation.path}\n")
        if mutation.new_content:
            preview = mutation.new_content.strip()[:200]
            sys.stderr.write(f"Content preview:\n{preview}...\n")
        sys.stderr.write("[A]pprove / [R]eject / [Q]uit: ")
        sys.stderr.flush()
        try:
            choice = input().strip().upper()
        except (EOFError, KeyboardInterrupt):
            return "Q"
        if choice in ("A", "APPROVE"):
            return "A"
        if choice in ("R", "REJECT"):
            return "R"
        return "Q"

    def _execute_step(
        self,
        t: int,
        mutation: CodeMutation,
        intent_id: str,
        curr_m: str,
        curr_r: str,
    ) -> StateTransitionRecord:
        """Route mutation through DevGuard sink and update state anchors if approved."""
        self._record_pre_mutation_state(mutation.path)
        verdict = self.guard.propose_mutation(mutation, intent_id, nonce=f"step-{t}")
        op_name = mutation.op.value if isinstance(mutation.op, MutationOp) else str(mutation.op)

        if verdict.is_applied:
            self._write_disk_mutation(mutation)
            self._update_merkle_graph(mutation)
            post_m = self.merkle_graph.compute_merkle_root()
            post_r = self.guard.commit()
        else:
            post_m = curr_m
            post_r = curr_r

        return StateTransitionRecord(
            step=t,
            action=op_name,
            target_path=mutation.path,
            status="APPROVED" if verdict.is_applied else "BLOCKED",
            violation_codes=list(verdict.violation_codes),
            pre_merkle_root=curr_m,
            post_merkle_root=post_m,
            pre_tree_oid=curr_r,
            post_tree_oid=post_r,
        )

    def _resolve_status(
        self, blocked: int, quit_flag: bool, budget_flag: bool, step_limit_flag: bool
    ) -> str:
        """Determine final report status based on loop outcome."""
        if blocked > 0:
            return "VIOLATIONS_DETECTED"
        if quit_flag:
            return "USER_QUIT"
        if budget_flag:
            return "BUDGET_EXHAUSTED"
        if step_limit_flag:
            return "STEP_LIMIT"
        return "SUCCESS"

    def _init_run_session(
        self, task: str, task_id: Optional[str], allowed_paths: Optional[Sequence[str]]
    ) -> Tuple[str, str, str, str]:
        """Initialize session identifiers, anchors, Merkle graph, and authenticated intent."""
        effective_task = str(task or "").strip()
        tid = task_id or f"TASK-{hashlib.sha256(effective_task.encode('utf-8')).hexdigest()[:8]}"
        self._initial_workspace = dict(self.guard.workspace)
        self._touched_files = {}
        self._initial_ledger_len = len(self.guard.ledger) if hasattr(self.guard, "ledger") else 0
        self._initial_arch_blocks_len = (
            len(self.guard.arch_ledger._blocks)
            if hasattr(self.guard, "arch_ledger") and hasattr(self.guard.arch_ledger, "_blocks")
            else 0
        )
        r0 = self.guard.anchor.tree_oid()
        self._init_merkle_graph()
        m0 = self.merkle_graph.compute_merkle_root()
        self.guard.register_intent(tid, effective_task, allowed_paths or ["*"])
        return effective_task, tid, r0, m0

    def _fetch_proposals(
        self, tid: str, task: str, untrusted: Optional[Sequence[Tuple[str, str]]]
    ) -> List[CodeMutation]:
        """Fetch code mutations from provider using epistemic envelope prompt and routed cryptographic context."""
        all_untrusted = list(untrusted or [])
        try:
            router = CryptographicContextRouter(self.merkle_graph, self.guard.arch_ledger)
            target_keys = list(self.guard.workspace.keys())
            bundle: RoutedContextBundle = router.route_context(task_query=task, target_paths=target_keys)
            self.last_routed_bundle = bundle
            if bundle.formatted_context:
                all_untrusted.append(("cryptographic_context_router", bundle.formatted_context))
        except Exception:
            pass

        envelope = wrap_envelopes(intent_id=tid, goal=task, untrusted_contexts=all_untrusted)
        proposals = self.provider.propose_mutations(task, envelope, self.guard.workspace)
        return [p.to_code_mutation() if hasattr(p, "to_code_mutation") else p for p in proposals]

    def _record_user_rejection(
        self, t: int, mutation: CodeMutation, curr_m: str, curr_r: str
    ) -> None:
        """Record user rejection transition record in audit trail."""
        op_val = mutation.op.value if isinstance(mutation.op, MutationOp) else str(mutation.op)
        self.transitions.append(
            StateTransitionRecord(
                step=t,
                action=op_val,
                target_path=mutation.path,
                status="REJECTED_BY_USER",
                violation_codes=["USER_REJECTED"],
                pre_merkle_root=curr_m,
                post_merkle_root=curr_m,
                pre_tree_oid=curr_r,
                post_tree_oid=curr_r,
            )
        )

    def _process_step_mutation(
        self, t: int, mutation: CodeMutation, tid: str, curr_m: str, curr_r: str
    ) -> bool:
        """Handle interactive check and step execution. Returns True if quit requested."""
        if self.interactive:
            choice = self._prompt_interactive(t, mutation)
            if choice == "Q":
                return True
            if choice == "R":
                self._record_user_rejection(t, mutation, curr_m, curr_r)
                return False

        record = self._execute_step(t, mutation, tid, curr_m, curr_r)
        self.transitions.append(record)
        return False

    def _run_loop(
        self, tid: str, task: str, untrusted: Optional[Sequence[Tuple[str, str]]]
    ) -> Tuple[bool, bool, bool]:
        """Execute bounded iteration loop. Returns (quit_flag, budget_flag, step_limit_flag)."""
        pending: List[CodeMutation] = []
        seen: Set[Tuple[str, str, str]] = set()
        spent_budget = 0.0
        limit_flag = False

        for t in range(1, max(0, self.max_steps) + 1):
            if self.budget is not None and spent_budget >= self.budget:
                return False, True, False
            if not pending:
                pending = self._fetch_proposals(tid, task, untrusted)
            if not pending:
                break
            mutation = pending.pop(0)
            op_str = mutation.op.value if isinstance(mutation.op, MutationOp) else str(mutation.op)
            sig = (op_str, mutation.path, mutation.new_content)
            if sig in seen:
                break
            seen.add(sig)

            quit_req = self._process_step_mutation(
                t, mutation, tid, self.merkle_graph.compute_merkle_root(), self.guard.anchor.tree_oid()
            )
            if quit_req:
                return True, False, False
            spent_budget += 1.0
            if t == self.max_steps and (pending or not self.transitions):
                limit_flag = True
        return False, False, limit_flag

    def run(
        self,
        task: str,
        task_id: Optional[str] = None,
        allowed_paths: Optional[Sequence[str]] = None,
        context: str = "",
        untrusted_contexts: Optional[Sequence[Tuple[str, str]]] = None,
        rollback_on_failure: Optional[bool] = None,
    ) -> UnforgeableVerificationReport:
        """Run the multi-step autonomous agent loop with fail-closed gating."""
        all_untrusted = list(untrusted_contexts or [])
        if context:
            all_untrusted.append(("context", context))
        for _label, text in all_untrusted:
            self.guard.register_context(text, origin=SourceOrigin.UNTRUSTED_WEB)

        eff_task, tid, r0, m0 = self._init_run_session(task, task_id, allowed_paths)
        quit_flag, budget_flag, limit_flag = self._run_loop(tid, eff_task, all_untrusted)

        applied = sum(1 for tr in self.transitions if tr.status == "APPROVED")
        blocked = sum(1 for tr in self.transitions if tr.status == "BLOCKED")
        final_status = self._resolve_status(blocked, quit_flag, budget_flag, limit_flag)

        do_rollback = self.rollback_on_failure if rollback_on_failure is None else rollback_on_failure
        if not do_rollback and os.environ.get("AGENTPOI_ROLLBACK_ON_FAILURE") in ("1", "true", "True"):
            do_rollback = True

        final_r = self.guard.anchor.tree_oid()
        final_m = self.merkle_graph.compute_merkle_root()

        if do_rollback and final_status in ("VIOLATIONS_DETECTED", "USER_QUIT"):
            self.rollback()
            for tr in self.transitions:
                if tr.status == "APPROVED":
                    tr.status = "ROLLED_BACK"
            applied = 0
            final_r = r0
            final_m = m0

        return UnforgeableVerificationReport(
            task_id=tid,
            goal=eff_task,
            initial_tree_oid=r0,
            final_tree_oid=final_r,
            initial_merkle_root=m0,
            final_merkle_root=final_m,
            total_steps=len(self.transitions),
            mutations_applied=applied,
            mutations_blocked=blocked,
            transitions=self.transitions,
            ledger_chain_verified=self.guard.arch_ledger.verify_chain_integrity(),
            status=final_status,
        )

