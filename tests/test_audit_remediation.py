"""Unit tests verifying all fixes from the external architecture and code audit report."""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_poi.memory.schema import SourceOrigin
from agentpoi_sde.anchor.policy_registry import default_policy
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.delta.diff_parser import extract_git_mutations
from agentpoi_sde.domain import CodeMutation, GuardPolicy, MutationDelta, MutationOp
from agentpoi_sde.eval.repo_sandbox import DEFAULT_FILES, LOCKED_ENGINE, RepoSandbox
from agentpoi_sde.facade import DevGuard
from agentpoi_sde.sandbox.isolated_sandbox import IsolatedConfigurationSandbox
from agentpoi_sde.sink.atomic_writer import AtomicDiskTransaction, AtomicDiskWriter


# ---------------------------------------------------------------------------
# Finding 1: Git Diff Baseline & Reversed staged/unstaged Base Selection
# ---------------------------------------------------------------------------

def test_diff_parser_git_base_selection_staged_vs_unstaged():
    """Verify show_ref uses HEAD:path for staged and :path for unstaged."""
    captured_refs = []

    def mock_run(cmd, *args, **kwargs):
        if cmd[0] == "git" and cmd[1] == "diff":
            proc = MagicMock()
            proc.stdout = "--- a/svc/core.py\n+++ b/svc/core.py\n@@ -1 +1 @@\n-old\n+new\n"
            return proc
        if cmd[0] == "git" and cmd[1] == "show":
            captured_refs.append(cmd[2])
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = "old\n"
            return proc
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = ""
        return proc

    with patch("subprocess.run", side_effect=mock_run):
        # Staged diff: base is in HEAD
        extract_git_mutations(repo_path=".", staged=True)
        assert captured_refs[-1] == "HEAD:svc/core.py"

        # Unstaged diff: base is in the index (:path)
        extract_git_mutations(repo_path=".", staged=False)
        assert captured_refs[-1] == ":svc/core.py"


# ---------------------------------------------------------------------------
# Finding 2: Guarded Atomic Disk Writer & Transaction Rollback
# ---------------------------------------------------------------------------

def test_atomic_disk_writer_writes_and_replaces_atomically():
    with tempfile.TemporaryDirectory() as tmp_dir:
        writer = AtomicDiskWriter(tmp_dir)
        mutation = CodeMutation("svc/core/engine.py", MutationOp.CREATE, "def run(): return 42\n")
        res = writer.apply_mutation(mutation)
        assert "written:" in res

        target = Path(tmp_dir) / "svc/core/engine.py"
        assert target.is_file()
        assert target.read_text(encoding="utf-8") == "def run(): return 42\n"


def test_atomic_disk_writer_rejects_path_traversal():
    with tempfile.TemporaryDirectory() as tmp_dir:
        writer = AtomicDiskWriter(tmp_dir)
        with pytest.raises(ValueError, match="path traversal escape rejected|absolute path rejected"):
            writer.write_file_atomic("../../outside.txt", "evil")


def test_atomic_disk_transaction_rollback():
    with tempfile.TemporaryDirectory() as tmp_dir:
        writer = AtomicDiskWriter(tmp_dir)
        orig_file = Path(tmp_dir) / "orig.py"
        orig_file.write_text("initial content", encoding="utf-8")

        with pytest.raises(RuntimeError, match="Transaction aborted"):
            with writer.transaction() as tx:
                # Modify existing file
                tx.apply(CodeMutation("orig.py", MutationOp.MODIFY, "modified content"))
                assert orig_file.read_text(encoding="utf-8") == "modified content"

                # Create new file
                tx.apply(CodeMutation("new.py", MutationOp.CREATE, "new content"))
                new_file = Path(tmp_dir) / "new.py"
                assert new_file.exists()

                # Simulate a mid-transaction verification or execution failure
                raise RuntimeError("Transaction aborted")

        # After rollback: original file restored, new file deleted
        assert orig_file.read_text(encoding="utf-8") == "initial content"
        assert not (Path(tmp_dir) / "new.py").exists()


def test_devguard_apply_to_disk_enabled():
    with tempfile.TemporaryDirectory() as tmp_dir:
        guard = DevGuard(
            repo_dir=tmp_dir,
            apply_to_disk=True,
            files={"engine.py": "def f(): return 1\n"},
        )
        intent = guard.register_intent("T1", "update", ["engine.py"])
        verdict = guard.propose_mutation(
            CodeMutation("engine.py", MutationOp.MODIFY, "def f(): return 2\n"),
            intent_id=intent.intent_id,
        )
        assert verdict.is_applied
        disk_file = Path(tmp_dir) / "engine.py"
        assert disk_file.exists()
        assert disk_file.read_text(encoding="utf-8") == "def f(): return 2\n"


# ---------------------------------------------------------------------------
# Finding 3: Provenance Trust Boundary (VERIFIED_USER Requires auth_token)
# ---------------------------------------------------------------------------

def test_provenance_trust_boundary_unauthenticated_verified_user_blocked():
    guard = DevGuard(files={"svc/app.py": "x = 1\n"})
    intent = guard.register_intent("T1", "update", ["svc/app.py"])

    # Attempting to assert VERIFIED_USER without the valid intent auth_token must be blocked fail-closed
    verdict = guard.propose_mutation(
        CodeMutation("svc/app.py", MutationOp.MODIFY, "x = 2\n"),
        intent_id=intent.intent_id,
        mutation_origin=SourceOrigin.VERIFIED_USER,
        auth_token="wrong_token",
    )
    assert not verdict.is_applied
    assert verdict.status == "BLOCKED"
    assert "P1" in verdict.violation_codes
    assert "unauthenticated caller cannot self-assert VERIFIED_USER origin" in str(verdict.violations)


def test_provenance_authenticated_verified_user_accepted():
    guard = DevGuard(files={"svc/app.py": "x = 1\n"})
    intent = guard.register_intent("T1", "update", ["svc/app.py"])
    assert intent.auth_token

    # Supplying the authentic intent auth_token authorizes VERIFIED_USER origin
    verdict = guard.propose_mutation(
        CodeMutation("svc/app.py", MutationOp.MODIFY, "x = 2\n"),
        intent_id=intent.intent_id,
        mutation_origin=SourceOrigin.VERIFIED_USER,
        auth_token=intent.auth_token,
    )
    assert verdict.is_applied
    assert verdict.status == "APPROVED"


def test_provenance_default_to_internal_tool():
    guard = DevGuard(files={"svc/app.py": "x = 1\n"})
    intent = guard.register_intent("T1", "update", ["svc/app.py"])

    # Default call without specifying mutation_origin uses INTERNAL_TOOL (autonomous agent execution)
    verdict = guard.propose_mutation(
        CodeMutation("svc/app.py", MutationOp.MODIFY, "x = 2\n"),
        intent_id=intent.intent_id,
    )
    assert verdict.is_applied


# ---------------------------------------------------------------------------
# Finding 4: Sandbox Path Traversal Rejection
# ---------------------------------------------------------------------------

def test_isolated_sandbox_rejects_path_traversal():
    sandbox = IsolatedConfigurationSandbox()
    with pytest.raises(ValueError, match="sandbox path traversal rejected"):
        sandbox._write_files(Path("."), {"../../outside.txt": "evil content"})


def test_isolated_sandbox_rejects_absolute_path():
    sandbox = IsolatedConfigurationSandbox()
    with pytest.raises(ValueError, match="absolute path rejected in sandbox"):
        sandbox._write_files(Path("."), {"/etc/passwd": "evil content"})


# ---------------------------------------------------------------------------
# Finding 5: Real Hash Fixture in RepoSandbox
# ---------------------------------------------------------------------------

def test_repo_sandbox_real_hash_fixture():
    sandbox = RepoSandbox.default()
    expected_hash = hashlib.sha256(DEFAULT_FILES[LOCKED_ENGINE].encode("utf-8")).hexdigest()
    assert sandbox.working_anchor.is_file_registered(LOCKED_ENGINE)
    assert sandbox.working_anchor.registered_files[LOCKED_ENGINE].sha256_hash == expected_hash
    assert sandbox.working_anchor.registered_files[LOCKED_ENGINE].sha256_hash != "locked_kernel_sha256"


# ---------------------------------------------------------------------------
# Finding 6: Meaningful Default Architecture Policy
# ---------------------------------------------------------------------------

def test_default_architecture_policy_has_meaningful_rules():
    policy = default_policy()
    assert len(policy.layer_roots) > 0
    assert "core" in policy.layer_roots
    assert len(policy.forbidden_edges) > 0
    assert ("core", "api") in policy.forbidden_edges


# ---------------------------------------------------------------------------
# Finding 7: Enforce max_files Budget in CapabilityScope
# ---------------------------------------------------------------------------

def test_capability_scope_max_files_budget_enforced():
    scope = CapabilityScope("cap-budget", allowed_paths=["svc/**"], max_files=2)
    delta1 = MutationDelta("svc/a.py", MutationOp.MODIFY, None, "hash1")
    delta2 = MutationDelta("svc/b.py", MutationOp.MODIFY, None, "hash2")
    delta3 = MutationDelta("svc/c.py", MutationOp.MODIFY, None, "hash3")

    # File 1 touches allowed
    assert scope.validate(delta1) == []
    scope.record_touched_file("svc/a.py")

    # File 2 touches allowed (total 2 unique files = budget)
    assert scope.validate(delta2) == []
    scope.record_touched_file("svc/b.py")

    # Modifying an already touched file within budget is allowed
    assert scope.validate(delta1) == []

    # File 3 exceeds the max_files budget of 2 -> K4 violation
    violations = scope.validate(delta3)
    codes = [v.code for v in violations]
    assert "K4" in codes
    assert "file budget exceeded" in violations[0].message


# ---------------------------------------------------------------------------
# Finding 8: Disconnected Runtime Merkle Graph Tracking in DevGuard
# ---------------------------------------------------------------------------

def test_merkle_graph_live_runtime_tracking_in_devguard():
    guard = DevGuard(files={"svc/core/engine.py": "def f(): return 1\n"})
    intent = guard.register_intent("T1", "update", ["svc/core/engine.py"])

    # Initial Merkle graph has empty nodes
    assert guard.merkle_graph.node_count == 0

    verdict = guard.propose_mutation(
        CodeMutation("svc/core/engine.py", MutationOp.MODIFY, "def f(): return 2\n"),
        intent_id=intent.intent_id,
    )
    assert verdict.is_applied

    # After approved mutation, Merkle graph contains the node and ledger records the live root
    assert guard.merkle_graph.node_count > 0
    assert guard.merkle_graph.get_node("file:svc/core/engine.py") is not None
    live_root = guard.merkle_graph.compute_root_hash()
    assert guard.arch_ledger.latest_root == live_root


# ---------------------------------------------------------------------------
# Finding 9: Live Configuration Wiring (monitoring_applies_mutations)
# ---------------------------------------------------------------------------

def test_monitoring_applies_mutations_live_config_toggle():
    # When monitoring_applies_mutations is False: mutation is logged but NOT applied
    guard_logged = DevGuard(
        policy=GuardPolicy.MONITORING,
        monitoring_applies_mutations=False,
        files={"svc/app.py": "x = 1\n"},
    )
    intent = guard_logged.register_intent("T1", "test", ["svc/app.py"])
    v_logged = guard_logged.propose_mutation(
        CodeMutation("svc/app.py", MutationOp.MODIFY, "x = 2\n"),
        intent_id=intent.intent_id,
    )
    assert not v_logged.is_applied
    assert v_logged.action_taken == "monitoring_logged"
    assert guard_logged.workspace["svc/app.py"] == "x = 1\n"

    # When monitoring_applies_mutations is True: mutation is applied in monitoring mode
    guard_applied = DevGuard(
        policy=GuardPolicy.MONITORING,
        monitoring_applies_mutations=True,
        files={"svc/app.py": "x = 1\n"},
    )
    intent2 = guard_applied.register_intent("T2", "test", ["svc/app.py"])
    v_applied = guard_applied.propose_mutation(
        CodeMutation("svc/app.py", MutationOp.MODIFY, "x = 2\n"),
        intent_id=intent2.intent_id,
    )
    assert v_applied.is_applied
    assert v_applied.action_taken == "monitoring_applied"
    assert guard_applied.workspace["svc/app.py"] == "x = 2\n"
