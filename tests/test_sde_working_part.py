"""Tests for Phase P8: Working-Part Anchor and Isolated Configuration Sandbox (Invariant I9).

Verifies:
- Registration of verified working files and regression tests.
- Rejection of mutations that touch protected working files without explicit capability scope.
- Detection of regressions in working files.
- Isolated sandbox execution running tests in clean isolated configuration without touching primary working tree.
"""

from pathlib import Path

from agentpoi_sde.anchor.working_part_anchor import WorkingPartAnchor
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.domain import MutationOp
from agentpoi_sde.sandbox.isolated_sandbox import (
    IsolatedConfigurationSandbox,
)


class TestWorkingPartAnchor:
    """Tests for the WorkingPartAnchor protecting immutable working code."""

    def test_protect_working_file(self, tmp_path: Path):
        """A file marked as working is protected against unauthorized edits."""
        work_file = tmp_path / "payment_engine.py"
        work_file.write_text("def disburse(payee, amount): return True", encoding="utf-8")

        anchor = WorkingPartAnchor()
        anchor.register_working_file(
            file_path="payment_engine.py",
            content_hash="hash123",
            description="Core payment disbursement engine",
        )

        assert anchor.is_working_file("payment_engine.py") is True
        assert anchor.is_working_file("new_feature.py") is False

    def test_unauthorized_mutation_to_working_file_rejected(self):
        """Attempting to modify a working file without explicit capability is rejected."""
        anchor = WorkingPartAnchor()
        anchor.register_working_file(
            file_path="services/auth.py",
            content_hash="auth_hash",
            description="Production authentication gateway",
        )

        # Agent scope only allows modifying views/
        scope = CapabilityScope(
            scope_id="SCOPE-FEAT-1",
            allowed_paths=("views/profile.py",),
            allowed_ops=(MutationOp.MODIFY,),
        )

        # Modifying views/profile.py is allowed
        assert anchor.can_mutate_file("views/profile.py", scope) is True

        # Modifying services/auth.py is strictly blocked (touching working part)
        assert anchor.can_mutate_file("services/auth.py", scope) is False


class TestIsolatedConfigurationSandbox:
    """Tests for running end-to-end tests in an isolated sandbox configuration."""

    def test_sandbox_executes_isolated_tests(self, tmp_path: Path):
        """Executes a test script inside an isolated sandbox directory."""
        sandbox = IsolatedConfigurationSandbox(base_dir=tmp_path)

        # Create a benign test in the sandbox
        test_code = """
def test_addition():
    assert 2 + 2 == 4
"""
        result = sandbox.run_test_in_isolation(
            feature_name="Math Module",
            test_files={"test_math.py": test_code},
            source_files={"math_mod.py": "def add(a, b): return a + b"},
        )

        assert result.success is True
        assert result.exit_code == 0
        assert "passed" in result.output.lower()

    def test_sandbox_catches_regression(self, tmp_path: Path):
        """Catches a regression test failure in isolated sandbox."""
        sandbox = IsolatedConfigurationSandbox(base_dir=tmp_path)

        failing_test_code = """
def test_failing_regression():
    assert 1 == 2, "Regression: expected 1 == 2"
"""
        result = sandbox.run_test_in_isolation(
            feature_name="Broken Feature",
            test_files={"test_fail.py": failing_test_code},
            source_files={},
        )

        assert result.success is False
        assert result.exit_code != 0
        assert "regression" in result.output.lower() or "assertionerror" in result.output.lower()
