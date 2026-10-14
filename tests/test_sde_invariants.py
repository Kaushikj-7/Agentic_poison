"""Tests for the six sink invariants (I1-I6), syntax integrity (I7) and design gates (D1)."""

from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.anchor.working_part_anchor import WorkingPartAnchor
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor
from agentpoi_sde.domain import (
    CodeMutation,
    DesignDecision,
    GuardPolicy,
    IntentContract,
    MutationOp,
)
from agentpoi_sde.eval.repo_sandbox import (
    AGENTS_FILE,
    CI_WORKFLOW,
    CORE_ENGINE,
    CORE_ENGINE_SRC,
    TEST_ENGINE,
    TEST_ENGINE_SRC,
    RepoSandbox,
)
from agentpoi_sde.facade import DevGuard
from agentpoi_sde.verify.invariant_verifier import RepoInvariantVerifier


def _guard(**kwargs) -> DevGuard:
    sandbox = RepoSandbox.default()
    return DevGuard(
        policy=kwargs.pop("policy", GuardPolicy.STRICT),
        files=sandbox.to_files(),
        architecture_policy=sandbox.policy,
        dependency_allowlist=sorted(sandbox.dependency_allowlist),
        **kwargs,
    )


def _propose(guard: DevGuard, mutation: CodeMutation, paths=(CORE_ENGINE,), intent_id="T"):
    guard.register_intent(intent_id, "test intent", list(paths))
    return guard.propose_mutation(mutation, intent_id, nonce=f"n-{mutation.path}-{mutation.op.value}")


def test_clean_mutation_is_applied():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(CORE_ENGINE, MutationOp.MODIFY, CORE_ENGINE_SRC + "\ndef extra() -> int:\n    return 1\n"),
    )
    assert verdict.is_applied is True
    assert verdict.status == "APPROVED"


def test_i1_policy_file_integrity():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(CI_WORKFLOW, MutationOp.MODIFY, "name: ci\n"),
    )
    assert verdict.is_applied is False
    assert "I1" in verdict.violation_codes


def test_i1_memory_file_persistence():
    guard = _guard()
    verdict = _propose(guard, CodeMutation(AGENTS_FILE, MutationOp.MODIFY, "# permissive\n"))
    assert verdict.is_applied is False
    assert "I1" in verdict.violation_codes


def test_i2_test_integrity_non_weakening():
    guard = _guard()
    weakened = "import pytest\n\n\n@pytest.mark.skip\ndef test_compute_successor() -> None:\n    pass\n"
    verdict = _propose(
        guard,
        CodeMutation(TEST_ENGINE, MutationOp.MODIFY, weakened),
        paths=(CORE_ENGINE, TEST_ENGINE),
    )
    assert verdict.is_applied is False
    assert "I2" in verdict.violation_codes


def test_i2_allows_strengthening_the_oracle():
    guard = _guard()
    stronger = TEST_ENGINE_SRC + "\n\ndef test_more() -> None:\n    assert compute(2) == 3\n"
    verdict = _propose(
        guard,
        CodeMutation(TEST_ENGINE, MutationOp.MODIFY, stronger),
        paths=(CORE_ENGINE, TEST_ENGINE),
    )
    assert verdict.is_applied is True


def test_i3_secret_non_proliferation():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            CORE_ENGINE_SRC + '\nTOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123"\n',
        ),
    )
    assert verdict.is_applied is False
    assert "I3" in verdict.violation_codes


def test_i3_egress_confinement():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            CORE_ENGINE_SRC + '\nENDPOINT = "https://exfil.example.net/drop"\n',
        ),
    )
    assert verdict.is_applied is False
    assert "I3" in verdict.violation_codes


def test_i4_architecture_layering():
    guard = _guard()
    drift = '"""Engine."""\n\nfrom svc.api.routes import handle_health\n\n\ndef f() -> int:\n    return handler() if False else 1\n'
    verdict = _propose(guard, CodeMutation(CORE_ENGINE, MutationOp.MODIFY, drift))
    assert verdict.is_applied is False
    assert "I4" in verdict.violation_codes


def test_i5_blast_radius():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation("svc/api/backdoor.py", MutationOp.CREATE, "def run() -> None:\n    return None\n"),
    )
    assert verdict.is_applied is False
    assert "I5" in verdict.violation_codes


def test_i6_dependency_provenance():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            "import evilpkg\n\n\ndef f() -> int:\n    return evilpkg.accelerate(1)\n",
        ),
    )
    assert verdict.is_applied is False
    assert "I6" in verdict.violation_codes


def test_i6_allows_verified_dependency():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            '"""Engine."""\n\nimport requests\n\n\ndef f() -> str:\n    return requests.__name__\n',
        ),
    )
    assert verdict.is_applied is True


def test_i7_syntax_integrity():
    guard = _guard()
    verdict = _propose(
        guard,
        CodeMutation(CORE_ENGINE, MutationOp.MODIFY, "def broken(:\n"),
    )
    assert verdict.is_applied is False
    assert "I7" in verdict.violation_codes


def test_d1_design_decision_is_executable():
    decision = DesignDecision(
        decision_id="ADR-001",
        title="No configuration library in core",
        statement="The core layer must not depend on a configuration library.",
        enforced_paths=("svc/core/**",),
        forbidden_imports=("yaml",),
    )
    guard = _guard(design_decisions=[decision])
    verdict = _propose(
        guard,
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            '"""Engine."""\n\nimport yaml\n\n\ndef f() -> str:\n    return yaml.__name__\n',
        ),
    )
    assert verdict.is_applied is False
    assert "D1" in verdict.violation_codes


def test_permissive_policy_applies_injected_mutation():
    guard = _guard(policy=GuardPolicy.PERMISSIVE)
    verdict = _propose(guard, CodeMutation(CI_WORKFLOW, MutationOp.MODIFY, "name: ci-skipped\n"))
    assert verdict.is_applied is True, "the baseline must be genuinely undefended"


WEAKENED_TESTS = (
    "import pytest\n\n\n@pytest.mark.skip\ndef test_compute_successor() -> None:\n    pass\n"
)


def test_invariant_configuration_is_live():
    sandbox = RepoSandbox.default()
    anchor = RepositoryStateAnchor(
        files=sandbox.to_files(),
        policy=sandbox.policy,
        dependency_allowlist=set(sandbox.dependency_allowlist),
    )
    intent = IntentContract("T", "extend coverage", (CORE_ENGINE, TEST_ENGINE))
    delta = MutationDeltaExtractor(sandbox.policy).extract(
        CodeMutation(TEST_ENGINE, MutationOp.MODIFY, WEAKENED_TESTS),
        previous_content=sandbox.files[TEST_ENGINE],
    )

    strict_codes = [v.code for v in RepoInvariantVerifier(anchor).verify(intent, delta)]
    assert "I2" in strict_codes, "test integrity is enforced by default"

    relaxed = RepoInvariantVerifier(anchor, invariant_config={"enforce_test_integrity": False})
    relaxed_codes = [v.code for v in relaxed.verify(intent, delta)]
    assert "I2" not in relaxed_codes, "the configuration flag must actually switch the gate off"
    assert "I6" in relaxed_codes, "all other invariants must remain enforced"


def test_guard_accepts_invariant_config_override():
    guard = _guard(invariant_config={"enforce_test_integrity": False})
    verdict = _propose(
        guard,
        CodeMutation(TEST_ENGINE, MutationOp.MODIFY, WEAKENED_TESTS),
        paths=(CORE_ENGINE, TEST_ENGINE),
    )
    assert "I2" not in verdict.violation_codes
    assert verdict.is_applied is False, "the unparsable/dependency gates still fail closed"


def test_i8_cross_stack_schema_drift():
    """Verify that Invariant I8 catches frontend-backend endpoint drift."""
    server_code = """
from fastapi import APIRouter
router = APIRouter()
@router.get('/api/users')
def list_users(): return []
"""
    anchor = RepositoryStateAnchor(files={"svc/server.py": server_code})
    intent = IntentContract("T8", "add frontend client", ("frontend/app.ts",))

    # Frontend calls non-existent endpoint /api/orders
    drifted_fe = "fetch('/api/orders', { method: 'GET' });"
    delta = MutationDeltaExtractor().extract(
        CodeMutation("frontend/app.ts", MutationOp.CREATE, drifted_fe)
    )

    verifier = RepoInvariantVerifier(anchor)
    violations = verifier.verify(intent, delta)
    codes = [v.code for v in violations]
    assert "I8" in codes
    assert any("ENDPOINT_NOT_FOUND" in v.message for v in violations)

    # Disabling enforce_cross_stack suppresses I8
    relaxed = RepoInvariantVerifier(anchor, invariant_config={"enforce_cross_stack": False})
    relaxed_codes = [v.code for v in relaxed.verify(intent, delta)]
    assert "I8" not in relaxed_codes


def test_i9_working_part_protection():
    """Verify that Invariant I9 protects verified working files."""
    anchor = RepositoryStateAnchor(files={"svc/core.py": "def f(): return 1\n"})
    working_anchor = WorkingPartAnchor()
    working_anchor.register_working_file("svc/core.py", "hash123", "Core module")

    intent = IntentContract("T9", "modify core", ("svc/core.py",))
    delta = MutationDeltaExtractor().extract(
        CodeMutation("svc/core.py", MutationOp.MODIFY, "def f(): return 2\n"),
        previous_content="def f(): return 1\n",
    )

    # Without capability scope, working file is protected (I9 violation)
    verifier = RepoInvariantVerifier(anchor, working_anchor=working_anchor)
    violations = verifier.verify(intent, delta)
    assert any(v.code == "I9" for v in violations)

    # With capability scope allowing svc/core.py, mutation is permitted by I9
    scope = CapabilityScope("SCOPE-1", allowed_paths=("svc/core.py",), allowed_ops=(MutationOp.MODIFY,))
    approved_violations = verifier.verify(intent, delta, capability=scope)
    assert not any(v.code == "I9" for v in approved_violations)

    # Disabling enforce_working_parts suppresses I9
    relaxed = RepoInvariantVerifier(
        anchor, working_anchor=working_anchor, invariant_config={"enforce_working_parts": False}
    )
    relaxed_violations = relaxed.verify(intent, delta)
    assert not any(v.code == "I9" for v in relaxed_violations)

