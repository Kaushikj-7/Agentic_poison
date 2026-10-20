"""Unit and integration test suite for Joint Epistemic Verifier (JEV).

Requirement R2: Fast (< 5ms on CPU) epistemic pre-screener validating AST syntax,
structural diff boundaries, and credential leakage locally with zero network calls.
"""

from __future__ import annotations

import pytest

from agentpoi_sde.agent.armor import CodeMutationProposal
from agentpoi_sde.agent.jev import (
    JEV_APPROVED,
    JEV_CREDENTIAL_LEAK,
    JEV_STRUCTURAL_ERROR,
    JEV_SYNTAX_ERROR,
    JointEpistemicVerifier,
)
from agentpoi_sde.domain import CodeMutation, MutationOp


def test_jev_valid_python_mutation_approved():
    """Verify clean Python mutation passes all JEV gates."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="src/service/calc.py",
        op=MutationOp.CREATE,
        new_content="def add(a: int, b: int) -> int:\n    return a + b\n",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is True
    assert verdict.code == JEV_APPROVED
    assert verdict.error is None
    assert verdict.latency_ms < 5.0
    assert bool(verdict) is True


def test_jev_syntax_error_rejected():
    """Verify syntax error in Python code triggers JEV_SYNTAX_ERROR fail-closed."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="src/service/broken.py",
        op=MutationOp.MODIFY,
        new_content="def broken(:\n    return False\n",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_SYNTAX_ERROR
    assert "syntax error" in str(verdict.error).lower()
    assert verdict.latency_ms < 5.0


def test_jev_non_python_syntax_permitted():
    """Verify non-Python files (e.g. markdown/json/txt) do not fail AST syntax gate."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="docs/guide.md",
        op=MutationOp.CREATE,
        new_content="# Title\nSome description: not python code () def",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is True
    assert verdict.code == JEV_APPROVED


def test_jev_structural_diff_traversal_path_rejected():
    """Verify directory traversal path triggers JEV_STRUCTURAL_ERROR."""
    verifier = JointEpistemicVerifier()
    # Path traversal via ..
    proposal = CodeMutation(
        path="../../etc/passwd",
        op=MutationOp.CREATE,
        new_content="root:x:0:0::/root:/bin/bash\n",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_STRUCTURAL_ERROR
    assert "traversal" in str(verdict.error).lower() or "invalid" in str(verdict.error).lower()


def test_jev_structural_diff_uri_scheme_rejected():
    """Verify URI scheme path triggers JEV_STRUCTURAL_ERROR."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="file:///var/secret.py",
        op=MutationOp.CREATE,
        new_content="x = 1\n",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_STRUCTURAL_ERROR
    assert "uri" in str(verdict.error).lower() or "scheme" in str(verdict.error).lower()


def test_jev_structural_diff_unc_path_rejected():
    """Verify UNC or Windows device path triggers JEV_STRUCTURAL_ERROR."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="\\\\server\\share\\evil.py",
        op=MutationOp.CREATE,
        new_content="x = 1\n",
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_STRUCTURAL_ERROR


def test_jev_structural_diff_malformed_unified_diff_rejected():
    """Verify malformed unified diff string triggers JEV_STRUCTURAL_ERROR."""
    verifier = JointEpistemicVerifier()
    corrupt_diff = "--- a/test.py\n+++ b/test.py\n@@ garbage header @@\n+print('hello')\n"
    verdict = verifier.verify_proposal(corrupt_diff)
    assert verdict.approved is False
    assert verdict.code == JEV_STRUCTURAL_ERROR


def test_jev_structural_diff_valid_diff_approved():
    """Verify valid unified diff string is parsed and verified."""
    verifier = JointEpistemicVerifier()
    valid_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def main():\n"
        "+    print('hello world')\n"
        "     return 0\n"
    )
    workspace = {"app.py": "def main():\n    return 0\n"}
    verdict = verifier.verify_proposal(valid_diff, workspace=workspace)
    assert verdict.approved is True
    assert verdict.code == JEV_APPROVED


def test_jev_credential_leak_private_key_rejected():
    """Verify multiline private key injection triggers JEV_CREDENTIAL_LEAK."""
    verifier = JointEpistemicVerifier()
    key_content = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0mockprivatekeycontent123456789\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    proposal = CodeMutation(
        path="src/config/key.py",
        op=MutationOp.CREATE,
        new_content=f'SECRET_KEY = """{key_content}"""\n',
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_CREDENTIAL_LEAK
    assert "credential" in str(verdict.error).lower() or "key" in str(verdict.error).lower()


def test_jev_credential_leak_prefixed_api_key_rejected():
    """Verify prefixed API key assignment triggers JEV_CREDENTIAL_LEAK (Rule 8 compliance)."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="src/settings.py",
        op=MutationOp.MODIFY,
        new_content='DEPLOY_API_KEY = "sk-proj-supersecretkey1234567890"\n',
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_CREDENTIAL_LEAK


def test_jev_credential_leak_token_assignment_rejected():
    """Verify sensitive token assignment triggers JEV_CREDENTIAL_LEAK."""
    verifier = JointEpistemicVerifier()
    proposal = CodeMutation(
        path="src/auth.py",
        op=MutationOp.CREATE,
        new_content='GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n',
    )
    verdict = verifier.verify_proposal(proposal)
    assert verdict.approved is False
    assert verdict.code == JEV_CREDENTIAL_LEAK


def test_jev_latency_budget_sub_5ms():
    """Assert JEV verification executes comfortably within the 5ms CPU latency budget."""
    verifier = JointEpistemicVerifier()
    warmup_prop = CodeMutation(
        path="src/warmup.py",
        op=MutationOp.CREATE,
        new_content="def warmup() -> None:\n    pass\n",
    )
    # Warmup pass to eliminate initial Python AST/regex compilation and CPU scheduler cold-start jitter
    verifier.verify_proposal(warmup_prop)

    proposal = CodeMutation(
        path="src/service/worker.py",
        op=MutationOp.CREATE,
        new_content=(
            "import os\n\n"
            "class Worker:\n"
            "    def __init__(self, name: str) -> None:\n"
            "        self.name = name\n"
            "    def run(self) -> int:\n"
            "        return len(self.name)\n"
        ),
    )
    # Run 3 iterations and take the minimum latency to avoid Windows scheduler interruptions
    verdicts = [verifier.verify_proposal(proposal) for _ in range(3)]
    for v in verdicts:
        assert v.approved is True
    best_verdict = min(verdicts, key=lambda v: v.latency_ms)
    # Strict sub-5ms CPU execution
    assert best_verdict.latency_ms < 5.0
    verifier.assert_latency_budget(best_verdict)


def test_jev_latency_budget_strict_assertion_failure():
    """Verify strict latency mode raises AssertionError if threshold is exceeded."""
    verifier = JointEpistemicVerifier(max_latency_ms=0.0001, strict_latency=True)
    proposal = CodeMutation(
        path="src/app.py",
        op=MutationOp.CREATE,
        new_content="x = 1\n",
    )
    with pytest.raises(AssertionError, match="latency budget exceeded"):
        verifier.verify_proposal(proposal)


def test_jev_batch_proposals_fail_closed():
    """Verify batch proposal verification fails closed if any single mutation fails."""
    verifier = JointEpistemicVerifier()
    good = CodeMutation(path="good.py", op=MutationOp.CREATE, new_content="x = 1\n")
    bad = CodeMutation(path="bad.py", op=MutationOp.CREATE, new_content="x = (\n")
    verdict = verifier.verify_proposal([good, bad])
    assert verdict.approved is False
    assert verdict.code == JEV_SYNTAX_ERROR


def test_jev_supports_proposal_types():
    """Verify JEV accepts CodeMutationProposal, CodeMutation, and dictionary representations."""
    verifier = JointEpistemicVerifier()
    p1 = CodeMutationProposal(path="a.py", op=MutationOp.CREATE, new_content="a = 1\n")
    p2 = {"path": "b.py", "op": "create", "new_content": "b = 2\n"}
    verdict1 = verifier.verify_proposal(p1)
    verdict2 = verifier.verify_proposal(p2)
    assert verdict1.approved is True
    assert verdict2.approved is True
