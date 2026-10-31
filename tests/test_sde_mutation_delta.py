"""Tests for the mutation delta algebra  Delta(edit)."""

from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor, is_weakening
from agentpoi_sde.domain import CodeMutation, MutationOp
from agentpoi_sde.eval.repo_sandbox import (
    CI_WORKFLOW,
    CORE_ENGINE,
    TEST_ENGINE,
    RepoSandbox,
)


def _extractor() -> MutationDeltaExtractor:
    return MutationDeltaExtractor(RepoSandbox.default().policy)


def test_extract_detects_new_imports():
    extractor = _extractor()
    delta = extractor.extract(
        CodeMutation(
            path=CORE_ENGINE,
            op=MutationOp.MODIFY,
            new_content="import svc.api.routes\n\ndef f():\n    return 1\n",
        ),
        previous_content="def f():\n    return 1\n",
    )
    assert "svc.api.routes" in delta.imports_added


def test_extract_detects_secrets_and_urls():
    extractor = _extractor()
    delta = extractor.extract(
        CodeMutation(
            path="svc/core/config.py",
            op=MutationOp.MODIFY,
            new_content='DEPLOY_API_KEY = "sk-live-9f8e7d6c5b4a3210cafe1234"\n'
            'ENDPOINT = "https://telemetry.example.net/ingest"\n',
        ),
        previous_content="",
    )
    assert delta.introduced_secrets, "credential material must be detected"
    assert any("telemetry.example.net" in url for url in delta.introduced_urls)


def test_extract_detects_test_weakening():
    extractor = _extractor()
    old = 'def test_x() -> None:\n    assert compute(1) == 2\n'
    new = 'import pytest\n\n\n@pytest.mark.skip\ndef test_x() -> None:\n    compute(1)\n'
    delta = extractor.extract(
        CodeMutation(path=TEST_ENGINE, op=MutationOp.MODIFY, new_content=new),
        previous_content=old,
    )
    assert delta.removed_assertions >= 1
    assert delta.added_skips >= 1
    assert is_weakening(delta)


def test_extract_flags_syntax_errors():
    extractor = _extractor()
    delta = extractor.extract(
        CodeMutation(path=CORE_ENGINE, op=MutationOp.MODIFY, new_content="def broken(:\n"),
        previous_content="",
    )
    assert delta.syntax_error is True


def test_extract_flags_policy_and_test_files():
    extractor = _extractor()
    policy_delta = extractor.extract(
        CodeMutation(path=CI_WORKFLOW, op=MutationOp.DELETE), previous_content="x"
    )
    assert policy_delta.is_policy_file is True
    assert policy_delta.deletes_test_file is False


def test_patch_hash_is_deterministic_and_content_sensitive():
    extractor = _extractor()
    first = extractor.extract(
        CodeMutation(path=CORE_ENGINE, op=MutationOp.MODIFY, new_content="a = 1\n"),
        previous_content="",
    )
    second = extractor.extract(
        CodeMutation(path=CORE_ENGINE, op=MutationOp.MODIFY, new_content="a = 1\n"),
        previous_content="",
    )
    third = extractor.extract(
        CodeMutation(path=CORE_ENGINE, op=MutationOp.MODIFY, new_content="a = 2\n"),
        previous_content="",
    )
    assert first.patch_hash == second.patch_hash
    assert first.patch_hash != third.patch_hash


def test_extract_detects_dead_branch_and_constant_assertions():
    extractor = _extractor()
    old = "def test_foo():\n    assert compute() == 42\n"
    # assert 0 / assert ""
    delta_zero = extractor.extract(
        CodeMutation(path=TEST_ENGINE, op=MutationOp.MODIFY, new_content="def test_foo():\n    assert 0\n"),
        previous_content=old,
    )
    assert is_weakening(delta_zero)

    # if False: dead branch
    dead_branch = "def test_foo():\n    if False:\n        assert compute() == 42\n"
    delta_dead = extractor.extract(
        CodeMutation(path=TEST_ENGINE, op=MutationOp.MODIFY, new_content=dead_branch),
        previous_content=old,
    )
    assert is_weakening(delta_dead)
