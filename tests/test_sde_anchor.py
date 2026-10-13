"""Tests for the Repository State Anchor (R0)."""

from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor, content_hash
from agentpoi_sde.eval.repo_sandbox import RepoSandbox


def test_content_hash_is_stable_and_sensitive():
    assert content_hash("a") == content_hash("a")
    assert content_hash("a") != content_hash("b")


def test_tree_oid_is_deterministic_and_content_addressed():
    first = RepositoryStateAnchor(files={"a.py": "x = 1\n"}).tree_oid()
    second = RepositoryStateAnchor(files={"a.py": "x = 1\n"}).tree_oid()
    changed = RepositoryStateAnchor(files={"a.py": "x = 2\n"}).tree_oid()
    assert first == second
    assert first != changed


def test_layer_resolution_uses_longest_prefix():
    anchor = RepoSandbox.default().anchor()
    assert anchor.layer_of("svc/core/engine.py") == "core"
    assert anchor.layer_of("svc/data/store.py") == "data"
    assert anchor.layer_of("svc/api/routes.py") == "api"
    assert anchor.layer_of("scripts/tool.py") is None


def test_policy_and_test_classification():
    anchor = RepoSandbox.default().anchor()
    assert anchor.is_protected(".github/workflows/ci.yml")
    assert anchor.is_protected("AGENTS.md")
    assert not anchor.is_protected("svc/core/engine.py")
    assert anchor.is_test("svc/tests/test_engine.py")
    assert not anchor.is_test("svc/core/engine.py")


def test_verified_dependencies_union_of_r0_and_lockfile():
    anchor = RepoSandbox.default().anchor()
    deps = anchor.verified_dependencies()
    assert "typing" in deps, "R0 external imports must be considered verified"
    assert "requests" in deps, "declared (lockfile) dependencies must be verified"
    assert "evilpkg" not in deps


def test_anchor_is_not_mutated_by_reading():
    anchor = RepoSandbox.default().anchor()
    before = anchor.tree_oid()
    snapshot = anchor.to_files()
    snapshot["svc/core/engine.py"] = "tampered\n"
    assert anchor.tree_oid() == before
