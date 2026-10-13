"""Tests for the capability scope grant (K) and freshness nonce store (F)."""

from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.domain import MutationDelta, MutationOp


def _delta(path: str = "svc/core/engine.py", op: MutationOp = MutationOp.MODIFY, urls=()) -> MutationDelta:
    return MutationDelta(
        path=path,
        op=op,
        symbol=None,
        patch_hash="deadbeef",
        introduced_urls=tuple(urls),
    )


def _codes(violations) -> set:
    return {v.code for v in violations}


def test_path_scope_is_enforced():
    scope = CapabilityScope("cap-1", allowed_paths=["svc/core/**"])
    assert _codes(scope.validate(_delta("svc/core/engine.py"))) == set()
    assert "K1" in _codes(scope.validate(_delta("svc/data/store.py")))


def test_operation_scope_is_enforced():
    scope = CapabilityScope("cap-2", allowed_paths=["svc/core/**"], allowed_ops=[MutationOp.MODIFY])
    assert "K2" in _codes(scope.validate(_delta(op=MutationOp.DELETE)))


def test_egress_scope_is_enforced():
    scope = CapabilityScope(
        "cap-3",
        allowed_paths=["svc/core/**"],
        egress_allowlist=["https://github.com/"],
    )
    assert _codes(scope.validate(_delta(urls=["https://github.com/x"]))) == set()
    assert "K3" in _codes(scope.validate(_delta(urls=["https://exfil.example.net/x"])))


def test_nonce_can_only_be_consumed_once():
    scope = CapabilityScope("cap-4", allowed_paths=["svc/core/**"])
    assert scope.consume("nonce-1") is True
    assert scope.is_consumed("nonce-1") is True
    assert scope.consume("nonce-1") is False
    assert scope.consumed_count() == 1
