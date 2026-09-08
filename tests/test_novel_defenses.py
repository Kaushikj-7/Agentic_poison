"""Tests for novel production defense promotions.

Covers:
  - 3-Way Matching PO obligation enforcement in FinancialStateAnchor
  - Idempotency Key Registry replay prevention
  - protect_with_po() end-to-end via FinancialGuard facade
  - Architecture Ranker component scoring
"""

import pytest
from agent_poi.financial.state_anchor import FinancialStateAnchor
from agent_poi.facade import FinancialGuard, SecurityPolicy, GuardVerdict
from agent_poi.evaluation.architecture_ranker import ArchitectureRanker


# ──────────────────────────────────────────────────────────────
# 3-Way Matching Tests
# ──────────────────────────────────────────────────────────────

class TestThreeWayMatching:
    """Validates 3-Way Matching PO enforcement in FinancialStateAnchor."""

    @pytest.fixture
    def anchor_with_po(self):
        anchor = FinancialStateAnchor()
        anchor.register_purchase_order(
            po_number="PO-TEST-001",
            vendor_account="1122-3344-55",
            authorized_amount=5000.0,
            goods_receipt_confirmed=True,
        )
        return anchor

    def test_valid_three_way_match_passes(self, anchor_with_po):
        """Invoice matching PO on all 3 dimensions must be approved."""
        is_matched, violations = anchor_with_po.validate_three_way_match(
            po_number="PO-TEST-001",
            invoice_amount=4800.0,
            to_account="1122-3344-55",
        )
        assert is_matched, f"Expected match, got violations: {violations}"
        assert len(violations) == 0

    def test_unknown_po_fails_match(self, anchor_with_po):
        """Invoice referencing a PO not in the registry must fail."""
        is_matched, violations = anchor_with_po.validate_three_way_match(
            po_number="PO-BOGUS-999",
            invoice_amount=1000.0,
            to_account="1122-3344-55",
        )
        assert not is_matched
        assert any("not found" in v for v in violations)

    def test_invoice_amount_over_po_authorization_fails(self, anchor_with_po):
        """Invoice exceeding PO authorized amount must fail."""
        is_matched, violations = anchor_with_po.validate_three_way_match(
            po_number="PO-TEST-001",
            invoice_amount=5500.0,    # Exceeds 5000.0 PO limit
            to_account="1122-3344-55",
        )
        assert not is_matched
        assert any("3-WAY MATCH FAIL" in v and "exceeds" in v for v in violations)

    def test_vendor_account_mismatch_fails(self, anchor_with_po):
        """Invoice with wrong vendor account must fail even if PO exists."""
        is_matched, violations = anchor_with_po.validate_three_way_match(
            po_number="PO-TEST-001",
            invoice_amount=4000.0,
            to_account="ROGUE-ACCOUNT-999",  # Different from PO vendor
        )
        assert not is_matched
        assert any("does not match PO registered vendor" in v for v in violations)

    def test_goods_receipt_not_confirmed_fails(self):
        """Invoice without goods receipt confirmation must fail."""
        anchor = FinancialStateAnchor()
        anchor.register_purchase_order(
            po_number="PO-NO-RECEIPT",
            vendor_account="1122-3344-55",
            authorized_amount=5000.0,
            goods_receipt_confirmed=False,   # No receipt
        )
        is_matched, violations = anchor.validate_three_way_match(
            po_number="PO-NO-RECEIPT",
            invoice_amount=4000.0,
            to_account="1122-3344-55",
        )
        assert not is_matched
        assert any("receipt not confirmed" in v for v in violations)

    def test_double_settlement_blocked(self, anchor_with_po):
        """PO settled on first invoice must reject second invoice (double-payment)."""
        # First settlement — should pass
        is_matched, _ = anchor_with_po.validate_three_way_match(
            po_number="PO-TEST-001",
            invoice_amount=5000.0,
            to_account="1122-3344-55",
        )
        assert is_matched, "First settlement should succeed"

        # Second attempt — same PO, should be blocked
        is_matched2, violations2 = anchor_with_po.validate_three_way_match(
            po_number="PO-TEST-001",
            invoice_amount=5000.0,
            to_account="1122-3344-55",
        )
        assert not is_matched2
        assert any("already been settled" in v for v in violations2)


# ──────────────────────────────────────────────────────────────
# Idempotency Key Registry Tests
# ──────────────────────────────────────────────────────────────

class TestIdempotencyRegistry:
    """Validates idempotency key replay prevention in FinancialStateAnchor."""

    def test_fresh_key_returns_true(self):
        """First use of an idempotency key must return True (proceed)."""
        anchor = FinancialStateAnchor()
        result = anchor.register_idempotency_key("INV-2026-001", "TXN-00001")
        assert result is True

    def test_duplicate_key_returns_false(self):
        """Second use of the same idempotency key must return False (replay)."""
        anchor = FinancialStateAnchor()
        anchor.register_idempotency_key("INV-2026-002", "TXN-00002")
        result = anchor.register_idempotency_key("INV-2026-002", "TXN-00003")
        assert result is False, "Expected replay detection on duplicate key"

    def test_different_keys_are_independent(self):
        """Different idempotency keys must not interfere with each other."""
        anchor = FinancialStateAnchor()
        r1 = anchor.register_idempotency_key("INV-A", "TXN-A")
        r2 = anchor.register_idempotency_key("INV-B", "TXN-B")
        assert r1 is True
        assert r2 is True


# ──────────────────────────────────────────────────────────────
# protect_with_po() Facade Tests
# ──────────────────────────────────────────────────────────────

class TestProtectWithPO:
    """End-to-end tests for FinancialGuard.protect_with_po()."""

    @pytest.fixture
    def guard_with_po(self):
        guard = FinancialGuard(policy=SecurityPolicy.STRICT)
        guard.register_payee(
            account_number="1122-3344-55",
            name="Acme Cloud Infrastructure Inc.",
        )
        guard.register_purchase_order(
            po_number="PO-FACADE-001",
            vendor_account="1122-3344-55",
            authorized_amount=5000.0,
            goods_receipt_confirmed=True,
        )
        return guard

    def test_valid_invoice_with_po_passes(self, guard_with_po):
        """Valid invoice matching all PO criteria and CIV invariants should be approved."""
        verdict = guard_with_po.protect_with_po(
            task_query="Process invoice PO-FACADE-001 from Acme",
            context="Invoice INV-2026-001: Amount $4800.00 to account 1122-3344-55",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=4800.0,
            vendor_account="1122-3344-55",
            idempotency_key="INV-2026-001",
            task_id="TASK-PO-001",
        )
        assert isinstance(verdict, GuardVerdict)
        assert verdict.is_approved is True
        assert verdict.status == "APPROVED"
        assert verdict.disbursement_executed is True
        assert verdict.task_id == "TASK-PO-001"

    def test_nan_invoice_amount_rejected(self, guard_with_po):
        """Non-finite NaN amount in 3-Way Match must fail closed and be blocked."""
        verdict = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice INV-NAN: Amount NaN to account 1122-3344-55",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=float("nan"),
            vendor_account="1122-3344-55",
            task_id="TASK-NAN",
        )
        assert not verdict.is_approved
        assert verdict.status == "BLOCKED"
        assert any("non-finite" in v.lower() or "invalid" in v.lower() for v in verdict.violations)

    def test_infinite_invoice_amount_rejected(self, guard_with_po):
        """Non-finite infinity amount in 3-Way Match must fail closed."""
        verdict = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice INV-INF",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=float("inf"),
            vendor_account="1122-3344-55",
            task_id="TASK-INF",
        )
        assert not verdict.is_approved
        assert verdict.status == "BLOCKED"
        assert any("non-finite" in v.lower() or "invalid" in v.lower() for v in verdict.violations)

    def test_negative_or_zero_invoice_amount_rejected(self, guard_with_po):
        """Zero or negative invoice amount must be rejected by 3-Way Matching."""
        verdict_zero = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice INV-ZERO",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=0.0,
            vendor_account="1122-3344-55",
            task_id="TASK-ZERO",
        )
        assert not verdict_zero.is_approved
        assert verdict_zero.status == "BLOCKED"

        verdict_neg = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice INV-NEG",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=-500.0,
            vendor_account="1122-3344-55",
            task_id="TASK-NEG",
        )
        assert not verdict_neg.is_approved
        assert verdict_neg.status == "BLOCKED"

    def test_unknown_po_returns_blocked_verdict(self, guard_with_po):
        """Invoice with unknown PO must be blocked before reaching CIV."""
        verdict = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Some context",
            purchase_order_number="PO-DOES-NOT-EXIST",
            invoice_amount=1000.0,
            vendor_account="1122-3344-55",
            task_id="TASK-PO-BAD",
        )
        assert not verdict.is_approved
        assert verdict.status == "BLOCKED"
        assert any("not found" in v for v in verdict.violations)

    def test_duplicate_idempotency_key_blocked(self, guard_with_po):
        """Submitting the same invoice twice must be blocked on second submission."""
        # First submission
        guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice context",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=1000.0,
            vendor_account="1122-3344-55",
            idempotency_key="REPLAY-KEY-001",
            task_id="TASK-PO-REPLAY-1",
        )
        # Second submission — same key
        verdict2 = guard_with_po.protect_with_po(
            task_query="Process invoice",
            context="Invoice context",
            purchase_order_number="PO-FACADE-001",
            invoice_amount=1000.0,
            vendor_account="1122-3344-55",
            idempotency_key="REPLAY-KEY-001",   # SAME key
            task_id="TASK-PO-REPLAY-2",
        )
        assert not verdict2.is_approved
        assert verdict2.status == "BLOCKED"
        assert any("IDEMPOTENCY VIOLATION" in v for v in verdict2.violations)

    def test_check_idempotency_key_helper(self, guard_with_po):
        """FinancialGuard.check_idempotency_key() must return True then False."""
        assert guard_with_po.check_idempotency_key("IDEM-TEST-1", "TXN-A") is True
        assert guard_with_po.check_idempotency_key("IDEM-TEST-1", "TXN-B") is False


# ──────────────────────────────────────────────────────────────
# Architecture Ranker Tests
# ──────────────────────────────────────────────────────────────

class TestArchitectureRanker:
    """Validates ArchitectureRanker produces dynamic, well-formed rankings."""

    @pytest.fixture(scope="class")
    @classmethod
    def ranker(cls):
        return ArchitectureRanker()

    @pytest.fixture(scope="class")
    @classmethod
    def scores(cls, ranker):
        return ranker.rank_all_components()

    def test_returns_all_components(self, scores):
        """Ranker must return a score for every registered component."""
        assert len(scores) >= 8, f"Expected ≥8 component scores, got {len(scores)}"

    def test_scores_are_ranked_descending(self, scores):
        """Weighted totals must be in non-increasing order."""
        totals = [s.weighted_total for s in scores]
        assert totals == sorted(totals, reverse=True), (
            f"Scores are not properly ranked: {totals}"
        )

    def test_all_scores_in_valid_range(self, scores):
        """All dimension scores must be in [0, 10]."""
        for s in scores:
            assert 0.0 <= s.effectiveness <= 10.0, f"{s.component_name} effectiveness out of range"
            assert 0.0 <= s.reliability <= 10.0, f"{s.component_name} reliability out of range"
            assert 0.0 <= s.ethics_score <= 10.0, f"{s.component_name} ethics out of range"
            assert 0.0 <= s.novelty <= 10.0, f"{s.component_name} novelty out of range"
            assert 0.0 <= s.weighted_total <= 10.0, f"{s.component_name} total out of range"

    def test_ranks_are_sequential(self, scores):
        """Rank values must be sequential integers starting at 1."""
        ranks = [s.rank for s in scores]
        assert ranks == list(range(1, len(scores) + 1)), f"Non-sequential ranks: {ranks}"

    def test_novelty_report_has_contributions(self, ranker):
        """Novelty report must identify at least 3 novel contributions."""
        report = ranker.rank_novelty_vs_sota()
        assert len(report.novel_contributions) >= 3
        assert len(report.educational_only_gaps) >= 1
        assert 0.0 < report.overall_novelty_score <= 10.0

    def test_civ_or_full_defense_ranks_highly(self, scores):
        """CIV or Fail-Closed Sink must appear in top 3 by weighted total."""
        top3_names = [s.component_name for s in scores[:3]]
        high_tier = {"CIV Invariant Verifier", "Fail-Closed Execution Sink", "AuthGraph Cryptographic DAG"}
        assert len(high_tier.intersection(top3_names)) >= 1, (
            f"Expected at least one of {high_tier} in top 3, got: {top3_names}"
        )
