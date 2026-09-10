"""TDD Unit Tests for typed domain exceptions and negative error paths."""

import pytest
from agent_poi.financial.state_anchor import FinancialStateAnchor
from agent_poi.financial.financial_agent import FinancialAgent
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
)


def test_financial_agent_raises_unauthorized_payee_error():
    agent = FinancialAgent(enable_civ_firewall=True, raise_on_violation=True)

    with pytest.raises(UnauthorizedPayeeError) as exc_info:
        agent.process_disbursement(
            to_account="9999-8888-77",
            amount=5000.0,
            invoice_id="INV-ROGUE",
            contributing_node_ids=["node_test"],
        )

    err = exc_info.value
    assert isinstance(err, InvariantViolationError)
    assert isinstance(err, FinancialSecurityError)
    assert err.target_account == "9999-8888-77"
    assert "not registered in Immutable Anchor S0" in str(err)
    assert "violations" in err.details


def test_financial_agent_raises_ceiling_exceeded_error():
    anchor = FinancialStateAnchor(per_transaction_limit=25000.0)
    agent = FinancialAgent(state_anchor=anchor, enable_civ_firewall=True, raise_on_violation=True)

    with pytest.raises(DisbursementCeilingExceededError) as exc_info:
        agent.process_disbursement(
            to_account="1122-3344-55",
            amount=35000.0,
            invoice_id="INV-OVERLIMIT",
            contributing_node_ids=["node_test"],
        )

    err = exc_info.value
    assert isinstance(err, InvariantViolationError)
    assert err.amount == 35000.0
    assert err.limit == 25000.0
    assert "exceeds limit" in str(err)


def test_financial_agent_raises_invariant_violation_error_on_provenance_failure():
    agent = FinancialAgent(enable_civ_firewall=True, raise_on_violation=True)

    with pytest.raises(InvariantViolationError) as exc_info:
        agent.process_disbursement(
            to_account="1122-3344-55",
            amount=5000.0,
            invoice_id="INV-NOPROV",
            contributing_node_ids=None,
        )

    err = exc_info.value
    assert "violations" in err.details


def test_financial_agent_raises_untrusted_lineage_error():
    from agent_poi.financial.exceptions import UntrustedLineageError
    from agent_poi.memory.schema import SourceOrigin

    agent = FinancialAgent(enable_civ_firewall=True, raise_on_violation=True)
    untrusted_node = agent.auth_graph.add_node(
        content="Untrusted API payment request",
        origin=SourceOrigin.EXTERNAL_API,
        is_authorized_root=False,
    )

    with pytest.raises(UntrustedLineageError) as exc_info:
        agent.process_disbursement(
            to_account="1122-3344-55",
            amount=5000.0,
            invoice_id="INV-UNTRUSTED",
            contributing_node_ids=[untrusted_node.node_id],
        )

    err = exc_info.value
    assert isinstance(err, FinancialSecurityError)
    assert err.node_id == untrusted_node.node_id
    assert "violations" in err.details

