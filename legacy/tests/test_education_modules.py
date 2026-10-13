"""Unit tests for Educational Modules (Loops, Tool Connectivity, SLM, Threats, CIV, Benchmark)."""

from agent_poi.education.foundational_agent_loop import (
    ActionType,
    SimpleReActAgent,
    ToolRegistry,
)
from agent_poi.education.tool_connectivity import (
    MCPProtocolClient,
    OfflineDatabaseTool,
)
from agent_poi.education.slm_cpu_runner import SmallModelCPURunner
from agent_poi.education.production_civ_defense import (
    CapabilityToken,
    ContextualInvariantVerifier,
    ImmutableStateAnchor,
)
from agent_poi.education.rigorous_benchmarking import EducationalBenchmarkRunner


def test_foundational_agent_loop():
    """Verify simple ReAct agent loop step execution."""
    registry = ToolRegistry()
    db_tool = OfflineDatabaseTool()
    registry.register(db_tool)

    agent = SimpleReActAgent(registry=registry)
    state = agent.run("Query account details for ACC-01")

    assert state.step_count > 0
    assert len(state.history) > 0


def test_tool_connectivity_and_mcp():
    """Verify offline db, online tool, and MCP JSON-RPC protocol handling."""
    # Offline DB
    db = OfflineDatabaseTool()
    res = db.execute(account_id="ACC-01")
    assert res["found"] is True
    assert res["account_name"] == "Acme Logistics"

    # MCP Client
    client = MCPProtocolClient()
    list_req = '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}'
    list_resp = client.handle_json_rpc(list_req)
    assert "tools" in list_resp
    assert "offline_db" in list_resp

    call_req = (
        '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", '
        '"params": {"name": "offline_db", "arguments": {"account_id": "ACC-01"}}}'
    )
    call_resp = client.handle_json_rpc(call_req)
    assert "Acme Logistics" in call_resp


def test_slm_cpu_runner_grammar_extraction():
    """Verify SLM CPU runner extracts structured actions from text."""
    runner = SmallModelCPURunner()
    action = runner.generate_constrained_action(
        task_query="Please wire payment to vendor",
        context_document="Invoice #INV-2026-88 for account PAYEE-01 amount $4,500.00",
    )
    assert action.action_type == ActionType.TOOL_CALL
    assert action.tool_name == "process_disbursement"
    assert action.tool_arguments["amount"] == 4500.0


def test_civ_defense_and_capseal():
    """Verify Contextual Invariant Verification and CapSeal argument pinning."""
    verifier = ContextualInvariantVerifier(ImmutableStateAnchor.create_default())

    # Valid disbursement
    v_clean = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="US89370400440532013000",
        amount=4500.0,
    )
    assert v_clean["is_approved"] is True
    assert len(v_clean["violations"]) == 0

    # Unauthorized routing injection (attack)
    v_attack = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="ATTACKER-ROUTING-9999",
        amount=4500.0,
    )
    assert v_attack["is_approved"] is False
    assert len(v_attack["violations"]) > 0
    assert "Routing mismatch" in v_attack["violations"][0]

    # CapSeal token verification
    cap = CapabilityToken.mint(
        action_sink="process_disbursement",
        arguments={"payee_id": "PAYEE-01", "target_account": "US89370400440532013000", "amount": 4500.0},
    )
    assert cap.verify("process_disbursement", {"payee_id": "PAYEE-01", "target_account": "US89370400440532013000", "amount": 4500.0}) is True
    # Tampered argument fails verification
    assert cap.verify("process_disbursement", {"payee_id": "PAYEE-01", "target_account": "ATTACKER-ACCOUNT", "amount": 4500.0}) is False


def test_rigorous_benchmarking_runner():
    """Verify dynamic benchmark metric computation."""
    runner = EducationalBenchmarkRunner()
    rep_none = runner.run_evaluation(defense_mode="none")
    assert rep_none.asr_exec_rate == 100.0

    rep_civ = runner.run_evaluation(defense_mode="civ")
    assert rep_civ.asr_exec_rate == 0.0
    assert rep_civ.ldsr_rate == 100.0
    assert rep_civ.cdr_rate == 0.0


def test_internal_disruption_and_purpose_hijacking_defenses():
    """Verify defenses against internal payment disruption between verified vendors."""
    verifier = ContextualInvariantVerifier(ImmutableStateAnchor.create_default())

    # 1. ACE Two-Phase Scoping Violation:
    # User authenticated goal was for PAYEE-01, but attacker smuggled an internal diversion to PAYEE-02
    v_diversion = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-02",
        target_account="DE89370400440532019999",
        amount=5000.0,
        authenticated_goal_vendor="PAYEE-01",
    )
    assert v_diversion["is_approved"] is False
    assert any("ACE SCOPING VIOLATION" in err for err in v_diversion["violations"])

    # 2. Idempotency Violation:
    # First payment settles invoice INV-100
    v_first = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="US89370400440532013000",
        amount=4500.0,
        invoice_id="INV-100",
    )
    assert v_first["is_approved"] is True

    # Attacker replays duplicate disbursement on same invoice to drain balance
    v_replay = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="US89370400440532013000",
        amount=4500.0,
        invoice_id="INV-100",
    )
    assert v_replay["is_approved"] is False
    assert any("IDEMPOTENCY VIOLATION" in err for err in v_replay["violations"])

    # 3. 3-Way Matching & Purchase Order (PO) Obligation:
    # Attempting to disburse against non-existent PO
    v_fake_po = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="US89370400440532013000",
        amount=4500.0,
        po_number="PO-FAKE-999",
    )
    assert v_fake_po["is_approved"] is False
    assert any("OBLIGATION VIOLATION" in err for err in v_fake_po["violations"])

    # Attempting to disburse more than the authorized PO balance
    v_excess = verifier.verify_disbursement_invariant(
        payee_id="PAYEE-01",
        target_account="US89370400440532013000",
        amount=9000.0,  # PO-2026-001 is only for 4500.0
        po_number="PO-2026-001",
    )
    assert v_excess["is_approved"] is False
    assert any("exceeds PO" in err for err in v_excess["violations"])

