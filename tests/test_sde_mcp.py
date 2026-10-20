"""Comprehensive tests for AgentPOI-SDE MCP tool integration and schema validation subsystem.

Tests registration, Pydantic v2 fail-closed schema gating (extra="forbid"),
path traversal prevention, concrete tool execution, DevGuard invariant enforcement,
and JSON-RPC 2.0 stdio and in-process dispatching.
"""

from __future__ import annotations

import io
import json

from agentpoi_sde.domain import GuardPolicy
from agentpoi_sde.facade import DevGuard
from agentpoi_sde.mcp.client import MCPClient
from agentpoi_sde.mcp.dispatcher import MCPDispatcher
from agentpoi_sde.mcp.gateway import ToolGateway
from agentpoi_sde.mcp.protocol import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JSONRPCRequest,
)
from agentpoi_sde.mcp.schemas import (
    ASTSearchOutput,
    ComponentHarvestOutput,
    MutationProposalOutput,
    TestRunnerOutput,
)


def _create_test_guard() -> DevGuard:
    """Fixture helper building DevGuard with in-memory workspace."""
    files = {
        "svc/calc.py": (
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n\n"
            "class Calculator:\n"
            "    def multiply(self, x: int, y: int) -> int:\n"
            "        return x * y\n"
        ),
        "svc/util.py": (
            "import math\n"
            "from svc.calc import add\n\n"
            "def compute_total(values):\n"
            "    return sum(values)\n"
        ),
        ".github/workflows/ci.yml": "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    }
    guard = DevGuard(files=files, policy=GuardPolicy.STRICT)
    guard.register_intent(
        intent_id="T0_TEST_TASK",
        goal="Perform legitimate calculation modifications",
        allowed_paths=["svc/calc.py", "svc/util.py"],
    )
    return guard


# ---------------------------------------------------------------------------
# Suite 1: Tool Registration & Schema Introspection
# ---------------------------------------------------------------------------

def test_dispatcher_core_tools_registration() -> None:
    """Verify all four core MCP tools are registered in dispatcher."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    tool_names = [t.name for t in dispatcher.list_tools()]
    assert "sde_ast_search" in tool_names
    assert "sde_harvest_component" in tool_names
    assert "sde_propose_mutation" in tool_names
    assert "sde_run_tests" in tool_names
    assert len(tool_names) == 4


def test_tool_definitions_schema_structure() -> None:
    """Verify JSON schema definitions conform to MCP specification."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    for tool in dispatcher.list_tools():
        assert tool.name
        assert tool.description
        schema = tool.inputSchema
        assert schema.get("type") == "object"
        assert "properties" in schema
        assert schema.get("additionalProperties") is False or schema.get("extra") != "allow"


def test_openai_tools_formatting() -> None:
    """Verify conversion to OpenAI/OpenRouter function calling format."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    openai_tools = client.to_openai_tools()
    assert len(openai_tools) == 4
    for item in openai_tools:
        assert item["type"] == "function"
        fn = item["function"]
        assert fn["name"] in ("sde_ast_search", "sde_harvest_component", "sde_propose_mutation", "sde_run_tests")
        assert "parameters" in fn


def test_markdown_documentation_generation() -> None:
    """Verify markdown prompt documentation generation."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    md = client.to_markdown_description()
    assert "### Available MCP Tools" in md
    assert "`sde_ast_search`" in md
    assert "`sde_propose_mutation`" in md
    assert "**Parameters**:" in md


# ---------------------------------------------------------------------------
# Suite 2: Fail-Closed Gateway & Extra Argument Rejection (extra="forbid")
# ---------------------------------------------------------------------------

def test_gateway_rejects_extra_hallucinated_arguments() -> None:
    """Verify unexpected arguments are rejected at the gateway boundary."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # Extra hallucinated parameter in sde_ast_search
    res = dispatcher.call_tool(
        "sde_ast_search",
        {"query": "add", "bypass_invariants": True},
    )
    assert res.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res.content[0].text
    assert "Extra inputs are not permitted" in res.content[0].text or "extra_forbidden" in res.content[0].text

    # Extra parameter in sde_propose_mutation
    res_mut = dispatcher.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "path": "svc/calc.py",
            "op": "modify",
            "new_content": "def add(a, b): return a + b\n",
            "force_override": True,
        },
    )
    assert res_mut.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res_mut.content[0].text


def test_gateway_rejects_missing_required_fields() -> None:
    """Verify missing required parameters are rejected before tool execution."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # Missing file_path in harvest
    res = dispatcher.call_tool("sde_harvest_component", {"symbol_name": "add"})
    assert res.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res.content[0].text
    assert "file_path" in res.content[0].text

    # Missing test_paths in run_tests
    res_test = dispatcher.call_tool("sde_run_tests", {})
    assert res_test.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res_test.content[0].text


def test_gateway_rejects_strict_type_mismatches() -> None:
    """Verify strict type validation rejects coercions like string for bool."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # string "true" instead of bool True under strict=True
    res = dispatcher.call_tool(
        "sde_ast_search",
        {"include_dependencies": "true"},
    )
    assert res.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res.content[0].text

    # invalid literal symbol_type
    res_literal = dispatcher.call_tool(
        "sde_ast_search",
        {"symbol_type": "variable"},
    )
    assert res_literal.isError is True
    assert "SCHEMA_VALIDATION_ERROR" in res_literal.content[0].text


def test_gateway_rejects_unknown_tool_fail_closed() -> None:
    """Verify unknown tool identifiers fail closed immediately."""
    gateway = ToolGateway()
    res = gateway.validate_and_call("sde_delete_repository", {})
    assert res.isError is True
    assert "UNKNOWN_TOOL" in res.content[0].text


# ---------------------------------------------------------------------------
# Suite 3: Path Traversal & Containment Verification
# ---------------------------------------------------------------------------

def test_path_traversal_rejection() -> None:
    """Verify path traversal (..) is caught and blocked at the gateway."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # '..' in file_path
    res1 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "../../../etc/passwd"},
    )
    assert res1.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res1.content[0].text

    # '..' in mutation path
    res2 = dispatcher.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "path": "svc/../../config.py",
            "op": "modify",
            "new_content": "# pass",
        },
    )
    assert res2.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res2.content[0].text

    # '..' in test_paths
    res3 = dispatcher.call_tool(
        "sde_run_tests",
        {"test_paths": ["tests/../../outside_test.py"]},
    )
    assert res3.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res3.content[0].text


def test_null_byte_path_rejection() -> None:
    """Verify null byte injection in paths is rejected."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    res = dispatcher.call_tool(
        "sde_harvest_component",
        {
            "file_path": "svc/calc.py\x00.exe",
            "symbol_name": "add",
        },
    )
    assert res.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res.content[0].text
    assert "null bytes" in res.content[0].text


def test_drive_root_absolute_path_rejection() -> None:
    """Verify absolute paths with drive roots are rejected."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # Windows drive root
    res1 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "C:\\Windows\\System32\\calc.py"},
    )
    assert res1.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res1.content[0].text

    # Unix root slash
    res2 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "/etc/shadow"},
    )
    assert res2.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res2.content[0].text


# ---------------------------------------------------------------------------
# Suite 4: Concrete Tool Execution & DevGuard Invariant Integration
# ---------------------------------------------------------------------------

def test_ast_search_tool_execution() -> None:
    """Verify sde_ast_search discovers symbols and resolved dependencies."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_ast_search",
        {"query": "calc", "include_dependencies": True},
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, ASTSearchOutput)
    assert parsed is not None
    assert parsed.total_matches >= 1
    assert any(m.name == "Calculator" and m.kind == "class" for m in parsed.matches)
    assert parsed.dependencies is not None
    assert "svc/util.py" in parsed.dependencies


def test_component_harvest_tool_execution() -> None:
    """Verify sde_harvest_component slices target symbol and passes security."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_harvest_component",
        {"file_path": "svc/calc.py", "symbol_name": "add"},
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, ComponentHarvestOutput)
    assert parsed is not None
    assert parsed.is_approved is True
    assert "def add" in parsed.sliced_code
    assert parsed.content_hash != ""


def test_component_harvest_security_violation() -> None:
    """Verify component harvest screens and flags dangerous calls."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    unsafe_code = "import os\n\ndef dangerous():\n    os.system('rm -rf /')\n"
    res = client.call_tool(
        "sde_harvest_component",
        {
            "file_path": "svc/dangerous.py",
            "symbol_name": "dangerous",
            "source_code": unsafe_code,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, ComponentHarvestOutput)
    assert parsed is not None
    assert parsed.is_approved is False
    assert len(parsed.security_violations) > 0


def test_propose_mutation_approved_execution() -> None:
    """Verify legitimate code mutation passes DevGuard invariants and applies."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    new_calc_code = (
        "def add(a: int, b: int) -> int:\n"
        "    return a + b + 0\n"
    )
    res = client.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "path": "svc/calc.py",
            "op": "modify",
            "new_content": new_calc_code,
            "dry_run": False,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, MutationProposalOutput)
    assert parsed is not None
    assert parsed.overall_approved is True
    assert len(parsed.verdicts) == 1
    assert parsed.verdicts[0].is_applied is True
    assert guard.workspace["svc/calc.py"] == new_calc_code


def test_propose_mutation_dry_run_preserves_state() -> None:
    """Verify dry_run evaluates invariants without mutating workspace state."""
    guard = _create_test_guard()
    original_code = guard.workspace["svc/calc.py"]
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "path": "svc/calc.py",
            "op": "modify",
            "new_content": "def add(a: int, b: int) -> int: return 12345\n",
            "dry_run": True,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, MutationProposalOutput)
    assert parsed is not None
    assert parsed.overall_approved is True
    assert parsed.verdicts[0].is_applied is False
    assert parsed.verdicts[0].status == "APPROVED"
    # Ensure workspace was not permanently modified
    assert guard.workspace["svc/calc.py"] == original_code


def test_propose_mutation_blocks_unauthorized_policy_mutation() -> None:
    """Verify DevGuard Invariant I1 blocks unauthorized mutation to CI workflow."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "path": ".github/workflows/ci.yml",
            "op": "modify",
            "new_content": "name: Corrupted\n",
            "dry_run": False,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, MutationProposalOutput)
    assert parsed is not None
    assert parsed.overall_approved is False
    assert parsed.verdicts[0].is_applied is False
    assert parsed.verdicts[0].status == "BLOCKED"
    assert "I1" in parsed.verdicts[0].violation_codes or "I0" in parsed.verdicts[0].violation_codes


def test_run_tests_in_isolated_sandbox() -> None:
    """Verify sde_run_tests executes pytest in an isolated scratch environment."""
    test_code = (
        "def test_addition():\n"
        "    assert 1 + 1 == 2\n"
    )
    guard = DevGuard(files={"tests/test_demo.py": test_code})
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_run_tests",
        {
            "test_paths": ["tests/test_demo.py"],
            "isolated": True,
            "timeout_seconds": 15,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, TestRunnerOutput)
    assert parsed is not None
    assert parsed.success is True
    assert parsed.passed_count >= 1
    assert parsed.failed_count == 0


def test_run_tests_failure_reporting() -> None:
    """Verify sde_run_tests parses test failure information accurately."""
    failing_test_code = (
        "def test_broken():\n"
        "    assert 1 == 99, 'One does not equal ninety nine'\n"
    )
    guard = DevGuard(files={"tests/test_fail.py": failing_test_code})
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)
    client = MCPClient(dispatcher)

    res = client.call_tool(
        "sde_run_tests",
        {
            "test_paths": ["tests/test_fail.py"],
            "isolated": True,
            "timeout_seconds": 15,
        },
    )
    assert res.isError is False
    parsed = client.parse_tool_result(res, TestRunnerOutput)
    assert parsed is not None
    assert parsed.success is False
    assert parsed.failed_count >= 1
    assert len(parsed.failures) >= 1
    assert "test_broken" in parsed.failures[0].test_id


# ---------------------------------------------------------------------------
# Suite 5: JSON-RPC 2.0 Lifecycle & Stdio Transport
# ---------------------------------------------------------------------------

def test_jsonrpc_initialize_request() -> None:
    """Verify MCP initialize method returns protocol version and serverInfo."""
    dispatcher = MCPDispatcher()
    req = JSONRPCRequest(id=1, method="initialize", params={})
    resp = dispatcher.dispatch_request(req)
    assert resp is not None
    assert resp.id == 1
    assert resp.error is None
    assert resp.result["protocolVersion"] == "2024-11-05"
    assert resp.result["serverInfo"]["name"] == "agentpoi-sde-mcp"


def test_jsonrpc_tools_list_request() -> None:
    """Verify MCP tools/list returns registered tool definitions."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    req = JSONRPCRequest(id="req-2", method="tools/list", params={})
    resp = dispatcher.dispatch_request(req)
    assert resp is not None
    assert resp.id == "req-2"
    assert resp.error is None
    tools = resp.result["tools"]
    assert len(tools) == 4
    names = [t["name"] for t in tools]
    assert "sde_ast_search" in names


def test_jsonrpc_tools_call_dispatch() -> None:
    """Verify MCP tools/call dispatches arguments and wraps CallToolResult."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    req = JSONRPCRequest(
        id=10,
        method="tools/call",
        params={
            "name": "sde_ast_search",
            "arguments": {"query": "Calculator"},
        },
    )
    resp = dispatcher.dispatch_request(req)
    assert resp is not None
    assert resp.id == 10
    assert resp.error is None
    assert resp.result["isError"] is False
    assert "Calculator" in resp.result["content"][0]["text"]


def test_jsonrpc_invalid_params_error() -> None:
    """Verify missing 'name' in tools/call returns JSON-RPC INVALID_PARAMS (-32602)."""
    dispatcher = MCPDispatcher()
    req = JSONRPCRequest(id=99, method="tools/call", params={})
    resp = dispatcher.dispatch_request(req)
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == INVALID_PARAMS


def test_jsonrpc_method_not_found_error() -> None:
    """Verify unhandled method returns JSON-RPC METHOD_NOT_FOUND (-32601)."""
    dispatcher = MCPDispatcher()
    req = JSONRPCRequest(id=101, method="nonexistent/method", params={})
    resp = dispatcher.dispatch_request(req)
    assert resp is not None
    assert resp.error is not None
    assert resp.error.code == METHOD_NOT_FOUND


def test_jsonrpc_raw_parse_error() -> None:
    """Verify malformed JSON payload returns JSON-RPC PARSE_ERROR (-32700)."""
    dispatcher = MCPDispatcher()
    out = dispatcher.dispatch_raw("{not valid json}")
    assert out is not None
    data = json.loads(out)
    assert data["error"]["code"] == PARSE_ERROR


def test_stdio_transport_stream() -> None:
    """Verify stdio line-delimited request and response streaming."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    input_lines = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    )
    in_stream = io.StringIO(input_lines)
    out_stream = io.StringIO()

    dispatcher.run_stdio(input_stream=in_stream, output_stream=out_stream)
    out_lines = [line.strip() for line in out_stream.getvalue().splitlines() if line.strip()]

    assert len(out_lines) == 2
    resp1 = json.loads(out_lines[0])
    resp2 = json.loads(out_lines[1])
    assert resp1["id"] == 1
    assert resp1["result"]["protocolVersion"] == "2024-11-05"
    assert resp2["id"] == 2
    assert len(resp2["result"]["tools"]) == 4


# ---------------------------------------------------------------------------
# Suite 7: Hardened Path Traversal & Strict Schema Invariant Tests
# ---------------------------------------------------------------------------

def test_url_encoded_path_traversal_rejection() -> None:
    """Verify URL-encoded and double URL-encoded path traversals are blocked."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    # %2e%2e traversal in file_path
    res1 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "%2e%2e/%2e%2e/etc/passwd"},
    )
    assert res1.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res1.content[0].text

    # Double-encoded traversal %252e%252e in harvest
    res2 = dispatcher.call_tool(
        "sde_harvest_component",
        {
            "file_path": "%252e%252e/evil.py",
            "symbol_name": "steal_keys",
        },
    )
    assert res2.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res2.content[0].text


def test_uri_scheme_rejection() -> None:
    """Verify URI schemes like file:// and smb:// are blocked fail-closed."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    res_file = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "file:///etc/passwd"},
    )
    assert res_file.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res_file.content[0].text

    res_smb = dispatcher.call_tool(
        "sde_harvest_component",
        {
            "file_path": "smb://192.168.1.1/share/evil.py",
            "symbol_name": "fn",
        },
    )
    assert res_smb.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res_smb.content[0].text


def test_unc_path_rejection() -> None:
    """Verify Windows UNC paths and device paths are blocked fail-closed."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    res_unc1 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": r"\\server\share\file.py"},
    )
    assert res_unc1.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res_unc1.content[0].text

    res_unc2 = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": "//server/share/file.py"},
    )
    assert res_unc2.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res_unc2.content[0].text

    res_dev = dispatcher.call_tool(
        "sde_ast_search",
        {"file_path": r"\\?\C:\secret.txt"},
    )
    assert res_dev.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res_dev.content[0].text


def test_diff_header_path_traversal_rejection() -> None:
    """Verify path traversal embedded in unified diff headers is blocked fail-closed."""
    guard = _create_test_guard()
    dispatcher = MCPDispatcher()
    dispatcher.register_core_tools(guard)

    evil_diff = (
        "--- a/../../etc/passwd\n"
        "+++ b/../../etc/passwd\n"
        "@@ -1,1 +1,1 @@\n"
        "+root::0:0:root:/root:/bin/bash\n"
    )
    res = dispatcher.call_tool(
        "sde_propose_mutation",
        {
            "intent_id": "T0_TEST_TASK",
            "diff": evil_diff,
        },
    )
    assert res.isError is True
    assert "PATH_TRAVERSAL_ERROR" in res.content[0].text


def test_schema_field_validators_reject_traversal() -> None:
    """Verify Pydantic models directly reject traversal via field validators."""
    import pydantic
    import pytest

    from agentpoi_sde.mcp.schemas import (
        ASTSearchInput,
        ComponentHarvestInput,
        MutationProposalInput,
        TestRunnerInput,
    )

    # MutationProposalInput path
    with pytest.raises(pydantic.ValidationError):
        MutationProposalInput(
            intent_id="T0",
            path="../../etc/shadow",
            op="modify",
            new_content="# pass",
        )

    # MutationProposalInput diff traversal
    with pytest.raises(pydantic.ValidationError):
        MutationProposalInput(
            intent_id="T0",
            diff="--- a/../secret.txt\n+++ b/../secret.txt\n@@ -1 +1 @@\n+x\n",
        )

    # ComponentHarvestInput
    with pytest.raises(pydantic.ValidationError):
        ComponentHarvestInput(
            file_path="../../../evil.py",
            symbol_name="steal",
        )

    # ASTSearchInput
    with pytest.raises(pydantic.ValidationError):
        ASTSearchInput(
            file_path="C:\\Windows\\System32\\cmd.exe",
        )

    # TestRunnerInput
    with pytest.raises(pydantic.ValidationError):
        TestRunnerInput(
            test_paths=["tests/../../outside.py"],
        )


def test_strict_true_and_extra_forbid_on_schemas_and_protocol() -> None:
    """Verify strict=True and extra='forbid' on output schemas and JSON-RPC protocol models."""
    import pydantic
    import pytest

    from agentpoi_sde.mcp.protocol import (
        CallToolResult,
        InitializeResult,
        JSONRPCError,
        JSONRPCRequest,
        JSONRPCResponse,
        ToolContent,
        ToolDefinition,
    )
    from agentpoi_sde.mcp.schemas import (
        ASTSearchOutput,
        ComponentHarvestOutput,
        MutationProposalOutput,
        MutationVerdictItem,
        SymbolMatch,
        TestFailureItem,
        TestRunnerOutput,
    )

    # Output schemas reject extra fields
    with pytest.raises(pydantic.ValidationError):
        ASTSearchOutput(matches=[], total_matches=0, extra_field="forbidden")

    with pytest.raises(pydantic.ValidationError):
        SymbolMatch(name="fn", kind="function", file_path="a.py", module="a", extra_field=1)

    with pytest.raises(pydantic.ValidationError):
        ComponentHarvestOutput(
            symbol_name="fn",
            file_path="a.py",
            sliced_code="def fn(): pass",
            content_hash="abc",
            is_approved=True,
            extra_field=True,
        )

    with pytest.raises(pydantic.ValidationError):
        MutationVerdictItem(
            path="a.py",
            op="create",
            is_applied=True,
            status="APPROVED",
            extra_field=True,
        )

    with pytest.raises(pydantic.ValidationError):
        MutationProposalOutput(
            overall_approved=True,
            extra_field=True,
        )

    with pytest.raises(pydantic.ValidationError):
        TestFailureItem(
            test_id="t1",
            message="fail",
            traceback="tb",
            extra_field=True,
        )

    with pytest.raises(pydantic.ValidationError):
        TestRunnerOutput(
            success=True,
            exit_code=0,
            extra_field=True,
        )

    # Output schemas reject type coercion under strict=True (e.g. string for int/bool)
    with pytest.raises(pydantic.ValidationError):
        ASTSearchOutput(matches=[], total_matches="10")  # str instead of int

    with pytest.raises(pydantic.ValidationError):
        TestRunnerOutput(success="true", exit_code=0)  # str instead of bool

    # Protocol models reject extra fields and strict type mismatches
    with pytest.raises(pydantic.ValidationError):
        ToolContent(type="text", text="hello", unknown=123)

    with pytest.raises(pydantic.ValidationError):
        CallToolResult(isError="false")  # str instead of bool

    with pytest.raises(pydantic.ValidationError):
        ToolDefinition(name="tool", description="desc", inputSchema={}, unknown="bad")

    with pytest.raises(pydantic.ValidationError):
        InitializeResult(protocolVersion=12345)  # int instead of str

    with pytest.raises(pydantic.ValidationError):
        JSONRPCError(code="INVALID", message="bad code")  # str instead of int

    with pytest.raises(pydantic.ValidationError):
        JSONRPCRequest(method=123)  # int instead of str

    with pytest.raises(pydantic.ValidationError):
        JSONRPCResponse(jsonrpc=2.0)  # float instead of str

