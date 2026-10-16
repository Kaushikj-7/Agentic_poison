"""MCP Tool Dispatcher handling in-memory and stdio JSON-RPC 2.0 communication.

Provides tool lifecycle methods (initialize, tools/list, tools/call),
routing through the fail-closed ToolGateway boundary.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional, TextIO, Union

from agentpoi_sde.facade import DevGuard
from agentpoi_sde.mcp.gateway import ToolGateway
from agentpoi_sde.mcp.protocol import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    CallToolResult,
    InitializeResult,
    JSONRPCRequest,
    JSONRPCResponse,
    ToolDefinition,
)
from agentpoi_sde.mcp.schemas import (
    ASTSearchInput,
    ASTSearchOutput,
    ComponentHarvestInput,
    ComponentHarvestOutput,
    MutationProposalInput,
    MutationProposalOutput,
    TestRunnerInput,
    TestRunnerOutput,
)
from agentpoi_sde.mcp.tools import (
    handle_ast_search,
    handle_harvest_component,
    handle_propose_mutation,
    handle_run_tests,
)


class MCPDispatcher:
    """Central MCP JSON-RPC 2.0 dispatcher with tool registry and transport loops."""

    def __init__(self, gateway: Optional[ToolGateway] = None) -> None:
        self.gateway: ToolGateway = gateway or ToolGateway()

    def register_core_tools(self, guard: DevGuard) -> None:
        """Register the four standard AgentPOI-SDE MCP repository tools."""
        self.gateway.register(
            name="sde_ast_search",
            input_cls=ASTSearchInput,
            output_cls=ASTSearchOutput,
            handler=lambda params: handle_ast_search(params, guard=guard),
            description="Search top-level AST symbols and import dependencies across repository Python files.",
        )
        self.gateway.register(
            name="sde_harvest_component",
            input_cls=ComponentHarvestInput,
            output_cls=ComponentHarvestOutput,
            handler=lambda params: handle_harvest_component(params, guard=guard),
            description="Safely slice, isolate, and screen a reusable function or class component.",
        )
        self.gateway.register(
            name="sde_propose_mutation",
            input_cls=MutationProposalInput,
            output_cls=MutationProposalOutput,
            handler=lambda params: handle_propose_mutation(params, guard=guard),
            description="Propose code mutations or unified diffs evaluated fail-closed against DevGuard invariants.",
        )
        self.gateway.register(
            name="sde_run_tests",
            input_cls=TestRunnerInput,
            output_cls=TestRunnerOutput,
            handler=lambda params: handle_run_tests(params, guard=guard),
            description="Execute pytest test suites in the deterministic verification sink or isolated sandbox.",
        )

    def list_tools(self) -> List[ToolDefinition]:
        """Return definitions of all registered tools."""
        return self.gateway.list_tool_definitions()

    def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> CallToolResult:
        """Execute a tool call in-memory through the fail-closed gateway."""
        return self.gateway.validate_and_call(name, arguments)

    def dispatch_request(self, request: JSONRPCRequest) -> Optional[JSONRPCResponse]:
        """Dispatch a single parsed JSON-RPC request to its corresponding handler."""
        method = request.method
        req_id = request.id
        params = request.params or {}

        if method == "initialize":
            init_res = InitializeResult()
            return JSONRPCResponse.success(req_id, init_res.model_dump())

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            tools_data = [t.model_dump() for t in self.list_tools()]
            return JSONRPCResponse.success(req_id, {"tools": tools_data})

        if method == "tools/call":
            tool_name = params.get("name")
            if not tool_name or not isinstance(tool_name, str):
                return JSONRPCResponse.failure(
                    req_id,
                    INVALID_PARAMS,
                    "Parameter 'name' (string) is required for tools/call",
                )
            raw_args = params.get("arguments") or {}
            if not isinstance(raw_args, dict):
                return JSONRPCResponse.failure(
                    req_id,
                    INVALID_PARAMS,
                    "Parameter 'arguments' must be an object/dict if provided",
                )
            result = self.call_tool(tool_name, raw_args)
            return JSONRPCResponse.success(req_id, result.model_dump())

        return JSONRPCResponse.failure(
            req_id,
            METHOD_NOT_FOUND,
            f"Method '{method}' not implemented or recognized",
        )

    def dispatch_raw(self, raw_input: Union[str, Dict[str, Any]]) -> Optional[str]:
        """Parse raw JSON string or dict, dispatch request, and return JSON response string."""
        if isinstance(raw_input, str):
            try:
                data = json.loads(raw_input)
            except json.JSONDecodeError as exc:
                err_resp = JSONRPCResponse.failure(None, PARSE_ERROR, f"Invalid JSON payload: {str(exc)}")
                return json.dumps(err_resp.model_dump())
        else:
            data = raw_input

        if not isinstance(data, dict):
            err_resp = JSONRPCResponse.failure(None, INVALID_REQUEST, "JSON-RPC request must be a JSON object")
            return json.dumps(err_resp.model_dump())

        try:
            req = JSONRPCRequest.model_validate(data)
        except Exception as exc:
            req_id = data.get("id") if isinstance(data, dict) else None
            err_resp = JSONRPCResponse.failure(req_id, INVALID_REQUEST, f"Malformed JSON-RPC request: {str(exc)}")
            return json.dumps(err_resp.model_dump())

        response = self.dispatch_request(req)
        return json.dumps(response.model_dump()) if response is not None else None

    def run_stdio(
        self,
        input_stream: Optional[TextIO] = None,
        output_stream: Optional[TextIO] = None,
    ) -> None:
        """Run standard I/O line-delimited JSON-RPC loop until EOF."""
        in_stream = input_stream or sys.stdin
        out_stream = output_stream or sys.stdout

        for line in in_stream:
            line_str = line.strip()
            if not line_str:
                continue
            response_json = self.dispatch_raw(line_str)
            if response_json:
                out_stream.write(response_json + "\n")
                out_stream.flush()
