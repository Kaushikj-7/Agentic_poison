"""Model Context Protocol (MCP) tool integration and schema validation subsystem.

Provides deterministic in-process and stdio JSON-RPC 2.0 tool dispatch,
fail-closed schema gating with rigid Pydantic v2 models, path containment verification,
and bindings to the AgentPOI-SDE verification sink.
"""

from agentpoi_sde.mcp.client import MCPClient
from agentpoi_sde.mcp.dispatcher import MCPDispatcher
from agentpoi_sde.mcp.gateway import ToolGateway
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
    ASTSearchInput,
    ASTSearchOutput,
    ComponentHarvestInput,
    ComponentHarvestOutput,
    MutationProposalInput,
    MutationProposalOutput,
    MutationVerdictItem,
    SymbolMatch,
    TestFailureItem,
    TestRunnerInput,
    TestRunnerOutput,
)
from agentpoi_sde.mcp.tools import (
    handle_ast_search,
    handle_harvest_component,
    handle_propose_mutation,
    handle_run_tests,
)

__all__ = [
    "MCPClient",
    "MCPDispatcher",
    "ToolGateway",
    "CallToolResult",
    "InitializeResult",
    "JSONRPCError",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "ToolContent",
    "ToolDefinition",
    "ASTSearchInput",
    "ASTSearchOutput",
    "SymbolMatch",
    "ComponentHarvestInput",
    "ComponentHarvestOutput",
    "MutationProposalInput",
    "MutationProposalOutput",
    "MutationVerdictItem",
    "TestRunnerInput",
    "TestRunnerOutput",
    "TestFailureItem",
    "handle_ast_search",
    "handle_harvest_component",
    "handle_propose_mutation",
    "handle_run_tests",
]
