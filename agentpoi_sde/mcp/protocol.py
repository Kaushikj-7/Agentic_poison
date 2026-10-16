"""Model Context Protocol (MCP) JSON-RPC 2.0 models and protocol constants.

Provides standard dataclasses and Pydantic models for JSON-RPC 2.0 messaging,
MCP protocol lifecycle (initialize, tools/list, tools/call), and tool result containers.
All types are deterministic and execute entirely in-memory or over standard I/O streams.
"""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

# Standard JSON-RPC 2.0 Error Codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP Application-specific Error Codes
TOOL_EXECUTION_ERROR = -32000
SCHEMA_VALIDATION_ERROR = -32001
UNKNOWN_TOOL = -32002
PATH_TRAVERSAL_ERROR = -32003

DEFAULT_PROTOCOL_VERSION = "2024-11-05"


class ToolContent(BaseModel):
    """A single content item returned in a CallToolResult."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(default="text", description="Content type (typically 'text')")
    text: str = Field(..., description="Text payload of the tool output")


class CallToolResult(BaseModel):
    """Result returned from an MCP tools/call request."""

    model_config = ConfigDict(extra="forbid")

    content: List[ToolContent] = Field(
        default_factory=list,
        description="List of content items returned by the tool",
    )
    isError: bool = Field(
        default=False,
        description="Whether the tool execution failed or was rejected",
    )
    structured_output: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional typed dictionary of the structured tool result",
    )

    @classmethod
    def text(cls, text: str, is_error: bool = False, structured: Optional[Dict[str, Any]] = None) -> "CallToolResult":
        """Convenience constructor for simple text output."""
        return cls(
            content=[ToolContent(type="text", text=text)],
            isError=is_error,
            structured_output=structured,
        )

    @classmethod
    def error(cls, message: str, structured: Optional[Dict[str, Any]] = None) -> "CallToolResult":
        """Convenience constructor for error output."""
        return cls(
            content=[ToolContent(type="text", text=message)],
            isError=True,
            structured_output=structured,
        )


class ToolDefinition(BaseModel):
    """Metadata describing a callable tool under the MCP specification."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Human-readable description of tool capabilities")
    inputSchema: Dict[str, Any] = Field(
        ...,
        description="JSON Schema describing expected tool arguments",
    )


class InitializeResult(BaseModel):
    """Result of the MCP initialize handshake."""

    model_config = ConfigDict(extra="forbid")

    protocolVersion: str = Field(
        default=DEFAULT_PROTOCOL_VERSION,
        description="Negotiated protocol version",
    )
    capabilities: Dict[str, Any] = Field(
        default_factory=lambda: {"tools": {"listChanged": False}},
        description="Capabilities supported by the server",
    )
    serverInfo: Dict[str, str] = Field(
        default_factory=lambda: {
            "name": "agentpoi-sde-mcp",
            "version": "0.1.0",
        },
        description="Information about the server implementation",
    )


class JSONRPCError(BaseModel):
    """JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="forbid")

    code: int = Field(..., description="Numeric error code")
    message: str = Field(..., description="Short error message")
    data: Optional[Any] = Field(default=None, description="Optional diagnostic data")


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 request or notification envelope."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version string")
    id: Optional[Union[str, int]] = Field(
        default=None,
        description="Request identifier; None indicates a notification",
    )
    method: str = Field(..., description="Method name to invoke")
    params: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parameters payload for the method",
    )


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 response envelope."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version string")
    id: Optional[Union[str, int]] = Field(
        default=None,
        description="Matching request identifier",
    )
    result: Optional[Any] = Field(
        default=None,
        description="Successful result payload",
    )
    error: Optional[JSONRPCError] = Field(
        default=None,
        description="Error payload if the request failed",
    )

    @classmethod
    def success(cls, req_id: Optional[Union[str, int]], result: Any) -> "JSONRPCResponse":
        """Construct a successful JSON-RPC response."""
        return cls(id=req_id, result=result, error=None)

    @classmethod
    def failure(
        cls,
        req_id: Optional[Union[str, int]],
        code: int,
        message: str,
        data: Optional[Any] = None,
    ) -> "JSONRPCResponse":
        """Construct a failed JSON-RPC response."""
        return cls(
            id=req_id,
            result=None,
            error=JSONRPCError(code=code, message=message, data=data),
        )
