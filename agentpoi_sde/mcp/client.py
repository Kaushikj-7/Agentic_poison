"""In-process MCP Client for autonomous agent loops and LLM provider integration.

Formats registered tool schemas into OpenAI/OpenRouter function tool definitions
and Markdown prompt guides, executes tool calls, and parses structured results.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel

from agentpoi_sde.mcp.dispatcher import MCPDispatcher
from agentpoi_sde.mcp.protocol import CallToolResult, ToolDefinition

T = TypeVar("T", bound=BaseModel)


def _parse_content_item(item: Any, output_model: Type[T]) -> Optional[T]:
    """Helper to parse a single content item into output_model."""
    if item.type != "text" or not item.text:
        return None
    try:
        data = json.loads(item.text)
        return output_model.model_validate(data) if isinstance(data, dict) else None
    except Exception:
        return None


class MCPClient:
    """Client interface for autonomous agent reasoning loops to inspect and invoke MCP tools."""

    def __init__(self, dispatcher: MCPDispatcher) -> None:
        self.dispatcher: MCPDispatcher = dispatcher

    def list_tools(self) -> List[ToolDefinition]:
        """Return all available ToolDefinitions from the dispatcher."""
        return self.dispatcher.list_tools()

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Return the definition of a specific tool by identifier, or None."""
        for tool in self.list_tools():
            if tool.name == name:
                return tool
        return None

    def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> CallToolResult:
        """Invoke a tool through the dispatcher and return its CallToolResult."""
        return self.dispatcher.call_tool(name, arguments)

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        """Format registered tools as OpenAI/OpenRouter standard function calling schemas."""
        tools_payload: List[Dict[str, Any]] = []
        for tool in self.list_tools():
            tools_payload.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema,
                    },
                }
            )
        return tools_payload

    def to_markdown_description(self) -> str:
        """Generate human- and LLM-readable Markdown documentation of available tools."""
        lines: List[str] = ["### Available MCP Tools\n"]
        for tool in self.list_tools():
            lines.append(f"#### `{tool.name}`")
            lines.append(f"{tool.description}\n")
            schema = tool.inputSchema
            props = schema.get("properties", {})
            required_fields = set(schema.get("required", []))

            if props:
                lines.append("**Parameters**:")
                for prop_name, prop_data in sorted(props.items()):
                    p_type = prop_data.get("type", "any")
                    desc = prop_data.get("description", "")
                    req_mark = "(required)" if prop_name in required_fields else "(optional)"
                    lines.append(f"- `{prop_name}` ({p_type}, {req_mark}): {desc}")
            else:
                lines.append("**Parameters**: None")
            lines.append("")
        return "\n".join(lines).strip()

    @staticmethod
    def parse_tool_result(result: CallToolResult, output_model: Type[T]) -> Optional[T]:
        """Safely deserialize a CallToolResult into a typed Pydantic output model."""
        if result.isError:
            return None

        if result.structured_output:
            try:
                return output_model.model_validate(result.structured_output)
            except Exception:
                pass

        for item in result.content:
            parsed = _parse_content_item(item, output_model)
            if parsed is not None:
                return parsed
        return None

