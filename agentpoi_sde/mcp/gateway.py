"""Fail-closed schema gateway for AgentPOI-SDE MCP tool invocations.

Intercepts tool execution requests, validates parameters against rigid Pydantic v2 schemas
(extra="forbid", strict=True), rejects path traversal and drive roots, and blocks unauthorized
or malformed calls BEFORE any underlying tool or handler executes.
"""

from __future__ import annotations

import json
import posixpath
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

import pydantic
from pydantic import BaseModel

from agentpoi_sde.mcp.protocol import CallToolResult, ToolContent, ToolDefinition

DRIVE_OR_ABSOLUTE_PATTERN = re.compile(r"^([a-zA-Z]:|[/\\])")
URI_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
UNC_PATH_PATTERN = re.compile(r"^([/\\]{2}|[/\\]\?[/\\]|[/\\]\.[/\\])")


def check_path_string(path_str: str) -> Optional[str]:
    """Validate a path string fail-closed.

    Unquotes URL encoding, rejects null bytes, URI schemes (file://, smb://),
    UNC/device paths (\\\\, //), drive roots, absolute paths, and path traversal (..).
    Returns an error message if invalid, or None if acceptable.
    """
    if not isinstance(path_str, str):
        return None

    # Null byte check on raw input
    if "\x00" in path_str:
        return f"Path contains null bytes: {path_str!r}"

    # Decode percent-encoding (iteratively up to 3 times to prevent nested encoding bypass)
    decoded = path_str
    for _ in range(3):
        next_decoded = urllib.parse.unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded

    if "\x00" in decoded:
        return f"Path contains null bytes after decoding: {path_str!r}"

    # Reject URI schemes (e.g. file:///, smb://, http://)
    if URI_SCHEME_PATTERN.match(decoded):
        return f"URI schemes not permitted; path must be repository-relative: {path_str!r}"

    # Reject UNC paths and Windows device namespaces (\\\\server, //server, \\\\?\\, //?/)
    if decoded.startswith(("\\\\", "//")) or UNC_PATH_PATTERN.match(decoded):
        return f"Absolute path or drive root not permitted; must be repository-relative: {path_str!r}"

    # Reject drive roots (C:) or absolute roots (/ or \)
    if DRIVE_OR_ABSOLUTE_PATTERN.match(decoded):
        return f"Absolute path or drive root not permitted; must be repository-relative: {path_str!r}"

    # Normalize backslashes for segment checking
    normalized = decoded.replace("\\", "/")

    # Reject UNC paths after normalization if double slash
    if normalized.startswith("//"):
        return f"Absolute path or drive root not permitted; must be repository-relative: {path_str!r}"

    segments = normalized.split("/")
    if any(seg == ".." for seg in segments):
        return f"Path traversal ('..') detected in path: {path_str!r}"

    # Check normalized relative path containment
    clean_norm = posixpath.normpath(normalized)
    if clean_norm == ".." or clean_norm.startswith("../"):
        return f"Path traversal detected escaping repository root: {path_str!r}"

    return None


def extract_diff_paths(diff_text: str) -> List[str]:
    """Extract candidate target file paths from unified diff headers.

    Extracts paths from '--- ' and '+++ ' header lines, stripping traditional
    'a/' and 'b/' prefix indicators while filtering out '/dev/null'.
    """
    if not isinstance(diff_text, str) or not diff_text.strip():
        return []

    extracted: List[str] = []
    for line in diff_text.splitlines():
        line = line.strip()
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue

        parts = line.split(None, 2)
        if len(parts) < 2:
            continue

        raw = parts[1].strip()
        # Strip git diff prefixes a/ and b/
        if raw.startswith("a/") or raw.startswith("b/") or raw.startswith("a\\") or raw.startswith("b\\"):
            candidate = raw[2:]
        else:
            candidate = raw

        # Ignore standard /dev/null used for additions and deletions
        normalized_candidate = candidate.replace("\\", "/").strip()
        if normalized_candidate in {"dev/null", "/dev/null"}:
            continue

        extracted.append(candidate)

    return extracted


def sanitize_path_arguments(args: Any) -> Optional[str]:
    """Inspect arguments recursively for path containment issues and diff header traversals."""
    if isinstance(args, dict):
        for key, value in args.items():
            key_str = str(key).lower()
            # If the field is a unified diff, extract paths from headers and check each
            if "diff" in key_str and isinstance(value, str):
                diff_paths = extract_diff_paths(value)
                for dp in diff_paths:
                    err = check_path_string(dp)
                    if err:
                        return f"Path traversal in diff header: {err}"

            # If the field name indicates a path or file
            if "path" in key_str or "file" in key_str:
                if isinstance(value, str):
                    err = check_path_string(value)
                    if err:
                        return err
                elif isinstance(value, (list, tuple, set)):
                    for item in value:
                        if isinstance(item, str):
                            err = check_path_string(item)
                        else:
                            err = sanitize_path_arguments(item)
                        if err:
                            return err
                elif isinstance(value, dict):
                    err = sanitize_path_arguments(value)
                    if err:
                        return err
            else:
                # Recursively check other nested structures
                err = sanitize_path_arguments(value)
                if err:
                    return err

    elif isinstance(args, (list, tuple, set)):
        for item in args:
            if isinstance(item, str):
                err = check_path_string(item)
                if err:
                    return err
            else:
                err = sanitize_path_arguments(item)
                if err:
                    return err

    return None


@dataclass
class ToolRegistration:
    """Registered tool handler with rigid input/output schema contracts."""

    name: str
    description: str
    input_cls: Type[BaseModel]
    output_cls: Type[BaseModel]
    handler: Callable[[Any], Any]


class ToolGateway:
    """Fail-closed boundary verifying tool presence, arguments, and path safety."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolRegistration] = {}

    def register(
        self,
        name: str,
        input_cls: Type[BaseModel],
        output_cls: Type[BaseModel],
        handler: Callable[[Any], Any],
        description: str = "",
    ) -> None:
        """Register a tool with its schema contracts and execution handler."""
        self._tools[name] = ToolRegistration(
            name=name,
            description=description,
            input_cls=input_cls,
            output_cls=output_cls,
            handler=handler,
        )

    def is_registered(self, name: str) -> bool:
        """Return True if tool is registered in gateway."""
        return name in self._tools

    @property
    def registered_tool_names(self) -> List[str]:
        """Return sorted list of registered tool names."""
        return sorted(self._tools.keys())

    def get_tool_definition(self, name: str) -> Optional[ToolDefinition]:
        """Return the MCP ToolDefinition with JSON schema for a registered tool."""
        reg = self._tools.get(name)
        if not reg:
            return None
        schema = reg.input_cls.model_json_schema()
        return ToolDefinition(
            name=reg.name,
            description=reg.description,
            inputSchema=schema,
        )

    def list_tool_definitions(self) -> List[ToolDefinition]:
        """Return ToolDefinitions for all registered tools."""
        return [
            self.get_tool_definition(name)
            for name in self.registered_tool_names
            if self.get_tool_definition(name) is not None
        ]

    def validate_arguments(
        self,
        tool_name: str,
        raw_arguments: Optional[Dict[str, Any]],
    ) -> Tuple[bool, Optional[BaseModel], Optional[str]]:
        """Validate raw arguments against schema before tool execution."""
        reg = self._tools.get(tool_name)
        if not reg:
            msg = (
                f"GATEWAY_ERROR [UNKNOWN_TOOL]: Unknown tool '{tool_name}'. "
                f"Available tools: {self.registered_tool_names}"
            )
            return False, None, msg

        args = raw_arguments or {}
        path_err = sanitize_path_arguments(args)
        if path_err:
            msg = f"GATEWAY_ERROR [PATH_TRAVERSAL_ERROR]: {path_err}"
            return False, None, msg

        try:
            validated = reg.input_cls.model_validate(args)
            return True, validated, None
        except pydantic.ValidationError as exc:
            allowed = sorted(list(reg.input_cls.model_fields.keys()))
            error_details = self._format_validation_error(exc)
            msg = (
                f"GATEWAY_ERROR [SCHEMA_VALIDATION_ERROR]: Invalid arguments for '{tool_name}': "
                f"{error_details}. Allowed fields: {allowed}"
            )
            return False, None, msg

    def _format_validation_error(self, exc: pydantic.ValidationError) -> str:
        """Format Pydantic ValidationError into concise actionable error string."""
        messages: List[str] = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ())) or "root"
            err_type = err.get("type", "validation_error")
            msg = err.get("msg", "")
            messages.append(f"{loc}: {msg} (type={err_type})")
        return "; ".join(messages)

    def validate_and_call(
        self,
        tool_name: str,
        raw_arguments: Optional[Dict[str, Any]],
    ) -> CallToolResult:
        """Validate input arguments fail-closed, executing handler only on success."""
        ok, validated_model, err_msg = self.validate_arguments(tool_name, raw_arguments)
        if not ok or validated_model is None:
            return CallToolResult.error(err_msg or "Validation rejected")

        reg = self._tools[tool_name]
        try:
            handler_output = reg.handler(validated_model)
        except Exception as exc:
            return CallToolResult.error(
                f"GATEWAY_ERROR [TOOL_EXECUTION_ERROR]: Tool '{tool_name}' failed during execution: {str(exc)}"
            )

        if isinstance(handler_output, CallToolResult):
            return handler_output

        if isinstance(handler_output, BaseModel):
            structured = handler_output.model_dump()
            return CallToolResult(
                content=[ToolContent(type="text", text=json.dumps(structured, indent=2))],
                isError=False,
                structured_output=structured,
            )

        return CallToolResult.text(str(handler_output), is_error=False)
