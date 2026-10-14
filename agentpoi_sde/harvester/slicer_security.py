"""Security validation and sanitization for harvested program slices."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Set

from agentpoi_sde.anchor.policy_registry import INJECTION_MARKERS, SECRET_PATTERNS


@dataclass(frozen=True)
class SlicerSecurityResult:
    """Outcome of security analysis on harvested code slice."""

    is_safe: bool
    violations: List[str] = field(default_factory=list)
    found_secrets: List[str] = field(default_factory=list)
    dangerous_calls: List[str] = field(default_factory=list)
    injection_hits: List[str] = field(default_factory=list)


class SlicerSecurityValidator:
    """Validates that harvested code contains no credentials, injections, or backdoors."""

    DANGEROUS_BUILTINS: Set[str] = {"eval", "exec", "compile", "__import__"}

    DANGEROUS_MODULE_ATTRS: Set[str] = {
        "os.system",
        "os.popen",
        "os.spawn",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "pty.spawn",
        "socket.connect",
    }

    def __init__(self, allow_shell: bool = False) -> None:
        self.allow_shell = allow_shell

    def validate(self, code: str) -> SlicerSecurityResult:
        """Runs static analysis over code to verify safety."""
        violations: List[str] = []
        secrets = self._scan_secrets(code)
        injections = self._scan_injections(code)
        dangerous_calls: List[str] = []

        if secrets:
            violations.append(f"Contains credential material: {secrets}")
        if injections:
            violations.append(f"Contains injection directives: {injections}")

        try:
            tree = ast.parse(code)
            dangerous_calls = self._scan_dangerous_ast(tree)
            if dangerous_calls:
                violations.append(f"Contains prohibited execution calls: {dangerous_calls}")
        except SyntaxError as exc:
            violations.append(f"Syntax error in code slice: {exc}")

        return SlicerSecurityResult(
            is_safe=len(violations) == 0,
            violations=violations,
            found_secrets=secrets,
            dangerous_calls=dangerous_calls,
            injection_hits=injections,
        )

    def _scan_secrets(self, code: str) -> List[str]:
        """Scans for embedded secrets or API keys."""
        found: List[str] = []
        for pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, code)
            if matches:
                found.extend(matches[:3])
        return found

    def _scan_injections(self, code: str) -> List[str]:
        """Scans comments and string literals for injection directives."""
        found: List[str] = []
        lower = code.lower()
        for marker in INJECTION_MARKERS:
            if marker in lower:
                found.append(marker)
        return found

    def _build_alias_map(self, tree: ast.AST) -> dict[str, str]:
        """Maps local identifiers and aliases to qualified module/function names."""
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    aliases[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    full_name = f"{mod}.{alias.name}" if mod else alias.name
                    aliases[local_name] = full_name
        return aliases

    def _scan_dangerous_ast(self, tree: ast.AST) -> List[str]:
        """Inspects AST nodes for dangerous or prohibited function invocations."""
        aliases = self._build_alias_map(tree)
        dangerous: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._resolve_call_name(node.func, aliases)
                if name in self.DANGEROUS_BUILTINS:
                    dangerous.append(name)
                elif not self.allow_shell and (
                    name in self.DANGEROUS_MODULE_ATTRS or name.startswith("subprocess.")
                ):
                    dangerous.append(name)
        return dangerous

    def _resolve_call_name(self, node: ast.AST, aliases: Optional[dict[str, str]] = None) -> str:
        """Extracts dotted call name with alias expansion (e.g., 'sp.run' -> 'subprocess.run')."""
        if isinstance(node, ast.Name):
            if aliases and node.id in aliases:
                return aliases[node.id]
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = self._resolve_call_name(node.value, aliases)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""
