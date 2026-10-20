"""Security validation and sanitization for harvested program slices."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

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

    DANGEROUS_BUILTINS: Set[str] = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "builtins.eval",
        "builtins.exec",
        "__builtins__.eval",
        "__builtins__.exec",
        "importlib.import_module",
        "_socket",
        "_socket.",
        "ftplib.",
        "smtplib.",
        "urllib3.",
    }

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
        "_socket.connect",
    }

    DANGEROUS_SYSCALLS: Set[str] = {
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.kill",
        "os.killpg",
        "os.fork",
        "pty.spawn",
    }

    DANGEROUS_MODULE_PREFIXES: Tuple[str, ...] = (
        "subprocess.",
        "os.spawn",
        "requests.",
        "httpx.",
        "aiohttp.",
        "urllib.request.",
        "http.client.",
        "socket.",
        "_socket.",
        "_socket",
        "ftplib.",
        "smtplib.",
        "urllib3.",
    )

    DANGEROUS_MODULES: Set[str] = {
        "os",
        "subprocess",
        "socket",
        "_socket",
        "pty",
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "urllib.request",
        "urllib3",
        "http",
        "http.client",
        "ftplib",
        "smtplib",
        "asyncio",
        "builtins",
        "__builtins__",
        "importlib",
    }

    DANGEROUS_EXACT_CALLS: Set[str] = {
        "asyncio.open_connection",
        "asyncio.start_server",
    }

    SOCKET_METHOD_NAMES: Set[str] = {
        "connect",
        "connect_ex",
        "bind",
        "listen",
        "send",
        "sendall",
        "sendto",
        "recv",
        "recvfrom",
        "recv_into",
        "recvfrom_into",
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

    def _is_dangerous(self, name: str) -> bool:
        """Determines if a resolved symbol name corresponds to a dangerous builtin, syscall, or socket."""
        if not name:
            return False
        if name in self.DANGEROUS_BUILTINS:
            return True
        if name in ("socket", "_socket") or any(name.startswith(pfx) for pfx in self.DANGEROUS_MODULE_PREFIXES):
            return True
        if name in self.DANGEROUS_EXACT_CALLS:
            return True
        if not self.allow_shell:
            if name in self.DANGEROUS_SYSCALLS or name.startswith("subprocess.") or name.startswith("os.spawn"):
                return True
            if name in self.DANGEROUS_MODULE_ATTRS:
                return True
        return False

    def _is_dangerous_module(self, name: str) -> bool:
        """Determines if a resolved symbol name corresponds to a dangerous module."""
        if not name:
            return False
        if name in self.DANGEROUS_MODULES or name in self.DANGEROUS_BUILTINS:
            return True
        if any(pfx.rstrip(".") == name or pfx.startswith(f"{name}.") for pfx in self.DANGEROUS_MODULE_PREFIXES):
            return True
        if any(call.startswith(f"{name}.") for call in self.DANGEROUS_SYSCALLS):
            return True
        if any(attr.startswith(f"{name}.") for attr in self.DANGEROUS_MODULE_ATTRS):
            return True
        return False

    def _resolve_getattr_target(self, node: ast.AST, aliases: dict[str, str]) -> Optional[str]:
        """Inspects getattr(...) call to resolve the target attribute (e.g. getattr(os, 'system') -> 'os.system')."""
        while isinstance(node, ast.NamedExpr):
            node = node.value
        if not isinstance(node, ast.Call):
            return None
        func_name = self._resolve_call_name(node.func, aliases)
        if func_name in ("getattr", "builtins.getattr", "__builtins__.getattr") and len(node.args) >= 2:
            obj_arg = node.args[0]
            attr_arg = node.args[1]
            if isinstance(obj_arg, ast.Call) and self._resolve_call_name(obj_arg.func, aliases) in (
                "__import__",
                "builtins.__import__",
            ):
                if obj_arg.args and isinstance(obj_arg.args[0], ast.Constant) and isinstance(obj_arg.args[0].value, str):
                    target_obj = obj_arg.args[0].value
                else:
                    target_obj = ""
            else:
                target_obj = self._resolve_call_name(obj_arg, aliases)

            if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                return f"{target_obj}.{attr_arg.value}" if target_obj else attr_arg.value
        return None

    def _scan_dangerous_ast(self, tree: ast.AST) -> List[str]:
        """Inspects AST nodes for dangerous or prohibited function invocations."""
        initial_aliases = self._build_alias_map(tree)
        visitor = _SecurityASTVisitor(self, initial_aliases)
        visitor.visit(tree)
        return visitor.dangerous_calls

    def _resolve_call_name(self, node: ast.AST, aliases: Optional[dict[str, str]] = None) -> str:
        """Extracts dotted call name with alias expansion (e.g., 'sp.run' -> 'subprocess.run')."""
        if isinstance(node, ast.NamedExpr):
            return self._resolve_call_name(node.value, aliases)
        if isinstance(node, ast.Name):
            if aliases and node.id in aliases:
                return aliases[node.id]
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = self._resolve_call_name(node.value, aliases)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""


class _SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor traversing nodes in execution order to track assignment aliases and detect calls."""

    def __init__(self, validator: SlicerSecurityValidator, initial_aliases: dict[str, str]) -> None:
        self.validator = validator
        self.aliases = initial_aliases.copy()
        self.dangerous_calls: List[str] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self._check_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._check_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.iter, (ast.List, ast.Tuple)):
            for elt in node.iter.elts:
                self._check_assignment([node.target], elt)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        if isinstance(node.iter, (ast.List, ast.Tuple)):
            for elt in node.iter.elts:
                self._check_assignment([node.target], elt)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        if isinstance(node.iter, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.iter.elts:
                self._check_assignment([node.target], elt)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.key)
        self.visit(node.value)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        for gen in node.generators:
            self.visit(gen)
        self.visit(node.elt)

    def _check_assignment(self, targets: List[ast.AST], value: ast.AST) -> None:
        # Check if RHS is an assignment expression (ast.NamedExpr)
        if isinstance(value, ast.NamedExpr):
            self._check_assignment([value.target], value.value)
            self._check_assignment(targets, value.value)
            return

        # Check if RHS is a tuple or list unpacking
        if isinstance(value, (ast.Tuple, ast.List)):
            for target in targets:
                if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                    for sub_t, sub_v in zip(target.elts, value.elts):
                        self._check_assignment([sub_t], sub_v)
            return

        # Check if RHS is a getattr call
        getattr_target = self.validator._resolve_getattr_target(value, self.aliases)
        if getattr_target:
            if self.validator._is_dangerous(getattr_target):
                self.dangerous_calls.append(getattr_target)
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = getattr_target
                return
            if self.validator._is_dangerous_module(getattr_target):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = getattr_target
                return

        # Check if RHS is a Name or Attribute resolving to dangerous symbol or module
        if isinstance(value, (ast.Name, ast.Attribute)):
            resolved = self.validator._resolve_call_name(value, self.aliases)
            if self.validator._is_dangerous(resolved):
                self.dangerous_calls.append(resolved)
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = resolved
                return
            if self.validator._is_dangerous_module(resolved):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = resolved
                return

        # Check if RHS is a Call returning/creating dangerous resource (e.g. sock = socket.socket())
        if isinstance(value, ast.Call):
            resolved_call = self.validator._resolve_call_name(value.func, self.aliases)
            if self.validator._is_dangerous(resolved_call):
                self.dangerous_calls.append(resolved_call)
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = resolved_call
            return

    def visit_Call(self, node: ast.Call) -> None:
        # Check if call itself is getattr(...) targeting dangerous attribute
        getattr_target = self.validator._resolve_getattr_target(node, self.aliases)
        if getattr_target and self.validator._is_dangerous(getattr_target):
            self.dangerous_calls.append(getattr_target)

        # Check if func being invoked is a getattr(...) call
        getattr_target_func = self.validator._resolve_getattr_target(node.func, self.aliases)
        if getattr_target_func and self.validator._is_dangerous(getattr_target_func):
            self.dangerous_calls.append(getattr_target_func)

        # Check resolved name of invoked callable
        name = self.validator._resolve_call_name(node.func, self.aliases)
        if self.validator._is_dangerous(name):
            self.dangerous_calls.append(name)
        else:
            func_node = node.func
            while isinstance(func_node, ast.NamedExpr):
                func_node = func_node.value
            if (
                isinstance(func_node, ast.Attribute)
                and func_node.attr in self.validator.SOCKET_METHOD_NAMES
            ):
                prefix = self.validator._resolve_call_name(func_node.value, self.aliases)
                self.dangerous_calls.append(
                    f"{prefix}.{func_node.attr}" if prefix else f"socket.{func_node.attr}"
                )

        self.generic_visit(node)
