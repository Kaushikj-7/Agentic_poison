"""Python SAST adapter — wraps ``agentpoi_sde``'s SlicerSecurityValidator.

Parse-only by construction: the validator is a pure AST analyzer over a text
buffer; this adapter feeds it snapshot file contents and maps its violations to
canonical findings. It never imports, compiles or executes snapshot code.
"""

from __future__ import annotations

import ast

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult
from agentpoi_sde.harvester.slicer_security import SlicerSecurityValidator

SCANNER_NAME = "python_sast"

# Map validator violation kinds to (severity, maliciousness, vulnerability).
_HIGH_EXEC = ("high", 0.6, 0.7)
_LOW_EXEC = ("low", 0.05, 0.1)
_SECRET = ("high", 0.4, 0.3)
_INJECTION = ("medium", 0.8, 0.1)


class PythonSastScanner:
    """AST-level dangerous-call, secret and injection scan for ``*.py`` files."""

    name = SCANNER_NAME

    def __init__(self, allow_shell: bool = False) -> None:
        self._validator = SlicerSecurityValidator(allow_shell=allow_shell)

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for relpath in context.files_with_suffix([".py"]):
            code = context.read_text(relpath)
            if code is None:
                continue
            result = self._validator.validate(code)
            if result.is_safe:
                continue
            source_lines = code.splitlines()
            is_const_url = self._is_constant_https_urlopen(code, result.dangerous_calls)
            for violation in result.violations:
                severity, malicious, vuln = self._classify(violation, is_const_url)
                lines = self._resolve_lines(code, violation, result.dangerous_call_lines)
                line_no = lines[0] if lines else 1
                snippet = (
                    source_lines[line_no - 1].strip()[:300]
                    if 0 < line_no <= len(source_lines)
                    else ""
                )
                findings.append(
                    Finding(
                        file=relpath,
                        lines=lines,
                        snippet=snippet,
                        category=self._category(violation),
                        severity=severity,
                        title=self._title(violation, is_const_url),
                        detail=violation,
                        scanner=SCANNER_NAME,
                        commit_sha=context.commit_sha,
                        maliciousness=malicious,
                        vulnerability=vuln,
                        evidence=[
                            {"kind": "scanner_output", "text": violation[:400]}
                        ],
                    )
                )
        return ScanResult(scanner=SCANNER_NAME, findings=findings)

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _is_constant_https_urlopen(code: str, dangerous_calls: list[str]) -> bool:
        """Checks if all dangerous calls in a file are constant-literal https urlopen invocations."""
        if not dangerous_calls:
            return False
        for call in dangerous_calls:
            if not (call == "urlopen" or call.endswith(".urlopen")):
                return False
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return False
        urlopen_nodes: list[ast.Call] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
                if name == "urlopen":
                    urlopen_nodes.append(node)
        if not urlopen_nodes:
            return False
        for node in urlopen_nodes:
            if not node.args:
                return False
            first_arg = node.args[0]
            if not (
                isinstance(first_arg, ast.Constant)
                and isinstance(first_arg.value, str)
                and first_arg.value.startswith("https://")
            ):
                return False
        return True

    @classmethod
    def _resolve_lines(
        cls, code: str, violation: str, dangerous_call_lines: list[tuple[str, int]]
    ) -> list[int]:
        if dangerous_call_lines:
            import re

            tokens = set(re.findall(r"'([a-zA-Z_.][\w.]+)'", violation))
            if tokens:
                matched = [
                    lineno
                    for call_name, lineno in dangerous_call_lines
                    if lineno > 0
                    and (
                        call_name in tokens
                        or call_name.split(".")[-1] in tokens
                        or any(t == call_name or t.endswith(f".{call_name}") for t in tokens)
                    )
                ]
                if matched:
                    return sorted(set(matched))
            if "prohibited execution call" in violation.lower():
                lines = sorted({lineno for _, lineno in dangerous_call_lines if lineno > 0})
                if lines:
                    return lines
        return [cls._locate_line(code, violation)]

    @staticmethod
    def _classify(violation: str, is_constant_urlopen: bool = False) -> tuple:
        if is_constant_urlopen:
            return _LOW_EXEC
        lowered = violation.lower()
        if "credential" in lowered:
            return _SECRET
        if "injection" in lowered:
            return _INJECTION
        return _HIGH_EXEC

    @staticmethod
    def _category(violation: str) -> str:
        lowered = violation.lower()
        if "credential" in lowered:
            return "secrets"
        if "injection" in lowered:
            return "injection"
        return "sast"

    @staticmethod
    def _title(violation: str, is_constant_urlopen: bool = False) -> str:
        if is_constant_urlopen:
            return "constant-literal https fetch: urlopen"
        lowered = violation.lower()
        if "credential" in lowered:
            return "credential material in source"
        if "injection" in lowered:
            return "prompt injection directive in source"
        if "syntax error" in lowered:
            return "python syntax error"
        return "prohibited execution call"

    @staticmethod
    def _locate_line(code: str, violation: str) -> int:
        """Best-effort line location: use offending symbol found in text, avoiding import statements."""
        import re

        tokens = re.findall(r"'([a-zA-Z_.][\w.]+)'", violation)
        lines = code.splitlines()
        for token in tokens:
            bare = token.split(".")[-1]
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    continue
                if token in line:
                    return lineno
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    continue
                if f"{bare}(" in line or bare in line:
                    return lineno
            for lineno, line in enumerate(lines, start=1):
                if token in line:
                    return lineno
        return 1
