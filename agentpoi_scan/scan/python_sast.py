"""Python SAST adapter — wraps ``agentpoi_sde``'s SlicerSecurityValidator.

Parse-only by construction: the validator is a pure AST analyzer over a text
buffer; this adapter feeds it snapshot file contents and maps its violations to
canonical findings. It never imports, compiles or executes snapshot code.
"""

from __future__ import annotations

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult
from agentpoi_sde.harvester.slicer_security import SlicerSecurityValidator

SCANNER_NAME = "python_sast"

# Map validator violation kinds to (severity, maliciousness, vulnerability).
_HIGH_EXEC = ("high", 0.6, 0.7)
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
            for violation in result.violations:
                severity, malicious, vuln = self._classify(violation)
                line_no = self._locate_line(code, violation)
                snippet = (
                    source_lines[line_no - 1].strip()[:300]
                    if 0 < line_no <= len(source_lines)
                    else ""
                )
                findings.append(
                    Finding(
                        file=relpath,
                        lines=[line_no],
                        snippet=snippet,
                        category=self._category(violation),
                        severity=severity,
                        title=self._title(violation),
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
    def _classify(violation: str) -> tuple:
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
    def _title(violation: str) -> str:
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
        """Best-effort line location: use the first offending symbol found in text."""
        import re

        token = re.search(r"'([a-zA-Z_.][\w.]+)'", violation)
        if token:
            needle = token.group(1).split(".")[0]
            for lineno, line in enumerate(code.splitlines(), start=1):
                if needle in line:
                    return lineno
        return 1
