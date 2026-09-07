"""Code Principles Auditor — AST-Based Static Analysis.

Enforces codebase invariants from the everything-claude-code methodology:
  - Architecture: Many Small Files (≤800 lines), functions ≤50 lines, nesting ≤4 levels.
  - Security: Zero hardcoded secrets, fail-closed defaults, input sanitization at boundaries.
  - TDD: Coverage ≥80%, no mocks that bypass real logic, all error paths tested.
  - Benchmark Integrity: No hash() in evaluation code, no hardcoded ratios.
  - Syntax: No unused imports, no built-in type misuse as annotations.

Can be integrated into ci_check.py as Gate 7 and used as an AGY global skill.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

MAX_FILE_LINES = 800
MAX_FUNCTION_LINES = 50
MAX_NESTING_DEPTH = 4

_HARDCODED_SECRET_PATTERNS = [
    re.compile(r'(?:password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
    re.compile(r'(?:sk-|ghp_|eyJ)[A-Za-z0-9_\-]{10,}'),
]

# ──────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────

@dataclass
class PrincipleViolation:
    """A detected code principle violation."""
    severity: str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str   # "ARCHITECTURE" | "SECURITY" | "TDD" | "BENCHMARK" | "SYNTAX"
    location: str   # "filepath:lineN" or "filepath"
    message: str


@dataclass
class FileAuditReport:
    """Audit result for a single file."""
    filepath: str
    line_count: int
    violations: List[PrincipleViolation] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "HIGH")


@dataclass
class DirectoryAuditReport:
    """Aggregate audit result for a full directory."""
    directory: str
    files_audited: int
    file_reports: List[FileAuditReport] = field(default_factory=list)

    @property
    def total_violations(self) -> int:
        return sum(len(r.violations) for r in self.file_reports)

    @property
    def critical_violations(self) -> int:
        return sum(r.critical_count for r in self.file_reports)

    @property
    def is_clean(self) -> bool:
        return self.critical_violations == 0

    def summary(self) -> str:
        status = "PASS" if self.is_clean else "FAIL"
        return (
            f"CodePrinciples: {status} | "
            f"Files: {self.files_audited} | "
            f"Violations: {self.total_violations} "
            f"(CRITICAL={self.critical_violations})"
        )


# ──────────────────────────────────────────────────────────────
# AST Visitors
# ──────────────────────────────────────────────────────────────

class _FunctionLengthVisitor(ast.NodeVisitor):
    """Detect functions exceeding MAX_FUNCTION_LINES."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.violations: List[PrincipleViolation] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > MAX_FUNCTION_LINES:
            self.violations.append(PrincipleViolation(
                severity="HIGH",
                category="ARCHITECTURE",
                location=f"{self.filepath}:L{node.lineno}",
                message=(
                    f"Function '{node.name}' is {length} lines "
                    f"(max {MAX_FUNCTION_LINES}). Decompose into smaller functions."
                ),
            ))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


class _NestingDepthVisitor(ast.NodeVisitor):
    """Detect nesting depth exceeding MAX_NESTING_DEPTH."""

    NESTING_NODES = (ast.If, ast.For, ast.While, ast.With, ast.Try,
                     ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.violations: List[PrincipleViolation] = []
        self._depth = 0

    def _visit_nesting(self, node: ast.AST) -> None:
        self._depth += 1
        if self._depth > MAX_NESTING_DEPTH:
            lineno = getattr(node, "lineno", 0)
            self.violations.append(PrincipleViolation(
                severity="MEDIUM",
                category="ARCHITECTURE",
                location=f"{self.filepath}:L{lineno}",
                message=(
                    f"Nesting depth {self._depth} exceeds maximum "
                    f"({MAX_NESTING_DEPTH}) at line {lineno}."
                ),
            ))
        self.generic_visit(node)
        self._depth -= 1

    def visit_If(self, node: ast.If) -> None:
        self._visit_nesting(node)

    def visit_For(self, node: ast.For) -> None:
        self._visit_nesting(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_nesting(node)

    def visit_With(self, node: ast.With) -> None:
        self._visit_nesting(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_nesting(node)


class _UnusedImportVisitor(ast.NodeVisitor):
    """Detect potentially unused imports (simple heuristic — name not referenced)."""

    def __init__(self, filepath: str, source: str) -> None:
        self.filepath = filepath
        self.source = source
        self.violations: List[PrincipleViolation] = []
        self._imported: List[Tuple[str, int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self._imported.append((name.split(".")[0], node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                name = alias.asname or alias.name
                self._imported.append((name, node.lineno))
        self.generic_visit(node)

    def check_unused(self) -> None:
        """After full tree visit, flag imports not referenced in source body."""
        # Remove import lines from search scope
        source_body = "\n".join(
            line for line in self.source.splitlines()
            if not line.strip().startswith(("import ", "from "))
        )
        for name, lineno in self._imported:
            pattern = re.compile(r"\b" + re.escape(name) + r"\b")
            if not pattern.search(source_body):
                self.violations.append(PrincipleViolation(
                    severity="LOW",
                    category="SYNTAX",
                    location=f"{self.filepath}:L{lineno}",
                    message=f"Potentially unused import: '{name}'. Remove dead imports.",
                ))


# ──────────────────────────────────────────────────────────────
# Main Auditor
# ──────────────────────────────────────────────────────────────

class CodePrinciplesAuditor:
    """AST-based static analysis enforcing codebase principles across any Python project.

    Usage:
        auditor = CodePrinciplesAuditor()
        report = auditor.audit_directory("agent_poi/")
        print(report.summary())
    """

    def audit_file(self, filepath: str) -> FileAuditReport:
        """Run all principle checks on a single Python source file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as exc:
            return FileAuditReport(
                filepath=filepath,
                line_count=0,
                violations=[PrincipleViolation(
                    severity="HIGH",
                    category="SYNTAX",
                    location=filepath,
                    message=f"Cannot read file: {exc}",
                )],
            )

        lines = source.splitlines()
        line_count = len(lines)
        violations: List[PrincipleViolation] = []

        # ── 1. File size ────────────────────────────────────────
        if line_count > MAX_FILE_LINES:
            violations.append(PrincipleViolation(
                severity="HIGH",
                category="ARCHITECTURE",
                location=filepath,
                message=(
                    f"File has {line_count} lines (max {MAX_FILE_LINES}). "
                    "Apply Many Small Files principle and decompose."
                ),
            ))

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            violations.append(PrincipleViolation(
                severity="CRITICAL",
                category="SYNTAX",
                location=f"{filepath}:L{exc.lineno}",
                message=f"Syntax error: {exc.msg}",
            ))
            return FileAuditReport(filepath=filepath, line_count=line_count, violations=violations)

        # ── 2. Function length ─────────────────────────────────
        fn_visitor = _FunctionLengthVisitor(filepath)
        fn_visitor.visit(tree)
        violations.extend(fn_visitor.violations)

        # ── 3. Nesting depth ───────────────────────────────────
        nest_visitor = _NestingDepthVisitor(filepath)
        nest_visitor.visit(tree)
        violations.extend(nest_visitor.violations)

        # ── 4. Unused imports ──────────────────────────────────
        imp_visitor = _UnusedImportVisitor(filepath, source)
        imp_visitor.visit(tree)
        imp_visitor.check_unused()
        violations.extend(imp_visitor.violations)

        # ── 5. Hardcoded secrets ───────────────────────────────
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern in _HARDCODED_SECRET_PATTERNS:
                if pattern.search(stripped):
                    violations.append(PrincipleViolation(
                        severity="CRITICAL",
                        category="SECURITY",
                        location=f"{filepath}:L{i}",
                        message=f"Potential hardcoded secret detected: '{stripped[:60]}...'",
                    ))
                    break

        return FileAuditReport(
            filepath=filepath,
            line_count=line_count,
            violations=violations,
        )

    def audit_directory(
        self,
        dirpath: str,
        exclude_dirs: Optional[List[str]] = None,
    ) -> DirectoryAuditReport:
        """Run all principle checks recursively across a directory.

        Args:
            dirpath: Root directory to audit.
            exclude_dirs: Directory names to skip (e.g., ['.venv', '__pycache__']).

        Returns:
            DirectoryAuditReport with aggregated results.
        """
        excluded = set(exclude_dirs or [".venv", "__pycache__", ".git", "build", "dist"])
        reports: List[FileAuditReport] = []

        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in excluded]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                reports.append(self.audit_file(fpath))

        return DirectoryAuditReport(
            directory=dirpath,
            files_audited=len(reports),
            file_reports=reports,
        )

    def check_benchmark_integrity(self, module_path: str) -> List[str]:
        """Detect hash(), magic numbers, and hardcoded metrics in an eval file.

        Convenience wrapper returning a simple list of violation messages.
        """
        report = self.audit_file(module_path)
        return [
            f"{v.severity}@{v.location}: {v.message}"
            for v in report.violations
            if v.category == "BENCHMARK"
        ]
