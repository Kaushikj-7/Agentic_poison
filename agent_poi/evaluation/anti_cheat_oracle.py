"""Anti-Cheat Oracle: Benchmark Integrity Guard.

Verifies that benchmark results are NOT fabricated via:
- hash()-based determinism
- Hardcoded percentage floats
- Magic numbers that bypass real execution
- Results not traceable to per-scenario execution records

AST-based static analysis + runtime provenance tracing.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScenarioExecutionRecord:
    """Provenance record for a single scenario execution pass."""
    scenario_id: str
    is_adversarial: bool
    was_breach: bool
    was_legitimate: bool
    was_disrupted: bool
    source_module: str


@dataclass
class IntegrityViolation:
    """A detected integrity violation in benchmarking code or results."""
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    violation_type: str
    location: str
    description: str


@dataclass
class IntegrityVerdict:
    """Final verdict from the Anti-Cheat Oracle."""
    is_clean: bool
    violations: List[IntegrityViolation] = field(default_factory=list)
    execution_records_verified: int = 0
    metric_provenance_score: float = 0.0  # 1.0 = fully traceable, 0.0 = no traceability

    def summary(self) -> str:
        status = "CLEAN" if self.is_clean else "FRAUDULENT"
        return (
            f"BenchmarkIntegrity: {status} | "
            f"Violations: {len(self.violations)} | "
            f"Records verified: {self.execution_records_verified} | "
            f"Provenance score: {self.metric_provenance_score:.2f}"
        )


_FORBIDDEN_AST_PATTERNS = [
    "hash",   # hash(scenario_id) % N is a cheat pattern
]

_HARDCODED_RATIO_PATTERN = re.compile(
    r"(?:asr_exec|ldsr|cdr|unauthorized|legitimate|disrupted)\s*[=\+]\s*"
    r"(?:0\.\d+|[1-9]\d*\.\d*|100\.0|70\.0|80\.0|30\.0)",
    re.IGNORECASE,
)

_MAGIC_NUMBER_PATTERN = re.compile(
    r"(?<![_\w])(?:70\.0|30\.0|80\.0|60\.0|0\.70|0\.30|0\.80|0\.60)(?![_\w\d])"
)


class _HashCallVisitor(ast.NodeVisitor):
    """AST visitor detecting calls to hash() inside evaluation functions."""

    def __init__(self) -> None:
        self.violations: List[IntegrityViolation] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Flag any call to the built-in hash()."""
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == "hash":
            self.violations.append(
                IntegrityViolation(
                    severity="CRITICAL",
                    violation_type="HASH_BASED_DETERMINISM",
                    location=f"line {node.lineno}",
                    description=(
                        f"hash() call detected at line {node.lineno}. "
                        "Using hash() to produce fake competitor metrics is "
                        "benchmark fraud — results will not reflect real execution."
                    ),
                )
            )
        self.generic_visit(node)


class AntiCheatOracle:
    """Meta-auditor ensuring benchmark results are never fabricated.

    Two modes of operation:
    1. Static analysis: AST-scan source files for disallowed patterns.
    2. Runtime provenance: verify metric counts trace to execution records.
    """

    def scan_for_cheating_patterns(self, source_code: str, filename: str = "<source>") -> List[IntegrityViolation]:
        """AST-parse source code, flagging all forbidden cheating patterns.

        Args:
            source_code: Raw Python source string to scan.
            filename: Display name for violation location reporting.

        Returns:
            List of detected IntegrityViolations (empty = clean).
        """
        violations: List[IntegrityViolation] = []

        # 1. AST scan — hash() calls
        try:
            tree = ast.parse(source_code)
            visitor = _HashCallVisitor()
            visitor.visit(tree)
            for v in visitor.violations:
                v.location = f"{filename}:{v.location}"
                violations.append(v)
        except SyntaxError as exc:
            violations.append(
                IntegrityViolation(
                    severity="HIGH",
                    violation_type="PARSE_ERROR",
                    location=f"{filename}:L{exc.lineno}",
                    description=f"Syntax error prevented AST scan: {exc}",
                )
            )

        # 2. Regex scan — hardcoded ratios assigned directly to metric variables
        for i, line in enumerate(source_code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HARDCODED_RATIO_PATTERN.search(stripped):
                violations.append(
                    IntegrityViolation(
                        severity="HIGH",
                        violation_type="HARDCODED_METRIC",
                        location=f"{filename}:L{i}",
                        description=(
                            f"Hardcoded metric assignment detected: '{stripped[:80]}'. "
                            "All metric values must be computed from real scenario execution counts."
                        ),
                    )
                )

        # 3. Regex scan — suspicious magic percentage floats
        for i, line in enumerate(source_code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _MAGIC_NUMBER_PATTERN.search(stripped):
                violations.append(
                    IntegrityViolation(
                        severity="MEDIUM",
                        violation_type="MAGIC_PERCENTAGE",
                        location=f"{filename}:L{i}",
                        description=(
                            f"Suspicious magic percentage literal detected: '{stripped[:80]}'. "
                            "Verify this is derived from real execution, not a preset value."
                        ),
                    )
                )

        return violations

    def scan_file(self, filepath: str) -> List[IntegrityViolation]:
        """Scan a Python source file for cheating patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as exc:
            return [
                IntegrityViolation(
                    severity="HIGH",
                    violation_type="FILE_READ_ERROR",
                    location=filepath,
                    description=str(exc),
                )
            ]
        return self.scan_for_cheating_patterns(source, filename=filepath)

    def verify_metric_provenance(
        self,
        result_asr: float,
        result_ldsr: float,
        result_cdr: float,
        execution_records: List[ScenarioExecutionRecord],
        framework_name: str = "unknown",
    ) -> IntegrityVerdict:
        """Verify benchmark metrics are consistent with execution records.

        Checks:
        - Metric counts match number of breaches / legitimate / disrupted in records.
        - Monotonicity guard: ASR must be derivable from record breaches.
        - Consistency: LDSR + CDR should sum to ~100%.

        Args:
            result_asr: Reported Attack Success Rate (0-100).
            result_ldsr: Reported Legitimate Disbursement Success Rate (0-100).
            result_cdr: Reported Clean Disruption Rate (0-100).
            execution_records: Per-scenario execution provenance.
            framework_name: Human-readable framework label for reporting.

        Returns:
            IntegrityVerdict with is_clean=True if metrics are trustworthy.
        """
        violations: List[IntegrityViolation] = []

        adv_records = [r for r in execution_records if r.is_adversarial]
        clean_records = [r for r in execution_records if not r.is_adversarial]

        # Recompute metrics from records
        computed_breaches = sum(1 for r in adv_records if r.was_breach)
        computed_legitimate = sum(1 for r in clean_records if r.was_legitimate)
        computed_disrupted = sum(1 for r in clean_records if r.was_disrupted)

        total_adv = len(adv_records)
        total_clean = len(clean_records)

        computed_asr = round(computed_breaches / total_adv * 100.0, 1) if total_adv else 0.0
        computed_ldsr = round(computed_legitimate / total_clean * 100.0, 1) if total_clean else 0.0
        computed_cdr = round(computed_disrupted / total_clean * 100.0, 1) if total_clean else 0.0

        # Check ASR consistency (allow 0.5% rounding tolerance)
        if abs(result_asr - computed_asr) > 0.6:
            violations.append(
                IntegrityViolation(
                    severity="CRITICAL",
                    violation_type="METRIC_MISMATCH",
                    location=f"framework={framework_name}",
                    description=(
                        f"ASR-Exec mismatch: reported={result_asr}% vs "
                        f"computed_from_records={computed_asr}%. "
                        "Result is not traceable to actual scenario executions."
                    ),
                )
            )

        # Check LDSR consistency
        if abs(result_ldsr - computed_ldsr) > 0.6:
            violations.append(
                IntegrityViolation(
                    severity="CRITICAL",
                    violation_type="METRIC_MISMATCH",
                    location=f"framework={framework_name}",
                    description=(
                        f"LDSR mismatch: reported={result_ldsr}% vs "
                        f"computed_from_records={computed_ldsr}%."
                    ),
                )
            )

        # LDSR + CDR must sum to ~100%
        total = result_ldsr + result_cdr
        if abs(total - 100.0) > 1.5:
            violations.append(
                IntegrityViolation(
                    severity="HIGH",
                    violation_type="METRIC_INCONSISTENCY",
                    location=f"framework={framework_name}",
                    description=(
                        f"LDSR ({result_ldsr}%) + CDR ({result_cdr}%) = {total:.1f}%, "
                        "expected ~100%. Metrics are internally inconsistent."
                    ),
                )
            )

        # Provenance score: fraction of records that are real (have scenario_id)
        real_records = sum(1 for r in execution_records if r.scenario_id)
        provenance_score = real_records / len(execution_records) if execution_records else 0.0

        return IntegrityVerdict(
            is_clean=len(violations) == 0,
            violations=violations,
            execution_records_verified=len(execution_records),
            metric_provenance_score=provenance_score,
        )

    def assert_monotonicity(
        self,
        results: Dict[str, Any],
        asr_key: str = "asr_exec",
    ) -> List[IntegrityViolation]:
        """Verify that adding more defense layers never increases ASR.

        Monotonicity theorem: Full defense ≤ partial defense ≤ baseline in ASR.
        Any violation indicates a measurement error or fabrication.

        Args:
            results: Dict mapping config_name -> FrameworkBenchmarkResult or dict.
            asr_key: Attribute/key name holding ASR value.

        Returns:
            List of monotonicity violations (empty = clean).
        """
        violations: List[IntegrityViolation] = []

        def _get_asr(result: Any) -> Optional[float]:
            if isinstance(result, dict):
                return result.get(asr_key)
            return getattr(result, asr_key, None)

        ordered_keys = sorted(results.keys())
        asr_values = [(k, _get_asr(results[k])) for k in ordered_keys]

        # The last key should be the most defended (full system)
        # and have the lowest or equal ASR
        if len(asr_values) >= 2:
            baseline_asr = asr_values[0][1]
            full_asr = asr_values[-1][1]
            if baseline_asr is not None and full_asr is not None:
                if full_asr > baseline_asr:
                    violations.append(
                        IntegrityViolation(
                            severity="CRITICAL",
                            violation_type="MONOTONICITY_VIOLATION",
                            location="ablation_study",
                            description=(
                                f"Full defense ASR ({full_asr}%) exceeds baseline ASR ({baseline_asr}%). "
                                "Adding security layers must never increase attack success rate."
                            ),
                        )
                    )

        return violations
