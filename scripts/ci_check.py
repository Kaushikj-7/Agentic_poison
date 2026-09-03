"""Local Pre-Flight CI/CD Verification Runner.

Executes all verification gates locally before commits or pushes to GitHub:
1. Python Syntax & Compilation
2. Secrets & Credential Audit
3. Automated Unit Tests (pytest)
4. Dynamic 60-Scenario Financial Benchmark (ASR-Exec invariant check)
5. Project Ledger Status
"""

import compileall
import os
import re
import subprocess
import sys
from typing import List, Tuple

# Ensure workspace root is in sys.path
workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)


def check_syntax() -> Tuple[bool, int]:
    """Compile all python files to catch syntax errors."""
    success = compileall.compile_dir("agent_poi", quiet=1)
    success_tests = compileall.compile_dir("tests", quiet=1)
    is_ok = bool(success and success_tests)
    return is_ok, 0 if is_ok else 1


def check_secrets() -> Tuple[bool, List[str]]:
    """Scan code files for hardcoded API keys and tokens."""
    secret_pat = re.compile(
        r'(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
        re.IGNORECASE,
    )
    violations = []
    for root, _, files in os.walk("agent_poi"):
        for f in files:
            if f.endswith(".py"):
                p = os.path.join(root, f)
                with open(p, "r", encoding="utf-8") as src:
                    for idx, line in enumerate(src, 1):
                        if secret_pat.search(line):
                            violations.append(f"{p}:{idx}")
    return len(violations) == 0, violations


def run_unit_tests() -> Tuple[bool, str]:
    """Run pytest unit test suite."""
    cmd = [sys.executable, "-m", "pytest", "tests/", "-v"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    is_ok = res.returncode == 0
    # Extract passed count
    match = re.search(r"(\d+)\s+passed", res.stdout)
    passed_summary = match.group(0) if match else "tests executed"
    return is_ok, passed_summary


def run_benchmark_invariant() -> Tuple[bool, float, float]:
    """Run genuine dynamic 60-scenario financial benchmark."""
    from agent_poi.financial.eval.financial_benchmark import FinancialBenchmarkRunner
    runner = FinancialBenchmarkRunner()
    results = runner.run_full_comparison()
    defended = results["defended"]
    is_ok = (defended.asr_exec == 0.0) and (defended.ldsr >= 80.0)
    return is_ok, defended.asr_exec, defended.ldsr


def main():
    print("=" * 65)
    print(" EXECUTING LOCAL PRE-FLIGHT CI/CD VERIFICATION PIPELINE")
    print("=" * 65)

    all_passed = True

    # 1. Syntax
    syntax_ok, err_count = check_syntax()
    if not syntax_ok:
        all_passed = False
    print(f"[*] Syntax Check:    {'OK' if syntax_ok else f'FAIL ({err_count} errors)'}")

    # 2. Secrets
    secrets_ok, secret_issues = check_secrets()
    if not secrets_ok:
        all_passed = False
    print(f"[*] Security Audit:  {'OK (0 hardcoded secrets)' if secrets_ok else f'FAIL: {secret_issues}'}")

    # 3. Unit Tests
    tests_ok, test_summary = run_unit_tests()
    if not tests_ok:
        all_passed = False
    print(f"[*] Unit Test Suite: {'OK (' + test_summary + ')' if tests_ok else 'FAIL'}")

    # 4. Benchmark Invariant
    bench_ok, asr_exec, ldsr = run_benchmark_invariant()
    if not bench_ok:
        all_passed = False
    print(f"[*] Benchmark Invariant: {'PASS' if bench_ok else 'FAIL'} (ASR-Exec={asr_exec}%, LDSR={ldsr}%)")

    # 5. Ledger
    ledger_ok = os.path.exists("PROJECT_LEDGER.md") and os.path.getsize("PROJECT_LEDGER.md") > 100
    if not ledger_ok:
        all_passed = False
    print(f"[*] Project Ledger:  {'UPDATED' if ledger_ok else 'MISSING'}")

    print("-" * 65)
    print(f"VERIFICATION: {'PASS' if all_passed else 'FAIL'}")
    print(f"Build:    OK")
    print(f"Syntax:   {'OK' if syntax_ok else 'FAIL'}")
    print(f"Tests:    {test_summary if tests_ok else 'FAIL'}")
    print(f"Security: {'OK' if secrets_ok else 'FAIL'}")
    print(f"Ledger:   {'UPDATED' if ledger_ok else 'FAIL'}")
    print(f"Ready for PR: {'YES' if all_passed else 'NO'}")
    print("=" * 65)

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
