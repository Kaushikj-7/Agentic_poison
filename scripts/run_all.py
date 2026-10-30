#!/usr/bin/env python3
"""One-command end-to-end verification for the whole AgentPOI system.

Usage:
    python scripts/run_all.py

Runs every gate in order, prints PASS/FAIL per gate, and exits nonzero if
any gate fails:

  1. Lint                     ruff check .
  2. Pre-flight CI            scripts/ci_check.py --allow-dirty
                              (syntax, secrets audit, 1100+ unit tests,
                               financial + SDE benchmarks, docs sync,
                               ledger, anti-cheat principles)
  3. Scanner CLI smoke        agentpoi_scan.cli run <fixture> --offline
                              (zero-host-execution static scan)
  4. Figure regeneration      scripts/generate_arch_diagram.py
  5. Figure style gate        scripts/verify_paper_style.py

The script re-executes itself under the workspace .venv interpreter when one
is present, so the same command works from any shell without activation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def venv_python() -> str | None:
    """Return the workspace virtual-environment interpreter, if it exists."""
    for rel in (".venv/Scripts/python.exe", ".venv/bin/python"):
        path = os.path.join(ROOT, rel)
        if os.path.isfile(path):
            return path
    return None


def ensure_venv() -> None:
    """Re-exec under the workspace venv so tooling resolves consistently."""
    vp = venv_python()
    if vp and os.path.realpath(vp) != os.path.realpath(sys.executable):
        code = subprocess.call(
            [vp, os.path.abspath(__file__), *sys.argv[1:]], cwd=ROOT
        )
        raise SystemExit(code)


def ruff_command() -> list[str]:
    """Resolve ruff from PATH, the venv, or the current interpreter."""
    exe = shutil.which("ruff")
    if exe:
        return [exe, "check", "."]
    for rel in (".venv/Scripts/ruff.exe", ".venv/bin/ruff"):
        path = os.path.join(ROOT, rel)
        if os.path.isfile(path):
            return [path, "check", "."]
    return [sys.executable, "-m", "ruff", "check", "."]


def run_gate(label: str, cmd: list[str], timeout: int = 900) -> tuple[str, bool, float]:
    """Run one gate, streaming its output, and report PASS/FAIL with timing."""
    print(f"\n{'=' * 70}\n GATE: {label}\n{'=' * 70}", flush=True)
    started = time.time()
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    try:
        proc = subprocess.run(
            cmd, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        ok = proc.returncode == 0
    except FileNotFoundError:
        print(f"[FAIL] command not found: {cmd[0]}")
        ok = False
    except subprocess.TimeoutExpired:
        print(f"[FAIL] timed out after {timeout}s")
        ok = False
    elapsed = time.time() - started
    print(f"[{'PASS' if ok else 'FAIL'}] {label}  ({elapsed:.1f}s)", flush=True)
    return label, ok, elapsed


def main() -> int:
    ensure_venv()

    gates: list[tuple[str, list[str]]] = [
        ("Lint (ruff)", ruff_command()),
        (
            "Pre-flight CI: syntax, secrets, 1100+ tests, benchmarks, docs, ledger",
            [sys.executable, os.path.join(ROOT, "scripts", "ci_check.py"), "--allow-dirty"],
        ),
        (
            "Scanner CLI offline smoke test",
            [
                sys.executable,
                "-m",
                "agentpoi_scan.cli",
                "run",
                os.path.join(ROOT, "tests", "fixtures", "legacy_php_repo"),
                "--offline",
            ],
        ),
        (
            "Architecture figure regeneration",
            [sys.executable, os.path.join(ROOT, "scripts", "generate_arch_diagram.py")],
        ),
        (
            "Paper-style figure verification",
            [sys.executable, os.path.join(ROOT, "scripts", "verify_paper_style.py")],
        ),
    ]

    results = [run_gate(label, cmd) for label, cmd in gates]

    print(f"\n{'=' * 70}\n SYSTEM VERIFICATION SUMMARY\n{'=' * 70}")
    for label, ok, elapsed in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}  ({elapsed:.1f}s)")
    failed = [label for label, ok, _ in results if not ok]
    total = sum(elapsed for _, _, elapsed in results)
    print("-" * 70)
    if failed:
        print(f"  RESULT: FAILED  ({len(failed)} gate(s), {total:.1f}s)")
        for label in failed:
            print(f"    - {label}")
        return 1
    print(f"  RESULT: ALL GATES PASSED  ({len(results)} gates, {total:.1f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
