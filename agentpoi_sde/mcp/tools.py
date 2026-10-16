"""Concrete MCP tool handlers for AgentPOI-SDE.

Wraps SymbolIndex, ComponentHarvester, DevGuard, and IsolatedConfigurationSandbox
into deterministic, fail-closed tool execution functions.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agentpoi_sde.anchor.symbol_index import SymbolIndex
from agentpoi_sde.delta.diff_parser import parse_unified_diff
from agentpoi_sde.domain import CodeMutation, MutationOp
from agentpoi_sde.facade import DevGuard
from agentpoi_sde.harvester.component_harvester import ComponentHarvester
from agentpoi_sde.mcp.schemas import (
    ASTSearchInput,
    ASTSearchOutput,
    ComponentHarvestInput,
    ComponentHarvestOutput,
    MutationProposalInput,
    MutationProposalOutput,
    MutationVerdictItem,
    SymbolMatch,
    TestFailureItem,
    TestRunnerInput,
    TestRunnerOutput,
)

# Regex patterns for pytest output parsing
PYTEST_PASSED_RE = re.compile(r"(\d+)\s+passed")
PYTEST_FAILED_RE = re.compile(r"(\d+)\s+failed")
PYTEST_SKIPPED_RE = re.compile(r"(\d+)\s+skipped")
PYTEST_DURATION_RE = re.compile(r"in\s+([\d\.]+)\s*s")
PYTEST_SUMMARY_FAIL_RE = re.compile(r"^FAILED\s+([^\s]+)(?:\s+-\s+(.*))?$", re.MULTILINE)


def parse_pytest_output(output: str, exit_code: int, duration_seconds: float) -> TestRunnerOutput:
    """Parse pytest stdout/stderr output into a typed TestRunnerOutput."""
    passed_m = PYTEST_PASSED_RE.search(output)
    failed_m = PYTEST_FAILED_RE.search(output)
    skipped_m = PYTEST_SKIPPED_RE.search(output)
    dur_m = PYTEST_DURATION_RE.search(output)

    passed_count = int(passed_m.group(1)) if passed_m else 0
    failed_count = int(failed_m.group(1)) if failed_m else 0
    skipped_count = int(skipped_m.group(1)) if skipped_m else 0
    parsed_duration = float(dur_m.group(1)) if dur_m else duration_seconds

    failures: List[TestFailureItem] = []
    for match in PYTEST_SUMMARY_FAIL_RE.finditer(output):
        test_id = match.group(1).strip()
        msg = (match.group(2) or "Test assertion failed").strip()
        failures.append(TestFailureItem(test_id=test_id, message=msg, traceback=output))

    return TestRunnerOutput(
        success=(exit_code == 0),
        exit_code=exit_code,
        passed_count=passed_count,
        failed_count=failed_count,
        skipped_count=skipped_count,
        duration_seconds=round(parsed_duration, 3),
        output=output,
        failures=failures,
    )


def handle_ast_search(
    params: ASTSearchInput,
    guard: Optional[DevGuard] = None,
    workspace: Optional[Dict[str, str]] = None,
) -> ASTSearchOutput:
    """Execute AST symbol discovery across repository Python files."""
    files = workspace if workspace is not None else (guard.workspace if guard else {})
    if not files and guard and guard.anchor:
        files = guard.anchor.files

    index = SymbolIndex().build(files)
    matches: List[SymbolMatch] = []
    target_path = params.file_path.replace("\\", "/") if params.file_path else None
    query_str = params.query.lower() if params.query else None

    for path, entry in sorted(index.files.items()):
        if target_path and path != target_path:
            continue
        for sym_name, kind in sorted(entry.symbols.items()):
            if params.symbol_type != "all" and kind != params.symbol_type:
                continue
            if query_str and query_str not in sym_name.lower():
                continue
            matches.append(
                SymbolMatch(
                    name=sym_name,
                    kind=kind,
                    file_path=path,
                    module=entry.module,
                )
            )

    dependencies: Optional[Dict[str, List[str]]] = None
    if params.include_dependencies:
        edges = index.internal_edges()
        dependencies = {
            p: sorted(list(targets)) for p, targets in sorted(edges.items()) if targets
        }

    return ASTSearchOutput(
        matches=matches,
        total_matches=len(matches),
        dependencies=dependencies,
    )


def handle_harvest_component(
    params: ComponentHarvestInput,
    guard: Optional[DevGuard] = None,
    harvester: Optional[ComponentHarvester] = None,
) -> ComponentHarvestOutput:
    """Slice and screen an isolated function or class component."""
    active_harvester = harvester or (guard.harvester if guard else ComponentHarvester())
    code = params.source_code
    if not code and guard and params.file_path in guard.workspace:
        code = guard.workspace[params.file_path]

    component = active_harvester.harvest(
        repo_name="local",
        file_path=params.file_path,
        target_symbol=params.symbol_name,
        source_code=code,
    )

    sec_violations = (
        component.security_verdict.violations if component.security_verdict else []
    )
    return ComponentHarvestOutput(
        symbol_name=component.target_symbol,
        file_path=component.file_path,
        sliced_code=component.sliced_code,
        content_hash=component.content_hash,
        is_approved=component.is_approved,
        retained_symbols=component.retained_symbols,
        pruned_symbols=component.pruned_symbols,
        security_violations=sec_violations,
        error=component.error,
    )


def _eval_single_mutation(
    guard: DevGuard,
    mutation: CodeMutation,
    intent_id: str,
    dry_run: bool,
) -> MutationVerdictItem:
    """Evaluate one mutation against DevGuard, isolating dry-run state if requested."""
    saved_ws = dict(guard.workspace)
    saved_anchor = dict(guard.anchor.files)
    saved_ledger_len = len(guard.ledger)
    saved_audit_len = len(guard.audit_log)

    verdict = guard.propose_mutation(mutation, intent_id=intent_id)

    if dry_run:
        guard.workspace = saved_ws
        guard.anchor.files = saved_anchor
        guard.anchor.symbol_index = SymbolIndex().build(saved_anchor)
        guard.anchor.import_graph = guard.anchor.symbol_index.internal_edges()
        if len(guard.ledger) > saved_ledger_len:
            guard.ledger = guard.ledger[:saved_ledger_len]
        if len(guard.audit_log) > saved_audit_len:
            guard.audit_log = guard.audit_log[:saved_audit_len]

    violations_str = [
        v if isinstance(v, str) else getattr(v, "message", str(v))
        for v in verdict.violations
    ]
    return MutationVerdictItem(
        path=verdict.mutation_path,
        op=mutation.op.value,
        is_applied=verdict.is_applied if not dry_run else False,
        status=verdict.status,
        violation_codes=verdict.violation_codes,
        violations=violations_str,
        patch_hash=verdict.delta.patch_hash if verdict.delta else None,
    )


def handle_propose_mutation(
    params: MutationProposalInput,
    guard: DevGuard,
) -> MutationProposalOutput:
    """Evaluate code mutation proposals or unified diff patches through DevGuard."""
    verdict_items: List[MutationVerdictItem] = []

    if params.diff:
        mutations = parse_unified_diff(params.diff, base_files=guard.workspace)
        for mut in mutations:
            item = _eval_single_mutation(guard, mut, params.intent_id, params.dry_run)
            verdict_items.append(item)
    elif params.path and params.op:
        old_content = guard.workspace.get(params.path, "")
        mut = CodeMutation(
            path=params.path,
            op=MutationOp(params.op),
            new_content=params.new_content or "",
            old_content=old_content,
        )
        item = _eval_single_mutation(guard, mut, params.intent_id, params.dry_run)
        verdict_items.append(item)

    overall_approved = bool(
        verdict_items
        and (
            all(v.is_applied for v in verdict_items)
            if not params.dry_run
            else all(v.status == "APPROVED" for v in verdict_items)
        )
    )

    return MutationProposalOutput(
        verdicts=verdict_items,
        overall_approved=overall_approved,
        working_tree_oid=guard.anchor.tree_oid(),
        intent_id=params.intent_id,
    )


def _prepare_isolated_files(
    test_paths: List[str],
    guard: Optional[DevGuard],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Partition test files and source files for isolated sandbox execution."""
    test_files: Dict[str, str] = {}
    source_files: Dict[str, str] = {}
    workspace = guard.workspace if guard else {}

    for rel_path, content in workspace.items():
        if rel_path in test_paths or "test" in rel_path.lower():
            test_files[rel_path] = content
        else:
            source_files[rel_path] = content

    for target in test_paths:
        target_norm = target.replace("\\", "/")
        if target_norm not in test_files and Path(target).is_file():
            test_files[target_norm] = Path(target).read_text(encoding="utf-8")

    return test_files, source_files


def _run_isolated_tests(
    params: TestRunnerInput,
    guard: Optional[DevGuard],
    start_time: float,
) -> TestRunnerOutput:
    """Run tests inside temporary isolated directory."""
    test_files, source_files = _prepare_isolated_files(params.test_paths, guard)
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_path = Path(tmp_dir_str)
        for path_str, content in {**source_files, **test_files}.items():
            dest = tmp_path / path_str
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(tmp_path),
            "-v",
            "--tb=short",
            "-o",
            f"cache_dir={tmp_path / '.pytest_cache'}",
        ]
        if params.expression:
            cmd.extend(["-k", params.expression])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(tmp_path),
                timeout=params.timeout_seconds,
            )
            duration = time.perf_counter() - start_time
            output = proc.stdout + "\n" + proc.stderr
            return parse_pytest_output(output, proc.returncode, duration)
        except subprocess.TimeoutExpired:
            duration = time.perf_counter() - start_time
            return TestRunnerOutput(
                success=False,
                exit_code=124,
                duration_seconds=round(duration, 3),
                output=f"Execution timed out after {params.timeout_seconds}s",
            )


def _run_inrepo_tests(
    params: TestRunnerInput,
    start_time: float,
) -> TestRunnerOutput:
    """Run tests directly against workspace repository targets."""
    cmd = [sys.executable, "-m", "pytest"] + list(params.test_paths) + ["-v", "--tb=short"]
    if params.expression:
        cmd.extend(["-k", params.expression])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=params.timeout_seconds,
        )
        duration = time.perf_counter() - start_time
        output = proc.stdout + "\n" + proc.stderr
        return parse_pytest_output(output, proc.returncode, duration)
    except subprocess.TimeoutExpired:
        duration = time.perf_counter() - start_time
        return TestRunnerOutput(
            success=False,
            exit_code=124,
            duration_seconds=round(duration, 3),
            output=f"Execution timed out after {params.timeout_seconds}s",
        )


def handle_run_tests(
    params: TestRunnerInput,
    guard: Optional[DevGuard] = None,
) -> TestRunnerOutput:
    """Execute pytest suites either in an isolated temporary directory or in-repo."""
    start_time = time.perf_counter()
    if params.isolated:
        return _run_isolated_tests(params, guard, start_time)
    return _run_inrepo_tests(params, start_time)

