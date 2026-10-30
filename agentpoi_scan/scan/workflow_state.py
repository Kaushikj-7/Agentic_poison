"""Explicit-state checker for attacker-controlled GitHub Actions workflows.

This is a bounded abstract interpreter, not a YAML linter: it checks whether a
pull_request_target event can reach either an untrusted expression in a shell
command or execution after checking out the PR head. Repository code is never
executed; workflow YAML is parsed as data only.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Iterable

import yaml

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult


@dataclass(frozen=True)
class WorkflowState:
    """Finite abstraction of the workflow's relevant trust/execution state."""

    pull_request_target: bool = False
    privileged_context: bool = False
    untrusted_checkout: bool = False
    tainted_shell: bool = False
    untrusted_code_executed: bool = False


@dataclass(frozen=True)
class Transition:
    """One abstract state transition and its source evidence."""

    target: WorkflowState
    label: str
    line: int


@dataclass(frozen=True)
class Counterexample:
    """Shortest reachable unsafe state and the transitions proving reachability."""

    state: WorkflowState
    transitions: tuple[Transition, ...]


_PR_VALUE = re.compile(
    r"\$\{\{\s*github\.(?:event\.pull_request\.(?:title|body|head\.ref)|"
    r"event\.comment\.body|event\.issue\.(?:title|body))\s*\}\}",
    re.IGNORECASE,
)
_PR_HEAD_REF = re.compile(
    r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}",
    re.IGNORECASE,
)
_EXEC_COMMAND = re.compile(
    r"(?im)^\s*(?:run:\s*)?(?:[-]\s*)?(?:npm\s+(?:install|ci|test|run)|"
    r"pip\s+install|python\s+-m\s+(?:pytest|unittest)|pytest\b|"
    r"make\b|cargo\s+test|go\s+test|\.\.?/[^\s]+)"
)


def _line_of(text: str, pattern: re.Pattern[str]) -> int:
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _is_pull_request_target(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    triggers = document.get("on", document.get(True, {}))
    if isinstance(triggers, str):
        triggers = [triggers]
    if isinstance(triggers, list):
        return "pull_request_target" in triggers
    return isinstance(triggers, dict) and "pull_request_target" in triggers


def _workflow_jobs(document: object) -> Iterable[list[dict]]:
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        return
    for job in document["jobs"].values():
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            yield [step for step in job["steps"] if isinstance(step, dict)]


def _reachable_bad_state(trigger_line: int, steps: list[dict], text: str) -> Counterexample | None:
    """BFS state reachability over ordered workflow steps in one job."""
    if not trigger_line:
        return None
    start = WorkflowState()
    event = WorkflowState(pull_request_target=True, privileged_context=True)
    adjacency: dict[WorkflowState, list[Transition]] = {
        start: [Transition(event, "untrusted PR event enters privileged workflow", trigger_line)],
        event: [],
    }
    current = event
    for step in steps:
        run = step.get("run")
        if isinstance(run, str) and _PR_VALUE.search(run) and not current.tainted_shell:
            target = WorkflowState(True, True, current.untrusted_checkout, True, current.untrusted_code_executed)
            adjacency.setdefault(current, []).append(
                Transition(target, "PR-controlled value interpolated into run shell", _line_of(text, _PR_VALUE))
            )
            adjacency.setdefault(target, [])
            current = target
        uses = str(step.get("uses", ""))
        with_args = step.get("with") or {}
        ref = with_args.get("ref", "") if isinstance(with_args, dict) else ""
        if "actions/checkout" in uses and isinstance(ref, str) and _PR_HEAD_REF.search(ref) and not current.untrusted_checkout:
            target = WorkflowState(True, True, True, current.tainted_shell, current.untrusted_code_executed)
            adjacency.setdefault(current, []).append(
                Transition(target, "workflow checks out attacker-controlled PR head", _line_of(text, _PR_HEAD_REF))
            )
            adjacency.setdefault(target, [])
            current = target
        if isinstance(run, str) and _EXEC_COMMAND.search(run) and current.untrusted_checkout and not current.untrusted_code_executed:
            target = WorkflowState(True, True, True, current.tainted_shell, True)
            adjacency.setdefault(current, []).append(
                Transition(target, "build/test command can execute checked-out code", _line_of(text, _EXEC_COMMAND))
            )
            adjacency.setdefault(target, [])
            current = target

    queue = deque([start])
    predecessor: dict[WorkflowState, tuple[WorkflowState, Transition] | None] = {start: None}
    while queue:
        state = queue.popleft()
        unsafe = (state.privileged_context and state.tainted_shell) or (
            state.privileged_context and state.untrusted_checkout and state.untrusted_code_executed
        )
        if unsafe:
            path: list[Transition] = []
            cursor = state
            while predecessor[cursor] is not None:
                parent, edge = predecessor[cursor]
                path.append(edge)
                cursor = parent
            return Counterexample(state, tuple(reversed(path)))
        for edge in adjacency.get(state, []):
            if edge.target not in predecessor:
                predecessor[edge.target] = (state, edge)
                queue.append(edge.target)
    return None


class WorkflowStateChecker:
    """Finds reachable privilege-boundary violations in GitHub Actions workflows."""

    name = "workflow_state_check"

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for path in context.file_index:
            normalized_path = path.replace("\\\\", "/")
            if not normalized_path.startswith(".github/workflows/") or not normalized_path.lower().endswith((".yml", ".yaml")):
                continue
            text = context.read_text(path) or ""
            try:
                document = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            if not _is_pull_request_target(document):
                continue

            trigger_line = _line_of(text, re.compile(r"pull_request_target"))
            witness = next(
                (
                    candidate
                    for steps in _workflow_jobs(document)
                    if (candidate := _reachable_bad_state(trigger_line, steps, text)) is not None
                ),
                None,
            )
            if witness is None:
                continue
            path_text = " -> ".join(edge.label for edge in witness.transitions)
            evidence = [
                {"kind": "state_transition", "text": f"line {edge.line}: {edge.label}"}
                for edge in witness.transitions
            ]
            lines = sorted({edge.line for edge in witness.transitions})
            findings.append(
                Finding(
                    file=path,
                    lines=lines,
                    category="ci_iac",
                    severity="high",
                    title="reachable privileged GitHub Actions trust-boundary violation",
                    detail=(
                        f"Explicit-state reachability found an unsafe path: {path_text}. "
                        "This conservative abstraction assumes pull_request_target has a privileged context; "
                        "review the workflow permissions, secrets, and command semantics."
                    ),
                    scanner=self.name,
                    commit_sha=context.commit_sha,
                    maliciousness=0.7,
                    vulnerability=0.8,
                    evidence=evidence,
                )
            )
        return ScanResult(scanner=self.name, findings=findings)
