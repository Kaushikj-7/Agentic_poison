"""Joint Epistemic Verifier (JEV) for AgentPOI-SDE.

Fast (< 5ms on CPU) speculative pre-screener validating candidate code mutations
before downstream execution or MCP tool dispatch:
1. AST syntax gate (ast.parse) fail-closed for Python source code (JEV_SYNTAX_ERROR).
2. Structural diff gate validating patch well-formedness and file paths (JEV_STRUCTURAL_ERROR).
3. Credential leakage gate scanning newly introduced content using regex (JEV_CREDENTIAL_LEAK).
4. Strictly bounded CPU execution time (< 5ms).
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Union

from agentpoi_sde.agent.transport_security import (
    CREDENTIAL_PATTERN,
    PRIVATE_KEY_PATTERN,
    REDACTED_SECRET,
)
from agentpoi_sde.delta.diff_parser import MalformedDiffError, parse_unified_diff
from agentpoi_sde.domain import CodeMutation, MutationOp
from agentpoi_sde.mcp.gateway import check_path_string

JEV_APPROVED = "JEV_APPROVED"
JEV_SYNTAX_ERROR = "JEV_SYNTAX_ERROR"
JEV_STRUCTURAL_ERROR = "JEV_STRUCTURAL_ERROR"
JEV_CREDENTIAL_LEAK = "JEV_CREDENTIAL_LEAK"
JEV_LATENCY_EXCEEDED = "JEV_LATENCY_EXCEEDED"


@dataclass(frozen=True)
class JEVVerdict:
    """Verdict produced by the Joint Epistemic Verifier."""

    approved: bool
    code: str
    error: Optional[str] = None
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Return True when approved."""
        return self.approved


class JointEpistemicVerifier:
    """Pre-screens candidate code proposals on CPU with sub-5ms latency assertion."""

    def __init__(self, max_latency_ms: float = 5.0, strict_latency: bool = False) -> None:
        self.max_latency_ms = max_latency_ms
        self.strict_latency = strict_latency

    def assert_latency_budget(self, verdict: JEVVerdict) -> None:
        """Assert that verdict latency completed within the configured budget."""
        assert verdict.latency_ms < self.max_latency_ms, (
            f"JEV latency budget exceeded: {verdict.latency_ms:.3f}ms >= {self.max_latency_ms}ms"
        )

    def verify_proposal(
        self,
        proposal: Union[CodeMutation, Any, Sequence[Any]],
        workspace: Optional[Dict[str, str]] = None,
    ) -> JEVVerdict:
        """Verify candidate code mutation(s) against syntax, structure, and leak gates."""
        start_time = time.perf_counter()

        def _make_verdict(
            approved: bool,
            code: str,
            error: Optional[str] = None,
            details: Optional[Dict[str, Any]] = None,
        ) -> JEVVerdict:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if self.strict_latency and elapsed_ms >= self.max_latency_ms:
                raise AssertionError(
                    f"JEV latency budget exceeded: {elapsed_ms:.3f}ms >= {self.max_latency_ms}ms"
                )
            if approved and elapsed_ms >= self.max_latency_ms:
                return JEVVerdict(
                    approved=False,
                    code=JEV_LATENCY_EXCEEDED,
                    error=f"Verification exceeded latency budget: {elapsed_ms:.3f}ms >= {self.max_latency_ms}ms",
                    latency_ms=elapsed_ms,
                    details=details or {},
                )
            return JEVVerdict(
                approved=approved,
                code=code,
                error=error,
                latency_ms=elapsed_ms,
                details=details or {},
            )

        # Handle list/tuple batch proposals
        if isinstance(proposal, (list, tuple)):
            if not proposal:
                return _make_verdict(True, JEV_APPROVED)
            for item in proposal:
                item_verdict = self.verify_proposal(item, workspace=workspace)
                if not item_verdict.approved:
                    return item_verdict
            return _make_verdict(True, JEV_APPROVED)

        # Handle raw unified diff string
        if isinstance(proposal, str):
            diff_text = proposal.strip()
            if not diff_text:
                return _make_verdict(True, JEV_APPROVED)
            try:
                mutations = parse_unified_diff(diff_text, base_files=workspace)
            except (MalformedDiffError, Exception) as exc:
                return _make_verdict(
                    False,
                    JEV_STRUCTURAL_ERROR,
                    error=f"Malformed unified diff: {exc}",
                )
            return self.verify_proposal(mutations, workspace=workspace)

        # Extract path, op, and new_content from various representations
        path: Optional[str] = None
        op: Optional[MutationOp] = None
        new_content: str = ""

        if isinstance(proposal, dict):
            if "diff" in proposal and isinstance(proposal["diff"], str):
                return self.verify_proposal(proposal["diff"], workspace=workspace)
            path = proposal.get("path")
            op_raw = str(proposal.get("op", "modify")).lower()
            try:
                op = MutationOp(op_raw)
            except ValueError:
                return _make_verdict(
                    False,
                    JEV_STRUCTURAL_ERROR,
                    error=f"Invalid mutation op: {op_raw!r}",
                )
            new_content = str(proposal.get("new_content", ""))
        elif hasattr(proposal, "path") and hasattr(proposal, "op"):
            path = getattr(proposal, "path")
            op_val = getattr(proposal, "op")
            if isinstance(op_val, str):
                try:
                    op = MutationOp(op_val.lower())
                except ValueError:
                    return _make_verdict(
                        False,
                        JEV_STRUCTURAL_ERROR,
                        error=f"Invalid mutation op: {op_val!r}",
                    )
            elif isinstance(op_val, MutationOp):
                op = op_val
            new_content = str(getattr(proposal, "new_content", "") or "")
        else:
            return _make_verdict(
                False,
                JEV_STRUCTURAL_ERROR,
                error=f"Unsupported proposal type: {type(proposal).__name__}",
            )

        # Gate 1: Structural Diff Gate - Target path validation
        if not path or not isinstance(path, str):
            return _make_verdict(
                False,
                JEV_STRUCTURAL_ERROR,
                error="Mutation path cannot be empty",
            )

        path_error = check_path_string(path)
        if path_error:
            return _make_verdict(
                False,
                JEV_STRUCTURAL_ERROR,
                error=f"Invalid target path: {path_error}",
            )

        # Gate 2: AST Syntax Gate (for Python files and non-delete ops)
        normalized_path = path.replace("\\", "/").lower()
        if normalized_path.endswith(".py") and op != MutationOp.DELETE:
            try:
                ast.parse(new_content, filename=path)
            except SyntaxError as exc:
                return _make_verdict(
                    False,
                    JEV_SYNTAX_ERROR,
                    error=f"AST syntax error in {path} at line {exc.lineno}: {exc.msg}",
                )
            except Exception as exc:
                return _make_verdict(
                    False,
                    JEV_SYNTAX_ERROR,
                    error=f"Failed to parse AST for {path}: {exc}",
                )

        # Gate 3: Credential Leakage Gate
        if op != MutationOp.DELETE and new_content:
            # Check multiline private keys
            if PRIVATE_KEY_PATTERN.search(new_content):
                return _make_verdict(
                    False,
                    JEV_CREDENTIAL_LEAK,
                    error=f"Private key detected in proposed content for {path}",
                )

            # Check prefixed credential assignments
            cred_match = CREDENTIAL_PATTERN.search(new_content)
            if cred_match:
                matched_text = cred_match.group(0)
                if REDACTED_SECRET not in matched_text:
                    return _make_verdict(
                        False,
                        JEV_CREDENTIAL_LEAK,
                        error=f"Credential leakage detected in {path}: {matched_text[:40]}",
                    )

        return _make_verdict(True, JEV_APPROVED)
