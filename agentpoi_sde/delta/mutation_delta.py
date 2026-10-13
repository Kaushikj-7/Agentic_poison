"""Mutation Delta extraction  Delta(edit): normalise a mutation into a typed tuple.

Turns a proposed ``CodeMutation`` into a deterministic ``MutationDelta`` describing exactly
what changes structurally: imports added, lines touched, credential material introduced,
egress endpoints added, and whether the test oracle is weakened. The agent's natural-language
rationale is never trusted; only the artefacts are inspected.
"""

import ast
import difflib
import hashlib
import io
import re
import tokenize
from typing import Any, List, Optional, Tuple

from agentpoi_sde.anchor.policy_registry import (
    collect_secret_signals,
    collect_urls,
    default_policy,
    injection_marker_hits,
    is_policy_file,
    is_test_file,
)
from agentpoi_sde.anchor.symbol_index import extract_imports, module_name_from_path
from agentpoi_sde.domain import ArchitecturePolicy, CodeMutation, MutationDelta, MutationOp

ASSERT_PATTERN = re.compile(r"\bassert\b|\.assert(?:Equal|True|False|In|Is|Raises|AlmostEqual|Greater|Less)\b")
SKIP_PATTERN = re.compile(r"pytest\.skip|pytest\.mark\.skip|unittest\.skip|@skip|xfail|@unittest\.skip")


def _eval_const_expr(node: ast.AST) -> Tuple[bool, Any]:
    """Safely evaluate compile-time constant expressions in AST without execution."""
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, (ast.Tuple, ast.List)):
        vals = []
        for elt in node.elts:
            ok, val = _eval_const_expr(elt)
            if not ok:
                return False, None
            vals.append(val)
        return True, tuple(vals) if isinstance(node, ast.Tuple) else vals
    if isinstance(node, ast.UnaryOp):
        ok, operand = _eval_const_expr(node.operand)
        if ok:
            if isinstance(node.op, ast.Not):
                return True, not operand
            if isinstance(node.op, ast.UAdd):
                return True, +operand
            if isinstance(node.op, ast.USub):
                return True, -operand
    if isinstance(node, ast.BoolOp):
        vals = []
        for val_node in node.values:
            ok, val = _eval_const_expr(val_node)
            if not ok:
                return False, None
            vals.append(val)
        if isinstance(node.op, ast.And):
            return True, all(vals)
        if isinstance(node.op, ast.Or):
            return True, any(vals)
    if isinstance(node, ast.Compare):
        ok_left, current = _eval_const_expr(node.left)
        if not ok_left:
            return False, None
        for op, comp in zip(node.ops, node.comparators):
            ok_comp, comp_val = _eval_const_expr(comp)
            if not ok_comp:
                return False, None
            try:
                if isinstance(op, ast.Eq) and not (current == comp_val):
                    return True, False
                elif isinstance(op, ast.NotEq) and not (current != comp_val):
                    return True, False
                elif isinstance(op, ast.Lt) and not (current < comp_val):
                    return True, False
                elif isinstance(op, ast.LtE) and not (current <= comp_val):
                    return True, False
                elif isinstance(op, ast.Gt) and not (current > comp_val):
                    return True, False
                elif isinstance(op, ast.GtE) and not (current >= comp_val):
                    return True, False
                elif isinstance(op, ast.Is) and current is not comp_val:
                    return True, False
                elif isinstance(op, ast.IsNot) and not (current is not comp_val):
                    return True, False
                elif isinstance(op, ast.In) and current not in comp_val:
                    return True, False
                elif isinstance(op, ast.NotIn) and not (current not in comp_val):
                    return True, False
            except TypeError:
                return False, None
            current = comp_val
        return True, True
    return False, None


def _is_trivial_assertion(node: ast.Assert) -> bool:
    """Return True if an assert statement is a tautological triviality."""
    ok, val = _eval_const_expr(node.test)
    if ok:
        return bool(val) or val is False
    return False


def _count_effective_assertions(source: str) -> int:
    """Count effective, non-trivial assertions using AST analysis."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return len(ASSERT_PATTERN.findall(source))

    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            if not _is_trivial_assertion(node):
                count += 1
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr.startswith("assert"):
                if node.func.attr in ("assertTrue", "assertFalse"):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        continue
                elif node.func.attr == "assertEqual":
                    if (
                        len(node.args) >= 2
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[1], ast.Constant)
                        and node.args[0].value == node.args[1].value
                    ):
                        continue
                count += 1
    return count


def _has_trivial_assertion(source: str) -> bool:
    """Return True if the source contains any tautological/trivial assertion."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert) and _is_trivial_assertion(node):
            return True
    return False


def extract_comments_and_docstrings(source: str) -> List[str]:
    """Extract all comments and docstring literals from Python source code."""
    parts: List[str] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok_type, tok_string, _, _, _ in tokens:
            if tok_type == tokenize.COMMENT:
                parts.append(tok_string)
    except Exception:
        pass

    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node)
                if doc:
                    parts.append(doc)
    except Exception:
        pass

    return parts


def screen_mutation_content(source: str) -> List[str]:
    """Scan source code comments, docstrings, and literals for prompt injection markers."""
    comments_and_docstrings = extract_comments_and_docstrings(source)
    hits = set()
    for text in comments_and_docstrings:
        for marker in injection_marker_hits(text):
            hits.add(marker)
    for marker in injection_marker_hits(source):
        hits.add(marker)
    return sorted(hits)


class MutationDeltaExtractor:
    """Deterministic extractor producing ``MutationDelta`` tuples."""

    def __init__(self, policy: Optional[ArchitecturePolicy] = None) -> None:
        self.policy = policy or default_policy()

    @staticmethod
    def _safe_imports(source: str, module: str) -> set:
        """Extract imports, tolerating parse errors (an unparsable edit extracts nothing)."""
        try:
            return extract_imports(source, module)
        except SyntaxError:
            return set()

    @staticmethod
    def _count(pattern: re.Pattern, text: str) -> int:
        """Count regex matches in ``text``."""
        return len(pattern.findall(text))

    def _line_diff_counts(self, old: str, new: str) -> Tuple[int, int]:
        """Return (added, removed) line counts using a deterministic difflib comparison."""
        added = removed = 0
        for line in difflib.unified_diff(
            old.splitlines(), new.splitlines(), lineterm="", n=0
        ):
            if line.startswith("+++") or line.startswith("---"):
                continue
            if line.startswith("+"):
                added += 1
            elif line.startswith("-"):
                removed += 1
        return added, removed

    def _new_imports(self, old: str, new: str, module: str) -> Tuple[str, ...]:
        """Return the import targets introduced by this mutation, sorted."""
        before = self._safe_imports(old, module)
        after = self._safe_imports(new, module)
        return tuple(sorted(after - before))

    def _new_secrets(self, old: str, new: str) -> Tuple[str, ...]:
        """Return credential signals newly introduced by this mutation."""
        before = set(collect_secret_signals(old))
        return tuple(sig for sig in collect_secret_signals(new) if sig not in before)

    def _new_urls(self, old: str, new: str) -> Tuple[str, ...]:
        """Return egress endpoints newly introduced by this mutation."""
        before = set(collect_urls(old))
        return tuple(url for url in collect_urls(new) if url not in before)

    def extract(
        self,
        mutation: CodeMutation,
        provenance_node_id: str = "",
        previous_content: Optional[str] = None,
    ) -> MutationDelta:
        """Produce the normalised mutation delta for ``mutation``."""
        path = mutation.path.replace("\\", "/")
        old = previous_content if previous_content is not None else (mutation.old_content or "")
        new = mutation.new_content or ""
        if mutation.op == MutationOp.DELETE:
            old, new = (old or ""), ""

        module = module_name_from_path(path)
        added_lines, removed_lines = self._line_diff_counts(old, new)
        if path.endswith(".py"):
            removed_assertions = max(0, _count_effective_assertions(old) - _count_effective_assertions(new))
            if is_test_file(path, self.policy) and _has_trivial_assertion(new):
                removed_assertions = max(1, removed_assertions)
        else:
            removed_assertions = max(0, self._count(ASSERT_PATTERN, old) - self._count(ASSERT_PATTERN, new))
        added_skips = max(0, self._count(SKIP_PATTERN, new) - self._count(SKIP_PATTERN, old))

        patch_hash = hashlib.sha256(
            f"{path}\x00{mutation.op.value}\x00{old}\x00{new}".encode("utf-8")
        ).hexdigest()

        syntax_error = False
        if path.endswith(".py") and mutation.op != MutationOp.DELETE:
            try:
                ast.parse(new)
            except SyntaxError:
                syntax_error = True

        return MutationDelta(
            path=path,
            op=mutation.op,
            symbol=mutation.symbol,
            patch_hash=patch_hash,
            imports_added=self._new_imports(old, new, module),
            added_lines=added_lines,
            removed_lines=removed_lines,
            introduced_secrets=self._new_secrets(old, new),
            introduced_urls=self._new_urls(old, new),
            removed_assertions=removed_assertions,
            added_skips=added_skips,
            deletes_test_file=(mutation.op == MutationOp.DELETE and is_test_file(path, self.policy)),
            is_policy_file=is_policy_file(path, self.policy),
            is_test_file=is_test_file(path, self.policy),
            syntax_error=syntax_error,
            provenance_node_id=provenance_node_id,
            old_content=old,
            new_content=new,
        )


def is_weakening(delta: MutationDelta) -> bool:
    """Return True when a mutation weakens the test oracle (I2 signal)."""
    return bool(
        delta.removed_assertions > 0 or delta.added_skips > 0 or delta.deletes_test_file
    )
