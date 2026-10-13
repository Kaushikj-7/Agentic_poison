"""Mutation Delta extraction  Delta(edit): normalise a mutation into a typed tuple.

Turns a proposed ``CodeMutation`` into a deterministic ``MutationDelta`` describing exactly
what changes structurally: imports added, lines touched, credential material introduced,
egress endpoints added, and whether the test oracle is weakened. The agent's natural-language
rationale is never trusted; only the artefacts are inspected.
"""

import ast
import difflib
import hashlib
import re
from typing import Optional, Tuple

from agentpoi_sde.anchor.policy_registry import (
    collect_secret_signals,
    collect_urls,
    default_policy,
    is_policy_file,
    is_test_file,
)
from agentpoi_sde.anchor.symbol_index import extract_imports, module_name_from_path
from agentpoi_sde.domain import ArchitecturePolicy, CodeMutation, MutationDelta, MutationOp

ASSERT_PATTERN = re.compile(r"\bassert\b|\.assert(?:Equal|True|False|In|Is|Raises|AlmostEqual|Greater|Less)\b")
SKIP_PATTERN = re.compile(r"pytest\.skip|pytest\.mark\.skip|unittest\.skip|@skip|xfail|@unittest\.skip")


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
