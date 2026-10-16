"""Unified diff parser and git mutation extractor for AgentPOI-SDE.

Parses standard unified diffs into typed CodeMutation instances fail-closed.
Extracts working tree and staged mutations from local git repositories.
"""

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from agentpoi_sde.domain import CodeMutation, MutationOp


class MalformedDiffError(ValueError, SyntaxError):
    """Raised fail-closed when a diff is corrupted or unparsable."""


HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
)


@dataclass
class DiffHunk:
    """Represents a single unified diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: List[Tuple[str, str]]


@dataclass
class RawFileDiff:
    """Raw parsed diff for a single file before mutation synthesis."""

    old_path: Optional[str]
    new_path: Optional[str]
    hunks: List[DiffHunk]


def _clean_diff_path(raw_path: str) -> str:
    """Normalize path from diff header line."""
    clean = raw_path.strip().strip('"').strip("'")
    if clean == "/dev/null":
        return "/dev/null"
    clean = clean.split("\t")[0].strip().replace("\\", "/")
    if clean.startswith("a/") or clean.startswith("b/"):
        clean = clean[2:]
    return clean.strip()


def _parse_hunk_header(line: str) -> Tuple[int, int, int, int]:
    """Parse @@ -x,y +z,w @@ header fail-closed."""
    m = HUNK_HEADER_RE.match(line)
    if not m:
        raise MalformedDiffError(f"Invalid hunk header: {line}")
    old_start = int(m.group(1))
    old_count = int(m.group(2)) if m.group(2) is not None else 1
    new_start = int(m.group(3))
    new_count = int(m.group(4)) if m.group(4) is not None else 1
    return old_start, old_count, new_start, new_count


def _apply_hunks_to_content(base_content: str, hunks: List[DiffHunk]) -> str:
    """Apply unified diff hunks sequentially to base file content."""
    base_lines = base_content.splitlines()
    result_lines: List[str] = []
    current_idx = 0

    for hunk in hunks:
        target_start = max(0, hunk.old_start - 1) if hunk.old_start > 0 else 0
        while current_idx < target_start and current_idx < len(base_lines):
            result_lines.append(base_lines[current_idx])
            current_idx += 1

        for marker, text in hunk.lines:
            if marker == " ":
                if current_idx < len(base_lines):
                    result_lines.append(base_lines[current_idx])
                    current_idx += 1
                else:
                    result_lines.append(text)
            elif marker == "-":
                if current_idx < len(base_lines):
                    current_idx += 1
            elif marker == "+":
                result_lines.append(text)

    while current_idx < len(base_lines):
        result_lines.append(base_lines[current_idx])
        current_idx += 1

    res = "\n".join(result_lines)
    if base_content.endswith("\n") or not base_content:
        res += "\n"
    return res


def _reconstruct_from_hunks(hunks: List[DiffHunk], take_new: bool) -> str:
    """Reconstruct file content from hunks alone when base content is absent."""
    lines: List[str] = []
    target_marker = "+" if take_new else "-"
    for hunk in hunks:
        for marker, text in hunk.lines:
            if marker == " " or marker == target_marker:
                lines.append(text)
    res = "\n".join(lines)
    if res and not res.endswith("\n"):
        res += "\n"
    return res


def _parse_raw_diff_blocks(diff_text: str) -> List[RawFileDiff]:
    """Parse diff text into list of RawFileDiff blocks."""
    lines = diff_text.splitlines()
    blocks: List[RawFileDiff] = []
    i = 0
    total = len(lines)

    while i < total:
        line = lines[i]
        if line.startswith("--- "):
            old_path = _clean_diff_path(line[4:])
            i += 1
            if i >= total or not lines[i].startswith("+++ "):
                raise MalformedDiffError(f"Expected +++ after --- at line {i}")
            new_path = _clean_diff_path(lines[i][4:])
            i += 1

            hunks: List[DiffHunk] = []
            while i < total:
                curr = lines[i]
                if curr.startswith("--- ") or curr.startswith("diff --git "):
                    break
                if curr.startswith("@@"):
                    old_s, old_c, new_s, new_c = _parse_hunk_header(curr)
                    i += 1
                    hunk_lines: List[Tuple[str, str]] = []
                    while i < total:
                        hline = lines[i]
                        if hline.startswith("@@") or hline.startswith("--- ") or hline.startswith("diff --git "):
                            break
                        if hline.startswith(("\\", "index ", "new file", "deleted file")):
                            i += 1
                            continue
                        if not hline:
                            hunk_lines.append((" ", ""))
                        elif hline[0] in (" ", "+", "-"):
                            hunk_lines.append((hline[0], hline[1:]))
                        else:
                            raise MalformedDiffError(f"Corrupt line in diff hunk: {hline}")
                        i += 1
                    hunks.append(DiffHunk(old_s, old_c, new_s, new_c, hunk_lines))
                else:
                    i += 1
            blocks.append(RawFileDiff(old_path, new_path, hunks))
        else:
            if line.startswith("diff --git ") or line.startswith("index ") or not line.strip():
                i += 1
            else:
                if "@@" in line:
                    raise MalformedDiffError(f"Corrupt header outside block: {line}")
                i += 1
    return blocks


def parse_unified_diff(
    diff_text: str, base_files: Optional[Dict[str, str]] = None
) -> List[CodeMutation]:
    """Parse unified diff text into typed CodeMutation instances fail-closed."""
    if not diff_text or not diff_text.strip():
        return []

    blocks = _parse_raw_diff_blocks(diff_text)
    mutations: List[CodeMutation] = []
    bases = base_files or {}

    for block in blocks:
        old_p, new_p = block.old_path, block.new_path
        if not block.hunks:
            continue
        if old_p == "/dev/null" and new_p:
            new_c = _reconstruct_from_hunks(block.hunks, take_new=True)
            mutations.append(
                CodeMutation(
                    path=new_p,
                    op=MutationOp.CREATE,
                    new_content=new_c,
                    old_content="",
                )
            )
        elif new_p == "/dev/null" and old_p:
            old_c = bases.get(old_p) or _reconstruct_from_hunks(block.hunks, take_new=False)
            mutations.append(
                CodeMutation(
                    path=old_p,
                    op=MutationOp.DELETE,
                    new_content="",
                    old_content=old_c,
                )
            )
        elif new_p:
            target_path = new_p
            old_c = bases.get(target_path)
            if old_c is not None:
                new_c = _apply_hunks_to_content(old_c, block.hunks)
            else:
                old_c = _reconstruct_from_hunks(block.hunks, take_new=False)
                new_c = _reconstruct_from_hunks(block.hunks, take_new=True)
            mutations.append(
                CodeMutation(
                    path=target_path,
                    op=MutationOp.MODIFY,
                    new_content=new_c,
                    old_content=old_c,
                )
            )

    return mutations


def extract_git_mutations(
    repo_path: str = ".", staged: bool = False
) -> List[CodeMutation]:
    """Extract code mutations from local git working tree."""
    cmd = ["git", "diff", "--staged"] if staged else ["git", "diff"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        diff_text = proc.stdout
    except Exception as exc:
        raise ValueError(f"Failed to run git diff in {repo_path}: {exc}") from exc

    untracked_mutations: List[CodeMutation] = []
    if not staged:
        status_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        for line in status_proc.stdout.splitlines():
            if line.startswith("?? "):
                rel_p = line[3:].strip().strip('"')
                full_p = os.path.join(repo_path, rel_p)
                if os.path.isfile(full_p):
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        untracked_mutations.append(
                            CodeMutation(
                                path=rel_p.replace("\\", "/"),
                                op=MutationOp.CREATE,
                                new_content=content,
                                old_content="",
                            )
                        )
                    except Exception:
                        pass

    base_files: Dict[str, str] = {}
    muts = parse_unified_diff(diff_text, base_files=None) if diff_text.strip() else []
    for m in muts:
        show_ref = f"HEAD:{m.path}" if staged else f":{m.path}"
        try:
            res = subprocess.run(
                ["git", "show", show_ref],
                cwd=repo_path,
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                base_files[m.path] = res.stdout
        except Exception:
            pass

    if base_files and diff_text.strip():
        muts = parse_unified_diff(diff_text, base_files=base_files)

    return muts + untracked_mutations
