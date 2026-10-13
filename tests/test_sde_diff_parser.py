"""Unit tests for unified diff parsing and git mutation extraction."""

import subprocess

import pytest

from agentpoi_sde.delta.diff_parser import extract_git_mutations, parse_unified_diff
from agentpoi_sde.domain import MutationOp


def test_parse_unified_diff_create_file():
    """Verify parsing a diff that creates a new file."""
    diff = """--- /dev/null
+++ b/src/hello.py
@@ -0,0 +1,3 @@
+def hello():
+    return "world"
+
"""
    mutations = parse_unified_diff(diff)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.path == "src/hello.py"
    assert m.op == MutationOp.CREATE
    assert "def hello():" in m.new_content
    assert 'return "world"' in m.new_content
    assert m.old_content == ""


def test_parse_unified_diff_modify_file():
    """Verify parsing a diff that modifies an existing file with base content."""
    base_files = {
        "src/calc.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"
    }
    diff = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -1,4 +1,5 @@\n"
        " def add(a, b):\n"
        "+    # added comment\n"
        "     return a + b\n"
        " \n"
        " def sub(a, b):\n"
    )
    mutations = parse_unified_diff(diff, base_files=base_files)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.path == "src/calc.py"
    assert m.op == MutationOp.MODIFY
    assert "# added comment" in m.new_content
    assert m.old_content == base_files["src/calc.py"]


def test_parse_unified_diff_delete_file():
    """Verify parsing a diff that deletes a file."""
    base_files = {
        "src/obsolete.py": "def deprecated():\n    pass\n"
    }
    diff = """--- a/src/obsolete.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def deprecated():
-    pass
"""
    mutations = parse_unified_diff(diff, base_files=base_files)
    assert len(mutations) == 1
    m = mutations[0]
    assert m.path == "src/obsolete.py"
    assert m.op == MutationOp.DELETE
    assert m.new_content == ""
    assert m.old_content == base_files["src/obsolete.py"]


def test_parse_unified_diff_multi_file():
    """Verify parsing a single patch containing changes to multiple files."""
    diff = """--- /dev/null
+++ b/file1.py
@@ -0,0 +1 @@
+x = 1
--- a/file2.py
+++ b/file2.py
@@ -1 +1 @@
-old = 1
+new = 2
"""
    base_files = {"file2.py": "old = 1\n"}
    mutations = parse_unified_diff(diff, base_files=base_files)
    assert len(mutations) == 2
    assert mutations[0].path == "file1.py"
    assert mutations[0].op == MutationOp.CREATE
    assert mutations[1].path == "file2.py"
    assert mutations[1].op == MutationOp.MODIFY
    assert "new = 2" in mutations[1].new_content


def test_parse_unified_diff_fail_closed_on_corrupt():
    """Verify that corrupt or malformed diffs fail closed by raising ValueError."""
    bad_diff = """--- a/broken.py
+++ b/broken.py
@@ invalid hunk header @@
corrupted data
"""
    with pytest.raises(ValueError):
        parse_unified_diff(bad_diff)


def test_parse_unified_diff_empty():
    """Verify that empty diff text returns an empty mutation list."""
    assert parse_unified_diff("") == []
    assert parse_unified_diff("   \n\n  ") == []


def test_extract_git_mutations_temporary_repo(tmp_path):
    """Verify extract_git_mutations from a real local git repository."""
    repo = tmp_path / "repo"
    repo.mkdir()

    # Initialize a git repo
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)

    # Initial file
    base_file = repo / "main.py"
    base_file.write_text("def run():\n    return 42\n", encoding="utf-8")
    subprocess.run(["git", "add", "main.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True)

    # Unstaged modification
    base_file.write_text("def run():\n    return 100\n", encoding="utf-8")
    unstaged_muts = extract_git_mutations(repo_path=str(repo), staged=False)
    assert len(unstaged_muts) == 1
    assert unstaged_muts[0].path == "main.py"
    assert unstaged_muts[0].op == MutationOp.MODIFY
    assert "return 100" in unstaged_muts[0].new_content

    # Stage the change
    subprocess.run(["git", "add", "main.py"], cwd=repo, check=True)
    staged_muts = extract_git_mutations(repo_path=str(repo), staged=True)
    assert len(staged_muts) == 1
    assert staged_muts[0].path == "main.py"
    assert "return 100" in staged_muts[0].new_content
