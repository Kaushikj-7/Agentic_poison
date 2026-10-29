"""Empirical Stress Tests by Challenger M1-2.

Evaluates:
1. Complex Python agentic deserialization cases (torch.load, pickle.loads, yaml.unsafe_load, shelve.open).
2. Boundary conditions (empty files, non-UTF-8 corrupt encodings, 1MB truncation limit, binary with .php extension).
3. ScanPipeline integration with mixed Python/PHP snapshots and nested directories.
4. Strict Zero Host Execution Invariant under hostile payloads.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

from agentpoi_scan.fetch.safe_extract import extract_snapshot
from agentpoi_scan.pipeline import ScanPipeline
from agentpoi_scan.scan.base import ScanContext
from agentpoi_scan.scan.legacy_patterns import LegacyPatternScanner

# ==============================================================================
# 1. Complex Python Deserialization Detection Tests
# ==============================================================================


class TestComplexPythonDeserialization:
    """Stress tests Python deserialization detection across complex code structures."""

    def test_pickle_inside_functions_classes_and_lambdas(self, tmp_path: Path):
        code = """import pickle
import _pickle
from functools import wraps

class DataVault:
    def __init__(self, raw: bytes):
        self._raw = raw

    def unpack(self):
        # Pickle inside class method
        return pickle.loads(self._raw)

    @classmethod
    def from_disk(cls, path: str):
        with open(path, "rb") as f:
            return cls(pickle.load(f))

def deserialize_hook(data):
    try:
        return _pickle.loads(data)
    except Exception:
        return None

# Lambda with pickle
processor = lambda b: pickle.loads(b)
"""
        f = tmp_path / "complex_pickle.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="complex_pickle.py")

        deser = [x for x in findings if getattr(x, "rule_id", None) == "agentic.python.deserialization"]
        # Expected matches: pickle.loads in unpack(), pickle.load in from_disk(),
        # _pickle.loads in deserialize_hook(), and pickle.loads in lambda
        assert len(deser) == 4
        lines = {x.line_number for x in deser}
        assert 11 in lines  # pickle.loads(self._raw)
        assert 16 in lines  # pickle.load(f)
        assert 20 in lines  # _pickle.loads(data)
        assert 25 in lines  # lambda b: pickle.loads(b)

    def test_pickle_aliased_import_limitation(self, tmp_path: Path):
        """Documents the regex scanner limitation on aliased imports (e.g. import pickle as pkl)."""
        code = """import pickle as pkl
import _pickle as fast_pickle
data1 = pkl.loads(b"exploit")
data2 = fast_pickle.loads(b"exploit")
"""
        f = tmp_path / "aliased_pickle.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="aliased_pickle.py")
        # Pure regex scanner without AST dataflow does not track aliases like 'pkl' or 'fast_pickle'
        aliased_deser = [x for x in findings if getattr(x, "rule_id", None) == "agentic.python.deserialization"]
        # Confirmed empirical observation: regex scanner misses aliased imports
        assert len(aliased_deser) == 0

    def test_torch_load_variations(self, tmp_path: Path):
        """Tests single-line and multi-line torch.load calls with various arguments."""
        code = """import torch

# Vulnerable: default torch.load without weights_only (Line 4)
m1 = torch.load("model_checkpoint.pt")

# Vulnerable: explicit weights_only=False (Line 7)
m2 = torch.load("model.pt", weights_only=False)

# Safe: explicit weights_only=True (Line 10)
m3 = torch.load("model_safe.pt", weights_only=True)

# Safe: weights_only=True with other parameters (Line 13)
m4 = torch.load("safe.pt", map_location="cpu", weights_only=True)

# Multi-line vulnerable torch.load without weights_only (Line 16)
m5 = torch.load(
    "weights_untrusted.pt",
    map_location="cpu"
)

# Multi-line safe torch.load (Line 22)
m6 = torch.load(
    "weights_trusted.pt",
    weights_only=True
)
"""
        f = tmp_path / "torch_cases.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="torch_cases.py")

        torch_findings = [
            x
            for x in findings
            if getattr(x, "rule_id", None) == "agentic.python.deserialization"
            and ("torch" in x.title.lower() or "torch" in x.detail.lower())
        ]
        # m1 and m2 MUST be detected as vulnerable
        detected_lines = {x.line_number for x in torch_findings}
        assert 4 in detected_lines  # m1
        assert 7 in detected_lines  # m2
        assert 10 not in detected_lines  # m3 is safe
        assert 13 not in detected_lines  # m4 is safe
        # Empirical observation on multi-line calls:
        # Since line-by-line scanning is used, multi-line torch.load( without closing ')' on same line
        # does not match PY_TORCH_LOAD_RE (which requires both parens on the line)
        assert 16 not in detected_lines

    def test_yaml_load_and_unsafe_load_variations(self, tmp_path: Path):
        code = """import yaml

# High risk: unsafe_load
cfg1 = yaml.unsafe_load(raw_input)

# High risk: default or standard Loader
cfg2 = yaml.load(raw_input, Loader=yaml.Loader)
cfg3 = yaml.load(raw_input, Loader=yaml.CLoader)
cfg4 = yaml.load(raw_input)

# Safe: safe_load
cfg5 = yaml.safe_load(raw_input)

# Safe: Loader=yaml.SafeLoader
cfg6 = yaml.load(raw_input, Loader=yaml.SafeLoader)
cfg7 = yaml.load(raw_input, Loader=yaml.CSafeLoader)
"""
        f = tmp_path / "yaml_cases.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="yaml_cases.py")

        yaml_findings = [
            x
            for x in findings
            if x.rule_id == "agentic.python.deserialization"
            and "yaml" in x.detail.lower()
        ]
        detected_lines = {x.line_number for x in yaml_findings}
        assert 4 in detected_lines  # unsafe_load
        assert 7 in detected_lines  # Loader=yaml.Loader
        assert 8 in detected_lines  # Loader=yaml.CLoader
        assert 9 in detected_lines  # yaml.load without Loader
        assert 12 not in detected_lines  # safe_load
        assert 15 not in detected_lines  # SafeLoader
        assert 16 not in detected_lines  # CSafeLoader

    def test_shelve_open_inside_contexts_and_functions(self, tmp_path: Path):
        code = """import shelve

def get_cache():
    return shelve.open("app_cache.db")

class PersistentSession:
    def open(self):
        with shelve.open("sessions.db", flag="r") as db:
            return db.get("user")
"""
        f = tmp_path / "shelve_cases.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="shelve_cases.py")

        shelve_findings = [
            x
            for x in findings
            if x.rule_id == "agentic.python.deserialization"
            and "shelve" in x.detail.lower()
        ]
        assert len(shelve_findings) >= 2
        lines = {x.line_number for x in shelve_findings}
        assert 4 in lines
        assert 8 in lines

    def test_multi_deserialization_patterns_in_single_file(self, tmp_path: Path):
        """A single file containing pickle, torch, yaml, and shelve on separate lines."""
        code = """import pickle
import torch
import yaml
import shelve

d1 = pickle.loads(b"exploit")
m1 = torch.load("checkpoint.pt")
c1 = yaml.unsafe_load("user: admin")
s1 = shelve.open("cache.db")
"""
        f = tmp_path / "all_in_one_deser.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="all_in_one_deser.py")

        deser = [x for x in findings if getattr(x, "rule_id", None) == "agentic.python.deserialization"]
        assert len(deser) == 4
        lines = {x.line_number for x in deser}
        assert lines == {6, 7, 8, 9}


# ==============================================================================
# 2. Boundary Condition Tests
# ==============================================================================


class TestBoundaryConditions:
    """Tests edge cases: empty files, binary headers, large files, corrupt encodings."""

    def test_empty_python_and_php_files(self, tmp_path: Path):
        empty_py = tmp_path / "empty.py"
        empty_php = tmp_path / "empty.php"
        empty_py.write_bytes(b"")
        empty_php.write_bytes(b"")

        scanner = LegacyPatternScanner()
        findings_py = scanner.scan_file(empty_py, rel_path="empty.py")
        findings_php = scanner.scan_file(empty_php, rel_path="empty.php")

        assert findings_py == []
        assert findings_php == []

        # Directory scan over empty files
        findings_dir = scanner.scan_directory(tmp_path)
        assert findings_dir == []

    def test_corrupted_non_utf8_encoding_resilience(self, tmp_path: Path):
        """Ensures non-UTF-8 bytes do not crash the scanner and decode safely."""
        corrupt_bytes = (
            b"# Header with non-utf8 \xff\xfe\x00\x80\xa5 bytes\n"
            b"import pickle\n"
            b"data = pickle.loads(b'valid_payload_after_corrupt_header')\n"
        )
        f_py = tmp_path / "corrupt.py"
        f_py.write_bytes(corrupt_bytes)

        scanner = LegacyPatternScanner()
        # scan_file uses errors='replace'
        findings = scanner.scan_file(f_py, rel_path="corrupt.py")
        assert len(findings) >= 1
        assert findings[0].rule_id == "agentic.python.deserialization"
        assert findings[0].line_number == 3

    def test_binary_file_with_php_extension(self, tmp_path: Path):
        """ELF binary or arbitrary byte stream with .php extension must not crash scanner."""
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200 + b"<?php exec($_GET['x']); ?>"
        bin_php = tmp_path / "binary_disguised.php"
        bin_php.write_bytes(elf_header)

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(bin_php, rel_path="binary_disguised.php")
        # Should gracefully scan the text snippet without crashing
        assert isinstance(findings, list)
        assert any(f.rule_id == "legacy.php.command_injection" for f in findings)

    def test_large_file_truncation_safety_limit(self, tmp_path: Path):
        """Files > 1MB are safely truncated to 1MB without memory exhaustion or crash."""
        # Create a >1.3MB file with a payload near the front and one past the 1MB mark
        padding_600kb = "# " + ("A" * 78 + "\n") * 8000  # ~640KB
        early_payload = "import pickle\ndata = pickle.loads(b'early')\n"
        padding_800kb = "# " + ("B" * 78 + "\n") * 10000  # ~800KB
        late_payload = "data2 = pickle.loads(b'late')\n"

        content = padding_600kb + early_payload + padding_800kb + late_payload
        assert len(content) > 1_300_000

        f = tmp_path / "huge_file.py"
        f.write_text(content, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="huge_file.py")

        # The early payload (< 1MB) MUST be found
        assert any(
            getattr(f, "rule_id", None) == "agentic.python.deserialization" and "early" in f.snippet
            for f in findings
        )
        # The late payload (> 1MB) is safely excluded due to the 1MB truncation limit
        assert not any("late" in f.snippet for f in findings)

    def test_nested_directories_and_hidden_filtering(self, tmp_path: Path):
        """Recursively scans deep directories, properly ignoring .git or hidden subfolders."""
        nested_dir = tmp_path / "level1" / "level2" / "level3"
        nested_dir.mkdir(parents=True)
        (nested_dir / "app.py").write_text("import shelve\nshelve.open('cache')", encoding="utf-8")

        hidden_dir = tmp_path / ".git" / "hooks"
        hidden_dir.mkdir(parents=True)
        (hidden_dir / "hook.py").write_text("import pickle\npickle.loads(b'hook')", encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_directory(tmp_path)

        assert any(f.file_path == "level1/level2/level3/app.py" for f in findings)
        assert not any(".git" in f.file_path for f in findings)


# ==============================================================================
# 3. ScanPipeline Integration Tests
# ==============================================================================


class TestScanPipelineIntegration:
    """Tests ScanPipeline end-to-end integration with LegacyPatternScanner."""

    def test_pipeline_scans_mixed_repository(self, tmp_path: Path):
        snap_dir = tmp_path / "snapshot"
        snap_dir.mkdir()

        # Mixed codebase
        (snap_dir / "service.py").write_text(
            "import yaml\ncfg = yaml.unsafe_load(data)\n", encoding="utf-8"
        )
        (snap_dir / "query.php").write_text(
            "<?php mysqli_query($conn, 'SELECT * FROM x WHERE id=' . $_GET['id']); ?>",
            encoding="utf-8",
        )
        (snap_dir / "safe.py").write_text(
            "import json\nd = json.loads('{}')\n", encoding="utf-8"
        )

        manifest_mock = type(
            "ManifestMock",
            (),
            {
                "files": ["service.py", "query.php", "safe.py"],
                "binary_candidates": [],
            },
        )()

        pipeline = ScanPipeline(
            store_path=tmp_path / "store.sqlite3",
            config={"router": {"escalate_min_severity": "critical"}},
        )

        findings = pipeline.run_scanners(
            snapshot_dir=snap_dir,
            repo="org/mixed-repo",
            commit_sha="a" * 40,
            manifest=manifest_mock,
        )

        assert len(findings) >= 2
        scanners_involved = {f.scanner for f in findings}
        assert "legacy_patterns" in scanners_involved

        # Extract rule IDs from legacy_patterns findings or evidence
        legacy_rules = set()
        for f in findings:
            if getattr(f, "rule_id", None):
                legacy_rules.add(f.rule_id)
            for ev in f.evidence:
                if isinstance(ev, dict) and "rule_id" in ev:
                    legacy_rules.add(ev["rule_id"])

        assert "agentic.python.deserialization" in legacy_rules
        assert "legacy.php.sqli" in legacy_rules

    def test_pipeline_scan_context_corrupted_file_handling(self, tmp_path: Path):
        """Verifies that non-UTF8 files in ScanContext are safely skipped without pipeline failure."""
        snap_dir = tmp_path / "snapshot"
        snap_dir.mkdir()

        corrupt_file = snap_dir / "corrupt.py"
        corrupt_file.write_bytes(b"\x80\xff\xfe\xaa\xbb\xcc")

        context = ScanContext(
            snapshot_dir=snap_dir,
            repo="org/repo",
            commit_sha="b" * 40,
            file_index=["corrupt.py"],
            binary_candidates=[],
        )

        scanner = LegacyPatternScanner()
        result = scanner.run(context)
        # Context.read_text returns None for non-UTF8 -> scanner skips without error
        assert result.scanner == "legacy_patterns"
        assert result.findings == []

    def test_end_to_end_tarball_extraction_and_pipeline_scan(self, tmp_path: Path):
        """End-to-end test: safe extraction of mixed tarball followed by ScanPipeline execution."""
        # Create tarball in memory
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            # 1. Nested Python file with deserialization
            f1_bytes = b"import pickle\nd = pickle.loads(b'payload')\n"
            t1 = tarfile.TarInfo(name="repo/deep/nested/worker.py")
            t1.size = len(f1_bytes)
            tf.addfile(t1, io.BytesIO(f1_bytes))

            # 2. Nested PHP file with SQLi
            f2_bytes = b"<?php mysqli_query($db, 'SELECT * FROM u WHERE id=' . $_GET['id']); ?>"
            t2 = tarfile.TarInfo(name="repo/deep/nested/query.php")
            t2.size = len(f2_bytes)
            tf.addfile(t2, io.BytesIO(f2_bytes))

            # 3. Empty Python file
            t3 = tarfile.TarInfo(name="repo/empty.py")
            t3.size = 0
            tf.addfile(t3, io.BytesIO(b""))

            # 4. Safe Python file
            f4_bytes = b"import json\nd = json.loads('{}')\n"
            t4 = tarfile.TarInfo(name="repo/safe.py")
            t4.size = len(f4_bytes)
            tf.addfile(t4, io.BytesIO(f4_bytes))

        tar_bytes = buf.getvalue()
        extract_dir = tmp_path / "extracted_snap"
        extract_dir.mkdir()

        # Step 1: Safe extract
        manifest = extract_snapshot(tar_bytes, extract_dir)
        assert len(manifest.files) == 4

        # Step 2: Pipeline execution
        pipeline = ScanPipeline(
            store_path=tmp_path / "store_e2e.sqlite3",
            config={"router": {"escalate_min_severity": "critical"}},
        )
        findings = pipeline.run_scanners(
            snapshot_dir=extract_dir,
            repo="org/tarball-repo",
            commit_sha="f" * 40,
            manifest=manifest,
        )

        assert len(findings) >= 2
        legacy_rules = set()
        for f in findings:
            if getattr(f, "rule_id", None):
                legacy_rules.add(f.rule_id)
            for ev in f.evidence:
                if isinstance(ev, dict) and "rule_id" in ev:
                    legacy_rules.add(ev["rule_id"])

        assert "agentic.python.deserialization" in legacy_rules
        assert "legacy.php.sqli" in legacy_rules


# ==============================================================================
# 4. Zero Host Execution Invariant Tests
# ==============================================================================


class TestZeroHostExecutionStrictEnforcement:
    """Verifies that hostile payloads never execute, import, or alter the host."""

    def test_malicious_host_execution_payloads_never_execute(self, tmp_path: Path):
        canary_file = tmp_path / "HOST_EXECUTED.txt"

        hostile_py = f"""
import os
import sys

# Attempted host side-effects
with open(r'{canary_file.as_posix()}', 'w') as f:
    f.write('HOST_EXPLOITED')

os.system('echo "HOST_EXPLOITED" > exploit.txt')

import pickle
data = pickle.loads(b'payload')
"""
        hostile_php = f"""<?php
file_put_contents('{canary_file.as_posix()}', 'HOST_EXPLOITED_PHP');
exec('echo pwned');
?>"""

        f_py = tmp_path / "hostile.py"
        f_php = tmp_path / "hostile.php"
        f_py.write_text(hostile_py, encoding="utf-8")
        f_php.write_text(hostile_php, encoding="utf-8")

        initial_modules = set(sys.modules.keys())

        scanner = LegacyPatternScanner()

        with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
            findings = scanner.scan_directory(tmp_path)

            # Invariant 1: No subshell or process spawned
            assert not mock_popen.called, "Subprocess was spawned during scan!"
            assert not mock_run.called, "Subprocess.run was called during scan!"

        # Invariant 2: No file write canary executed
        assert not canary_file.exists(), "Canary file was created! Host execution occurred!"

        # Invariant 3: No new modules loaded from target files
        new_modules = set(sys.modules.keys()) - initial_modules
        for mod in new_modules:
            assert "hostile" not in mod, f"Module {mod} was imported into sys.modules!"

        # Invariant 4: Scanner correctly identified the dangerous patterns without running them
        rule_ids = {f.rule_id for f in findings}
        assert "agentic.python.deserialization" in rule_ids
        assert "legacy.php.command_injection" in rule_ids
