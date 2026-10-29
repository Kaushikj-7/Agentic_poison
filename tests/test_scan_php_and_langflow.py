"""End-to-end multi-tier test suite for AgentPOI-Scan static verification.

Validates zero-execution static analysis against:
1. Legacy PHP repositories (SQLi, command injection, deserialization, webshell backdoors, benign baseline)
2. Langflow agentic repositories (hidden autorun surfaces, deserialization risks, prompt injection, benign components)
3. Pipeline risk scorecards, persistence, and DEC-105 authoritative findings invariants.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch

import pytest

from agentpoi_scan.findings.model import (
    CRITICAL,
    HIGH,
    dedupe,
    is_authoritative,
)
from agentpoi_scan.findings.risk_score import repo_risk_score
from agentpoi_scan.pipeline import ScanPipeline
from agentpoi_scan.report.sarif import write_sarif
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.scan.autorun_surface import AutorunSurfaceScanner
from agentpoi_scan.scan.base import ScanContext, ScanResult
from agentpoi_scan.scan.legacy_patterns import LegacyPatternScanner
from agentpoi_scan.scan.prompt_injection import PromptInjectionScanner
from agentpoi_scan.scan.python_sast import PythonSastScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LEGACY_PHP_DIR = FIXTURES_DIR / "legacy_php_repo"
LANGFLOW_DIR = FIXTURES_DIR / "langflow_snapshot"


# ------------------------------------------------------------------------------
# Test Context Helpers
# ------------------------------------------------------------------------------

def _build_context(root_dir: Path, repo_name: str, commit_sha: str = "feedface1234567890abcdef") -> ScanContext:
    """Builds a deterministic ScanContext for a fixture directory."""
    file_index: List[str] = []
    for p in sorted(root_dir.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root_dir)).replace("\\", "/")
            file_index.append(rel)
    return ScanContext(
        snapshot_dir=root_dir,
        repo=repo_name,
        commit_sha=commit_sha,
        file_index=file_index,
        binary_candidates=[],
    )


class DummyManifest:
    """Minimal manifest object matching SafeTarballExtractor output."""

    def __init__(self, root_dir: Path) -> None:
        self.files: Dict[str, int] = {}
        self.binary_candidates: List[str] = []
        for p in sorted(root_dir.rglob("*")):
            if p.is_file():
                rel = str(p.relative_to(root_dir)).replace("\\", "/")
                self.files[rel] = p.stat().st_size


# ==============================================================================
# Tier 1: Sanity & Zero-Host-Execution Verification
# ==============================================================================

class TestTier1ZeroExecutionSanity:
    """Tier 1: Verifies zero execution, no process spawning, no module imports, and state immutability."""

    def test_fixtures_directories_exist_and_non_empty(self) -> None:
        """Confirm both fixture directory trees exist and contain files."""
        assert LEGACY_PHP_DIR.is_dir(), f"Missing fixture directory: {LEGACY_PHP_DIR}"
        assert LANGFLOW_DIR.is_dir(), f"Missing fixture directory: {LANGFLOW_DIR}"

        php_files = list(LEGACY_PHP_DIR.rglob("*"))
        langflow_files = list(LANGFLOW_DIR.rglob("*"))
        assert len(php_files) >= 5, "Legacy PHP fixture should have at least 5 files"
        assert len(langflow_files) >= 8, "Langflow snapshot fixture should have at least 8 files"

    def test_zero_execution_php_repo_never_spawns_subprocesses(self) -> None:
        """Verify scanning PHP fixtures executes 0 subprocesses and 0 shell commands."""
        context = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        scanner = LegacyPatternScanner()

        with patch("subprocess.Popen") as mock_popen, \
             patch("subprocess.run") as mock_run, \
             patch("os.system") as mock_system:
            result = scanner.run(context)
            assert isinstance(result, ScanResult)
            assert len(result.findings) > 0, "Should detect findings in vulnerable PHP fixtures"

            mock_popen.assert_not_called()
            mock_run.assert_not_called()
            mock_system.assert_not_called()

    def test_zero_execution_langflow_repo_never_imported(self) -> None:
        """Verify scanning Python/Langflow fixtures never imports target modules into sys.modules."""
        sys_modules_before = set(sys.modules.keys())
        context = _build_context(LANGFLOW_DIR, "test/langflow-snapshot")

        scanner = LegacyPatternScanner()
        sast_scanner = PythonSastScanner()
        autorun_scanner = AutorunSurfaceScanner()
        prompt_scanner = PromptInjectionScanner()

        scanner.run(context)
        sast_scanner.run(context)
        autorun_scanner.run(context)
        prompt_scanner.run(context)

        sys_modules_after = set(sys.modules.keys())
        newly_imported = sys_modules_after - sys_modules_before

        for mod in newly_imported:
            assert "langflow_snapshot" not in mod, f"Target repo code was imported into runtime: {mod}"

    def test_fixture_file_immutability_during_scan(self) -> None:
        """Verify that scanning is strictly read-only and leaves fixture hashes unaltered."""
        def hash_dir(d: Path) -> Dict[str, str]:
            hashes = {}
            for p in d.rglob("*"):
                if p.is_file():
                    hashes[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
            return hashes

        php_before = hash_dir(LEGACY_PHP_DIR)
        langflow_before = hash_dir(LANGFLOW_DIR)

        # Execute multiple scanner passes
        ctx_php = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        ctx_langflow = _build_context(LANGFLOW_DIR, "test/langflow-snapshot")
        LegacyPatternScanner().run(ctx_php)
        LegacyPatternScanner().run(ctx_langflow)
        AutorunSurfaceScanner().run(ctx_langflow)
        PromptInjectionScanner().run(ctx_langflow)

        php_after = hash_dir(LEGACY_PHP_DIR)
        langflow_after = hash_dir(LANGFLOW_DIR)

        assert php_before == php_after, "Legacy PHP fixture files were modified during scan"
        assert langflow_before == langflow_after, "Langflow snapshot fixture files were modified during scan"

    def test_scan_context_read_text_bounded_and_safe(self) -> None:
        """Verify ScanContext safely reads text with bounded buffer and zero execution."""
        context = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        for rel in context.file_index:
            text = context.read_text(rel)
            assert text is not None, f"Failed to read file in context: {rel}"
            assert len(text) > 0


# ==============================================================================
# Tier 2: Legacy PHP Vulnerability Detection
# ==============================================================================

class TestTier2LegacyPhpVulnerabilities:
    """Tier 2: Validates detection of SQLi, command injection, deserialization, and webshells in PHP."""

    @pytest.fixture(autouse=True)
    def setup_scanner(self) -> None:
        self.scanner = LegacyPatternScanner()
        self.context = _build_context(LEGACY_PHP_DIR, "test/legacy-php")

    def test_php_sqli_detection_in_vulnerable_file(self) -> None:
        """Verify detection of SQL injection patterns in sqli_vulnerable.php."""
        target_file = LEGACY_PHP_DIR / "sqli_vulnerable.php"
        findings = self.scanner.scan_file(target_file, "sqli_vulnerable.php")

        assert len(findings) >= 3, f"Expected at least 3 SQLi findings, got {len(findings)}"
        sqli_findings = [f for f in findings if f.rule_id == "legacy.php.sqli"]
        assert len(sqli_findings) >= 3

        for f in sqli_findings:
            assert f.category == "sast"
            assert f.severity in (CRITICAL, HIGH)
            assert f.confidence >= 0.90
            assert f.vulnerability >= 0.90
            assert any(kw in f.snippet for kw in ("mysqli_query", "query", "SELECT"))

    def test_php_command_injection_detection_in_vulnerable_file(self) -> None:
        """Verify detection of command execution and backticks in command_exec_vulnerable.php."""
        target_file = LEGACY_PHP_DIR / "command_exec_vulnerable.php"
        findings = self.scanner.scan_file(target_file, "command_exec_vulnerable.php")

        assert len(findings) >= 4, f"Expected at least 4 command injection findings, got {len(findings)}"
        cmd_findings = [f for f in findings if f.rule_id == "legacy.php.command_injection"]
        assert len(cmd_findings) >= 4

        snippets = " ".join(f.snippet for f in cmd_findings)
        assert "system(" in snippets
        assert "shell_exec(" in snippets
        assert "exec(" in snippets
        assert "`" in snippets or "tar" in snippets

        for f in cmd_findings:
            assert f.category == "sast"
            assert f.severity in (CRITICAL, HIGH)
            assert f.vulnerability >= 0.90

    def test_php_unsafe_deserialization_detection(self) -> None:
        """Verify detection of unserialize without allowed_classes => false."""
        target_file = LEGACY_PHP_DIR / "deserialization_vulnerable.php"
        findings = self.scanner.scan_file(target_file, "deserialization_vulnerable.php")

        assert len(findings) >= 3, f"Expected at least 3 deserialization findings, got {len(findings)}"
        deser_findings = [f for f in findings if f.rule_id == "legacy.php.deserialization"]
        assert len(deser_findings) >= 3

        # Verify that safeLoadProfile with allowed_classes => false is NOT flagged
        safe_snippets = [f.snippet for f in deser_findings if "safeLoadProfile" in f.snippet or "allowed_classes" in f.snippet]
        assert len(safe_snippets) == 0, "Safe unserialize with allowed_classes=>false was incorrectly flagged"

    def test_php_webshell_backdoor_detection(self) -> None:
        """Verify detection of dynamic function dispatch, eval, and create_function."""
        target_file = LEGACY_PHP_DIR / "webshell_backdoor.php"
        findings = self.scanner.scan_file(target_file, "webshell_backdoor.php")

        assert len(findings) >= 4, f"Expected at least 4 webshell backdoor findings, got {len(findings)}"
        eval_findings = [f for f in findings if f.rule_id == "legacy.php.obfuscated_eval"]
        assert len(eval_findings) >= 4

        for f in eval_findings:
            assert f.category == "malware"
            assert f.severity == CRITICAL
            assert f.maliciousness >= 0.85
            assert f.confidence >= 0.90

    def test_php_benign_baseline_zero_false_positives(self) -> None:
        """Verify that benign, parameterized, clean PHP service yields exactly 0 findings."""
        target_file = LEGACY_PHP_DIR / "benign_baseline.php"
        findings = self.scanner.scan_file(target_file, "benign_baseline.php")

        assert len(findings) == 0, f"False positives on benign PHP baseline: {[f.title for f in findings]}"

    def test_php_directory_scan_aggregates_all_rules(self) -> None:
        """Verify scanning entire legacy PHP repository finds all vulnerability categories."""
        findings = self.scanner.scan_directory(LEGACY_PHP_DIR)
        rule_ids = {f.rule_id for f in findings}

        assert "legacy.php.sqli" in rule_ids
        assert "legacy.php.command_injection" in rule_ids
        assert "legacy.php.deserialization" in rule_ids
        assert "legacy.php.obfuscated_eval" in rule_ids
        assert len(findings) >= 14, f"Total PHP findings should be >= 14, got {len(findings)}"


# ==============================================================================
# Tier 3: Complex Multi-Component Agentic (Langflow) Detection
# ==============================================================================

class TestTier3LangflowAgenticRepository:
    """Tier 3: Validates detection of autorun surface, Python deserialization, prompt injection in Langflow."""

    @pytest.fixture(autouse=True)
    def setup_context(self) -> None:
        self.context = _build_context(LANGFLOW_DIR, "test/langflow-snapshot")

    def test_langflow_autorun_surface_detection(self) -> None:
        """Verify detection of pull_request_target workflow, package.json postinstall, tasks.json."""
        scanner = AutorunSurfaceScanner()
        result = scanner.run(self.context)
        findings = result.findings

        assert len(findings) >= 3, f"Expected at least 3 autorun findings, got {len(findings)}"
        files_flagged = {f.file for f in findings}

        assert any("review.yml" in f for f in files_flagged), "pull_request_target workflow was not flagged"
        assert any("package.json" in f for f in files_flagged), "package.json lifecycle script was not flagged"
        assert any("tasks.json" in f for f in files_flagged), "tasks.json was not flagged"

        # Check high severity on pull_request_target and postinstall lifecycle
        workflow_finding = next(f for f in findings if "review.yml" in f.file)
        assert workflow_finding.severity == HIGH
        assert "pull_request_target" in workflow_finding.detail

        pkg_finding = next(f for f in findings if "package.json" in f.file)
        assert pkg_finding.severity == HIGH
        assert "postinstall" in pkg_finding.detail or "lifecycle" in pkg_finding.detail

    def test_langflow_python_deserialization_risks(self) -> None:
        """Verify detection of pickle.loads, shelve.open, yaml.unsafe_load, torch.load."""
        scanner = LegacyPatternScanner()
        result = scanner.run(self.context)
        findings = [f for f in result.findings if f.rule_id == "agentic.python.deserialization"]

        assert len(findings) >= 5, f"Expected at least 5 agentic deserialization findings, got {len(findings)}"

        titles = [f.title for f in findings]
        assert any("pickle" in t.lower() for t in titles)
        assert any("shelve" in t.lower() for t in titles)
        assert any("unsafe yaml" in t.lower() for t in titles)
        assert any("torch" in t.lower() for t in titles)

        # Ensure safe equivalents in same files are not flagged
        safe_snippets = [f.snippet for f in findings if "yaml.safe_load" in f.snippet or "weights_only=True" in f.snippet]
        assert len(safe_snippets) == 0, f"Safe loaders incorrectly flagged: {safe_snippets}"

    def test_langflow_prompt_injection_detection(self) -> None:
        """Verify detection of prompt injection directives in markdown and code comments."""
        scanner = PromptInjectionScanner()
        result = scanner.run(self.context)
        findings = result.findings

        assert len(findings) >= 2, f"Expected at least 2 prompt injection findings, got {len(findings)}"
        for f in findings:
            assert f.category == "injection"
            assert f.maliciousness >= 0.70

        all_titles = " ".join(f.title for f in findings)
        assert any(m in all_titles for m in ("ignore previous", "bypass invariants", "disregard the above"))

        files = {f.file for f in findings}
        assert any("system_instructions.md" in f for f in files)
        assert any("autonomous_node.py" in f for f in files)

    def test_langflow_benign_components_zero_false_positives(self) -> None:
        """Verify that benign components (math_operator, text_transformer, graph_schema) produce zero findings."""
        benign_files = [
            LANGFLOW_DIR / "src" / "langflow_snapshot" / "components" / "math_operator.py",
            LANGFLOW_DIR / "src" / "langflow_snapshot" / "components" / "text_transformer.py",
            LANGFLOW_DIR / "src" / "langflow_snapshot" / "schemas" / "graph_schema.py",
        ]
        legacy_scanner = LegacyPatternScanner()
        sast_scanner = PythonSastScanner()

        for b_file in benign_files:
            rel = str(b_file.relative_to(LANGFLOW_DIR)).replace("\\", "/")
            legacy_findings = legacy_scanner.scan_file(b_file, rel)
            assert len(legacy_findings) == 0, f"False positive in legacy_scanner for {rel}: {[f.title for f in legacy_findings]}"

            # Also check Python SAST scanner
            mini_ctx = ScanContext(
                snapshot_dir=LANGFLOW_DIR,
                repo="test/langflow-snapshot",
                commit_sha="abcd1234",
                file_index=[rel],
            )
            sast_result = sast_scanner.run(mini_ctx)
            assert len(sast_result.findings) == 0, f"False positive in sast_scanner for {rel}: {[f.title for f in sast_result.findings]}"


# ==============================================================================
# Tier 4: Pipeline Integration, Risk Scoring & DEC-105 Invariants
# ==============================================================================

class TestTier4PipelineRiskAndInvariants:
    """Tier 4: Validates full ScanPipeline execution, two-axis risk scoring, ScanStore persistence, DEC-105."""

    def test_pipeline_run_scanners_on_legacy_php(self, tmp_path: Path) -> None:
        """Verify ScanPipeline integrates all deterministic scanners on legacy PHP snapshot."""
        pipeline = ScanPipeline(store_path=tmp_path / "scan_store.sqlite3")
        manifest = DummyManifest(LEGACY_PHP_DIR)
        commit_sha = "1111222233334444555566667777888899990000"

        findings = pipeline.run_scanners(LEGACY_PHP_DIR, "vendor/legacy-php-app", commit_sha, manifest)
        assert len(findings) >= 14
        assert all(f.commit_sha == commit_sha for f in findings)

        # Check deduplication integrity
        fingerprints = [f.fingerprint for f in findings]
        assert len(fingerprints) == len(set(fingerprints)), "Findings must be uniquely deduped by fingerprint"

    def test_pipeline_run_scanners_on_langflow(self, tmp_path: Path) -> None:
        """Verify ScanPipeline integrates all deterministic scanners on Langflow snapshot."""
        pipeline = ScanPipeline(store_path=tmp_path / "scan_store.sqlite3")
        manifest = DummyManifest(LANGFLOW_DIR)
        commit_sha = "aaaabbbbccccddddeeeeffff0000111122223333"

        findings = pipeline.run_scanners(LANGFLOW_DIR, "langflow-ai/langflow", commit_sha, manifest)
        assert len(findings) >= 10

        categories = {f.category for f in findings}
        assert "autorun" in categories
        assert "injection" in categories
        assert "sast" in categories

    def test_two_axis_risk_scorecard_calculation(self) -> None:
        """Verify repo_risk_score correctly computes vulnerable and malicious scores."""
        # PHP repo contains critical webshell (malicious) and SQLi/exec/unserialize (vulnerable)
        php_ctx = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        php_findings = LegacyPatternScanner().run(php_ctx).findings
        php_risk = repo_risk_score(php_findings)

        assert php_risk["vulnerable"] >= 0.90, f"Expected high vulnerable risk, got {php_risk['vulnerable']}"
        assert php_risk["malicious"] >= 0.90, f"Expected high malicious risk, got {php_risk['malicious']}"

        # Clean benign file yields 0.0 for both
        benign_risk = repo_risk_score([])
        assert benign_risk["vulnerable"] == 0.0
        assert benign_risk["malicious"] == 0.0

    def test_scan_store_persistence_and_filtering(self, tmp_path: Path) -> None:
        """Verify ScanStore records scans, computes counts by severity, and filters by criteria."""
        store_path = tmp_path / "test_store.sqlite3"
        store = ScanStore(store_path)

        php_ctx = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        php_findings = LegacyPatternScanner().run(php_ctx).findings

        scan_id = store.add_scan("vendor/legacy-php", "abcd0001", php_findings)
        assert scan_id == 1

        # Multi-scan history
        scans = store.list_scans()
        assert len(scans) == 1
        assert scans[0]["repo"] == "vendor/legacy-php"
        assert scans[0]["risk"]["vulnerable"] >= 0.90

        # Severity breakdown
        counts = store.count_findings_by_severity(scan_id)
        assert counts["critical"] >= 4
        assert counts["high"] >= 5
        assert sum(counts.values()) == len(php_findings)

        # Filter by severity
        crit_findings = store.get_findings_filtered(scan_id, severity="critical")
        assert len(crit_findings) == counts["critical"]
        assert all(f.severity == CRITICAL for f in crit_findings)

        # Filter by category
        malware_findings = store.get_findings_filtered(scan_id, category="malware")
        assert len(malware_findings) >= 4
        assert all(f.category == "malware" for f in malware_findings)

        # Filter by search text
        sqli_searched = store.get_findings_filtered(scan_id, search="SQL")
        assert len(sqli_searched) >= 3

        store.close()

    def test_dec105_authoritative_findings_invariant(self) -> None:
        """Verify DEC-105: High and Critical scanner findings are authoritative and cannot be cleared."""
        php_ctx = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        php_findings = LegacyPatternScanner().run(php_ctx).findings

        authoritative_findings = [f for f in php_findings if is_authoritative(f.severity)]
        assert len(authoritative_findings) > 0, "Expected authoritative findings in vulnerable PHP fixtures"

        for f in authoritative_findings:
            assert f.severity in (CRITICAL, HIGH)
            # Under DEC-105, is_authoritative MUST return True
            assert is_authoritative(f.severity) is True

    def test_sarif_export_generation(self, tmp_path: Path) -> None:
        """Verify SARIF 2.1 report generation from combined findings."""
        sarif_file = tmp_path / "report.sarif"

        php_ctx = _build_context(LEGACY_PHP_DIR, "test/legacy-php")
        php_findings = LegacyPatternScanner().run(php_ctx).findings

        langflow_ctx = _build_context(LANGFLOW_DIR, "test/langflow-snapshot")
        langflow_findings = AutorunSurfaceScanner().run(langflow_ctx).findings

        combined = dedupe(php_findings + langflow_findings)
        write_sarif(combined, sarif_file)

        assert sarif_file.is_file()
        content = json.loads(sarif_file.read_text(encoding="utf-8"))

        assert content["version"] == "2.1.0"
        assert len(content["runs"]) == 1
        run = content["runs"][0]
        assert run["tool"]["driver"]["name"] in ("agentpoi-scan", "AgentPOI-Scan")
        assert len(run["results"]) == len(combined)
