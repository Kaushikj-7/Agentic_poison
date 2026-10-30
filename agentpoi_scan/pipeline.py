"""End-to-end scan pipeline: fetch → extract → scanners → triage → escalate → persist.

Orchestration owns the safety invariants: nothing in this module ever executes
snapshot content; every scanner is parse-only; agents only ever receive
redacted snippets; authoritative findings can't be cleared by models; every
stage degrades gracefully when a component is unavailable.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from agentpoi_scan.agents.analyst import AnalystAgent, VerifierAgent
from agentpoi_scan.agents.llm_bridge import TieredProviders, build_default_providers
from agentpoi_scan.agents.router import EscalationPolicy, Router
from agentpoi_scan.agents.triage import TriageAgent
from agentpoi_scan.fetch.registry import load_scan_registry
from agentpoi_scan.fetch.safe_extract import Manifest, extract_snapshot
from agentpoi_scan.fetch.snapshot_client import SnapshotClient
from agentpoi_scan.fetch.workspace import (
    DEFAULT_WORKSPACE_ROOT,
    IsolatedWorkspace,
    PurgeResult,
)
from agentpoi_scan.findings.model import Finding, dedupe
from agentpoi_scan.intel.codebase import build_codebase_profile
from agentpoi_scan.report.sarif import write_sarif
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.scan.autorun_surface import AutorunSurfaceScanner
from agentpoi_scan.scan.base import ScanContext, ScanResult
from agentpoi_scan.scan.dependency_hygiene import DependencyHygieneScanner
from agentpoi_scan.scan.external_cmd import GITLEAKS, OSV, SEMGREP, ExternalToolScanner
from agentpoi_scan.scan.legacy_patterns import LegacyPatternScanner
from agentpoi_scan.scan.prompt_injection import PromptInjectionScanner
from agentpoi_scan.scan.python_sast import PythonSastScanner
from agentpoi_scan.scan.taint_flow import TaintFlowScanner
from agentpoi_scan.scan.unicode_trojan import UnicodeTrojanScanner
from agentpoi_scan.scan.workflow_state import WorkflowStateChecker


@dataclass
class ScanReport:
    repo: str
    commit_sha: str
    isolation: Dict[str, Any] = field(default_factory=dict)
    skipped_scanners: Dict[str, str] = field(default_factory=dict)
    risk: Dict[str, float] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    scan_id: Optional[int] = None
    triage: Dict[str, int] = field(default_factory=dict)
    profile: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        by_category: Dict[str, int] = {}
        for f in self.findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
        lines = [
            f"repo: {self.repo} @ {self.commit_sha[:12]}",
            f"risk: vulnerable={self.risk.get('vulnerable', 0.0):.2f} "
            f"malicious={self.risk.get('malicious', 0.0):.2f}",
            f"findings: {len(self.findings)} ({self._fmt_categories(by_category)})",
            f"triage: {self.triage}",
            f"skipped scanners: {self.skipped_scanners or 'none'}",
        ]
        if self.isolation:
            lines.append(
                f"isolation: {self.isolation.get('mode', 'unknown')} | "
                f"workspace purged: {self.isolation.get('purged', 'unknown')}"
            )
        if self.profile:
            languages = ", ".join(list(self.profile.get("languages", {}))[:3]) or "unknown"
            lines.append(
                f"codebase: {self.profile.get('total_files', 0)} files | languages: {languages} | "
                f"dependencies: {self.profile.get('dependency_count', 0)} | "
                f"routes: {self.profile.get('route_count', 0)} | "
                f"entrypoints: {len(self.profile.get('entrypoints', []))}"
            )
        return "\n".join(line for line in lines if line)

    @staticmethod
    def _fmt_categories(by_category: Dict[str, int]) -> str:
        return ", ".join(f"{k}={v}" for k, v in sorted(by_category.items()))


class ScanPipeline:
    """Wires the four zones together into a single local, no-execution run."""

    def __init__(
        self,
        store_path: Path | None = None,
        config: Optional[dict | str | Path] = None,
    ) -> None:
        if isinstance(config, (str, Path)):
            import yaml

            p = Path(config)
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) if p.is_file() else {}
            self.cfg = loaded if isinstance(loaded, dict) else {}
        else:
            self.cfg = dict(config or {})
        self.client = SnapshotClient(
            token=self.cfg.get("github_token") or os.environ.get("GITHUB_TOKEN") or None
        )
        self.scanners = [
            PythonSastScanner(),
            UnicodeTrojanScanner(),
            PromptInjectionScanner(),
            AutorunSurfaceScanner(),
            LegacyPatternScanner(),
            TaintFlowScanner(),
            DependencyHygieneScanner(),
            ExternalToolScanner(SEMGREP),
            ExternalToolScanner(GITLEAKS),
            ExternalToolScanner(OSV),
            WorkflowStateChecker(),
        ]
        self.router_policy = EscalationPolicy.from_config(self.cfg.get("router"))
        self.store = ScanStore(store_path or Path(".agentpoi_scan/scan_store.sqlite3"))
        self.sarif_path = Path(self.cfg.get("sarif_path") or ".agentpoi_scan/findings.sarif")
        self._last_skipped_scanners: Dict[str, str] = {}

    # -- zone 1 ---------------------------------------------------------------
    @staticmethod
    def _local_snapshot(target_path: Path):
        """Builds a manifest over a user-supplied local directory (never modified)."""
        target_path = target_path.resolve()
        repo_name = target_path.name or "local-target"
        commit_sha = "0" * 40
        files: Dict[str, int] = {}
        for p in sorted(target_path.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            rel = str(p.relative_to(target_path)).replace("\\", "/")
            parts = PurePosixPath(rel).parts
            if any(part in {".git", ".agentpoi_scan", "__pycache__"} for part in parts):
                continue
            files[rel] = p.stat().st_size
        manifest = Manifest(snapshot_dir=str(target_path), commit_sha=commit_sha, files=files)
        return target_path, repo_name, commit_sha, manifest

    def _remote_snapshot(
        self, repo_url: str, ref: Optional[str], workdir: Path | None
    ):
        """Fetches into a fresh isolated workspace; purges it if setup fails."""
        workspace = IsolatedWorkspace(root=workdir or DEFAULT_WORKSPACE_ROOT)
        try:
            snapshot = self.client.fetch(repo_url, ref=ref, dest_dir=workspace.path)
            snapshot_dir = workspace.snapshot_dir(snapshot.commit_sha)
            manifest = extract_snapshot(snapshot.tarball_path.read_bytes(), snapshot_dir)
        except Exception:
            workspace.purge()
            raise
        return workspace, snapshot, snapshot_dir, manifest

    # -- zone 2 ---------------------------------------------------------------
    def run_scanners(
        self,
        snapshot_dir: Path,
        repo: str,
        commit_sha: str,
        manifest,
        context: Optional[ScanContext] = None,
    ) -> List[Finding]:
        context = context or ScanContext.from_manifest(snapshot_dir, repo, commit_sha, manifest)
        all_findings: List[Finding] = []
        self._last_skipped_scanners = {}
        for scanner in self.scanners:
            result: ScanResult = scanner.run(context)
            if result.skipped:
                self._last_skipped_scanners[result.scanner] = result.skip_reason
            for finding in result.findings:
                finding.commit_sha = commit_sha
            all_findings.extend(result.findings)
        # binary candidates are flagged, never opened
        for rel in context.binary_candidates:
            all_findings.append(
                Finding(
                    file=rel,
                    lines=[],
                    category="binary",
                    severity="medium",
                    title="binary artifact present",
                    detail=f"{rel} is a binary blob — flagged, never opened",
                    scanner="binflag",
                    commit_sha=commit_sha,
                    maliciousness=0.3,
                    vulnerability=0.0,
                )
            )
        return dedupe(all_findings)

    # -- zones 2..4 ------------------------------------------------------------
    def scan_target(self, repo_url: str, ref: Optional[str] = None, workdir: Path | None = None) -> ScanReport:
        """Examines one repository, then deletes its workspace before returning.

        The remote path is: fetch tarball at a pinned SHA → extract into a fresh
        isolated workspace → scan/profile/triage in place → purge the workspace →
        persist findings and the codebase report to the dashboard store. A local
        directory is scanned read-only and is never deleted.
        """
        workspace: Optional[IsolatedWorkspace] = None
        purge: Optional[PurgeResult] = None
        profile: Dict[str, Any] = {}
        try:
            if Path(repo_url).is_dir():
                snapshot_dir, repo_name, commit_sha, manifest = self._local_snapshot(Path(repo_url))
                isolation: Dict[str, Any] = {
                    "mode": "local-directory (read-only)",
                    "workspace": str(snapshot_dir),
                    "network": "none",
                    "purged": "not-applicable",
                }
            else:
                # Zone 1
                workspace, snapshot, snapshot_dir, manifest = self._remote_snapshot(
                    repo_url, ref, workdir
                )
                repo_name, commit_sha = snapshot.repo, snapshot.commit_sha
                isolation = {
                    "mode": "static-no-execution (ephemeral workspace)",
                    "workspace": str(workspace.path),
                    "network": "github API tarball at pinned commit",
                    "purged": "pending",
                }
            context = ScanContext.from_manifest(snapshot_dir, repo_name, commit_sha, manifest)
            # Zone 2 — scanners + static codebase intelligence
            findings = self.run_scanners(
                snapshot_dir, repo_name, commit_sha, manifest, context=context
            )
            profile = build_codebase_profile(context).to_dict()
            # Zone 3
            providers, _unavail = build_default_providers(self.cfg)
            report = self.refine(findings, snapshot_dir, providers)
        finally:
            if workspace is not None:
                purge = workspace.purge()

        if purge is None:
            isolation["purged"] = "not-applicable"
        else:
            isolation["purged"] = "true" if purge.removed else "false"
            isolation["removed_files"] = purge.removed_files
            isolation["removed_bytes"] = purge.removed_bytes
            if purge.error:
                isolation["purge_error"] = purge.error

        report.skipped_scanners = dict(self._last_skipped_scanners)
        report.repo = repo_name
        report.commit_sha = commit_sha
        report.isolation = isolation
        report.profile = profile
        # Zone 4
        report.risk = {
            "vulnerable": max((f.vulnerability for f in report.findings), default=0.0),
            "malicious": max((f.maliciousness for f in report.findings), default=0.0),
        }
        report.scan_id = self.store.add_scan(repo_name, commit_sha, report.findings)
        self.store.add_report(report.scan_id, self._report_payload(report))
        write_sarif(report.findings, self.sarif_path)
        return report

    @staticmethod
    def _report_payload(report: ScanReport) -> Dict[str, Any]:
        """The dashboard record: what was examined, what was found, what was removed."""
        by_severity = Counter(f.severity for f in report.findings)
        by_category = Counter(f.category for f in report.findings)
        flagged_files = sorted({f.file for f in report.findings})
        return {
            "schema_version": 1,
            "scan_id": report.scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repo": report.repo,
            "commit_sha": report.commit_sha,
            "isolation": report.isolation,
            "codebase": report.profile,
            "risk": report.risk,
            "triage": report.triage,
            "skipped_scanners": report.skipped_scanners,
            "finding_summary": {
                "total": len(report.findings),
                "by_severity": dict(sorted(by_severity.items())),
                "by_category": dict(sorted(by_category.items())),
                "flagged_file_count": len(flagged_files),
                "flagged_files": flagged_files[:500],
            },
            "summary": report.summary(),
        }

    def refine(self, findings: List[Finding], snapshot_dir: Path, providers: TieredProviders) -> ScanReport:
        """Runs the LLM tiers over findings (all degrade to noop when unavailable)."""
        context = ScanContext(
            snapshot_dir=snapshot_dir,
            repo="",
            commit_sha="",
            file_index=sorted({f.file for f in findings}),
            binary_candidates=[],
        )
        router = Router(self.router_policy)
        triage_agent = TriageAgent(providers)
        analyst = AnalystAgent(providers)
        verifier = VerifierAgent(providers)
        stats = {"triaged": 0, "escalated": 0, "unavailable": 0}
        for finding in findings:
            verdict, escalated = triage_agent.triage(context, finding)
            if verdict is None:
                stats["unavailable"] += 1
            elif escalated:
                stats["escalated"] += 1
            else:
                stats["triaged"] += 1
            if router.escalate(finding, verdict):
                analyst_verdict, annotated = analyst.analyze(context, finding)
                if analyst_verdict is not None:
                    verifier.verify(context, annotated, analyst_verdict)
            # DEC-105: no finding is ever cleared here. Silencing needs
            # verifier agreement + a human flag — never an LLM alone.
        report = ScanReport(repo="", commit_sha="", findings=findings, triage=stats)
        return report


def validate_targets(registry_dir: str | Path) -> List[str]:
    """CLI-facing validation of the scan registry (OSS-Scanner style)."""
    result = load_scan_registry(registry_dir)
    return result.errors
