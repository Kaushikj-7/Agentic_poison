"""End-to-end scan pipeline: fetch → extract → scanners → triage → escalate → persist.

Orchestration owns the safety invariants: nothing in this module ever executes
snapshot content; every scanner is parse-only; agents only ever receive
redacted snippets; authoritative findings can't be cleared by models; every
stage degrades gracefully when a component is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from agentpoi_scan.agents.analyst import AnalystAgent, VerifierAgent
from agentpoi_scan.agents.llm_bridge import TieredProviders, build_default_providers
from agentpoi_scan.agents.router import EscalationPolicy, Router
from agentpoi_scan.agents.triage import TriageAgent
from agentpoi_scan.fetch.registry import load_scan_registry
from agentpoi_scan.fetch.safe_extract import extract_snapshot
from agentpoi_scan.fetch.snapshot_client import SnapshotClient
from agentpoi_scan.findings.model import Finding, dedupe
from agentpoi_scan.report.sarif import write_sarif
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.scan.autorun_surface import AutorunSurfaceScanner
from agentpoi_scan.scan.base import ScanContext, ScanResult
from agentpoi_scan.scan.external_cmd import GITLEAKS, OSV, SEMGREP, ExternalToolScanner
from agentpoi_scan.scan.legacy_patterns import LegacyPatternScanner
from agentpoi_scan.scan.prompt_injection import PromptInjectionScanner
from agentpoi_scan.scan.python_sast import PythonSastScanner
from agentpoi_scan.scan.unicode_trojan import UnicodeTrojanScanner


@dataclass
class ScanReport:
    repo: str
    commit_sha: str
    isolation: Dict[str, str] = field(default_factory=dict)
    skipped_scanners: Dict[str, str] = field(default_factory=dict)
    risk: Dict[str, float] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    scan_id: Optional[int] = None
    triage: Dict[str, int] = field(default_factory=dict)

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
        self.client = SnapshotClient(token=self.cfg.get("github_token") or None)
        self.scanners = [
            PythonSastScanner(),
            UnicodeTrojanScanner(),
            PromptInjectionScanner(),
            AutorunSurfaceScanner(),
            LegacyPatternScanner(),
            ExternalToolScanner(SEMGREP),
            ExternalToolScanner(GITLEAKS),
            ExternalToolScanner(OSV),
        ]
        self.router_policy = EscalationPolicy.from_config(self.cfg.get("router"))
        self.store = ScanStore(store_path or Path(".agentpoi_scan/scan_store.sqlite3"))
        self.sarif_path = Path(self.cfg.get("sarif_path") or ".agentpoi_scan/findings.sarif")

    # -- zone 1 ---------------------------------------------------------------
    def fetch_and_extract(self, repo_url: str, ref: Optional[str] = None, workdir: Path | None = None):
        workdir = Path(workdir or ".agentpoi_scan")
        snapshot = self.client.fetch(repo_url, ref=ref, dest_dir=workdir)
        snapshot_dir = workdir / f"snap_{snapshot.commit_sha[:12]}"
        if snapshot_dir.exists():
            import shutil

            shutil.rmtree(snapshot_dir)
        manifest = extract_snapshot(snapshot.tarball_path.read_bytes(), snapshot_dir)
        return snapshot, snapshot_dir, manifest

    # -- zone 2 ---------------------------------------------------------------
    def run_scanners(self, snapshot_dir: Path, repo: str, commit_sha: str, manifest) -> List[Finding]:
        context = ScanContext.from_manifest(snapshot_dir, repo, commit_sha, manifest)
        all_findings: List[Finding] = []
        for scanner in self.scanners:
            result: ScanResult = scanner.run(context)
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
        # Zone 1
        snapshot, snapshot_dir, manifest = self.fetch_and_extract(repo_url, ref=ref, workdir=workdir)
        # Zone 2
        findings = self.run_scanners(snapshot_dir, snapshot.repo, snapshot.commit_sha, manifest)
        # Zone 3
        providers, _unavail = build_default_providers(self.cfg)
        report = self.refine(findings, snapshot_dir, providers)
        # Zone 4
        report.risk = {
            "vulnerable": max((f.vulnerability for f in report.findings), default=0.0),
            "malicious": max((f.maliciousness for f in report.findings), default=0.0),
        }
        report.scan_id = self.store.add_scan(snapshot.repo, snapshot.commit_sha, report.findings)
        write_sarif(report.findings, self.sarif_path)
        return report

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
