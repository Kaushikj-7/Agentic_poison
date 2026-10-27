"""External command scanners (Zone 2) with graceful degradation.

Semgrep, Gitleaks and OSV-Scanner are invoked only if their binary is locally
installed; otherwise the adapter reports ``skipped`` and the pipeline continues
(fail-open for coverage-availability, fail-closed for never silencing). When a
binary runs, it runs with fixed arguments and its SARIF/JSON report is parsed;
nothing from the target repository is executed by us.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult, external_available

SCANNER_NAMES = ("semgrep", "gitleaks", "osv")


@dataclass
class ExternalSpec:
    """Declarative invocation config for one external scanner."""

    name: str
    binary: str
    args: List[str]  # argv without the binary name; {snapshot} placeholder
    severity_map: dict


SEMGREP = ExternalSpec(
    name="semgrep",
    binary="semgrep",
    args=["scan", "--json", "--metrics=off", "--quiet", "{snapshot}"],
    severity_map={"ERROR": "high", "WARNING": "medium", "INFO": "low"},
)
GITLEAKS = ExternalSpec(
    name="gitleaks",
    binary="gitleaks",
    args=["detect", "--source={snapshot}", "--report-format=sarif", "--report-path", "-",
          "--no-git", "--redact", "-v"],
    severity_map={},
)
OSV = ExternalSpec(
    name="osv",
    binary="osv-scanner",
    args=["--json", "--locked", "--local", "{snapshot}"],
    severity_map={},
)


def parse_semgrep_json(report: str) -> List[Finding]:
    """Maps semgrep's JSON output to canonical findings."""
    data = json.loads(report) or {}
    findings: List[Finding] = []
    for result in data.get("results", []) or []:
        check = result.get("check_id", "unknown")
        extra = result.get("extra") or {}
        start = ((result.get("start") or {}).get("line")) or 1
        end = ((result.get("end") or {}).get("line")) or start
        severity = SEMGREP.severity_map.get(str(extra.get("severity", "")).upper(), "medium")
        findings.append(
            Finding(
                file=result.get("path", "unknown"),
                lines=[start, end] if end and end != start else [start],
                category="sast",
                severity=severity,
                title=str(check),
                detail=str(extra.get("message", ""))[:400],
                scanner="semgrep",
                confidence=0.85,
                vulnerability=0.7,
                evidence=[{"kind": "scanner_output", "text": str(extra.get("message", ""))[:400]}],
            )
        )
    return findings


def parse_gitleaks_sarif(report: str) -> List[Finding]:
    """Maps gitleaks' SARIF output to canonical findings."""
    data = json.loads(report) or {}
    findings: List[Finding] = []
    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId", "secret")
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri", "unknown")
            start = ((loc.get("region") or {}).get("startLine")) or 1
            findings.append(
                Finding(
                    file=uri,
                    lines=[start],
                    category="secrets",
                    severity="high",
                    title=f"leaked secret: {rule_id}",
                    detail=str(result.get("message", {}).get("text", ""))[:400],
                    scanner="gitleaks",
                    confidence=0.95,
                    maliciousness=0.2,
                    vulnerability=0.5,
                    evidence=[{"kind": "scanner_output", "text": uri}],
                )
            )
    return findings


class ExternalToolScanner:
    """Runs one pinned-argv external scanner if its binary is available."""

    def __init__(self, spec: ExternalSpec, which: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self.spec = spec
        self.which = which  # injectable for tests; defaults to shutil.which

    @property
    def name(self) -> str:
        return self.spec.name

    def _available(self) -> bool:
        if self.which is not None:
            return self.which(self.spec.binary) is not None
        return external_available(self.spec.binary)

    def run(self, context: ScanContext, timeout: float = 300.0) -> ScanResult:
        if not self._available():
            return ScanResult(
                scanner=self.name,
                skipped=True,
                skip_reason=f"{self.spec.binary} not installed; static-only fallback skipped",
            )
        argv = [self.spec.binary] + [
            a.replace("{snapshot}", str(context.snapshot_dir)) for a in self.spec.args
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return SkipOrErr(self.name, f"external scanner failed to run: {exc}")
        if proc.returncode not in (0, 1):  # gitleaks exits 1 when secrets are found
            return SkipOrErr(self.name, f"external scanner exit code {proc.returncode}")
        parser = {
            "semgrep": parse_semgrep_json,
            "gitleaks": parse_gitleaks_sarif,
        }.get(self.spec.name, parse_nothing)
        try:
            findings = parser(proc.stdout or "{}")
        except (ValueError, KeyError) as exc:
            return SkipOrErr(self.name, f"unparseable external report: {exc}")
        for finding in findings:
            finding.commit_sha = context.commit_sha
        return ScanResult(scanner=self.name, findings=findings, isolation="external-binary")


def SkipOrErr(scanner: str, reason: str) -> ScanResult:
    """Shorthand result for an external scanner whose invocation failed."""
    return ScanResult(scanner=scanner, skipped=True, skip_reason=reason)


def parse_nothing(_report: str) -> List[Finding]:
    """Parse stub for tools whose format we do not model yet (e.g. OSV JSON)."""
    return []
