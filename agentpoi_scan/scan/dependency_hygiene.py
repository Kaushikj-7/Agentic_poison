"""Dependency-hygiene adapter — what a manifest pulls in and how tightly.

Supply-chain risk starts above the code: a dependency resolved from a URL, a
branch, or a floating range can change after review. This adapter turns the
static manifest inventory into findings — it never installs, resolves or
downloads a package.

Coverage: PyPI (requirements*.txt, pyproject.toml), npm (package.json),
Composer, Go modules, Bundler and Cargo. Lockfile presence is observed, not
assumed; missing locks are reported as low-severity hygiene findings.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Dict, List, Set

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.intel.codebase import Dependency, parse_dependencies
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "dependency_hygiene"

MAX_FINDINGS = 300

# Floating ranges are only flagged where the ecosystem resolves at install time
# (PyPI/pip and npm). Composer, Bundler, Go and Cargo are lockfile-first.
FLOATING_ECOSYSTEMS = {"pypi", "npm"}

LOCKFILES: Dict[str, Set[str]] = {
    "pypi": {"poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock"},
    "npm": {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
    },
    "composer": {"composer.lock"},
    "gomod": {"go.sum"},
    "cargo": {"cargo.lock"},
    "rubygems": {"gemfile.lock"},
}


class DependencyHygieneScanner:
    """Flags dependencies that cannot be pinned to reviewed, immutable code."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: List[Finding] = []
        dependencies = parse_dependencies(context)
        seen: Set[tuple] = set()

        for dep in dependencies:
            if len(findings) >= MAX_FINDINGS:
                break
            if dep.source in {"vcs", "path"}:
                key = ("source", dep.manifest, dep.name)
                if key in seen:
                    continue
                seen.add(key)
                kind = "remote VCS" if dep.source == "vcs" else "local path"
                findings.append(
                    self._finding(
                        dep,
                        title=f"dependency from {kind}: {dep.name}",
                        detail=(
                            f"{dep.name} ({dep.ecosystem}) is declared in {dep.manifest} "
                            f"from a {kind} source ({dep.specifier[:120]}); the resolved "
                            "code is not pinned to a reviewed release"
                        ),
                        severity="high",
                        maliciousness=0.35 if dep.source == "vcs" else 0.2,
                        vulnerability=0.5,
                        kind=dep.source,
                    )
                )
            elif dep.ecosystem in FLOATING_ECOSYSTEMS and not dep.pinned:
                key = ("unpinned", dep.manifest, dep.name, dep.line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self._finding(
                        dep,
                        title=f"unpinned dependency: {dep.name}",
                        detail=(
                            f"{dep.name} is declared as {dep.specifier or '(no version)'} in "
                            f"{dep.manifest}:{dep.line}; a floating range lets the resolved "
                            "code change without a diff review"
                        ),
                        severity="medium",
                        maliciousness=0.15,
                        vulnerability=0.3,
                        kind="unpinned",
                    )
                )

        findings.extend(self._missing_lockfiles(context, dependencies, seen))
        return ScanResult(scanner=SCANNER_NAME, findings=findings[:MAX_FINDINGS])

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _finding(
        dep: Dependency,
        *,
        title: str,
        detail: str,
        severity: str,
        maliciousness: float,
        vulnerability: float,
        kind: str,
    ) -> Finding:
        return Finding(
            file=dep.manifest,
            lines=[dep.line],
            category="deps",
            severity=severity,
            title=title,
            detail=detail,
            scanner=SCANNER_NAME,
            confidence=0.9,
            maliciousness=maliciousness,
            vulnerability=vulnerability,
            snippet=dep.raw[:300],
            evidence=[
                {
                    "kind": "manifest_entry",
                    "manifest": dep.manifest,
                    "line": dep.line,
                    "dependency": f"{dep.name}{(' ' + dep.specifier) if dep.specifier else ''}",
                    "issue": kind,
                }
            ],
        )

    @staticmethod
    def _missing_lockfiles(
        context: ScanContext, dependencies: List[Dependency], seen: Set[tuple]
    ) -> List[Finding]:
        present = {PurePosixPath(rel).name.lower() for rel in context.file_index}
        manifests: Dict[str, str] = {}
        for dep in dependencies:
            manifests.setdefault(dep.manifest, dep.ecosystem)

        findings: List[Finding] = []
        for manifest, ecosystem in sorted(manifests.items()):
            wanted = LOCKFILES.get(ecosystem)
            if not wanted or present & wanted:
                continue
            key = ("lockfile", manifest)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    file=manifest,
                    lines=[],
                    category="deps",
                    severity="low",
                    title=f"no lockfile pins the {ecosystem} dependency tree",
                    detail=(
                        f"{manifest} declares {ecosystem} dependencies but none of "
                        f"{', '.join(sorted(wanted))} is present; installs are not reproducible"
                    ),
                    scanner=SCANNER_NAME,
                    confidence=0.8,
                    maliciousness=0.05,
                    vulnerability=0.2,
                    evidence=[{"kind": "lockfile_absence", "manifest": manifest, "ecosystem": ecosystem}],
                )
            )
        return findings
