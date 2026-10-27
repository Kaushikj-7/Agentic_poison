"""Autorun-surface adapter — files whose content executes on open/install/build.

These are the highest-leverage supply-chain targets: code a victim runs merely
by installing, opening an editor, or triggering standard workflows. Purely
path/content-regex based; nothing is executed to inspect them.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "autorun_surface"

AUTORUN_FILES = {
    "setup.py": ("python package install script", "high"),
    "setup.cfg": ("python package metadata (build hooks possible)", "medium"),
    "package.json": ("npm package manifest (lifecycle scripts)", "high"),
    "tasks.json": ("editor tasks (may run on folder open)", "high"),
    "devcontainer.json": ("devcontainer setup (post-create scripts)", "high"),
    "Makefile": ("make recipe (arbitrary shell)", "high"),
}

LIFECYCLE_SCRIPTS = ("preinstall", "postinstall", "prepare", "prepack", "postpack")

SUSPICIOUS_PATTERNS = (
    ("curl", "curl|sh pipe pattern"),
    ("wget", "wget pipe pattern"),
    ("curl http", "curl download pattern"),
    ("Invoke-WebRequest", "powershell download pattern"),
    ("curl -fsSL", "curl-to-shell pattern"),
)


class AutorunSurfaceScanner:
    """Flags files that execute when someone installs/opens/uses a repo."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for relpath in context.file_index:
            basename = PurePosixPath(relpath).name
            target = relpath.split("/")
            # .vscode/tasks.json, .github/workflows/*.yml, .husky/*
            known = basename in AUTORUN_FILES
            is_workflow = (".github", "workflows") <= tuple(target)
            is_husky = ".husky" in target or "hooks" == (PurePosixPath(relpath).parent.name)
            if not (known or is_workflow or is_husky):
                continue
            text = context.read_text(relpath) or ""
            severity = AUTORUN_FILES.get(basename, ("source workflow / hook", "medium"))[1]
            detail_desc = AUTORUN_FILES.get(basename, ("repository automation file", "medium"))[0]

            extra = []
            lowered = text.lower()
            if basename == "package.json":
                try:
                    scripts = (json.loads(text) or {}).get("scripts", {}) or {}
                    suspicious_lifecycle = [s for s in scripts if str(s).lower() in LIFECYCLE_SCRIPTS]
                    if suspicious_lifecycle:
                        extra.append(f"npm lifecycle scripts: {', '.join(suspicious_lifecycle)}")
                        severity = "high"
                except (ValueError, AttributeError):
                    extra.append("package.json not valid JSON")

            flagged_patterns = [label for needle, label in SUSPICIOUS_PATTERNS if needle in lowered]
            if flagged_patterns:
                extra.append("; ".join(sorted(set(flagged_patterns))))

            if is_workflow and any("pull_request_target" in lowerl for lowerl in [text.lower()]):
                extra.append("pull_request_target workflow (untrusted-checkout trigger)")
                severity = "high"

            findings.append(
                Finding(
                    file=relpath,
                    lines=[1],
                    category="autorun",
                    severity=severity,
                    title=f"autorun surface: {detail_desc}",
                    detail=(
                        f"{relpath} executes when the repository is installed/opened/used"
                        + (f" — {'; '.join(extra)}" if extra else "")
                    ),
                    scanner=SCANNER_NAME,
                    commit_sha=context.commit_sha,
                    maliciousness=0.2 if not flagged_patterns and "lifecycle" not in " ".join(extra) else 0.5,
                    vulnerability=0.1,
                    evidence=[{"kind": "scanner_output", "text": relpath}],
                )
            )
        return ScanResult(scanner=SCANNER_NAME, findings=findings)
