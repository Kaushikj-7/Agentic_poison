"""Autorun-surface adapter — files whose content executes on open/install/build.

These are the highest-leverage supply-chain targets: code a victim runs merely
by installing, opening an editor, or triggering standard workflows. Purely
path/content-regex based; nothing is executed to inspect them.
"""

from __future__ import annotations

import json
import re
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

COMPILED_SUSPICIOUS_PATTERNS = (
    (
        re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:ba|z|da)?sh", re.IGNORECASE),
        "curl/wget pipe-to-shell pattern",
    ),
    (
        re.compile(
            r"(?:Invoke-WebRequest|iwr)[^\n|]*\|\s*(?:iex|Invoke-Expression)",
            re.IGNORECASE,
        ),
        "powershell download-and-execute pattern",
    ),
    (
        re.compile(
            r"(?:curl|wget)\s+-(?:[a-zA-Z]*s[a-zA-Z]*\s+)?https?://",
            re.IGNORECASE,
        ),
        "remote payload download pattern",
    ),
)


def _match_flagged_patterns(text: str) -> list[str]:
    matches: list[str] = []
    for pattern, label in COMPILED_SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    return sorted(set(matches))


def _eval_package_json(text: str, flagged: list[str]) -> tuple[bool, str, list[str]]:
    extra: list[str] = []
    try:
        scripts = (json.loads(text) or {}).get("scripts", {}) or {}
        suspicious = [s for s in scripts if str(s).lower() in LIFECYCLE_SCRIPTS]
        if suspicious:
            extra.append(f"npm lifecycle scripts: {', '.join(suspicious)}")
    except (ValueError, AttributeError):
        extra.append("package.json not valid JSON")
        suspicious = ["invalid_json"]

    if not suspicious and not flagged:
        return False, "low", []

    severity = "critical" if (suspicious and flagged) else "high"
    return True, severity, extra


def _eval_autorun_target(
    relpath: str, basename: str, target: list[str], text: str
) -> tuple[bool, str, str, list[str], list[str]]:
    """Evaluates whether relpath should emit an autorun finding."""
    is_wf = (
        len(target) >= 2
        and tuple(target[:2]) == (".github", "workflows")
        and relpath.lower().endswith((".yml", ".yaml"))
    )
    is_hk = ".husky" in target or PurePosixPath(relpath).parent.name == "hooks"
    known = basename in AUTORUN_FILES

    if not (known or is_wf or is_hk):
        return False, "", "", [], []

    lowered = text.lower()
    flagged = _match_flagged_patterns(text)
    desc = AUTORUN_FILES.get(basename, ("repository automation file", "medium"))[0]

    if basename == "package.json":
        emit, sev, pkg_extra = _eval_package_json(text, flagged)
        return emit, sev, desc, flagged, pkg_extra
    if basename == "tasks.json":
        if "folderopen" not in lowered and not flagged:
            return False, "", "", [], []
        sev = "high" if flagged else "medium"
        extra = ["folderOpen task trigger"] if "folderopen" in lowered else []
        return True, sev, desc, flagged, extra
    if is_wf:
        if "pull_request_target" not in lowered and not flagged:
            return False, "", "", [], []
        extra = (
            ["pull_request_target workflow (untrusted-checkout trigger)"]
            if "pull_request_target" in lowered
            else []
        )
        return True, "high", "workflow automation file", flagged, extra

    sev = "high" if flagged else ("medium" if basename != "setup.cfg" else "low")
    return True, sev, desc, flagged, []


class AutorunSurfaceScanner:
    """Flags files that execute when someone installs/opens/uses a repo."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for relpath in context.file_index:
            basename = PurePosixPath(relpath).name
            target = relpath.split("/")
            text = context.read_text(relpath) or ""
            emit, severity, detail_desc, flagged, extra = _eval_autorun_target(
                relpath, basename, target, text
            )
            if not emit:
                continue

            all_extra = list(extra)
            if flagged:
                all_extra.append("; ".join(flagged))

            has_suspicious = bool(flagged) or any("lifecycle" in e for e in all_extra)
            findings.append(
                Finding(
                    file=relpath,
                    lines=[1],
                    category="autorun",
                    severity=severity,
                    title=f"autorun surface: {detail_desc}",
                    detail=(
                        f"{relpath} executes when the repository is installed/opened/used"
                        + (f" — {'; '.join(all_extra)}" if all_extra else "")
                    ),
                    scanner=SCANNER_NAME,
                    commit_sha=context.commit_sha,
                    maliciousness=0.5 if has_suspicious else 0.2,
                    vulnerability=0.1,
                    evidence=[{"kind": "scanner_output", "text": relpath}],
                )
            )
        return ScanResult(scanner=SCANNER_NAME, findings=findings)
