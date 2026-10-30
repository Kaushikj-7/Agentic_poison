"""Prompt-injection-in-repo adapter — content aimed at AI reviewers.

Reuses the SDE branch's ``INJECTION_MARKERS`` as one signal, but applies it to
NFKC-normalized text and reports per occurrence with line numbers, so split
strings and homoglyph workarounds are harder. Injection content is treated as a
malicious signal (category=Injection), never dismissed.
"""

from __future__ import annotations

import re
import unicodedata

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "repo_injection"

from agentpoi_sde.anchor.policy_registry import INJECTION_MARKERS  # noqa: E402

# Known invisible/zero-width characters that can be used to split markers.
_INVISIBLE_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")


class PromptInjectionScanner:
    """Finds injection directives hidden in repo content, including AI comments."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for relpath in context.file_index:
            raw = context.read_text(relpath)
            if not raw:
                continue
            # weaken split-string evasion: drop invisible chars, fold width
            normalized = unicodedata.normalize("NFKC", raw)
            cleaned = _INVISIBLE_RE.sub("", normalized).lower()
            lines = cleaned.splitlines()
            raw_lines = raw.splitlines()
            for marker in INJECTION_MARKERS:
                for lineno, line in enumerate(lines, start=1):
                    if marker in line:
                        findings.append(
                            Finding(
                                file=relpath,
                                lines=[lineno],
                                snippet=(
                                    raw_lines[lineno - 1].strip()[:300]
                                    if 0 < lineno <= len(raw_lines)
                                    else ""
                                ),
                                category="injection",
                                severity="medium",
                                title=f"prompt injection marker: {marker!r}",
                                detail=(
                                    f"line {lineno} matches injection marker {marker!r}; "
                                    "content targeting AI reviewers is a malicious signal"
                                ),
                                scanner=SCANNER_NAME,
                                commit_sha=context.commit_sha,
                                maliciousness=0.75,
                                vulnerability=0.05,
                                evidence=[{"kind": "scanner_output", "text": f"{relpath}:{lineno}: {marker}"}],
                            )
                        )
                        break  # one finding per marker per file
        return ScanResult(scanner=SCANNER_NAME, findings=findings)
