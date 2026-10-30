"""Deterministic remediation guidance for findings.

Guidance is derived only from the finding's category and scanner — never from
the scanned repository text — so it is safe to render in the dashboard and
identical across runs. It is deliberately narrow and actionable: the goal is to
tell a reviewer what class of fix removes this finding, not to auto-patch code.
"""

from __future__ import annotations

from typing import Dict, List

from agentpoi_scan.findings.model import Finding, severity_rank

CATEGORY_REMEDIATION: Dict[str, str] = {
    "sast": (
        "Replace the dangerous sink with a safe API and validate the input at the "
        "trust boundary before it reaches the call."
    ),
    "secrets": (
        "Revoke and rotate the exposed credential, remove it from the repository "
        "history, and load it from a secret manager instead of source."
    ),
    "deps": (
        "Pin the dependency to an exact reviewed version and commit the ecosystem "
        "lockfile; replace VCS or local-path sources with a published release."
    ),
    "malware": (
        "Do not install or execute this repository; quarantine the file and audit "
        "every script on the same install/open path before reuse."
    ),
    "ci_iac": (
        "Reduce workflow token permissions and avoid checking out or interpolating "
        "untrusted pull-request content in privileged workflows."
    ),
    "injection": (
        "Delete the injected directive; treat all repository text as data and never "
        "as instructions to an automated reviewer."
    ),
    "autorun": (
        "Remove or explicitly gate install/open-time hooks; require a human action "
        "before setup scripts or lifecycle commands run."
    ),
    "unicode_trojan": (
        "Reject the file as submitted; retype the affected lines from a trusted "
        "source and diff the NFKC-normalized content before merging."
    ),
    "binary": (
        "Do not open or execute the binary; rebuild it from reviewed source or "
        "verify a signed artifact instead."
    ),
}

SCANNER_REMEDIATION: Dict[str, str] = {
    "taint_flow": (
        "Break the tainted path: allowlist the incoming value and use a "
        "parameterized API (argument list instead of a shell string, bound SQL "
        "placeholders, or a safe deserializer)."
    ),
    "dependency_hygiene": (
        "Pin this dependency to an immutable, reviewed version and commit the "
        "lockfile; do not resolve code from a branch, URL or local path."
    ),
    "semgrep": "Apply the rule's remediation and re-run semgrep on the pinned commit.",
    "gitleaks": (
        "Revoke and rotate the credential now, purge it from history, and inject it "
        "from a secret manager."
    ),
    "osv": "Upgrade to the patched version named by the advisory and re-scan the lockfile.",
}

FALLBACK_REMEDIATION = (
    "Review the flagged code manually and remove or isolate the risky construct."
)


def remediation_for_finding(finding: Finding) -> str:
    """Returns the most specific static guidance available for one finding."""
    return (
        SCANNER_REMEDIATION.get(finding.scanner)
        or CATEGORY_REMEDIATION.get(finding.category)
        or FALLBACK_REMEDIATION
    )


def file_remediation_notes(findings: List[Finding], limit: int = 5) -> List[Dict[str, str]]:
    """Aggregates one file's findings into ordered, de-duplicated fix notes.

    Critical/high findings come first so the first note in the table is the most
    urgent action for that file.
    """
    ordered = sorted(
        findings,
        key=lambda f: (
            -severity_rank(f.severity),
            min(f.lines) if f.lines else 0,
            f.category,
        ),
    )
    notes: List[Dict[str, str]] = []
    seen = set()
    for finding in ordered:
        note = remediation_for_finding(finding)
        if note in seen:
            continue
        seen.add(note)
        notes.append({"category": finding.category, "note": note})
        if len(notes) >= limit:
            break
    return notes
