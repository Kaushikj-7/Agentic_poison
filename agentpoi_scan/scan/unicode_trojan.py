"""Trojan Source / unicode-attack adapter — NFKC-normalized text inspection.

Detects bidirectional-control trickery, invisible characters, and homoglyph
normalization mismatches (Unicode Trojan Source, Boucher & Anderson 2021).
The legacy lowercase substring markers in ``policy_registry`` are evadable;
this adapter works over NFKC-normalized text and per-character classes.
"""

from __future__ import annotations

import unicodedata

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "unicode_trojan"

BIDI_CONTROL = frozenset(
    code for code in range(0x110000)
    if unicodedata.category(chr(code)) in ("Cf", "Co")
    or chr(code) in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    and unicodedata.category(chr(code)) == "Cf"
)
ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff")
BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_IGNORED_NFKC_CHARS = frozenset("™©®µ½¼¾²³‘’“”–—•…§¶†‡")
_IGNORED_NFKC_CATEGORIES = frozenset({"Po", "Pd", "Ps", "Pe", "Pi", "Pf", "Sm", "Sc", "Sk", "So"})


def _is_nfkc_homoglyph(ch: str, normal: str) -> bool:
    if normal == ch or not (normal.isprintable() and ch.isprintable()):
        return False
    if ch in _IGNORED_NFKC_CHARS:
        return False
    cat = unicodedata.category(ch)
    if cat in _IGNORED_NFKC_CATEGORIES:
        return False
    if ch.isidentifier() and normal.isidentifier():
        return True
    if cat.startswith(("L", "N")) and normal.isascii():
        return True
    return False


def _classify_char(ch: str) -> str:
    if ch in BIDI_CHARS:
        return "bidi"
    if ch in ZERO_WIDTH or (unicodedata.category(ch) == "Cf" and ch not in BIDI_CHARS):
        return "invisible"
    return ""


class UnicodeTrojanScanner:
    """Flags files using invisible- or bidi-character source attacks."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        for relpath in context.file_index:
            text = context.read_text(relpath)
            if not text:
                continue
            hits: list[tuple[int, str]] = []
            source_lines = text.splitlines()
            for lineno, line in enumerate(source_lines, start=1):
                kinds: list[str] = []
                for ch in line:
                    kind = _classify_char(ch)
                    if kind:
                        kinds.append(kind)
                    normal = unicodedata.normalize("NFKC", ch)
                    if _is_nfkc_homoglyph(ch, normal):
                        kinds.append("nfkc-mismatch")
                unique = sorted(set(kinds))
                if unique:
                    hits.append((lineno, ",".join(unique)))
            if hits:
                first_line, first_kinds = hits[0]
                findings.append(
                    Finding(
                        file=relpath,
                        lines=[line for line, _ in hits[:10]],
                        snippet=(
                            source_lines[first_line - 1].strip()[:300]
                            if 0 < first_line <= len(source_lines)
                            else ""
                        ),
                        category="unicode_trojan",
                        severity="high",
                        title=f"hidden unicode characters ({first_kinds})",
                        detail=(
                            f"{len(hits)} line(s) contain hidden/normalizing unicode "
                            f"({first_kinds} first at line {first_line}); "
                            "Trojan Source risk — display mangling or compiler divergence."
                        ),
                        scanner=SCANNER_NAME,
                        commit_sha=context.commit_sha,
                        maliciousness=0.7,
                        vulnerability=0.2,
                        evidence=[
                            {"kind": "scanner_output", "text": f"{relpath}:{first_line} {first_kinds}"}
                        ],
                    )
                )
        return ScanResult(scanner=SCANNER_NAME, findings=findings)
