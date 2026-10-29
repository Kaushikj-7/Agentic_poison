"""Zone 2 — parse-only scanner adapters (no network, no execution)."""
from agentpoi_scan.scan.base import LoadError, ScanContext, Scanner, ScanResult
from agentpoi_scan.scan.legacy_patterns import (
    FindingCategory,
    LegacyPatternScanner,
    Severity,
)

__all__ = [
    "ScanContext",
    "Scanner",
    "ScanResult",
    "LoadError",
    "LegacyPatternScanner",
    "Severity",
    "FindingCategory",
]

