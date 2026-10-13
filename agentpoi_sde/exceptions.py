"""Typed domain exceptions for the AgentPOI-SDE fail-closed mutation pipeline.

Mirrors the structure of ``agent_poi.financial.exceptions`` so the public SDK surface
is consistent across the financial and software-engineering platforms.
"""

from typing import Any, Dict, Optional


class SDESecurityError(Exception):
    """Base exception for all software-engineering-agent security violations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvariantViolationError(SDESecurityError):
    """Raised when a proposed mutation violates a repository invariant."""

    def __init__(self, message: str, code: str = "INVARIANT", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.code = code


class PolicyFileIntegrityError(InvariantViolationError):
    """Raised when untrusted context attempts to mutate agent/CI policy files (I1)."""

    def __init__(self, path: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Policy File Integrity (I1): untrusted mutation of protected policy path '{path}'.",
            code="I1",
            details=details,
        )
        self.path = path


class TestIntegrityError(InvariantViolationError):
    """Raised when a mutation weakens or deletes the test oracle (I2)."""

    def __init__(self, path: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Test Integrity (I2): mutation weakens or removes the test oracle at '{path}'.",
            code="I2",
            details=details,
        )
        self.path = path


class SecretProliferationError(InvariantViolationError):
    """Raised when a mutation introduces credential material or untrusted egress (I3)."""

    def __init__(self, signals: list, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Secret Non-Proliferation (I3): mutation introduces protected material {signals}.",
            code="I3",
            details=details,
        )
        self.signals = signals


class ArchitectureViolationError(InvariantViolationError):
    """Raised when a mutation breaks declared layering or creates a dependency cycle (I4)."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="I4", details=details)


class BlastRadiusError(InvariantViolationError):
    """Raised when a mutation writes outside its declared intent scope (I5)."""

    def __init__(self, path: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Blast Radius (I5): mutation path '{path}' is outside the declared intent scope.",
            code="I5",
            details=details,
        )
        self.path = path


class DependencyProvenanceError(InvariantViolationError):
    """Raised when a mutation introduces a dependency of unverified provenance (I6)."""

    def __init__(self, dependency: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Dependency Provenance (I6): introduced dependency '{dependency}' has no verified provenance.",
            code="I6",
            details=details,
        )
        self.dependency = dependency


class SyntaxIntegrityError(InvariantViolationError):
    """Raised when a mutation leaves a Python file unparsable (I7)."""

    def __init__(self, path: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Syntax Integrity (I7): mutation leaves '{path}' unparsable.",
            code="I7",
            details=details,
        )
        self.path = path


class UntrustedProvenanceError(SDESecurityError):
    """Raised when a mutation's ancestry lacks an authenticated intent root (P)."""

    def __init__(self, node_id: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Provenance (P): mutation node '{node_id}' traces to no authenticated intent root.",
            details,
        )
        self.node_id = node_id


class CapabilityScopeError(SDESecurityError):
    """Raised when a mutation exceeds the granted capability scope (K)."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Capability Scope (K): {message}", details)


class ReplayDetectedError(SDESecurityError):
    """Raised when a mutation replays a previously consumed idempotency key (F)."""

    def __init__(self, nonce: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Freshness (F): nonce '{nonce}' has already been consumed (replay).", details)
        self.nonce = nonce
