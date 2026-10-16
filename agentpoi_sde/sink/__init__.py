"""Sink package for AgentPOI-SDE guarded filesystem operations."""

from agentpoi_sde.sink.atomic_writer import (
    AtomicDiskTransaction,
    AtomicDiskWriter,
)

__all__ = [
    "AtomicDiskWriter",
    "AtomicDiskTransaction",
]
