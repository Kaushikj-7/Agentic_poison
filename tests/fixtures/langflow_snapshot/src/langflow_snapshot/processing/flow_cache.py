"""Flow caching and state serialization module.

Contains deserialization patterns for agentic snapshot verification.
"""

from __future__ import annotations

import pickle
import shelve
from typing import Any, Dict


class FlowCacheManager:
    """Manages cached agent execution states across graph executions."""

    def __init__(self, cache_dir: str = "/tmp/langflow_cache") -> None:
        self.cache_dir = cache_dir

    def restore_flow_state(self, serialized_state: bytes) -> Dict[str, Any]:
        """Unpickles raw flow state - triggers agentic.python.deserialization."""
        state = pickle.loads(serialized_state)
        return state

    def open_persistent_shelve(self, db_name: str = "agent_states") -> shelve.Shelf:
        """Opens persistent shelf storage - triggers agentic.python.deserialization."""
        return shelve.open(f"{self.cache_dir}/{db_name}")
