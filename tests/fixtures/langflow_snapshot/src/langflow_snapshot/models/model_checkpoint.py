"""Model checkpoint and weights loader.

Contains PyTorch model checkpoint loading pattern for agentic snapshot verification.
"""

from __future__ import annotations

from typing import Any

import torch


class CheckpointLoader:
    """Loads weights and model embeddings from disk."""

    @staticmethod
    def load_embedding_weights(weights_file_path: str) -> Any:
        """Loads checkpoint without weights_only=True - triggers agentic.python.deserialization."""
        checkpoint = torch.load(weights_file_path)
        return checkpoint

    @staticmethod
    def load_safe_checkpoint(weights_file_path: str) -> Any:
        """Loads checkpoint safely with weights_only=True."""
        return torch.load(weights_file_path, weights_only=True)
