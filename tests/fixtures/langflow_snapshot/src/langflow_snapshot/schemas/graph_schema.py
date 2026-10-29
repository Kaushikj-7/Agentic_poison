"""Pydantic schemas for graph nodes and connections."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NodeMetadata(BaseModel):
    node_id: str
    display_name: str
    category: str = "general"
    version: str = "1.0.0"


class EdgeDefinition(BaseModel):
    source_node: str
    target_node: str
    source_handle: str = "output"
    target_handle: str = "input"


class FlowGraphDefinition(BaseModel):
    flow_id: str
    name: str
    description: Optional[str] = None
    nodes: List[NodeMetadata] = Field(default_factory=list)
    edges: List[EdgeDefinition] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
