"""Zone 3 — tiered LLM agents (triage, analyst, verifier) and the router.

All agents are strictly read-only consumers of redacted snippets and fail
closed: an unavailable or malformed LLM response never silently clears a
finding; without triage the finding persists as ``escalated``.
"""
from agentpoi_scan.agents.llm_bridge import TieredProviders
from agentpoi_scan.agents.router import EscalationPolicy, Router

__all__ = ["TieredProviders", "EscalationPolicy", "Router"]
