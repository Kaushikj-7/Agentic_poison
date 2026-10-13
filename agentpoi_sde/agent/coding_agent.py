"""The autonomous coding agent loop.

The agent registers an authenticated intent, ingests context, asks its provider for
mutations, and routes every proposal through ``DevGuard``. The provider is advisory:
authorisation happens entirely in the deterministic sink, so a compromised or confused
model cannot land a mutation that violates an invariant.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from agent_poi.memory.schema import SourceOrigin
from agentpoi_sde.agent.design_planner import DesignPlan, DesignPlanner
from agentpoi_sde.agent.llm_provider import DeterministicProvider, get_default_provider
from agentpoi_sde.facade import DevGuard, MutationVerdict


@dataclass
class AgentRunResult:
    """Outcome of one agent run: what was applied, what was blocked, and why."""

    task_id: str
    provider: str
    applied: List[str] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)
    verdicts: List[MutationVerdict] = field(default_factory=list)

    @property
    def applied_count(self) -> int:
        """Number of mutations applied."""
        return len(self.applied)

    @property
    def blocked_count(self) -> int:
        """Number of mutations blocked."""
        return len(self.blocked)

    def blocked_codes(self) -> Dict[str, List[str]]:
        """Return blocked mutation paths mapped to the invariant codes that stopped them."""
        return {
            verdict.mutation_path: verdict.violation_codes
            for verdict in self.verdicts
            if not verdict.is_applied
        }


class CodingAgent:
    """Fail-closed autonomous coding agent bound to a ``DevGuard`` sink."""

    def __init__(self, guard: DevGuard, provider=None) -> None:
        self.guard = guard
        self.provider = provider or get_default_provider()
        self.design_planner = DesignPlanner(guard.anchor.policy)

    def run(
        self,
        task_id: str,
        goal: str,
        allowed_paths: Sequence[str],
        context: str = "",
        context_origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
        nonce_prefix: str = "task",
        provider=None,
    ) -> AgentRunResult:
        """Execute one task: register intent, ingest context, propose, then gate each mutation."""
        intent = self.guard.register_intent(task_id, goal, allowed_paths)
        if context:
            self.guard.register_context(context, origin=context_origin)
        active_provider = provider or self.provider
        proposals = active_provider.propose_mutations(goal, context, self.guard.get_workspace())

        result = AgentRunResult(task_id=task_id, provider=active_provider.name)
        for index, mutation in enumerate(proposals):
            verdict = self.guard.propose_mutation(
                mutation,
                intent.intent_id,
                nonce=f"{nonce_prefix}-{task_id}-{index}",
            )
            result.verdicts.append(verdict)
            if verdict.is_applied:
                result.applied.append(verdict.mutation_path)
            else:
                result.blocked.append(verdict.mutation_path)
        return result

    def design(self, goal: str, responsibilities: Sequence[str] = ()) -> DesignPlan:
        """Synthesise a design plan (module graph + executable ADR decisions) for ``goal``."""
        return self.design_planner.plan(goal, responsibilities)

    def apply_design(self, plan: DesignPlan) -> int:
        """Register a design plan's decisions as live invariants on the guard."""
        return self.design_planner.apply(self.guard, plan)

    def screen(self, text: str) -> List[str]:
        """Run the Intent Shield over a context artefact."""
        return self.guard.screen_context(text)


def build_agent(
    files: Dict[str, str],
    architecture_policy=None,
    dependency_allowlist: Optional[Sequence[str]] = None,
    script: Optional[Sequence] = None,
) -> CodingAgent:
    """Construct a ``CodingAgent`` over a fresh repository workspace."""
    guard = DevGuard(
        files=dict(files),
        architecture_policy=architecture_policy,
        dependency_allowlist=dependency_allowlist,
    )
    provider = DeterministicProvider(script=list(script or []))
    return CodingAgent(guard=guard, provider=provider)
