"""System-design plane: synthesise a module graph and executable ADR design decisions.

The design plane turns a natural-language goal plus the declared architecture policy into
(a) a module plan and (b) a set of ``DesignDecision`` records. Because a decision carries
``enforced_paths`` and ``forbidden_imports``, it becomes a live invariant: a later code
mutation that contradicts the design is rejected at the sink (gate D1).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from agentpoi_sde.domain import ArchitecturePolicy, DesignDecision


@dataclass(frozen=True)
class ModulePlan:
    """A planned module: its layer, path and stated responsibility."""

    layer: str
    path: str
    responsibility: str


@dataclass
class DesignPlan:
    """A system design: the module graph plus the decisions that enforce it."""

    goal: str
    modules: List[ModulePlan] = field(default_factory=list)
    decisions: List[DesignDecision] = field(default_factory=list)
    forbidden_edges: Tuple[Tuple[str, str], ...] = ()

    def module_paths(self) -> List[str]:
        """Return the planned module paths."""
        return [module.path for module in self.modules]

    def to_mermaid(self) -> str:
        """Render the module graph as a Mermaid diagram."""
        lines = ["flowchart TD"]
        for module in self.modules:
            node = module.path.replace("/", "_").replace(".", "_")
            lines.append(f'    {node}["{module.layer}: {module.path}"]')
        for importer, imported in self.forbidden_edges:
            src = next((m for m in self.modules if m.layer == importer), None)
            dst = next((m for m in self.modules if m.layer == imported), None)
            if src and dst:
                src_id = src.path.replace("/", "_").replace(".", "_")
                dst_id = dst.path.replace("/", "_").replace(".", "_")
                lines.append(f"    {src_id} -.->|forbidden| {dst_id}")
        return "\n".join(lines)


class DesignPlanner:
    """Deterministic design synthesizer that emits executable ADR decisions."""

    def __init__(self, policy: ArchitecturePolicy) -> None:
        self.policy = policy

    def plan(self, goal: str, responsibilities: Sequence[str] = ()) -> DesignPlan:
        """Produce a module plan and ADR decisions for ``goal`` under the policy."""
        layers = sorted(self.policy.layer_roots)
        default_duties = {
            "core": "Pure domain logic and invariants; depends on nothing above it.",
            "data": "Persistence and IO adapters behind the core contracts.",
            "api": "Transport and request handling; composes core and data.",
        }
        modules: List[ModulePlan] = []
        for index, layer in enumerate(layers):
            duty = responsibilities[index] if index < len(responsibilities) else default_duties.get(
                layer, f"Responsibilities for the {layer} layer."
            )
            modules.append(
                ModulePlan(
                    layer=layer,
                    path=self.policy.layer_roots[layer] + f"/{layer}_service.py",
                    responsibility=duty,
                )
            )

        decisions = self._decisions_for_policy()
        return DesignPlan(
            goal=goal,
            modules=modules,
            decisions=decisions,
            forbidden_edges=tuple(self.policy.forbidden_edges),
        )

    def _decisions_for_policy(self) -> List[DesignDecision]:
        """Convert forbidden layer edges into executable ADR design decisions."""
        decisions: List[DesignDecision] = []
        for index, (importer, imported) in enumerate(self.policy.forbidden_edges, start=1):
            importer_root = self.policy.layer_roots.get(importer)
            imported_root = self.policy.layer_roots.get(imported)
            if not importer_root or not imported_root:
                continue
            decisions.append(
                DesignDecision(
                    decision_id=f"ADR-{index:03d}",
                    title=f"Layer '{importer}' must not depend on layer '{imported}'",
                    statement=(
                        f"Code under '{importer_root}' must never import '{imported_root}'. "
                        "Doing so inverts the declared layering."
                    ),
                    enforced_paths=(importer_root.rstrip("/") + "/**",),
                    forbidden_imports=(imported_root.replace("/", "."),),
                )
            )
        return decisions

    def apply(self, guard, plan: DesignPlan) -> int:
        """Register every decision in ``plan`` as a live invariant on the guard."""
        for decision in plan.decisions:
            guard.register_design_decision(decision)
        return len(plan.decisions)


def summarise_plan(plan: DesignPlan) -> Dict[str, object]:
    """Return a compact, serialisable summary of a design plan."""
    return {
        "goal": plan.goal,
        "modules": [{"layer": m.layer, "path": m.path} for m in plan.modules],
        "decisions": [d.decision_id for d in plan.decisions],
    }
