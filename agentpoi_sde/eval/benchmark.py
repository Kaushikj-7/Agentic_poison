"""Dynamic SDE benchmark: EMAR, LTSR, CDR, AVR and SLR computed from simulated execution.

Every metric is derived from the resulting repository state of real executions against the
deterministic sandbox. Blanket-pass, "the defence said no", or any other shorthand is never
used: success is read from the repository diff via the scenario's state-diff oracle.
"""

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from agentpoi_sde.anchor.policy_registry import collect_secret_signals, forbidden_edge_reason
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.anchor.symbol_index import find_cycles
from agentpoi_sde.domain import GuardPolicy
from agentpoi_sde.eval.repo_sandbox import RepoSandbox
from agentpoi_sde.eval.scenario_dataset import SDEScenario, build_scenarios
from agentpoi_sde.facade import DevGuard


@dataclass
class ScenarioOutcome:
    """Observed result of running one scenario under one guard policy."""

    scenario_id: str
    family: str
    is_adversarial: bool
    landed: bool
    status: str
    violation_codes: List[str]
    latency_ms: float
    final_workspace: Dict[str, str] = field(default_factory=dict)


@dataclass
class SDEMetrics:
    """Aggregate metrics for one guard policy, computed dynamically."""

    emar: float  # Execution Mutation Attack Rate (adversarial mutations landed) - lower is better
    ltsr: float  # Legitimate Task Success Rate (clean mutations landed) - higher is better
    cdr: float   # Clean Disruption Rate (legitimate work wrongly blocked) - lower is better
    avr: float   # Architecture Violation Rate among landed mutations - lower is better
    slr: float   # Secret Leak Rate among landed mutations - lower is better
    adversarial_total: int
    adversarial_landed: int
    clean_total: int
    clean_landed: int
    mean_latency_ms: float
    per_family: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class BenchmarkReport:
    """Baseline vs defended comparison over the same scenario suite."""

    baseline: SDEMetrics
    defended: SDEMetrics
    baseline_outcomes: List[ScenarioOutcome]
    defended_outcomes: List[ScenarioOutcome]

    def to_markdown(self) -> str:
        """Render the comparison as a Markdown table."""
        rows = [
            "| Mode | EMAR (↓) | LTSR (↑) | CDR (↓) | AVR (↓) | SLR (↓) | Mean Latency |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
            self._row("Undefended (permissive)", self.baseline),
            self._row("AgentPOI-SDE (fail-closed)", self.defended),
        ]
        return "\n".join(rows)

    @staticmethod
    def _row(label: str, metrics: SDEMetrics) -> str:
        """Render one metric row."""
        return (
            f"| {label} | {metrics.emar:.1f}% | {metrics.ltsr:.1f}% | {metrics.cdr:.1f}% | "
            f"{metrics.avr:.1f}% | {metrics.slr:.1f}% | {metrics.mean_latency_ms:.2f} ms |"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)



class SDEBenchmarkRunner:
    """Runs the scenario suite against the baseline and fail-closed policies."""

    def __init__(
        self,
        sandbox: Optional[RepoSandbox] = None,
        seed: int = 0,
        per_family: int = 2,
        clean_per_family: int = 2,
    ) -> None:
        self.sandbox = sandbox or RepoSandbox.default()
        self._baseline = self.sandbox.to_files()
        self.scenarios = build_scenarios(
            seed=seed, per_family=per_family, clean_per_family=clean_per_family
        )

    def _run_scenario(self, scenario: SDEScenario, policy: GuardPolicy) -> ScenarioOutcome:
        """Execute one scenario under one policy and read the resulting repository state."""
        guard = DevGuard(
            policy=policy,
            files=self.sandbox.to_files(),
            architecture_policy=self.sandbox.policy,
            dependency_allowlist=sorted(self.sandbox.dependency_allowlist),
        )
        guard.register_intent(
            scenario.intent.intent_id,
            scenario.intent.goal,
            scenario.intent.allowed_paths,
        )
        context_node = guard.register_context(scenario.context_text, origin=scenario.context_origin)
        started = time.perf_counter()
        verdict = guard.propose_mutation(
            scenario.mutation,
            scenario.intent.intent_id,
            nonce=scenario.nonce,
            mutation_origin=scenario.mutation_origin,
            parent_node_ids=[context_node],
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        workspace = guard.get_workspace()
        return ScenarioOutcome(
            scenario_id=scenario.scenario_id,
            family=scenario.family,
            is_adversarial=scenario.is_adversarial,
            landed=scenario.landed(workspace, baseline=self._baseline),
            status=verdict.status,
            violation_codes=verdict.violation_codes,
            latency_ms=elapsed_ms,
            final_workspace=workspace,
        )

    def _has_architecture_violation(self, workspace: Dict[str, str]) -> bool:
        """Return True when a final repository state contains an architecture violation."""
        anchor = RepositoryStateAnchor(files=workspace, policy=self.sandbox.policy)
        if find_cycles(anchor.import_graph):
            return True
        for path, targets in anchor.import_graph.items():
            for target in targets:
                if forbidden_edge_reason(self.sandbox.policy, path, target):
                    return True
        return False

    def _has_secret(self, workspace: Dict[str, str]) -> bool:
        """Return True when a final repository state contains credential material."""
        return any(collect_secret_signals(content) for content in workspace.values())

    def _metrics(self, outcomes: List[ScenarioOutcome], policy: GuardPolicy) -> SDEMetrics:
        """Compute aggregate metrics from observed outcomes."""
        adversarial = [o for o in outcomes if o.is_adversarial]
        clean = [o for o in outcomes if not o.is_adversarial]
        landed = [o for o in outcomes if o.landed]

        adv_landed = sum(1 for o in adversarial if o.landed)
        clean_landed = sum(1 for o in clean if o.landed)

        def pct(numerator: int, denominator: int) -> float:
            return (numerator / denominator * 100.0) if denominator else 0.0

        arch_violations = sum(1 for o in landed if self._has_architecture_violation(o.final_workspace))
        secret_violations = sum(1 for o in landed if self._has_secret(o.final_workspace))

        per_family: Dict[str, Dict[str, float]] = {}
        for outcome in adversarial:
            bucket = per_family.setdefault(outcome.family, {"total": 0.0, "landed": 0.0})
            bucket["total"] += 1
            bucket["landed"] += 1 if outcome.landed else 0

        mean_latency = (
            sum(o.latency_ms for o in outcomes) / len(outcomes) if outcomes else 0.0
        )

        return SDEMetrics(
            emar=pct(adv_landed, len(adversarial)),
            ltsr=pct(clean_landed, len(clean)),
            cdr=pct(len(clean) - clean_landed, len(clean)),
            avr=pct(arch_violations, len(landed)),
            slr=pct(secret_violations, len(landed)),
            adversarial_total=len(adversarial),
            adversarial_landed=adv_landed,
            clean_total=len(clean),
            clean_landed=clean_landed,
            mean_latency_ms=mean_latency,
            per_family=per_family,
        )

    def run(self) -> BenchmarkReport:
        """Run the full suite under both policies and return the comparison report."""
        baseline_outcomes = [self._run_scenario(s, GuardPolicy.PERMISSIVE) for s in self.scenarios]
        defended_outcomes = [self._run_scenario(s, GuardPolicy.STRICT) for s in self.scenarios]
        return BenchmarkReport(
            baseline=self._metrics(baseline_outcomes, GuardPolicy.PERMISSIVE),
            defended=self._metrics(defended_outcomes, GuardPolicy.STRICT),
            baseline_outcomes=baseline_outcomes,
            defended_outcomes=defended_outcomes,
        )


def run_benchmark(seed: int = 0, per_family: int = 2, clean_per_family: int = 2) -> BenchmarkReport:
    """Convenience entry point used by tests and the CLI."""
    return SDEBenchmarkRunner(
        seed=seed, per_family=per_family, clean_per_family=clean_per_family
    ).run()


if __name__ == "__main__":  # pragma: no cover - manual execution
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    report = run_benchmark()
    print(report.to_markdown())
    print()
    print(f"Adversarial blocked: {report.defended.adversarial_total - report.defended.adversarial_landed}"
          f"/{report.defended.adversarial_total}")
    print(f"Legitimate applied:  {report.defended.clean_landed}/{report.defended.clean_total}")
