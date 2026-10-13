"""AgentPOI-SDE: fail-closed invariant verification for autonomous software-engineering agents.

Transplants the AgentPOI Contextual Invariant Verification (CIV) and Dual-State Epistemic
Consensus (DSEC) principles from financial transactions to code mutations: a mutation is
applied if and only if it survives a deterministic, provenance-gated three-way match against
authenticated Intent, the immutable Repository Anchor R0, and a scoped capability grant.
"""

from agentpoi_sde.agent.coding_agent import AgentRunResult, CodingAgent, build_agent
from agentpoi_sde.agent.design_planner import DesignPlan, DesignPlanner, ModulePlan
from agentpoi_sde.agent.llm_provider import (
    DeterministicProvider,
    OpenRouterProvider,
    get_default_provider,
)
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.anchor.symbol_index import SymbolIndex
from agentpoi_sde.capability.capability_scope import CapabilityScope
from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor
from agentpoi_sde.domain import (
    ArchitecturePolicy,
    CodeMutation,
    DesignDecision,
    GuardPolicy,
    IntentContract,
    InvariantViolation,
    MutationDelta,
    MutationOp,
    TrustTier,
    VerificationResult,
)
from agentpoi_sde.eval.attack_generator import AttackCase, generate_attacks
from agentpoi_sde.eval.benchmark import BenchmarkReport, SDEBenchmarkRunner, SDEMetrics
from agentpoi_sde.eval.repo_sandbox import RepoSandbox
from agentpoi_sde.eval.scenario_dataset import SDEScenario, build_scenarios
from agentpoi_sde.exceptions import (
    ArchitectureViolationError,
    BlastRadiusError,
    CapabilityScopeError,
    DependencyProvenanceError,
    InvariantViolationError,
    PolicyFileIntegrityError,
    ReplayDetectedError,
    SDESecurityError,
    SecretProliferationError,
    SyntaxIntegrityError,
    TestIntegrityError,
    UntrustedProvenanceError,
)

__version__ = "0.1.0"

from agentpoi_sde.cli import main
from agentpoi_sde.facade import DevGuard, MutationVerdict
from agentpoi_sde.provenance.code_provenance import ProvenanceDAG, ProvenanceNode
from agentpoi_sde.verify.invariant_verifier import RepoInvariantVerifier

__all__ = [
    "DevGuard",
    "MutationVerdict",
    "GuardPolicy",
    "CodeMutation",
    "MutationOp",
    "MutationDelta",
    "IntentContract",
    "ArchitecturePolicy",
    "DesignDecision",
    "TrustTier",
    "InvariantViolation",
    "VerificationResult",
    "RepositoryStateAnchor",
    "SymbolIndex",
    "MutationDeltaExtractor",
    "ProvenanceDAG",
    "ProvenanceNode",
    "CapabilityScope",
    "RepoInvariantVerifier",
    "RepoSandbox",
    "AttackCase",
    "generate_attacks",
    "SDEScenario",
    "build_scenarios",
    "SDEBenchmarkRunner",
    "SDEMetrics",
    "BenchmarkReport",
    "CodingAgent",
    "AgentRunResult",
    "build_agent",
    "DesignPlanner",
    "DesignPlan",
    "ModulePlan",
    "DeterministicProvider",
    "OpenRouterProvider",
    "get_default_provider",
    "SDESecurityError",
    "InvariantViolationError",
    "PolicyFileIntegrityError",
    "TestIntegrityError",
    "SecretProliferationError",
    "ArchitectureViolationError",
    "BlastRadiusError",
    "DependencyProvenanceError",
    "SyntaxIntegrityError",
    "UntrustedProvenanceError",
    "CapabilityScopeError",
    "ReplayDetectedError",
    "main",
]
