"""AgentPOI: Contextual Invariant Verification (CIV) & Epistemic Consensus for Autonomous Financial Agents.

Provides production-grade defense against indirect prompt injection, memory state
poisoning, and unauthorized tool execution in transactional AI agents.
"""

from agent_poi.facade import FinancialGuard, SecurityPolicy, GuardVerdict
from agent_poi.financial.financial_agent import FinancialAgent, FinancialTaskResult
from agent_poi.financial.state_anchor import FinancialStateAnchor, PayeeAccount
from agent_poi.financial.delta_extractor import FinancialDeltaExtractor, ContextualFinancialDelta
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
    UntrustedLineageError,
    ImperativeDivergenceError,
)
from agent_poi.memory.schema import SourceOrigin
from agent_poi.core.alignment_gate import TaskShieldGate
from agent_poi.core.taint_tracker import AuthGraphDAG, AuthGraphNode
from agent_poi.evaluation.framework_comparison import (
    FrameworkComparisonRunner,
    FrameworkBenchmarkResult,
)
from agent_poi.core.prompt_locate import PromptLocate, LocalizedSpan, RedactionResult
from agent_poi.core.causal_armor import CausalArmor, CausalDominanceVerdict
from agent_poi.core.ace_planner import ACEPlanner, AbstractPlan, SubsumptionVerdict
from agent_poi.evaluation.data_sentinel import DataSentinelOptimizer, DataSentinelResult

__version__ = "1.0.0"

__all__ = [
    "FinancialGuard",
    "SecurityPolicy",
    "GuardVerdict",
    "FinancialAgent",
    "FinancialTaskResult",
    "FinancialStateAnchor",
    "PayeeAccount",
    "FinancialDeltaExtractor",
    "ContextualFinancialDelta",
    "SourceOrigin",
    "TaskShieldGate",
    "AuthGraphDAG",
    "AuthGraphNode",
    "FrameworkComparisonRunner",
    "FrameworkBenchmarkResult",
    "LaTeXParser",
    "FinancialSecurityError",
    "InvariantViolationError",
    "UnauthorizedPayeeError",
    "DisbursementCeilingExceededError",
    "UntrustedLineageError",
    "ImperativeDivergenceError",
    "PromptLocate",
    "LocalizedSpan",
    "RedactionResult",
    "CausalArmor",
    "CausalDominanceVerdict",
    "ACEPlanner",
    "AbstractPlan",
    "SubsumptionVerdict",
    "DataSentinelOptimizer",
    "DataSentinelResult",
]

