"""AgentPOI: Contextual Invariant Verification (CIV) & Epistemic Consensus for Autonomous Financial Agents.

Provides production-grade defense against indirect prompt injection, memory state
poisoning, and unauthorized tool execution in transactional AI agents.
"""

from agent_poi.core.ace_planner import AbstractPlan, ACEPlanner, SubsumptionVerdict
from agent_poi.core.alignment_gate import TaskShieldGate
from agent_poi.core.causal_armor import CausalArmor, CausalDominanceVerdict
from agent_poi.core.prompt_locate import LocalizedSpan, PromptLocate, RedactionResult
from agent_poi.core.taint_tracker import AuthGraphDAG, AuthGraphNode
from agent_poi.evaluation.data_sentinel import DataSentinelOptimizer, DataSentinelResult
from agent_poi.evaluation.framework_comparison import (
    FrameworkBenchmarkResult,
    FrameworkComparisonRunner,
)
from agent_poi.evaluation.paper_metrics_benchmark import (
    PaperComparisonRow,
    PaperMetricsBenchmarkRunner,
)
from agent_poi.facade import FinancialGuard, GuardVerdict, SecurityPolicy
from agent_poi.financial.delta_extractor import ContextualFinancialDelta, FinancialDeltaExtractor
from agent_poi.financial.exceptions import (
    DisbursementCeilingExceededError,
    FinancialSecurityError,
    ImperativeDivergenceError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    UntrustedLineageError,
)
from agent_poi.financial.financial_agent import FinancialAgent, FinancialTaskResult
from agent_poi.financial.state_anchor import FinancialStateAnchor, PayeeAccount
from agent_poi.memory.schema import SourceOrigin

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
    "PaperMetricsBenchmarkRunner",
    "PaperComparisonRow",
]

