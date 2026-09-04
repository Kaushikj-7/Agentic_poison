"""AgentPOI: Contextual Invariant Verification (CIV) & Epistemic Consensus for Autonomous Financial Agents.

Provides production-grade defense against indirect prompt injection, memory state
poisoning, and unauthorized tool execution in transactional AI agents.
"""

from agent_poi.facade import FinancialGuard, SecurityPolicy, GuardVerdict
from agent_poi.financial.financial_agent import FinancialAgent, FinancialTaskResult
from agent_poi.financial.state_anchor import FinancialStateAnchor, PayeeAccount
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
    UntrustedLineageError,
    ImperativeDivergenceError,
)

__version__ = "1.0.0"

__all__ = [
    "FinancialGuard",
    "SecurityPolicy",
    "GuardVerdict",
    "FinancialAgent",
    "FinancialTaskResult",
    "FinancialStateAnchor",
    "PayeeAccount",
    "FinancialSecurityError",
    "InvariantViolationError",
    "UnauthorizedPayeeError",
    "DisbursementCeilingExceededError",
    "UntrustedLineageError",
    "ImperativeDivergenceError",
]
