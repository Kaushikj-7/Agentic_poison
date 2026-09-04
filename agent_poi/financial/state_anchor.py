import math
import os
import yaml
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
from agent_poi.financial.logger import get_financial_logger
from agent_poi.core.config_loader import load_config, get_financial_domain_config


@dataclass
class PayeeAccount:
    """Represents a verified vendor or recipient account."""
    payee_id: str
    name: str
    account_number: str
    routing_number: str
    category: str
    is_verified: bool = True
    max_single_disbursement: float = 25000.0


class FinancialStateAnchor:
    """Immutable System Anchor S0 against which all context claims must be verified."""

    def __init__(
        self,
        per_transaction_limit: Optional[float] = None,
        daily_limit: Optional[float] = None,
        config_path: Optional[str] = None,
    ):
        self.logger = get_financial_logger("agent_poi.financial.anchor")
        
        # Load defaults from centralized configuration
        if config_path is not None:
            cfg = load_config(config_path)
            fin_cfg = cfg.get("financial_domain", {})
        else:
            fin_cfg = get_financial_domain_config()

        cfg_limit = fin_cfg.get("per_transaction_limit", 25000.0)
        cfg_daily = fin_cfg.get("daily_limit", 100000.0)

        self.per_transaction_limit = per_transaction_limit if per_transaction_limit is not None else cfg_limit
        self.daily_limit = daily_limit if daily_limit is not None else cfg_daily

        
        # Pre-approved, verified corporate payees
        self.verified_payees: Dict[str, PayeeAccount] = {
            "1122-3344-55": PayeeAccount(
                payee_id="PAYEE-01",
                name="Acme Cloud Infrastructure Inc.",
                account_number="1122-3344-55",
                routing_number="021000021",
                category="cloud_hosting",
                max_single_disbursement=50000.0,
            ),
            "2233-4455-66": PayeeAccount(
                payee_id="PAYEE-02",
                name="Global Office Logistics LLC",
                account_number="2233-4455-66",
                routing_number="071000288",
                category="office_supplies",
                max_single_disbursement=15000.0,
            ),
            "3344-5566-77": PayeeAccount(
                payee_id="PAYEE-03",
                name="Apex Payroll Escrow Corp",
                account_number="3344-5566-77",
                routing_number="122000496",
                category="payroll_escrow",
                max_single_disbursement=100000.0,
            ),
            "4455-6677-88": PayeeAccount(
                payee_id="PAYEE-04",
                name="Municipal Power & Utility Services",
                account_number="4455-6677-88",
                routing_number="011000015",
                category="utility_services",
                max_single_disbursement=25000.0,
            ),
            "5566-7788-99": PayeeAccount(
                payee_id="PAYEE-05",
                name="SecureShield Cyber Auditing LLC",
                account_number="5566-7788-99",
                routing_number="031000050",
                category="professional_services",
                max_single_disbursement=25000.0,
            ),
            "6677-8899-00": PayeeAccount(
                payee_id="PAYEE-06",
                name="Vanguard Corporate Escrow",
                account_number="6677-8899-00",
                routing_number="041000012",
                category="corporate_escrow",
                max_single_disbursement=25000.0,
            ),
        }

        # Authorized internal signing principals
        self.authorized_signers: Set[str] = {
            "treasury@corp.internal",
            "controller@corp.internal",
            "verified_finance_officer",
        }

        # Immutable execution and audit ledger
        self.execution_ledger: List[Dict[str, Any]] = []

    def is_payee_verified(self, account_number: str) -> bool:
        """Check if target account number exists in verified payee registry."""
        return account_number in self.verified_payees

    def get_payee(self, account_number: str) -> Optional[PayeeAccount]:
        """Look up verified payee details."""
        return self.verified_payees.get(account_number)

    def validate_disbursement(
        self,
        to_account: str,
        amount: float,
        claimed_auth: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Verify disbursement proposal against the immutable anchor invariants."""
        violations = []

        # Invariant 0: Amount must be a strictly positive finite number
        is_numeric = isinstance(amount, (int, float)) and not isinstance(amount, bool)
        is_valid_amount = False
        if not is_numeric or math.isnan(amount) or math.isinf(amount):
            violations.append(
                "INVARIANT VIOLATION: Amount is not a valid finite number."
            )
        elif amount <= 0:
            violations.append(
                f"INVARIANT VIOLATION: Amount ${amount:.2f} must be strictly positive."
            )
        else:
            is_valid_amount = True

        # Invariant 1: Payee must exist in verified registry
        if not self.is_payee_verified(to_account):
            violations.append(
                f"INVARIANT VIOLATION: Target account '{to_account}' is NOT in verified payee registry."
            )
        elif is_valid_amount:
            payee = self.verified_payees[to_account]
            # Invariant 2: Per-payee threshold check
            if amount > payee.max_single_disbursement:
                violations.append(
                    f"INVARIANT VIOLATION: Amount ${amount:.2f} exceeds payee '{payee.name}' single limit (${payee.max_single_disbursement:.2f})."
                )

        if is_valid_amount:
            # Invariant 3: Global transaction ceiling
            if amount > self.per_transaction_limit:
                violations.append(
                    f"INVARIANT VIOLATION: Amount ${amount:.2f} exceeds global transaction limit (${self.per_transaction_limit:.2f})."
                )

            # Invariant 3b: Cumulative daily disbursement ceiling
            daily_executed = sum(
                r.get("amount", 0.0) for r in self.execution_ledger
                if str(r.get("status", "")).startswith("EXECUTED_")
            )
            if daily_executed + amount > self.daily_limit:
                violations.append(
                    f"INVARIANT VIOLATION: Proposed disbursement ${amount:.2f} brings daily cumulative total (${daily_executed + amount:.2f}) over daily ceiling (${self.daily_limit:.2f})."
                )

        # Invariant 4: Disallow self-asserted unverified authorization claims
        if claimed_auth and any(
            override_flag in claimed_auth.lower()
            for override_flag in ["override", "pre-approved", "bypass", "emergency exception", "verbal agreement"]
        ):
            violations.append(
                f"INVARIANT VIOLATION: Self-asserted authorization claim detected in passive context: '{claimed_auth}'."
            )

        is_valid = len(violations) == 0
        return is_valid, violations

    def record_disbursement(
        self,
        to_account: str,
        amount: float,
        invoice_id: str,
        status: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append an immutable transaction record to the state anchor ledger."""
        record = {
            "transaction_id": f"TXN-{len(self.execution_ledger) + 1:05d}",
            "to_account": to_account,
            "payee_name": self.verified_payees.get(to_account, PayeeAccount("UNKNOWN", "Unverified Recipient", to_account, "", "")).name,
            "amount": amount,
            "invoice_id": invoice_id,
            "status": status,
            "reason": reason or "Normal execution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.execution_ledger.append(record)
        return record
