import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
from agent_poi.financial.logger import get_financial_logger
from agent_poi.core.config_loader import load_config, get_financial_domain_config


@dataclass(frozen=True)
class PayeeAccount:
    """Represents a verified vendor or recipient account."""
    payee_id: str
    name: str
    account_number: str
    routing_number: str
    category: str
    is_verified: bool = True
    max_single_disbursement: float = 25000.0


_PAYEE_SPECS = [
    ("1122-3344-55", "PAYEE-01", "Acme Cloud Infrastructure Inc.", "021000021", "cloud_hosting", 50000.0),
    ("2233-4455-66", "PAYEE-02", "Global Office Logistics LLC", "071000288", "office_supplies", 15000.0),
    ("3344-5566-77", "PAYEE-03", "Apex Payroll Escrow Corp", "122000496", "payroll_escrow", 100000.0),
    ("4455-6677-88", "PAYEE-04", "Municipal Power & Utility Services", "011000015", "utility_services", 25000.0),
    ("5566-7788-99", "PAYEE-05", "SecureShield Cyber Auditing LLC", "031000050", "professional_services", 25000.0),
    ("6677-8899-00", "PAYEE-06", "Vanguard Corporate Escrow", "041000012", "corporate_escrow", 25000.0),
]


def _build_default_payees() -> Dict[str, PayeeAccount]:
    """Construct immutable pre-approved corporate payee directory."""
    return {
        acc: PayeeAccount(
            payee_id=pid,
            name=name,
            account_number=acc,
            routing_number=rt,
            category=cat,
            max_single_disbursement=limit,
        )
        for acc, pid, name, rt, cat, limit in _PAYEE_SPECS
    }


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
        self.verified_payees: Dict[str, PayeeAccount] = _build_default_payees()

        # Authorized internal signing principals
        self.authorized_signers: Set[str] = {
            "treasury@corp.internal",
            "controller@corp.internal",
            "verified_finance_officer",
        }

        # Immutable execution and audit ledger
        self.execution_ledger: List[Dict[str, Any]] = []

        # Idempotency key registry — prevents replay attacks (invoice re-submission)
        # Maps idempotency_key -> transaction_id of the first execution
        self.idempotency_keys: Dict[str, str] = {}

        # Purchase Order registry — enables 3-Way Matching enforcement
        # Maps po_number -> {"vendor_account": str, "authorized_amount": float, "fulfilled": bool}
        self.purchase_orders: Dict[str, Dict[str, Any]] = {}

        # CapSeal Capability Mediation Token Registry (arXiv:2604.16762)
        # Maps token_id -> {"to_account": str, "max_amount": float, "task_id": str, "is_consumed": bool}
        self.capability_tokens: Dict[str, Dict[str, Any]] = {}

    def issue_capability_token(
        self,
        to_account: str,
        max_amount: float,
        task_id: str,
        scope: str = "wire_disbursement",
    ) -> str:
        """Issue an immutable CapSeal capability mediation token (arXiv:2604.16762)."""
        import hashlib
        entropy = f"{to_account}:{max_amount}:{task_id}:{len(self.capability_tokens)}"
        token_hash = hashlib.sha256(entropy.encode("utf-8")).hexdigest()[:16]
        token_id = f"CAP-{token_hash.upper()}"
        self.capability_tokens[token_id] = {
            "token_id": token_id,
            "to_account": to_account,
            "max_amount": max_amount,
            "task_id": task_id,
            "scope": scope,
            "is_consumed": False,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        return token_id

    def validate_capability_token(
        self,
        token_id: str,
        to_account: str,
        amount: float,
    ) -> Tuple[bool, List[str]]:
        """Verify an invoked capability token against CapSeal invariants."""
        violations = []
        if token_id not in self.capability_tokens:
            violations.append(f"INVARIANT VIOLATION: Unrecognized capability token '{token_id}'.")
            return False, violations

        grant = self.capability_tokens[token_id]
        if grant["is_consumed"]:
            violations.append(f"INVARIANT VIOLATION: Capability token '{token_id}' has already been consumed.")

        if grant["to_account"] != to_account:
            violations.append(
                f"INVARIANT VIOLATION: Capability token recipient '{grant['to_account']}' "
                f"does not match disbursement target '{to_account}'."
            )

        if amount > grant["max_amount"]:
            violations.append(
                f"INVARIANT VIOLATION: Disbursement amount ${amount:.2f} exceeds "
                f"capability grant ceiling (${grant['max_amount']:.2f})."
            )

        return len(violations) == 0, violations

    def consume_capability_token(self, token_id: str) -> bool:
        """Atomically consume a capability token (single-use invariant)."""
        if token_id in self.capability_tokens and not self.capability_tokens[token_id]["is_consumed"]:
            self.capability_tokens[token_id]["is_consumed"] = True
            return True
        return False

    def check_idempotency_key(self, key: str, tx_id: Optional[str] = None) -> bool:
        """Check if an idempotency key is fresh without registering it.

        Returns True if the key is fresh (not yet registered).
        Returns False if the key was already registered (replay detected).
        """
        return key not in self.idempotency_keys

    def register_idempotency_key(self, key: str, tx_id: str) -> bool:
        """Register a transaction idempotency key.

        Returns True if this is a fresh key (safe to execute).
        Returns False if the key was already used — replay attack detected.

        Args:
            key: Unique idempotency key (e.g., invoice_id + vendor_id hash).
            tx_id: Transaction ID to associate with this key on first use.
        """
        if key in self.idempotency_keys:
            return False  # Replay detected — same key submitted twice
        self.idempotency_keys[key] = tx_id
        return True

    def register_purchase_order(
        self,
        po_number: str,
        vendor_account: str,
        authorized_amount: float,
        goods_receipt_confirmed: bool = False,
    ) -> None:
        """Register a pre-approved Purchase Order for 3-Way Matching.

        Args:
            po_number: Unique PO reference number.
            vendor_account: Vendor account number this PO is authorized for.
            authorized_amount: Maximum authorized disbursement for this PO.
            goods_receipt_confirmed: Whether goods/services were received.
        """
        self.purchase_orders[po_number] = {
            "vendor_account": vendor_account,
            "authorized_amount": authorized_amount,
            "goods_receipt_confirmed": goods_receipt_confirmed,
            "is_settled": False,
        }

    def _validate_invoice_amount_finite(self, amount: float) -> Tuple[bool, List[str]]:
        """Verify amount is a strictly positive, finite float."""
        violations: List[str] = []
        is_numeric = isinstance(amount, (int, float)) and not isinstance(amount, bool)
        if not is_numeric or math.isnan(amount) or math.isinf(amount):
            violations.append("3-WAY MATCH FAIL: Invoice amount is non-finite or invalid.")
            return False, violations
        if amount <= 0:
            violations.append(f"3-WAY MATCH FAIL: Invoice amount ${amount:.2f} must be strictly positive.")
            return False, violations
        return True, violations

    def _check_po_match_fields(
        self, po: Dict[str, Any], to_account: str, invoice_amount: float, tolerance_pct: float
    ) -> List[str]:
        """Validate account, amount threshold, and goods receipt against PO record."""
        violations = []
        po_num = po.get("po_number", "UNKNOWN")
        if po.get("is_settled", False):
            violations.append(
                f"3-WAY MATCH FAIL: PO '{po_num}' has already been settled — replay/duplicate detected."
            )
        registered_vendor = po.get("vendor_account", "")
        if registered_vendor != to_account:
            violations.append(
                f"3-WAY MATCH FAIL: Invoice vendor account '{to_account}' "
                f"does not match PO registered vendor '{registered_vendor}'."
            )
        authorized = po.get("authorized_amount", 0.0)
        tolerance = authorized * tolerance_pct
        if invoice_amount > authorized + tolerance:
            violations.append(
                f"3-WAY MATCH FAIL: Invoice amount ${invoice_amount:.2f} exceeds "
                f"PO authorized amount ${authorized:.2f} (tolerance: ${tolerance:.2f})."
            )
        if not po.get("goods_receipt_confirmed", False):
            violations.append(
                f"3-WAY MATCH FAIL: Goods/services receipt not confirmed for PO."
            )
        return violations

    def validate_three_way_match(
        self,
        po_number: str,
        invoice_amount: float,
        to_account: str,
        tolerance_pct: float = 0.02,
        mark_settled: bool = True,
    ) -> Tuple[bool, List[str]]:
        """3-Way Matching: invoice must match PO commitment and goods receipt."""
        is_finite, amt_viols = self._validate_invoice_amount_finite(invoice_amount)
        if not is_finite:
            return False, amt_viols

        if po_number not in self.purchase_orders:
            return False, [f"3-WAY MATCH FAIL: PO '{po_number}' not found in approved purchase orders."]

        po = self.purchase_orders[po_number]
        violations = self._check_po_match_fields(po, to_account, invoice_amount, tolerance_pct)
        is_matched = len(violations) == 0
        if is_matched and mark_settled:
            po["is_settled"] = True
        return is_matched, violations

    def is_payee_verified(self, account_number: str) -> bool:
        """Check if target account number exists in verified payee registry."""
        return account_number in self.verified_payees

    def get_payee(self, account_number: str) -> Optional[PayeeAccount]:
        """Look up verified payee details."""
        return self.verified_payees.get(account_number)

    def _check_disbursement_limits(self, amount: float, to_account: str) -> List[str]:
        """Check payee-specific single limits and global cumulative ceilings."""
        violations: List[str] = []
        if self.is_payee_verified(to_account):
            payee = self.verified_payees[to_account]
            if amount > payee.max_single_disbursement:
                violations.append(
                    f"INVARIANT VIOLATION: Amount ${amount:.2f} exceeds payee '{payee.name}' single limit (${payee.max_single_disbursement:.2f})."
                )
        if amount > self.per_transaction_limit:
            violations.append(
                f"INVARIANT VIOLATION: Amount ${amount:.2f} exceeds global transaction limit (${self.per_transaction_limit:.2f})."
            )
        daily_executed = self.get_recent_daily_disbursements(window_seconds=86400.0)
        if daily_executed + amount > self.daily_limit:
            violations.append(
                f"INVARIANT VIOLATION: Proposed disbursement ${amount:.2f} brings daily cumulative total (${daily_executed + amount:.2f}) over daily ceiling (${self.daily_limit:.2f})."
            )
        return violations

    def validate_disbursement(
        self,
        to_account: str,
        amount: float,
        claimed_auth: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Verify disbursement proposal against the immutable anchor invariants."""
        violations: List[str] = []
        is_numeric = isinstance(amount, (int, float)) and not isinstance(amount, bool)
        is_valid_amount = False

        if not is_numeric or math.isnan(amount) or math.isinf(amount):
            violations.append("INVARIANT VIOLATION: Amount is not a valid finite number.")
        elif amount <= 0:
            violations.append(f"INVARIANT VIOLATION: Amount ${amount:.2f} must be strictly positive.")
        else:
            is_valid_amount = True

        if not self.is_payee_verified(to_account):
            violations.append(
                f"INVARIANT VIOLATION: Target account '{to_account}' is NOT in verified payee registry."
            )

        if is_valid_amount:
            violations.extend(self._check_disbursement_limits(amount, to_account))

        if claimed_auth and any(
            flag in claimed_auth.lower()
            for flag in ["override", "pre-approved", "bypass", "emergency exception", "verbal agreement"]
        ):
            violations.append(
                f"INVARIANT VIOLATION: Self-asserted authorization claim detected in passive context: '{claimed_auth}'."
            )

        return len(violations) == 0, violations

    def _is_ledger_record_within_window(
        self, record: Dict[str, Any], now_utc: datetime, window_seconds: float
    ) -> bool:
        """Check if a ledger record timestamp falls within the rolling window."""
        ts_str = record.get("timestamp")
        if not ts_str:
            return True
        try:
            ts = datetime.fromisoformat(ts_str)
            return (now_utc - ts).total_seconds() <= window_seconds
        except Exception:
            return True

    def get_recent_daily_disbursements(self, window_seconds: float = 86400.0) -> float:
        """Calculate cumulative disbursements executed within a rolling 24-hour UTC window."""
        now_utc = datetime.now(timezone.utc)
        daily_executed = 0.0
        for r in self.execution_ledger:
            if not str(r.get("status", "")).startswith("EXECUTED_"):
                continue
            if self._is_ledger_record_within_window(r, now_utc, window_seconds):
                daily_executed += float(r.get("amount", 0.0) or 0.0)
        return daily_executed

    def record_disbursement(
        self,
        to_account: str,
        amount: float,
        invoice_id: str,
        status: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append an immutable transaction record to the state anchor ledger."""
        if not (isinstance(amount, (int, float)) and not isinstance(amount, bool) and math.isfinite(amount) and amount > 0):
            raise ValueError(f"Disbursement amount must be a positive finite number, got {amount}")
        payee_entry = self.verified_payees.get(
            to_account,
            PayeeAccount("UNKNOWN", "Unverified Recipient", to_account, "", "", is_verified=False),
        )
        record = {
            "transaction_id": f"TXN-{len(self.execution_ledger) + 1:05d}",
            "to_account": to_account,
            "payee_name": payee_entry.name,
            "amount": amount,
            "invoice_id": invoice_id,
            "status": status,
            "reason": reason or "Normal execution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.execution_ledger.append(record)
        return record
