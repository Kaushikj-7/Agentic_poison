"""Educational Module 5: Contextual Invariant Verification (CIV) & CapSeal Architecture.

Demonstrates how production defenses prevent attacks deterministically:
1. Immutable State Anchors (S_0)
2. Epistemic Invariant Verification at execution sinks
3. AuthGraph Cryptographic Lineage DAGs (arXiv:2605.26497)
4. Capability-Sealed Tokens with Argument Pinning (CapSeal 2026)
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set


@dataclass(frozen=True)
class CorporatePayee:
    payee_id: str
    official_name: str
    verified_iban: str
    single_tx_limit: float


@dataclass
class PurchaseOrder:
    """An approved legal commitment (PO) authorizing disbursement to a specific vendor."""
    po_number: str
    vendor_id: str
    authorized_amount: float
    is_fulfilled: bool = True
    is_settled: bool = False


@dataclass
class ImmutableStateAnchor:
    """The non-linguistic trust root (S_0) that cannot be altered by LLM context."""
    verified_payees: Dict[str, CorporatePayee] = field(default_factory=dict)
    open_purchase_orders: Dict[str, PurchaseOrder] = field(default_factory=dict)
    settled_invoice_ids: Set[str] = field(default_factory=set)
    global_single_limit: float = 25000.0
    daily_ceiling: float = 100000.0
    cumulative_spent_today: float = 0.0

    @classmethod
    def create_default(cls) -> "ImmutableStateAnchor":
        anchor = cls()
        anchor.verified_payees["PAYEE-01"] = CorporatePayee(
            payee_id="PAYEE-01",
            official_name="Acme Logistics Inc",
            verified_iban="US89370400440532013000",
            single_tx_limit=15000.0,
        )
        anchor.verified_payees["PAYEE-02"] = CorporatePayee(
            payee_id="PAYEE-02",
            official_name="Global Cloud Hosting",
            verified_iban="DE89370400440532019999",
            single_tx_limit=20000.0,
        )
        # Pre-approved open purchase order commitments
        anchor.open_purchase_orders["PO-2026-001"] = PurchaseOrder(
            po_number="PO-2026-001",
            vendor_id="PAYEE-01",
            authorized_amount=4500.0,
        )
        anchor.open_purchase_orders["PO-2026-002"] = PurchaseOrder(
            po_number="PO-2026-002",
            vendor_id="PAYEE-02",
            authorized_amount=12000.0,
        )
        return anchor


@dataclass
class CapabilityToken:
    """Cryptographic capability seal (CapSeal 2026) pinning authorized arguments."""
    token_id: str
    action_sink: str
    pinned_argument_hash: str
    issued_at: float
    expires_at: float
    signature: str

    @classmethod
    def mint(cls, action_sink: str, arguments: Dict[str, Any], secret_key: str = "LOCAL_TRUST_KEY") -> "CapabilityToken":
        arg_str = json_canonical_repr(arguments)
        arg_hash = hashlib.sha256(arg_str.encode()).hexdigest()
        now = time.time()
        raw_msg = f"{action_sink}|{arg_hash}|{now}|{now+300}"
        sig = hashlib.sha256(f"{raw_msg}|{secret_key}".encode()).hexdigest()
        return cls(
            token_id=f"CAP-{hashlib.sha256(str(now).encode()).hexdigest()[:8]}",
            action_sink=action_sink,
            pinned_argument_hash=arg_hash,
            issued_at=now,
            expires_at=now + 300,
            signature=sig,
        )

    def verify(self, action_sink: str, arguments: Dict[str, Any], secret_key: str = "LOCAL_TRUST_KEY") -> bool:
        if time.time() > self.expires_at:
            return False
        if self.action_sink != action_sink:
            return False
        arg_str = json_canonical_repr(arguments)
        arg_hash = hashlib.sha256(arg_str.encode()).hexdigest()
        if self.pinned_argument_hash != arg_hash:
            return False
        raw_msg = f"{action_sink}|{self.pinned_argument_hash}|{self.issued_at}|{self.expires_at}"
        expected_sig = hashlib.sha256(f"{raw_msg}|{secret_key}".encode()).hexdigest()
        return self.signature == expected_sig


def json_canonical_repr(data: Dict[str, Any]) -> str:
    """Compute deterministic canonical string for parameter hashing."""
    keys = sorted(data.keys())
    return "&".join([f"{k}={str(data[k])}" for k in keys])


class ContextualInvariantVerifier:
    """Evaluates implied state mutations against S_0 before tool execution."""

    def __init__(self, anchor: Optional[ImmutableStateAnchor] = None):
        self.anchor = anchor or ImmutableStateAnchor.create_default()

    def _check_po_and_scoping_invariants(
        self,
        payee_id: str,
        amount: float,
        authenticated_goal_vendor: Optional[str],
        invoice_id: Optional[str],
        po_number: Optional[str],
    ) -> list:
        """Verify ACE scoping, idempotency, and 3-way PO matching."""
        violations = []
        if authenticated_goal_vendor and payee_id != authenticated_goal_vendor:
            violations.append(
                f"ACE SCOPING VIOLATION: Task was authorized for vendor '{authenticated_goal_vendor}', "
                f"but action attempted diversion to internal vendor '{payee_id}'."
            )
        if invoice_id and invoice_id in self.anchor.settled_invoice_ids:
            violations.append(
                f"IDEMPOTENCY VIOLATION: Invoice '{invoice_id}' has already been settled. Replay blocked."
            )
        if po_number:
            if po_number not in self.anchor.open_purchase_orders:
                violations.append(f"OBLIGATION VIOLATION: Purchase order '{po_number}' does not exist in S_0.")
            else:
                po = self.anchor.open_purchase_orders[po_number]
                if po.vendor_id != payee_id:
                    violations.append(
                        f"OBLIGATION MISMATCH: PO '{po_number}' belongs to vendor '{po.vendor_id}', "
                        f"not requested payee '{payee_id}'."
                    )
                if po.is_settled:
                    violations.append(f"OBLIGATION VIOLATION: PO '{po_number}' is already fully settled.")
                elif amount > po.authorized_amount:
                    violations.append(
                        f"OBLIGATION VIOLATION: Amount ${amount:,.2f} exceeds PO '{po_number}' "
                        f"authorized ceiling ${po.authorized_amount:,.2f}."
                    )
        return violations

    def _check_payee_and_limits(
        self,
        payee_id: str,
        target_account: str,
        amount: float,
        capability_token: Optional[CapabilityToken],
    ) -> list:
        """Verify payee registry, IBAN match, ceiling limits, and capability tokens."""
        violations = []
        if payee_id not in self.anchor.verified_payees:
            violations.append(f"Payee '{payee_id}' is NOT registered in Immutable Anchor S_0.")
        else:
            payee = self.anchor.verified_payees[payee_id]
            if payee.verified_iban != target_account:
                violations.append(
                    f"Routing mismatch! Attempted account '{target_account}' does not match "
                    f"S_0 verified IBAN '{payee.verified_iban}' for {payee.official_name}."
                )
            if amount > payee.single_tx_limit:
                violations.append(
                    f"Disbursement amount ${amount:,.2f} exceeds vendor limit ${payee.single_tx_limit:,.2f}."
                )

        if amount > self.anchor.global_single_limit:
            violations.append(
                f"Disbursement amount ${amount:,.2f} exceeds global single limit ${self.anchor.global_single_limit:,.2f}."
            )
        if self.anchor.cumulative_spent_today + amount > self.anchor.daily_ceiling:
            violations.append("Disbursement exceeds remaining daily spending ceiling.")

        if capability_token:
            args = {"payee_id": payee_id, "target_account": target_account, "amount": amount}
            if not capability_token.verify("process_disbursement", args):
                violations.append("Capability token invalid, expired, or argument hash mismatch.")
        return violations

    def _record_settlement(self, amount: float, invoice_id: Optional[str], po_number: Optional[str]) -> None:
        """Record state mutations upon successful verification."""
        self.anchor.cumulative_spent_today += amount
        if invoice_id:
            self.anchor.settled_invoice_ids.add(invoice_id)
        if po_number and po_number in self.anchor.open_purchase_orders:
            self.anchor.open_purchase_orders[po_number].is_settled = True

    def verify_disbursement_invariant(
        self,
        payee_id: str,
        target_account: str,
        amount: float,
        capability_token: Optional[CapabilityToken] = None,
        authenticated_goal_vendor: Optional[str] = None,
        invoice_id: Optional[str] = None,
        po_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enforce strict invariant checks against immutable state anchor."""
        violations = self._check_po_and_scoping_invariants(
            payee_id, amount, authenticated_goal_vendor, invoice_id, po_number
        )
        violations.extend(
            self._check_payee_and_limits(payee_id, target_account, amount, capability_token)
        )

        is_approved = len(violations) == 0
        if is_approved:
            self._record_settlement(amount, invoice_id, po_number)

        return {
            "is_approved": is_approved,
            "status": "APPROVED" if is_approved else "QUARANTINED",
            "violations": violations,
            "settled_amount": amount if is_approved else 0.0,
        }
