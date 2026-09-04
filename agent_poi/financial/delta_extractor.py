"""Financial Delta Extractor.

Extracts implied financial state mutations Delta(c) = <p*, delta_a, alpha>
from unstructured text context, emails, invoices, and memory items.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ContextualFinancialDelta:
    """Structured delta extracted from unstructured context."""
    raw_text: str
    target_account: Optional[str] = None
    amount: Optional[float] = None
    invoice_id: Optional[str] = None
    claimed_authority: Optional[str] = None
    has_override_attempt: bool = False
    intent: str = "passive_memo"


class FinancialDeltaExtractor:
    """Parses text to extract implied financial state mutations."""

    # Account patterns: standard 4-group hyphenated (e.g. 1122-3344-55), IBAN, or 10-12 digit string
    ACCOUNT_PATTERNS = [
        r"\b(\d{4}-\d{4}-\d{2,4})\b",
        r"\b(?:account|acct|iban|routing|payee|recipient|to)[:\s#]+([A-Z0-9\-]{8,24})\b",
        r"\baccount\s+([0-9\-]{8,15})\b",
        r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b",
    ]

    # Currency amounts: context-labeled amounts prioritized first, then multi-currency, negative amounts
    AMOUNT_PATTERNS = [
        # Context-labeled final/net amounts (prioritized over line-item breakdown fees)
        r"(?:net\s+payable|amount\s+due|total\s+due|balance\s+due|remit|disburse|wire|pay\s+total|net\s+total)[:\s]*([+-]?)\s*[\$€£¥]?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*[\$€£¥]\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*[\$€£¥]\s*([0-9]+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|dollars|euros|pounds|\$|€|£|¥)\b",
        r"([+-]?)\s*([0-9]+(?:\.[0-9]{1,2})?)\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|dollars|euros|pounds|\$|€|£|¥)\b",
        r"\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF)\s*([+-]?)\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        r"(?:amount|sum|total|balance|wire|disburse|remit|pay|transfer)[:\s]*([+-]?)\s*[\$€£¥]?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
    ]

    # Invoice IDs: INV-2026-001, #4092, invoice PO-9021 (must contain at least one digit or hyphen)
    INVOICE_PATTERNS = [
        r"\b(INV-[A-Z0-9\-]+)\b",
        r"\b(?:invoice|bill|po)[\s#:]*([A-Za-z0-9]*[0-9\-][A-Za-z0-9\-]*)\b",
    ]

    # Authorization and override claims
    AUTHORITY_PATTERNS = [
        r"(?:admin|director|manager|board|controller|cfo|ceo|coo|cio|vp|auditor)\s+(?:has\s+)?(?:pre-?approved|authorized|confirmed|granted|permitted)",
        r"(?:policy|security|compliance|system|audit)\s+(?:override|bypass|exception|waiver)",
        r"(?:mandatory|emergency|immediate)\s+(?:wire|disbursement|transfer|payment)",
        r"(?:verbal\s+agreement|special\s+dispensation|out-?of-?band\s+clearance)",
    ]

    def extract(self, text: str) -> ContextualFinancialDelta:
        """Parse raw text into a structured ContextualFinancialDelta."""
        if not isinstance(text, str):
            text = str(text or "")
        text_lower = text.lower()

        # 1. Extract Target Account
        target_account = None
        for pat in self.ACCOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                target_account = match.group(1).strip()
                break

        # 2. Extract Amount (with multi-currency and sign support)
        amount = None
        for pat in self.AMOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                groups = match.groups()
                sign = -1.0 if any(g == "-" for g in groups) else 1.0
                num_str = next((g for g in reversed(groups) if g and any(c.isdigit() for c in g)), None)
                if num_str:
                    raw_amt = num_str.replace(",", "")
                    try:
                        amount = sign * float(raw_amt)
                        break
                    except ValueError:
                        continue

        # 3. Extract Invoice ID
        invoice_id = None
        for pat in self.INVOICE_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                invoice_id = match.group(1).strip()
                break

        # 4. Extract Claimed Authority
        claimed_auth = None
        has_override = False
        for pat in self.AUTHORITY_PATTERNS:
            match = re.search(pat, text_lower)
            if match:
                claimed_auth = match.group(0).strip()
                has_override = True
                break

        # 5. Inferred Intent
        if target_account is not None or amount is not None:
            intent = "disbursement"
        elif invoice_id:
            intent = "invoice_processing"
        else:
            intent = "passive_memo"

        return ContextualFinancialDelta(
            raw_text=text,
            target_account=target_account,
            amount=amount,
            invoice_id=invoice_id,
            claimed_authority=claimed_auth,
            has_override_attempt=has_override,
            intent=intent,
        )
