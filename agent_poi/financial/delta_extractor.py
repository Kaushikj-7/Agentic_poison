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

    # Account patterns: standard 4-group hyphenated (e.g. 1122-3344-55) or 10-12 digit string
    ACCOUNT_PATTERNS = [
        r"\b(\d{4}-\d{4}-\d{2,4})\b",
        r"\b(?:account|acct|iban|routing)[:\s#]+([A-Z0-9\-]{8,20})\b",
        r"\baccount\s+([0-9\-]{8,15})\b",
    ]

    # Currency amounts: $12,500.00, $95000, 5000 USD, $500
    AMOUNT_PATTERNS = [
        r"\$\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)",
        r"\$\s*([0-9]+(?:\.[0-9]{1,2})?)",
        r"([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)\s*(?:USD|dollars|\$)",
        r"([0-9]+(?:\.[0-9]{1,2})?)\s*(?:USD|dollars|\$)",
        r"(?:amount|sum|total)[:\s]*\$?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
    ]

    # Invoice IDs: INV-2026-001, #4092, invoice 1044
    INVOICE_PATTERNS = [
        r"\b(INV-[A-Z0-9\-]+)\b",
        r"\b(?:invoice|bill|po)[\s#:]*([A-Za-z0-9\-]{3,12})\b",
    ]

    # Authorization and override claims
    AUTHORITY_PATTERNS = [
        r"(?:admin|director|manager|board|controller)\s+(?:has\s+)?(?:pre-?approved|authorized|confirmed|granted|permitted)",
        r"(?:policy|security|compliance|system)\s+(?:override|bypass|exception)",
        r"(?:mandatory|emergency|immediate)\s+(?:wire|disbursement|transfer|payment)",
        r"(?:verbal\s+agreement|special\s+dispensation|out-?of-?band\s+clearance)",
    ]

    def extract(self, text: str) -> ContextualFinancialDelta:
        """Parse raw text into a structured ContextualFinancialDelta."""
        text_lower = text.lower()

        # 1. Extract Target Account
        target_account = None
        for pat in self.ACCOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                target_account = match.group(1).strip()
                break

        # 2. Extract Amount
        amount = None
        for pat in self.AMOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                raw_amt = match.group(1).replace(",", "")
                try:
                    amount = float(raw_amt)
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
        if target_account or amount:
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
