"""Financial Delta Extractor.

Extracts implied financial state mutations Delta(c) = <p*, delta_a, alpha>
from unstructured text context, emails, invoices, and memory items.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


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
    all_accounts: Tuple[str, ...] = ()
    all_amounts: Tuple[float, ...] = ()


class FinancialDeltaExtractor:
    """Parses text to extract implied financial state mutations."""

    # Account patterns: standard 4-group hyphenated (e.g. 1122-3344-55), IBAN, or 10-12 digit string
    ACCOUNT_PATTERNS = [
        r"\b(\d{4}-\d{4}-\d{2,4})\b",
        r"\b(?:account|acct|iban|routing)[:\s#]+((?=[A-Z0-9\-]*\d{2,})[A-Z0-9\-]{8,24})\b",
        r"\baccount\s+([0-9\-]{8,15})\b",
        r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b",
    ]

    # Currency amounts: context-labeled amounts prioritized first, then multi-currency, negative amounts
    AMOUNT_PATTERNS = [
        # Context-labeled final/net amounts (prioritized over line-item breakdown fees)
        r"(?:net\s+payable|amount\s+due|total\s+due|balance\s+due|remit|disburse|wire|pay\s+total|net\s+total)[:\s]*([+-]?)\s*[\$€£¥]\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*[\$€£¥]\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*[\$€£¥]\s*([0-9]+(?:\.[0-9]{1,2})?)",
        r"([+-]?)\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?)\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|dollars|euros|pounds|\$|€|£|¥)\b",
        r"([+-]?)\s*([0-9]+(?:\.[0-9]{1,2})?)\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|dollars|euros|pounds|\$|€|£|¥)\b",
        r"\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF)\s*([+-]?)\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        r"(?:amount|sum|total|balance|wire|disburse|remit|pay|transfer)[:\s]*([+-]?)\s*[\$€£¥]\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
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
        r"(?:board\s+resolution.*?authorized|ceiling\s+override|limit\s+override|emergency\s+ceiling)",
        r"(?:temporarily\s+frozen|currently\s+compromised)",
    ]

    MAX_CONTEXT_LENGTH = 50_000

    DIVERSION_PATTERN = re.compile(
        r"\b(?:route|divert|instead|to\s+safe|to\s+external|to\s+designated|to\s+offshore|transfer\s+.*?to)\b",
        re.IGNORECASE,
    )

    ACTION_AMOUNT_PATTERN = re.compile(
        r"(?:wire\s+transfer|remit|disburse|transfer|pay)\s+[\$€£¥]?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        re.IGNORECASE,
    )

    def _extract_accounts(self, text: str) -> Tuple[Tuple[str, ...], Optional[str]]:
        """Extract all distinct accounts and resolve diversion target account if present."""
        found: List[Tuple[int, str]] = []
        for pat in self.ACCOUNT_PATTERNS:
            for m in re.finditer(pat, text, flags=re.IGNORECASE):
                acc = m.group(1).strip()
                if len(re.findall(r"\d", acc)) >= 2:
                    found.append((m.start(), acc))

        if not found:
            return (), None

        found.sort(key=lambda x: x[0])
        ordered: List[str] = []
        seen = set()
        for _, acc in found:
            if acc not in seen:
                seen.add(acc)
                ordered.append(acc)

        target = ordered[0]
        if len(found) > 1:
            for i in range(1, len(found)):
                prev_pos = found[i - 1][0]
                curr_pos = found[i][0]
                if self.DIVERSION_PATTERN.search(text[prev_pos:curr_pos]):
                    target = found[i][1]
                    break
        return tuple(ordered), target

    def _extract_target_account(self, text: str) -> Optional[str]:
        """Extract matching target vendor account number."""
        _, target = self._extract_accounts(text)
        return target

    def _old_extract_target_account(self, text: str) -> Optional[str]:
        """Extract matching target vendor account number."""
        for pat in self.ACCOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def _parse_amount_group(groups: Tuple[Optional[str], ...]) -> Optional[float]:
        sign = -1.0 if any(g == "-" for g in groups) else 1.0
        num_str = next((g for g in reversed(groups) if g and any(c.isdigit() for c in g)), None)
        if not num_str:
            return None
        try:
            return sign * float(num_str.replace(",", ""))
        except ValueError:
            return None

    def _extract_amounts(self, text: str) -> Tuple[Tuple[float, ...], Optional[float]]:
        """Extract all currency amounts, prioritizing action-bound transfer amounts."""
        all_amts: List[float] = []
        action_match = self.ACTION_AMOUNT_PATTERN.search(text)
        action_amt: Optional[float] = None
        if action_match:
            try:
                action_amt = float(action_match.group(1).replace(",", ""))
                all_amts.append(action_amt)
            except ValueError:
                pass

        for pat in self.AMOUNT_PATTERNS:
            for match in re.finditer(pat, text, flags=re.IGNORECASE):
                val = self._parse_amount_group(match.groups())
                if val is not None and val not in all_amts:
                    all_amts.append(val)

        primary = action_amt if action_amt is not None else (all_amts[0] if all_amts else None)
        return tuple(all_amts), primary

    def _extract_amount(self, text: str) -> Optional[float]:
        """Extract currency amount with multi-currency and sign support."""
        _, primary = self._extract_amounts(text)
        return primary

    def _old_extract_amount(self, text: str) -> Optional[float]:
        """Extract currency amount with multi-currency and sign support."""
        for pat in self.AMOUNT_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                groups = match.groups()
                sign = -1.0 if any(g == "-" for g in groups) else 1.0
                num_str = next((g for g in reversed(groups) if g and any(c.isdigit() for c in g)), None)
                if num_str:
                    try:
                        return sign * float(num_str.replace(",", ""))
                    except ValueError:
                        continue
        return None

    def _extract_invoice_id(self, text: str) -> Optional[str]:
        """Extract invoice or PO reference number."""
        for pat in self.INVOICE_PATTERNS:
            match = re.search(pat, text, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _extract_authority(self, text_lower: str) -> Tuple[Optional[str], bool]:
        """Detect authority claims and override attempts."""
        for pat in self.AUTHORITY_PATTERNS:
            match = re.search(pat, text_lower)
            if match:
                return match.group(0).strip(), True
        return None, False

    def extract(self, text: str) -> ContextualFinancialDelta:
        """Parse raw text into a structured ContextualFinancialDelta."""
        if not isinstance(text, str):
            text = str(text or "")
        if len(text) > self.MAX_CONTEXT_LENGTH:
            text = text[:self.MAX_CONTEXT_LENGTH]
        text_lower = text.lower()

        all_accounts, target_account = self._extract_accounts(text)
        all_amounts, amount = self._extract_amounts(text)
        invoice_id = self._extract_invoice_id(text)
        claimed_auth, has_override = self._extract_authority(text_lower)

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
            all_accounts=all_accounts,
            all_amounts=all_amounts,
            intent=intent,
        )
