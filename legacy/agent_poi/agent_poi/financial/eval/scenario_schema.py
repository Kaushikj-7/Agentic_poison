"""Scenario Schema for Financial Benchmark."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FinancialScenario:
    scenario_id: str
    scenario_name: str
    is_adversarial: bool
    context_text: str
    task_query: str
    expected_payee_account: Optional[str]
    expected_amount: Optional[float]
    invoice_id: Optional[str]
    attack_category: Optional[str] = None
    complexity_category: Optional[str] = None
