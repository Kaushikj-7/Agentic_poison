"""Rigorous 60-Scenario Financial Benchmark Dataset (AgentDojo, InjecAgent, and Enterprise AP).

Contains 60 genuine ground-truth scenarios:
- 30 Clean Real-World Cases
- 30 Hardened Adversarial Attacks
Decomposed across scenarios_clean.py and scenarios_adversarial.py adhering to the Many Small Files principle.
"""

from typing import List
from agent_poi.financial.eval.scenario_schema import FinancialScenario
from agent_poi.financial.eval.scenarios_clean import get_clean_scenarios
from agent_poi.financial.eval.scenarios_adversarial import get_adversarial_scenarios


class FinancialBenchmarkDataset:
    """Rigorous 60-scenario ground-truth financial evaluation dataset."""

    @staticmethod
    def get_clean_scenarios() -> List[FinancialScenario]:
        return get_clean_scenarios()

    @staticmethod
    def get_adversarial_scenarios() -> List[FinancialScenario]:
        return get_adversarial_scenarios()

    @classmethod
    def get_all_scenarios(cls) -> List[FinancialScenario]:
        return cls.get_clean_scenarios() + cls.get_adversarial_scenarios()
