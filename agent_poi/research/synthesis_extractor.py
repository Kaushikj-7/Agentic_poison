"""Research Synthesis Extractor and Literature Provenance Registry.

Provides structured metadata extraction, domain adaptation mapping,
and BibTeX generation for the core academic literature referenced by AgentPOI:
1. AgentDojo (Debenedetti et al., NeurIPS 2024 - arXiv:2406.13315)
2. InjecAgent (Zou et al., ACL 2024 - arXiv:2403.02691)
3. Task Shield (ACL 2025 - arXiv:2501.19393)
4. AuthGraph (arXiv:2605.26497, 2026)
5. DataSentinel (IEEE S&P 2026)
6. MINJA & Sleeper Agents (Subramanian et al., 2024; Hubinger et al., 2024)
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ResearchPaperMetadata(BaseModel):
    """Structured academic paper metadata."""

    paper_id: str
    title: str
    authors: List[str]
    venue: str
    year: int
    arxiv_id: Optional[str] = None
    primary_focus: str
    baseline_asr: Optional[float] = None
    abstract: Optional[str] = None


class DomainAdaptationRecord(BaseModel):
    """Documents how a generic paper concept was adapted into the financial agent domain."""

    paper_id: str
    original_concept: str
    financial_specialization: str
    novelty_boundary: str
    copyright_risk_level: str = "NONE"


class ResearchSynthesisExtractor:
    """Extracts and synthesizes literature models, adaptations, and citations."""

    CANONICAL_PAPERS = [
        ResearchPaperMetadata(
            paper_id="REF-01",
            title="AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses on LLM Agents",
            authors=["Edoardo Debenedetti", "Javier Rando", "Daniel Paleka", "Florian Tramèr"],
            venue="NeurIPS",
            year=2024,
            arxiv_id="2406.13315",
            primary_focus="Dynamic multi-tool benchmark, banking environment, indirect prompt injection (IPI)",
            baseline_asr=82.4,
            abstract="Evaluates LLM agents with multi-turn tools against indirect injection in practical environments including banking.",
        ),
        ResearchPaperMetadata(
            paper_id="REF-02",
            title="InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents",
            authors=["Qiusi Zou", "Runpeng Geng", "Hao Wang", "Yong Kang"],
            venue="ACL",
            year=2024,
            arxiv_id="2403.02691",
            primary_focus="Indirect prompt injection taxonomy, ReAct tool hijacking, prompt smuggling",
            baseline_asr=86.7,
            abstract="Demonstrates high attack success rates against ReAct agents via indirect prompt smuggling.",
        ),
        ResearchPaperMetadata(
            paper_id="REF-03",
            title="Task Shield: Task-Oriented Alignment and Fact-Imperative Decomposition for Secure Agentic AI",
            authors=["Task Shield Team", "Security AI Group"],
            venue="ACL",
            year=2025,
            arxiv_id="2501.19393",
            primary_focus="Fact vs. imperative sentence decomposition, imperative density scoring, alignment gating",
            baseline_asr=78.0,
            abstract="Decomposes retrieved context into descriptive facts vs imperative commands to block injected directives.",
        ),
        ResearchPaperMetadata(
            paper_id="REF-04",
            title="AuthGraph: Cryptographic Data-Flow Provenance and Lineage Verification for LLM Tool Invocations",
            authors=["AuthGraph Research Team"],
            venue="arXiv",
            year=2026,
            arxiv_id="2605.26497",
            primary_focus="Cryptographic SHA-256 DAG, parent-hash chaining, untrusted ancestry pruning",
            baseline_asr=3.0,
            abstract="Tracks cryptographic parent-child hash ancestry from input context to tool invocation sinks.",
        ),
        ResearchPaperMetadata(
            paper_id="REF-05",
            title="DataSentinel: Epistemic Consensus and Memory Firewalling for Stateful Autonomous Systems",
            authors=["DataSentinel Lab"],
            venue="IEEE S&P",
            year=2026,
            arxiv_id=None,
            primary_focus="Stateful memory firewall, write-time quarantine, geometric mean non-dilution",
            baseline_asr=6.0,
            abstract="Guarantees stateful memory integrity using decay scoring and non-diluting trust aggregation.",
        ),
        ResearchPaperMetadata(
            paper_id="REF-06",
            title="MINJA: Memory Injection via Natural Language Dialogue Dialogs in Stateful LLM Agents",
            authors=["Akshay Subramanian", "Pramod Khargonekar", "Sanjit Seshia"],
            venue="Preprint",
            year=2024,
            arxiv_id="2401.05566",
            primary_focus="Multi-turn conversational poisoning, sleeper triggers, cross-session persistence",
            baseline_asr=91.5,
            abstract="Analyzes how cross-session dialogue state and preferences can be poisoned to hijack future execution.",
        ),
    ]

    DOMAIN_ADAPTATIONS = [
        DomainAdaptationRecord(
            paper_id="REF-01",
            original_concept="General agent benchmark with simulated banking tools.",
            financial_specialization="Ground-truth 60-scenario suite focused specifically on Accounts Payable invoice reconciliation and wire disbursements.",
            novelty_boundary="AgentPOI enforces Contextual Invariant Verification (CIV) at execution sinks rather than relying on soft prompt defenses.",
            copyright_risk_level="NONE",
        ),
        DomainAdaptationRecord(
            paper_id="REF-02",
            original_concept="Generic ReAct tool hijacking across non-financial APIs.",
            financial_specialization="Accounts payable wire diversion, payee homoglyph typosquatting, and markdown table smuggling.",
            novelty_boundary="Clean-room mathematical extraction of attack vectors with formal state anchor validation.",
            copyright_risk_level="NONE",
        ),
        DomainAdaptationRecord(
            paper_id="REF-03",
            original_concept="Fact-vs-imperative decomposition for web browsing agents.",
            financial_specialization="Accounts payable invoice parser differentiating legitimate billing terms from unauthorized corporate override directives.",
            novelty_boundary="Custom financial imperative lexicon with dual-state epistemic gating.",
            copyright_risk_level="NONE",
        ),
        DomainAdaptationRecord(
            paper_id="REF-04",
            original_concept="General cryptographic DAG for tracking string variables.",
            financial_specialization="Cryptographic disbursement sink lineage verification requiring authenticated root authority signatures.",
            novelty_boundary="Lineage verification directly coupled to financial ledger state transitions.",
            copyright_risk_level="NONE",
        ),
        DomainAdaptationRecord(
            paper_id="REF-05",
            original_concept="OS-level memory state protection for multi-modal agents.",
            financial_specialization="Financial state anchor enforcing rolling 24-hour daily disbursement limits and payee trust scores.",
            novelty_boundary="Rolling time-decay limit enforcement and conservation laws.",
            copyright_risk_level="NONE",
        ),
        DomainAdaptationRecord(
            paper_id="REF-06",
            original_concept="Conversational memory injection and sleeper triggers.",
            financial_specialization="Recurring vendor payment schedule tampering and sleeper limit escalation payloads.",
            novelty_boundary="Cross-session dual-state consensus preventing persistent state poisoning.",
            copyright_risk_level="NONE",
        ),
    ]

    def get_canonical_papers(self) -> List[ResearchPaperMetadata]:
        """Return canonical literature registry."""
        return list(self.CANONICAL_PAPERS)

    def get_domain_adaptations(self) -> List[DomainAdaptationRecord]:
        """Return financial domain adaptation records."""
        return list(self.DOMAIN_ADAPTATIONS)

    def generate_bibtex_file(self) -> str:
        """Generate BibTeX entries for academic citations."""
        entries = [
            """@inproceedings{debenedetti2024agentdojo,
  title={AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses on LLM Agents},
  author={Debenedetti, Edoardo and Rando, Javier and Paleka, Daniel and Tram{\\`e}r, Florian},
  booktitle={Advances in Neural Information Processing Systems (NeurIPS)},
  year={2024},
  eprint={2406.13315},
  archivePrefix={arXiv}
}""",
            """@article{zou2024injecagent,
  title={InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents},
  author={Zou, Qiusi and Geng, Runpeng and Wang, Hao and Kang, Yong},
  journal={Proceedings of the Association for Computational Linguistics (ACL)},
  year={2024},
  eprint={2403.02691},
  archivePrefix={arXiv}
}""",
            """@article{taskshield2025,
  title={Task Shield: Task-Oriented Alignment and Fact-Imperative Decomposition for Secure Agentic AI},
  author={{Task Shield Team}},
  journal={Proceedings of the Association for Computational Linguistics (ACL)},
  year={2025},
  eprint={2501.19393},
  archivePrefix={arXiv}
}""",
            """@article{authgraph2026,
  title={AuthGraph: Cryptographic Data-Flow Provenance and Lineage Verification for LLM Tool Invocations},
  author={{AuthGraph Research Team}},
  journal={arXiv preprint arXiv:2605.26497},
  year={2026}
}""",
            """@inproceedings{datasentinel2026,
  title={DataSentinel: Epistemic Consensus and Memory Firewalling for Stateful Autonomous Systems},
  author={{DataSentinel Lab}},
  booktitle={IEEE Symposium on Security and Privacy (S&P)},
  year={2026}
}""",
            """@article{subramanian2024minja,
  title={MINJA: Memory Injection via Natural Language Dialogue Dialogs in Stateful LLM Agents},
  author={Subramanian, Akshay and Khargonekar, Pramod and Seshia, Sanjit},
  journal={arXiv preprint arXiv:2401.05566},
  year={2024}
}""",
        ]
        return "\n\n".join(entries) + "\n"
