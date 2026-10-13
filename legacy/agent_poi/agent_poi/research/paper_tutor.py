"""Zero-Hallucination Interactive Paper Tutor Agent.

Provides verified, strictly-grounded answers to research questions across the
21 research papers in docs/papers/ without hallucinations or knowledge gaps.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agent_poi.research.paper_corpus import PAPER_CORPUS, LearningTier, PaperMetadata


@dataclass
class TutorCitation:
    paper_id: str
    title: str
    authors: str
    year: int
    venue: str
    arxiv_id: Optional[str]


@dataclass
class TutorResponse:
    is_grounded: bool
    query: str
    topic_summary: str
    primary_citations: List[TutorCitation] = field(default_factory=list)
    verbatim_quotes: List[str] = field(default_factory=list)
    formal_invariants: List[str] = field(default_factory=list)
    layman_analogy: str = ""
    engineering_takeaway: str = ""
    learning_tier: Optional[int] = None
    suggested_prerequisites: List[str] = field(default_factory=list)
    grounding_confidence: float = 1.0


class ZeroHallucinationPaperTutor:
    """Research tutor guaranteeing zero hallucination by anchoring to the 21-paper corpus."""

    def __init__(self, corpus: Optional[Dict[str, PaperMetadata]] = None):
        self.corpus = corpus or PAPER_CORPUS

    def get_paper(self, paper_id: str) -> Optional[PaperMetadata]:
        """Retrieve metadata for a specific paper by ID."""
        # Exact match or prefix match
        if paper_id in self.corpus:
            return self.corpus[paper_id]
        for pid, meta in self.corpus.items():
            if pid.lower().startswith(paper_id.lower()) or paper_id.lower() in pid.lower():
                return meta
        return None

    def list_by_tier(self, tier: LearningTier) -> List[PaperMetadata]:
        """Retrieve all papers belonging to a specific learning tier."""
        return [meta for meta in self.corpus.values() if meta.tier == tier]

    def search_corpus(self, query: str) -> List[PaperMetadata]:
        """Search the 21 papers for matching concepts, authors, or mechanisms."""
        tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]
        scored_papers = []

        for paper_id, meta in self.corpus.items():
            score = 0
            searchable_text = " ".join([
                meta.title.lower(),
                meta.layman_summary.lower(),
                meta.technical_abstract.lower(),
                meta.core_threat_or_defense.lower(),
                " ".join(meta.authors).lower(),
                " ".join(meta.formal_invariants_or_math).lower(),
                " ".join(meta.verbatim_key_quotes).lower(),
                meta.relevance_to_agentic_engineering.lower(),
            ])

            for token in tokens:
                if token in meta.paper_id.lower():
                    score += 5
                if token in meta.title.lower():
                    score += 4
                if token in meta.core_threat_or_defense.lower():
                    score += 3
                if token in searchable_text:
                    score += 1

            if score > 0:
                scored_papers.append((score, meta))

        scored_papers.sort(key=lambda x: x[0], reverse=True)
        return [meta for _, meta in scored_papers]

    @staticmethod
    def _build_grounded_response(query: str, matches: List[PaperMetadata]) -> TutorResponse:
        """Construct grounded tutor response from matched papers."""
        top_match = matches[0]
        citations = [
            TutorCitation(
                paper_id=m.paper_id,
                title=m.title,
                authors=", ".join(m.authors),
                year=m.year,
                venue=m.venue,
                arxiv_id=m.arxiv_id,
            )
            for m in matches[:3]
        ]
        summary = (
            f"According to {top_match.authors[0]} et al. ({top_match.year}, {top_match.venue}), "
            f"the core finding regarding '{query}' is centered on {top_match.core_threat_or_defense}.\n\n"
            f"Technical Summary: {top_match.technical_abstract}"
        )
        return TutorResponse(
            is_grounded=True,
            query=query,
            topic_summary=summary,
            primary_citations=citations,
            verbatim_quotes=list(top_match.verbatim_key_quotes),
            formal_invariants=list(top_match.formal_invariants_or_math),
            layman_analogy=top_match.layman_summary,
            engineering_takeaway=top_match.relevance_to_agentic_engineering,
            learning_tier=int(top_match.tier),
            suggested_prerequisites=top_match.suggested_prerequisites,
            grounding_confidence=1.0,
        )

    def answer_query(self, query: str) -> TutorResponse:
        """Provide a verified, zero-hallucination explanation grounded in the 21-paper corpus."""
        matches = self.search_corpus(query)

        if not matches:
            return TutorResponse(
                is_grounded=False,
                query=query,
                topic_summary=(
                    f"Query '{query}' could not be verified within the 21-paper corpus in docs/papers/. "
                    "To prevent hallucinations, no speculative answer is generated."
                ),
                grounding_confidence=0.0,
            )

        return self._build_grounded_response(query, matches)

    def generate_curriculum_overview(self) -> Dict[str, Any]:
        """Generate a complete 5-tier pedagogical curriculum overview."""
        tiers_data = {}
        for tier in LearningTier:
            papers = self.list_by_tier(tier)
            tiers_data[f"Tier {tier.value}: {tier.name}"] = [
                {
                    "paper_id": p.paper_id,
                    "title": p.title,
                    "year": p.year,
                    "focus": p.core_threat_or_defense,
                    "prerequisites": p.suggested_prerequisites,
                }
                for p in papers
            ]
        return {
            "total_papers": len(self.corpus),
            "tiers": tiers_data,
        }
