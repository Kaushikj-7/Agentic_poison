"""Research utilities for arXiv paper downloading, LaTeX AST parsing, and benchmark synthesis."""

from agent_poi.research.arxiv_parser import (
    LaTeXParser,
    find_main_tex_file,
    load_arxiv_metadata,
    parse_all_papers,
)
from agent_poi.research.synthesis_extractor import (
    ResearchPaperMetadata,
    DomainAdaptationRecord,
    ResearchSynthesisExtractor,
)

__all__ = [
    "LaTeXParser",
    "find_main_tex_file",
    "load_arxiv_metadata",
    "parse_all_papers",
    "ResearchPaperMetadata",
    "DomainAdaptationRecord",
    "ResearchSynthesisExtractor",
]

