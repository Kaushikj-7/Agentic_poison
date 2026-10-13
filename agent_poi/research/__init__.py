"""Research utilities for arXiv paper downloading, LaTeX AST parsing, and benchmark synthesis."""

from agent_poi.research.architecture_synthesizer import (
    ArchitectureSynthesizer,
    CandidateArchitecture,
)
from agent_poi.research.arxiv_parser import (
    LaTeXParser,
    find_main_tex_file,
    load_arxiv_metadata,
    parse_all_papers,
)
from agent_poi.research.experiment_runner import (
    ExperimentOrchestrator,
    ExperimentResult,
    GitBranchManager,
)
from agent_poi.research.pdf_parser import (
    PDFPaperParser,
)
from agent_poi.research.pdf_parser import (
    parse_all_papers as parse_all_pdf_papers,
)
from agent_poi.research.synthesis_extractor import (
    DomainAdaptationRecord,
    ResearchPaperMetadata,
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
    "PDFPaperParser",
    "parse_all_pdf_papers",
    "ArchitectureSynthesizer",
    "CandidateArchitecture",
    "ExperimentOrchestrator",
    "ExperimentResult",
    "GitBranchManager",
]

