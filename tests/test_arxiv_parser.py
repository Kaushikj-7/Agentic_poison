"""Unit tests for arXiv LaTeXParser and research document ingestion."""

import os
import tempfile
import pytest

from agent_poi.research.arxiv_parser import (
    LaTeXParser,
    find_main_tex_file,
)


@pytest.fixture
def sample_tex_project(tmp_path):
    """Creates a temporary sample LaTeX paper project with multi-file inputs."""
    paper_dir = tmp_path / "sample_paper"
    paper_dir.mkdir()

    # Included chapter
    intro_tex = paper_dir / "intro.tex"
    intro_tex.write_text(
        r"""
\section{Introduction}
Contextual integrity is vital for agent security.
Visit our repository at \url{https://github.com/Kaushikj-7/Agentic_poison}.
""",
        encoding="utf-8",
    )

    # Main tex file
    main_tex = paper_dir / "main.tex"
    main_tex.write_text(
        r"""
\documentclass{article}
\title{Defense Against Agent Memory Poisoning}
\author{Kaushik\thanks{Corresponding author} \\
\institution{Deep Coding Security Lab}}

\begin{document}
\begin{abstract}
This paper presents Contextual Invariant Verification for autonomous agents.
\end{abstract}

% This is a comment to remove
\input{intro}

\section{Methodology}
We evaluate Dual-State Epistemic Consensus.

\subsection{State Anchor}
The anchor S0 guarantees execution safety.

\end{document}
""",
        encoding="utf-8",
    )

    return paper_dir, main_tex


def test_find_main_tex_file(sample_tex_project):
    paper_dir, main_tex = sample_tex_project
    detected_main = find_main_tex_file(str(paper_dir))
    assert detected_main is not None
    assert os.path.basename(detected_main) == "main.tex"


def test_latex_parser_comment_removal():
    parser = LaTeXParser("dummy.tex")
    text = "Text before % comment\nEscaped \\% percent\n% Full line comment\nEnd"
    cleaned = parser.remove_comments(text)
    assert "comment" not in cleaned
    assert "\\% percent" in cleaned
    assert "Text before" in cleaned
    assert "End" in cleaned


def test_latex_parser_end_to_end(sample_tex_project):
    paper_dir, main_tex = sample_tex_project
    parser = LaTeXParser(str(main_tex))
    result = parser.parse(arxiv_id="2605.17634")

    assert result is not None
    assert result["arxiv_id"] == "2605.17634"
    assert "Defense Against Agent Memory Poisoning" in result["title"]
    assert "Contextual Invariant Verification" in result["abstract"]
    assert len(result["authors"]) >= 1
    assert "Kaushik" in result["authors"][0]
    assert any("github.com/Kaushikj-7/Agentic_poison" in url for url in result["urls"])

    # Verify section extraction and input resolution
    sections = result["sections"]
    assert "Introduction" in sections
    assert "Methodology" in sections
    assert "State Anchor" in sections["Methodology"]


def test_latex_parser_parses_agentpoi_paper():
    """Verify LaTeXParser parses our own publication manuscript in paper/main.tex."""
    paper_path = os.path.join("paper", "main.tex")
    if os.path.exists(paper_path):
        parser = LaTeXParser(paper_path)
        result = parser.parse(arxiv_id="2609.xxxxx")
        assert result is not None
        assert "AgentPOI" in result["title"]
        assert "Contextual Invariant Verification" in result["title"]
        assert len(result["sections"]) >= 5
        assert "Introduction" in result["sections"]
        assert "Empirical Evaluation" in result["sections"]

