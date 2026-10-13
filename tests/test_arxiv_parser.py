"""Unit tests for arXiv LaTeXParser and research document ingestion."""

import os
import shutil
import tempfile

import pytest

from agent_poi.research.arxiv_parser import (
    LaTeXParser,
    find_main_tex_file,
)


@pytest.fixture
def sample_tex_project():
    """Creates a temporary sample LaTeX paper project using tempfile.mkdtemp().

    Uses a manual temp dir to avoid Windows AppData\\Local\\Temp PermissionError
    that occurs in restricted sandbox environments with pytest's tmp_path fixture.
    """
    base_dir = tempfile.mkdtemp(prefix="agentpoi_test_")
    paper_dir = os.path.join(base_dir, "sample_paper")
    os.makedirs(paper_dir)

    intro_tex_path = os.path.join(paper_dir, "intro.tex")
    with open(intro_tex_path, "w", encoding="utf-8") as f:
        f.write(r"""
\section{Introduction}
Contextual integrity is vital for agent security.
Visit our repository at \url{https://github.com/Kaushikj-7/Agentic_poison}.
""")

    main_tex_path = os.path.join(paper_dir, "main.tex")
    with open(main_tex_path, "w", encoding="utf-8") as f:
        f.write(r"""
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
""")

    yield paper_dir, main_tex_path

    # Cleanup temp directory after test
    shutil.rmtree(base_dir, ignore_errors=True)


def test_find_main_tex_file(sample_tex_project):
    """find_main_tex_file must locate main.tex in a temp directory."""
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
    """LaTeXParser must fully parse a temp paper project including included sections."""
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
    """Verify LaTeXParser parses our own publication manuscript in paper/main.tex.

    If the paper/main.tex file is inaccessible (PermissionError or missing),
    this test is skipped gracefully rather than erroring.
    """
    paper_path = os.path.join("paper", "main.tex")
    abs_paper_path = os.path.abspath(paper_path)

    if not os.path.exists(abs_paper_path):
        pytest.skip(f"paper/main.tex not found at {abs_paper_path} — skipping.")

    try:
        parser = LaTeXParser(abs_paper_path)
        result = parser.parse(arxiv_id="2609.xxxxx")
    except PermissionError:
        pytest.skip("PermissionError accessing paper/main.tex — skipping in restricted environment.")

    assert result is not None
    assert "AgentPOI" in result["title"]
    assert "Contextual Invariant Verification" in result["title"]
    assert len(result["sections"]) >= 5
    assert "Introduction" in result["sections"]
    assert "Empirical Evaluation" in result["sections"]
