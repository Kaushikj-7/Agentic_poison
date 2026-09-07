"""Tests for the PDF Research Paper Parser."""

import pytest
import os
from unittest.mock import patch, MagicMock
from agent_poi.research.pdf_parser import PDFPaperParser


class TestPDFPaperParser:
    def test_paper_id_extraction(self):
        parser = PDFPaperParser("docs/papers/01_abdelnabi2026_ai_agents_always_fall.pdf")
        assert parser.paper_id == "01"

    def test_paper_id_with_letter(self):
        parser = PDFPaperParser("docs/papers/15a_promptarmor2025_guardrails.pdf")
        assert parser.paper_id == "15a"

    def test_title_extraction(self):
        parser = PDFPaperParser("test.pdf")
        text = "Some Short Line\nAI Agents May Always Fall for Prompt Injections: A Theoretical Framework\nAuthor Name"
        title = parser._extract_title(text)
        assert "Prompt Injections" in title

    def test_abstract_extraction(self):
        parser = PDFPaperParser("test.pdf")
        text = "Abstract\nThis paper studies the security of LLM agents against prompt injection in multi-turn environments.\n1. Introduction\nHere we begin."
        abstract = parser._extract_abstract(text)
        assert "security" in abstract.lower()

    def test_defense_extraction(self):
        parser = PDFPaperParser("test.pdf")
        text = "We propose a novel firewall defense mechanism that prevents injection attacks. The system uses taint tracking to monitor data flow."
        defenses = parser._extract_defenses(text)
        assert len(defenses) >= 1

    def test_attack_extraction(self):
        parser = PDFPaperParser("test.pdf")
        text = "The adversarial injection payload exploits the agent to execute unauthorized transfers. Memory poisoning allows persistent manipulation."
        attacks = parser._extract_attacks(text)
        assert len(attacks) >= 1

    def test_arch_pattern_extraction(self):
        parser = PDFPaperParser("test.pdf")
        text = "The architecture uses a layered DAG with fail-closed semantics and zero trust principles."
        patterns = parser._extract_arch_patterns(text)
        assert "DAG" in patterns
        assert "fail-closed" in patterns
        assert "zero trust" in patterns

    def test_parse_nonexistent_file_returns_none(self):
        parser = PDFPaperParser("nonexistent_paper.pdf")
        assert parser.parse() is None

    def test_parse_non_pdf_extension_returns_none(self):
        parser = PDFPaperParser("README.md")
        assert parser.parse() is None

    @patch("os.path.isfile", return_value=True)
    @patch("os.path.getsize", return_value=0)
    def test_parse_empty_file_returns_none(self, mock_size, mock_isfile):
        parser = PDFPaperParser("empty.pdf")
        assert parser.parse() is None
