"""PDF Research Paper Parser.

Extracts structured metadata, abstracts, section headings,
key findings, defense mechanism descriptions, attack vectors,
and architecture patterns from PDF research papers.

Uses pdfplumber for zero-hardware CPU-only extraction (Rule 5).
All extracted data is saved as structured JSON for downstream synthesis.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("agent_poi.research.pdf_parser")


class PDFPaperParser:
    """Parse PDF research papers and extract structured content."""

    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.filename = os.path.basename(pdf_path)
        self.paper_id = self._extract_paper_id()

    def _extract_paper_id(self) -> str:
        """Extract paper ID from filename convention (e.g., '01_abdelnabi2026_...')."""
        match = re.match(r"^(\d+[a-z]?)_", self.filename)
        return match.group(1) if match else self.filename.replace(".pdf", "")

    def _validate_file_boundary(self) -> bool:
        """Validate existence, extension, and non-empty size."""
        if not os.path.isfile(self.pdf_path):
            logger.error(f"PDF file does not exist: {self.pdf_path}")
            return False
        if not self.pdf_path.lower().endswith(".pdf"):
            logger.error(f"Invalid file extension (expected .pdf): {self.pdf_path}")
            return False
        if os.path.getsize(self.pdf_path) == 0:
            logger.warning(f"Empty PDF file (0 bytes): {self.pdf_path}")
            return False
        return True

    def _extract_document_text(self) -> Optional[Tuple[str, int]]:
        """Extract full raw text and page count using pdfplumber."""
        try:
            import pdfplumber
        except ImportError:
            logger.error("pdfplumber not installed. Run: pip install pdfplumber")
            return None

        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                full_text = "".join(
                    (p.extract_text() or "") + "\n" for p in pdf.pages
                )
                if not full_text.strip():
                    logger.warning(f"No text extracted from {self.filename}")
                    return None
                return full_text, len(pdf.pages)
        except Exception as e:
            logger.error(f"Failed to extract text from {self.pdf_path}: {e}")
            return None

    def parse(self) -> Optional[Dict[str, Any]]:
        """Extract structured content from PDF."""
        if not self._validate_file_boundary():
            return None

        doc_data = self._extract_document_text()
        if not doc_data:
            return None

        full_text, total_pages = doc_data
        return {
            "paper_id": self.paper_id,
            "filename": self.filename,
            "total_pages": total_pages,
            "title": self._extract_title(full_text),
            "abstract": self._extract_abstract(full_text),
            "sections": self._extract_sections(full_text),
            "key_findings": self._extract_key_findings(full_text),
            "defense_mechanisms": self._extract_defenses(full_text),
            "attack_vectors": self._extract_attacks(full_text),
            "metrics": self._extract_metrics(full_text),
            "architecture_patterns": self._extract_arch_patterns(full_text),
        }

    def _extract_title(self, text: str) -> str:
        """Extract paper title from first page.

        Heuristic: title is typically the longest non-trivial line
        among the first 10 lines of the first page.
        """
        lines = text.split("\n")[:10]
        candidates = [
            (len(line.strip()), line.strip())
            for line in lines
            if len(line.strip()) > 10
        ]
        if not candidates:
            return ""
        return max(candidates, key=lambda x: x[0])[1]

    def _extract_abstract(self, text: str) -> str:
        """Extract abstract section from the paper."""
        patterns = [
            r"(?:Abstract|ABSTRACT)[.\s—\-]*\n(.*?)(?:\n\s*(?:1\.?\s+Introduction|Keywords|I\.\s+INTRODUCTION|CCS Concepts|Categories))",
            r"(?:Abstract|ABSTRACT)[.\s—\-]*\n(.*?)(?:\n\s*\d+\.?\s+[A-Z])",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                abstract = match.group(1).strip()
                if len(abstract) > 50:
                    return abstract
        return ""

    def _extract_sections(self, text: str) -> List[Dict[str, str]]:
        """Extract section structure (numbered headings)."""
        pattern = r"(?:^|\n)\s*(\d+\.?\d*\.?\d*)\s+([A-Z][^\n]{5,80})"
        matches = re.findall(pattern, text)
        seen = set()
        sections = []
        for num, title in matches:
            key = f"{num}-{title.strip()}"
            if key not in seen:
                seen.add(key)
                sections.append({"number": num, "title": title.strip()})
        return sections

    def _extract_key_findings(self, text: str) -> List[str]:
        """Extract key quantitative findings (ASR rates, accuracy, etc.)."""
        patterns = [
            r"(\d+\.?\d*)\s*%\s*(?:ASR|attack success|success rate)",
            r"(?:ASR|attack success|success rate)[^.]*?(\d+\.?\d*)\s*%",
            r"(?:reduces?|achieves?|reaches?|improves?)[^.]*?(\d+\.?\d*)\s*%",
        ]
        findings: List[str] = []
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                idx = match.start()
                # Find the sentence containing this finding
                start = max(0, text.rfind(".", 0, idx) + 1)
                end = text.find(".", idx)
                if end == -1:
                    end = min(idx + 200, len(text))
                else:
                    end += 1
                sentence = text[start:end].strip()
                if 20 < len(sentence) < 500 and sentence not in findings:
                    findings.append(sentence)

        return findings[:10]

    def _extract_defenses(self, text: str) -> List[str]:
        """Extract defense mechanism descriptions."""
        defense_keywords = [
            "firewall",
            "guardrail",
            "defense",
            "protection",
            "detection",
            "verification",
            "invariant",
            "isolation",
            "taint tracking",
            "provenance",
            "information flow",
            "sanitization",
        ]
        return self._extract_sentences_with_keywords(text, defense_keywords, limit=15)

    def _extract_attacks(self, text: str) -> List[str]:
        """Extract attack vector descriptions."""
        attack_keywords = [
            "injection",
            "poisoning",
            "hijacking",
            "evasion",
            "manipulation",
            "smuggling",
            "exploit",
            "adversarial",
            "malicious",
        ]
        return self._extract_sentences_with_keywords(text, attack_keywords, limit=15)

    def _extract_sentences_with_keywords(
        self, text: str, keywords: List[str], limit: int = 15
    ) -> List[str]:
        """Extract sentences containing any of the given keywords."""
        sentences = re.split(r"[.!?]\s+", text)
        results: List[str] = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 30 or len(sentence) > 500:
                continue
            if any(kw in sentence.lower() for kw in keywords):
                if sentence not in results:
                    results.append(sentence)
            if len(results) >= limit:
                break
        return results

    def _extract_metrics(self, text: str) -> Dict[str, Any]:
        """Extract quantitative metrics mentioned in the paper."""
        metrics: Dict[str, Any] = {}

        asr_match = re.search(
            r"ASR[^.]{0,50}?(\d+\.?\d*)\s*%", text, re.IGNORECASE
        )
        if asr_match:
            metrics["asr"] = float(asr_match.group(1))

        utility_match = re.search(
            r"(?:utility|LDSR|accuracy|F1)[^.]{0,50}?(\d+\.?\d*)\s*%",
            text,
            re.IGNORECASE,
        )
        if utility_match:
            metrics["utility"] = float(utility_match.group(1))

        latency_match = re.search(
            r"(?:latency|overhead)[^.]{0,50}?(\d+\.?\d*)\s*(?:ms|millisecond)",
            text,
            re.IGNORECASE,
        )
        if latency_match:
            metrics["latency_ms"] = float(latency_match.group(1))

        return metrics

    def _extract_arch_patterns(self, text: str) -> List[str]:
        """Extract architectural patterns mentioned in the paper."""
        pattern_keywords = [
            "DAG",
            "state machine",
            "pipeline",
            "layered",
            "microservice",
            "event-driven",
            "publish-subscribe",
            "multi-agent",
            "orchestrat",
            "choreograph",
            "fail-closed",
            "fail-open",
            "zero trust",
            "defense-in-depth",
            "least privilege",
            "separation of concerns",
        ]
        found: List[str] = []
        text_lower = text.lower()
        for kw in pattern_keywords:
            if kw.lower() in text_lower and kw not in found:
                found.append(kw)
        return found


def parse_all_papers(
    papers_dir: str, output_dir: str
) -> List[Dict[str, Any]]:
    """Parse all PDFs in a directory and save structured JSON.

    Skips already-parsed papers (idempotent). Returns list of all
    parsed paper dictionaries.
    """
    os.makedirs(output_dir, exist_ok=True)
    results: List[Dict[str, Any]] = []

    pdf_files = sorted(Path(papers_dir).glob("*.pdf"))
    logger.info(f"Found {len(pdf_files)} PDF papers to parse")

    for pdf_path in pdf_files:
        output_json = os.path.join(output_dir, f"{pdf_path.stem}.json")

        # Skip already-parsed papers
        if os.path.exists(output_json):
            try:
                with open(output_json, "r", encoding="utf-8") as f:
                    results.append(json.load(f))
                logger.info(f"  ↺ Cached: {pdf_path.name}")
                continue
            except (json.JSONDecodeError, OSError):
                pass  # Re-parse on corrupt cache

        parser = PDFPaperParser(str(pdf_path))
        result = parser.parse()

        if result:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            results.append(result)
            logger.info(
                f"  ✓ Parsed: {pdf_path.name} ({result['total_pages']} pages)"
            )
        else:
            logger.warning(f"  ✗ Failed: {pdf_path.name}")

    logger.info(
        f"Parsing complete: {len(results)}/{len(pdf_files)} papers extracted"
    )
    return results
