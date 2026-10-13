"""LaTeX parser for extracting structured content from arXiv paper source packages.

Extracts titles, abstracts, author affiliations, nested section hierarchies,
and code/project URLs from decompressed LaTeX e-print archives.
"""

import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("agent_poi.research.arxiv_parser")


class LaTeXParser:
    """Parse LaTeX source files and extract structured content."""

    def __init__(self, tex_file_path: str):
        self.tex_file_path = tex_file_path
        self.base_dir = os.path.dirname(tex_file_path)
        self.content = ""
        self.sections: Dict[str, Any] = {}

    def load_content(self) -> bool:
        """Load and preprocess LaTeX content with multiple encoding attempts."""
        encodings = ["utf-8", "latin-1", "iso-8859-1", "windows-1252"]

        for encoding in encodings:
            try:
                with open(self.tex_file_path, "r", encoding=encoding) as f:
                    self.content = f.read()
                logger.debug(f"Successfully loaded {self.tex_file_path} with {encoding}")
                break
            except (UnicodeDecodeError, LookupError):
                continue
            except Exception as e:
                logger.error(f"Failed to load {self.tex_file_path}: {e}")
                return False
        else:
            logger.warning(f"Skip {self.tex_file_path}: Unable to decode with any known encoding")
            return False

        # Remove comments
        self.content = self.remove_comments(self.content)

        # Handle \input and \include
        self.content = self.resolve_inputs(self.content)

        return True

    def remove_comments(self, text: str) -> str:
        """Remove LaTeX comments (lines starting with %) while preserving escaped \\%."""
        lines = text.split("\n")
        cleaned_lines = []
        for line in lines:
            if "\\%" in line:
                line = line.replace("\\%", "__PERCENT__")
            if "%" in line:
                line = line.split("%")[0]
            line = line.replace("__PERCENT__", "\\%")
            cleaned_lines.append(line)
        return "\n".join(cleaned_lines)

    def resolve_inputs(self, text: str) -> str:
        r"""Recursively resolve \input{file} and \include{file} up to 3 levels deep."""
        pattern = r"\\(?:input|include)\{([^\}]+)\}"

        def replace_input(match):
            filename = match.group(1).strip()
            if not filename.endswith(".tex"):
                filename += ".tex"

            input_path = os.path.join(self.base_dir, filename)

            if os.path.exists(input_path):
                for encoding in ["utf-8", "latin-1", "iso-8859-1", "windows-1252"]:
                    try:
                        with open(input_path, "r", encoding=encoding) as f:
                            return f.read()
                    except (UnicodeDecodeError, LookupError):
                        continue
                    except Exception:
                        return match.group(0)
                logger.warning(f"Could not decode included file: {input_path}")
                return match.group(0)
            return match.group(0)

        for _ in range(3):
            new_text = re.sub(pattern, replace_input, text)
            if new_text == text:
                break
            text = new_text

        return text

    def extract_title_abstract(self) -> Tuple[str, str]:
        """Extract paper title and abstract from LaTeX content."""
        title = ""
        abstract = ""

        title_match = re.search(r"\\title\{([^\}]+)\}", self.content)
        if title_match:
            title = title_match.group(1).strip()
            title = re.sub(r"\\[a-zA-Z]+\{([^\}]+)\}", r"\1", title)
            title = re.sub(r"\\[a-zA-Z]+", "", title)

        abstract_match = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", self.content, re.DOTALL)
        if abstract_match:
            abstract = abstract_match.group(1).strip()

        return title, abstract

    def extract_sections(self) -> Dict[str, Any]:
        """Extract nested section/subsection structure."""
        pattern = r"\\(section|subsection|subsubsection)\*?\{([^\}]+)\}"
        matches = list(re.finditer(pattern, self.content))

        if not matches:
            return {}

        sections: Dict[str, Any] = {}
        current_section_name: Optional[str] = None
        current_subsection_name: Optional[str] = None

        for i, match in enumerate(matches):
            level = match.group(1)
            title = match.group(2).strip()

            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(self.content)
            content = self.content[start_pos:end_pos].strip()

            if level == "section":
                current_section_name = title
                current_subsection_name = None
                sections[title] = {"level": "section", "content": content}

            elif level == "subsection" and current_section_name:
                current_subsection_name = title
                if current_section_name not in sections:
                    sections[current_section_name] = {"level": "section", "content": ""}
                sections[current_section_name][title] = {"level": "subsection", "content": content}

            elif level == "subsubsection" and current_section_name and current_subsection_name:
                if current_section_name not in sections:
                    sections[current_section_name] = {"level": "section", "content": ""}
                if current_subsection_name not in sections[current_section_name]:
                    sections[current_section_name][current_subsection_name] = {
                        "level": "subsection",
                        "content": "",
                    }
                sections[current_section_name][current_subsection_name][title] = {
                    "level": "subsubsection",
                    "content": content,
                }

        self.sections = sections
        return sections

    def extract_urls(self) -> List[str]:
        """Extract URLs from LaTeX (GitHub, HuggingFace, project pages, etc.)."""
        urls = []
        url_patterns = [
            r"\\url\{([^}]+)\}",
            r"\\href\{([^}]+)\}\{[^}]*\}",
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, self.content)
            urls.extend(matches)

        urls = list(dict.fromkeys(urls))
        filtered_urls = []
        for url in urls:
            url_lower = url.lower()
            if any(
                domain in url_lower
                for domain in [
                    "github.com",
                    "huggingface.co",
                    "arxiv.org",
                    "project",
                    "demo",
                    "paperswithcode.com",
                ]
            ):
                filtered_urls.append(url)

        return filtered_urls[:10]

    def extract_authors_and_affiliations(self) -> Tuple[List[str], List[str]]:
        """Extract authors and affiliations from LaTeX."""
        authors = []
        affiliations = []

        # Method 1: Multiple \author{} commands (ACM/IEEE style)
        author_pattern = r"\\author\{([^}]+)\}"
        author_matches = re.findall(author_pattern, self.content)

        if len(author_matches) > 1:
            for author_text in author_matches:
                clean_name = re.sub(r"\\[a-zA-Z]+\{?[^}]*\}?", "", author_text)
                clean_name = re.sub(r"\s+", " ", clean_name).strip()
                if clean_name and len(clean_name) > 2:
                    authors.append(clean_name)

            affil_patterns = [
                r"\\institution\{([^}]+)\}",
                r"\\affiliation\{[^}]*\\institution\{([^}]+)\}",
            ]
            for pattern in affil_patterns:
                matches = re.findall(pattern, self.content)
                for match in matches:
                    clean_affil = re.sub(r"\\[a-zA-Z]+", "", match)
                    clean_affil = re.sub(r"\s+", " ", clean_affil).strip()
                    if clean_affil and len(clean_affil) > 3:
                        affiliations.append(clean_affil)

            return list(dict.fromkeys(authors))[:20], list(dict.fromkeys(affiliations))[:10]

        # Method 2: Single \author{...} block (ICLR/NeurIPS style)
        author_start = self.content.find(r"\author{")
        if author_start == -1:
            return [], []

        start_pos = author_start + len(r"\author{")
        brace_count = 1
        pos = start_pos

        while pos < len(self.content) and brace_count > 0:
            if self.content[pos] == "{" and (pos == 0 or self.content[pos - 1] != "\\"):
                brace_count += 1
            elif self.content[pos] == "}" and (pos == 0 or self.content[pos - 1] != "\\"):
                brace_count -= 1
            pos += 1

        if brace_count == 0:
            author_block = self.content[start_pos : pos - 1]
            lines = author_block.split("\\\\")

            for line in lines:
                if re.match(r"^\s*\$\^{?\d+}?\$", line):
                    clean_line = re.sub(r"\$\^{?\d+}?\$", "", line)
                    clean_line = re.sub(r"\\quad", " ", clean_line)
                    clean_line = re.sub(r"\\[a-zA-Z]+", "", clean_line)
                    clean_line = re.sub(r"\s+", " ", clean_line).strip()
                    if clean_line and len(clean_line) > 3:
                        affiliations.append(clean_line)
                else:
                    clean_line = re.sub(r"\\thanks\{[^}]*\}", "", line)
                    clean_line = re.sub(r"\\footnotemark\[[^\]]*\]", "", clean_line)
                    clean_line = re.sub(r"\$\^{?\d+[,\d]*}?\$\*?", "", clean_line)
                    clean_line = re.sub(r"\\quad", " ", clean_line)
                    clean_line = re.sub(r"\\textbf\{([^}]*)\}", r"\1", clean_line)
                    clean_line = re.sub(r"\\[a-zA-Z]+", "", clean_line)
                    clean_line = re.sub(r"\s+", " ", clean_line).strip()

                    if clean_line:
                        author_list = re.split(r"\s+and\s+|(?<=[a-z])\s+(?=[A-Z][a-z])", clean_line)
                        for author in author_list:
                            author = author.strip()
                            if author and len(author) > 2 and not author.isdigit():
                                authors.append(author)

        return authors[:20], affiliations[:10]

    def parse(
        self,
        arxiv_id: Optional[str] = None,
        title: Optional[str] = None,
        publish_date: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Main parsing function - extract structured arXiv paper information."""
        if not self.load_content():
            return None

        if not arxiv_id:
            arxiv_id = os.path.basename(self.base_dir)

        if not title:
            title, _ = self.extract_title_abstract()

        _, abstract = self.extract_title_abstract()
        authors, affiliations = self.extract_authors_and_affiliations()
        urls = self.extract_urls()
        sections = self.extract_sections()

        return {
            "arxiv_id": arxiv_id,
            "title": title,
            "publish_date": publish_date,
            "authors": authors,
            "affiliations": affiliations,
            "urls": urls,
            "abstract": abstract,
            "sections": sections,
        }


def find_main_tex_file(latex_dir: str) -> Optional[str]:
    """Find the main .tex file in a directory."""
    tex_files = []
    for root, _, files in os.walk(latex_dir):
        for file in files:
            if file.endswith(".tex"):
                tex_files.append(os.path.join(root, file))

    if not tex_files:
        return None

    # Check for \documentclass or \begin{document}
    for tex_file in tex_files:
        try:
            with open(tex_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)
                if "\\documentclass" in content or "\\begin{document}" in content:
                    return tex_file
        except Exception:
            continue

    # Fallback to standard conventions
    for tex_file in tex_files:
        basename = os.path.basename(tex_file).lower()
        if basename in ["main.tex", "paper.tex", "manuscript.tex"]:
            return tex_file

    return tex_files[0] if tex_files else None


def load_arxiv_metadata(json_path: str) -> Dict[str, Dict[str, str]]:
    """Load arXiv metadata from JSON file."""
    metadata = {}
    if not os.path.exists(json_path):
        return metadata

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for papers in data.values():
            if isinstance(papers, dict):
                for arxiv_id, row in papers.items():
                    if isinstance(row, str):
                        parts = row.split("|")
                        if len(parts) >= 3:
                            date_str = parts[1].replace("**", "").strip()
                            title = parts[2].replace("**", "").strip()
                            metadata[arxiv_id] = {"title": title, "publish_date": date_str}
    except Exception as e:
        logger.warning(f"Failed to load arXiv metadata: {e}")

    return metadata


def parse_all_papers(
    latex_dir: str,
    saved_path: str,
    arxiv_json_path: str = "agent-arxiv-daily.json",
) -> bool:
    """Parse all LaTeX papers in a directory and save structured JSON files."""
    os.makedirs(saved_path, exist_ok=True)
    arxiv_metadata = load_arxiv_metadata(arxiv_json_path)

    if not os.path.exists(latex_dir):
        logger.warning(f"LaTeX directory {latex_dir} does not exist.")
        return False

    paper_dirs = [d for d in os.listdir(latex_dir) if os.path.isdir(os.path.join(latex_dir, d))]
    logger.info(f"Found {len(paper_dirs)} paper directories in {latex_dir}")

    successful = 0
    failed = 0

    for arxiv_id in paper_dirs:
        output_json = os.path.join(saved_path, f"{arxiv_id}.json")
        if os.path.exists(output_json):
            successful += 1
            continue

        latex_dir_full = os.path.join(latex_dir, arxiv_id)
        main_tex = find_main_tex_file(latex_dir_full)

        if not main_tex:
            failed += 1
            continue

        title = arxiv_metadata.get(arxiv_id, {}).get("title")
        publish_date = arxiv_metadata.get(arxiv_id, {}).get("publish_date")

        parser = LaTeXParser(main_tex)
        result = parser.parse(arxiv_id=arxiv_id, title=title, publish_date=publish_date)

        if result:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            successful += 1
        else:
            failed += 1

    return failed == 0
