"""Fetch and extract arXiv LaTeX source archives and parse into structured JSON."""

import os
import tarfile
import io
import argparse
import logging
import requests

from agent_poi.research.arxiv_parser import LaTeXParser, find_main_tex_file
import json

logging.basicConfig(
    format="[%(asctime)s %(levelname)s] %(message)s",
    datefmt="%m/%d/%Y %H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger("fetch_arxiv_papers")


def fetch_and_extract_arxiv(
    arxiv_id: str,
    output_dir: str = "results/raw_latex",
    user_agent: str = "AgentPOI-Research/1.0",
) -> str:
    """Download arXiv source archive and unpack into target directory."""
    target_dir = os.path.join(output_dir, arxiv_id)
    os.makedirs(target_dir, exist_ok=True)

    # Check if already downloaded and has files
    if os.listdir(target_dir):
        logger.info(f"arXiv {arxiv_id} already downloaded in {target_dir}")
        return target_dir

    url = f"https://arxiv.org/e-print/{arxiv_id}"
    logger.info(f"Downloading arXiv e-print source from {url}...")
    headers = {"User-Agent": user_agent}

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        # Unpack tar archive
        try:
            with tarfile.open(fileobj=io.BytesIO(response.content)) as tar:
                tar.extractall(path=target_dir)
            logger.info(f"Extracted tar archive for {arxiv_id} to {target_dir}")
        except tarfile.ReadError:
            # Single .tex or gzip file fallback
            single_file_path = os.path.join(target_dir, "main.tex")
            with open(single_file_path, "wb") as f:
                f.write(response.content)
            logger.info(f"Saved single source file for {arxiv_id} to {single_file_path}")

    except Exception as e:
        logger.error(f"Failed to fetch arXiv paper {arxiv_id}: {e}")

    return target_dir


def process_paper(arxiv_id: str, raw_dir: str = "results/raw_latex", parsed_dir: str = "results/parsed_papers") -> None:
    """Download, extract, and parse an arXiv paper into structured JSON."""
    paper_dir = fetch_and_extract_arxiv(arxiv_id, output_dir=raw_dir)
    main_tex = find_main_tex_file(paper_dir)
    if not main_tex:
        logger.warning(f"No main .tex file found for {arxiv_id}")
        return

    parser = LaTeXParser(main_tex)
    result = parser.parse(arxiv_id=arxiv_id)

    if result:
        os.makedirs(parsed_dir, exist_ok=True)
        out_file = os.path.join(parsed_dir, f"{arxiv_id}.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved structured JSON for {arxiv_id} to {out_file}")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description="Fetch and parse arXiv research papers.")
    cli.add_argument("--ids", nargs="+", default=["2605.17634"], help="arXiv paper IDs to fetch and parse.")
    cli.add_argument("--raw_dir", default="results/raw_latex", help="Directory for raw LaTeX sources.")
    cli.add_argument("--parsed_dir", default="results/parsed_papers", help="Directory for parsed JSON output.")
    args = cli.parse_args()

    for p_id in args.ids:
        process_paper(p_id, raw_dir=args.raw_dir, parsed_dir=args.parsed_dir)
