#!/usr/bin/env python3
"""Master Research & Architecture Experiment Pipeline.

Usage:
  uv run python scripts/run_experiment_pipeline.py

Workflow:
1. Parse research PDFs (from docs/papers/) into structured research JSON
2. Synthesize candidate defense architectures using system design principles
3. Execute automated git branches, test suites, and dynamic financial benchmarks
4. Log empirical results to data/experiment_results/
5. Generate comparison report table for developer review
"""

import os
import sys

workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from agent_poi.research.architecture_synthesizer import ArchitectureSynthesizer
from agent_poi.research.experiment_runner import ExperimentOrchestrator
from agent_poi.research.pdf_parser import parse_all_papers


def main():
    print("=" * 80)
    print(" AGENTPOI RESEARCH-DRIVEN ARCHITECTURE & EXPERIMENT PIPELINE")
    print("=" * 80)

    papers_dir = os.path.join(workspace_root, "docs", "papers")
    extracts_dir = os.path.join(workspace_root, "data", "research_extracts")

    # Phase 1: Parse PDFs
    print("\n[Phase 1/4] Parsing research PDFs in docs/papers/...")
    paper_data = parse_all_papers(papers_dir, extracts_dir)
    print(f"  ✓ Processed {len(paper_data)} papers into structured representation.")

    # Phase 2: Synthesize Architectures
    print("\n[Phase 2/4] Synthesizing candidate architectures via system design principles...")
    synthesizer = ArchitectureSynthesizer(paper_data)
    candidates = synthesizer.synthesize_candidates()
    print(f"  ✓ Synthesized {len(candidates)} candidate architectures.")

    # Print design comparison table
    comparison = synthesizer.generate_comparison_table(candidates)
    print("\n" + comparison)

    # Phase 3: Run Automated Branch Experiments with Worktree/Branch Pruning
    print("\n[Phase 3/4] Running automated git branch experiments and benchmarks...")
    orchestrator = ExperimentOrchestrator(workspace_root, cleanup_branch=True)

    # Evaluate candidate architectures
    for candidate in candidates:
        print(f"\n  -> Launching Experiment: {candidate.arch_id} ({candidate.name})")
        res = orchestrator.run_experiment(candidate.arch_id, candidate.name)
        bench = res.benchmark_results
        asr = f"ASR-Exec: {bench.get('asr_exec', 'N/A')}%" if bench else "No bench data"
        ldsr = f"LDSR: {bench.get('ldsr', 'N/A')}%" if bench else ""
        print(f"    Outcome: {res.status.upper()} | {asr} | {ldsr} | Duration: {res.duration_seconds}s")

    # Phase 4: Generate Developer Comparison Report & Reproducibility Guide
    print("\n[Phase 4/4] Generating developer comparison table & reproducibility guide...")
    report = orchestrator.generate_comparison_report()
    report_path = os.path.join(workspace_root, "data", "experiment_results", "COMPARISON_REPORT.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  [OK] Full report written to: {report_path}")

    repro_guide = orchestrator.generate_reproducibility_guide()
    repro_path = os.path.join(workspace_root, "data", "experiment_results", "REPRODUCIBILITY.md")
    with open(repro_path, "w", encoding="utf-8") as f:
        f.write(repro_guide)
    print(f"  [OK] Reproducibility guide written to: {repro_path}")

    print("\n" + report)
    print("\n" + "=" * 80)
    print(" PIPELINE EXECUTION COMPLETE — Ready for developer architecture selection")
    print("=" * 80)


if __name__ == "__main__":
    main()
