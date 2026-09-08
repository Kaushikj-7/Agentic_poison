"""Run DeepTeam LLM Red-Team Benchmark Across Isolated Git Worktrees.

Usage:
    uv run python scripts/run_worktree_redteam.py [--max-iterations N]

CLI to execute space-efficient, time-efficient DeepTeam adversarial red teaming
across isolated git worktrees, evaluating baseline vs defended agentic frameworks.
"""

import argparse
import logging
import sys
from agent_poi.research.worktree_runner import WorktreeBenchmarkOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("scripts.run_worktree_redteam")


def main():
    parser = argparse.ArgumentParser(
        description="Run DeepTeam Red Team Benchmark across isolated Git Worktrees."
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum iterations per OWASP category (default: 3, max: 10 to prevent system exhaustion)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Retain worktrees post-benchmark (default: False for space efficiency)",
    )
    args = parser.parse_args()

    logger.info(
        f"Starting DeepTeam Worktree Benchmark (max_iterations={args.max_iterations}, cleanup={not args.no_cleanup})"
    )

    orchestrator = WorktreeBenchmarkOrchestrator(
        workspace_root=".",
        max_iterations_per_category=args.max_iterations,
        cleanup=not args.no_cleanup,
    )

    results = orchestrator.run_comparative_worktree_suite()

    print("\n" + "=" * 80)
    print(results["markdown_report"])
    print("=" * 80)
    print(f"\n[SUCCESS] Raw benchmark metrics saved to: {results['result_file']}")


if __name__ == "__main__":
    main()
