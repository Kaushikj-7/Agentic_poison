"""File Classification Engine — Level 8 Git Hygiene.

Classifies every file in the workspace into:
- PUBLIC: Safe to push to GitHub (production code, public docs, tests, CI)
- DEVELOPER_ONLY: Local development artifacts (ledgers, agent configs, logs)
- NEVER_TRACK: Must NEVER enter git history (PDFs, binary data, secrets, venvs)

The default classification is DEVELOPER_ONLY (fail-closed). Unknown files
stay local unless explicitly whitelisted as PUBLIC.
"""

import fnmatch
import subprocess
from enum import Enum
from typing import List, Tuple


class FileClass(str, Enum):
    """Classification tier for workspace files."""

    PUBLIC = "PUBLIC"
    DEVELOPER_ONLY = "DEVELOPER_ONLY"
    NEVER_TRACK = "NEVER_TRACK"


# ─────────────────────────────────────────────────────────────────────
# Exhaustive classification rules (order: first match wins)
# ─────────────────────────────────────────────────────────────────────

NEVER_TRACK_RULES: List[str] = [
    # Binary research papers
    "docs/papers/*.pdf",
    "docs/papers/**/*.pdf",
    "**/*.pdf",
    # Generated binary images in non-essential locations
    "docs/pareto_frontier.png",
    # Developer governance artifacts (AGENTS.md Rule 6)
    "MISTAKES_LEDGER.md",
    "PROJECT_LEDGER.md",
    "AGENTS.md",
    "docs/MONITORING_AGENT.md",
    "everything-claude-code/**",
    ".agents/**",
    # Virtual environments & caches
    ".venv/**",
    "venv/**",
    "env/**",
    "ENV/**",
    "__pycache__/**",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".pytest_cache/**",
    ".pytest_tmp/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    # Build artifacts
    "build/**",
    "dist/**",
    "*.egg-info/**",
    "*.egg",
    # Data stores & databases
    "data/**",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    # IDE & OS artifacts
    ".idea/**",
    ".vscode/**",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.swp",
    "*.swo",
    # Secrets & environment
    ".env",
    "*.env",
    ".streamlit/secrets.toml",
    # Scratch, temp & output
    "scratch/**",
    "tmp/**",
    "temp/**",
    "output/**",
    "storage/**",
    "workspace/**",
    "logs/**",
    "*.log",
    # Lock files (auto-generated, large)
    "uv.lock",
    # System generated
    ".system_generated/**",
    ".gemini/**",
    # Node modules
    "node_modules/**",
    # Generated research & experiment data
    "data/research_extracts/**",
    "data/experiment_results/**",
    "data/redteam_results/**",
    "experiment_reports/**",
    ".experiment_state/**",
    # Git worktrees & isolated benchmark trees
    ".worktrees/**",
    ".worktrees/*",
    "worktrees/**",
    "worktrees/*",
]

DEVELOPER_ONLY_RULES: List[str] = [
    # Research survey & novelty docs (reference, not production)
    "docs/SURVEY_AND_PAPERS.md",
    "docs/RESEARCH_NOVELTY_LEDGER.md",
    "docs/BENCHMARK_METHODOLOGY.md",
    # Config files that may contain local paths
    "config.yaml",
    "agent_poi/config.yaml",
    # Internal tooling scripts & educational prototypes
    "scripts/fetch_arxiv_papers.py",
    "scripts/download_papers.py",
    "scripts/paper_tutor.py",
    "scripts/demo_vault_story.py",
    "scripts/audit_workspace_mistakes.py",
    "agent_poi/education/**",
    "agent_poi/education/*",
    "agent_poi/research/paper_tutor.py",
    "tests/test_education_modules.py",
    "tests/test_paper_tutor.py",
    # Academic paper LaTeX manuscript & build pipeline (Local only)
    "paper/**",
    "paper/*",
    "scripts/build_paper_pipeline.py",
    # Experimental & Red-Team Benchmarking code & test suites (Local only)
    "agent_poi/evaluation/advanced_experiments.py",
    "agent_poi/evaluation/deepteam_redteam.py",
    "agent_poi/research/worktree_runner.py",
    "scripts/run_worktree_redteam.py",
    "tests/test_advanced_experiments.py",
    "tests/test_deepteam_redteam.py",
    "tests/test_worktree_runner.py",
    # Live Gemini Probe harness & test (Local only)
    "scripts/run_gemini_onetime_probe.py",
    "tests/test_gemini_probe.py",
]

PUBLIC_EXPLICIT: List[str] = [
    # Production framework code
    "agent_poi/*.py",
    # Public tests
    "tests/*.py",
    "tests/conftest.py",
    # Packaging & CI
    "pyproject.toml",
    "requirements.txt",
    ".github/*",
    ".gitignore",
    # Public documentation
    "README.md",
    "LICENSE",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/MATHEMATICAL_FORMULATION.md",
    "docs/figures/*",
    # Production scripts
    "scripts/ci_check.py",
    "scripts/git_guardian.py",
    "scripts/run_experiment_pipeline.py",
]


def classify_file(relative_path: str) -> FileClass:
    """Classify a single file by its path relative to the workspace root.

    Uses first-match-wins semantics across three rule tiers:
    1. NEVER_TRACK — binary, secrets, caches, developer governance
    2. DEVELOPER_ONLY — internal reference docs, local configs
    3. PUBLIC — production code, tests, CI, public docs

    Default (no match): DEVELOPER_ONLY (fail-closed)
    """
    path = relative_path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]

    for pattern in NEVER_TRACK_RULES:
        if fnmatch.fnmatch(path, pattern):
            return FileClass.NEVER_TRACK

    for pattern in DEVELOPER_ONLY_RULES:
        if fnmatch.fnmatch(path, pattern):
            return FileClass.DEVELOPER_ONLY

    for pattern in PUBLIC_EXPLICIT:
        if fnmatch.fnmatch(path, pattern):
            return FileClass.PUBLIC

    # Default: DEVELOPER_ONLY (fail-closed — unknown files stay local)
    return FileClass.DEVELOPER_ONLY


def audit_git_staging(workspace_root: str) -> List[Tuple[str, FileClass, str]]:
    """Audit all git-staged files and flag non-PUBLIC violations.

    Returns a list of (filepath, classification, message) tuples for
    any staged file that should NOT be committed.
    """
    result = subprocess.run(
        ["git", "diff", "--cached", "--diff-filter=d", "--name-only"],
        capture_output=True,
        text=True,
        cwd=workspace_root,
    )
    violations: List[Tuple[str, FileClass, str]] = []

    for filepath in result.stdout.strip().split("\n"):
        filepath = filepath.strip()
        if not filepath:
            continue
        cls = classify_file(filepath)
        if cls != FileClass.PUBLIC:
            violations.append(
                (filepath, cls, f"BLOCKED: {filepath} classified as {cls.value}")
            )

    return violations


def audit_tracked_files(workspace_root: str) -> List[Tuple[str, FileClass, str]]:
    """Audit ALL currently tracked files and flag non-PUBLIC ones.

    Useful for identifying files that were previously committed
    but should not have been.
    """
    result = subprocess.run(
        ["git", "ls-files", "--cached"],
        capture_output=True,
        text=True,
        cwd=workspace_root,
    )
    violations: List[Tuple[str, FileClass, str]] = []

    for filepath in result.stdout.strip().split("\n"):
        filepath = filepath.strip()
        if not filepath:
            continue
        cls = classify_file(filepath)
        if cls != FileClass.PUBLIC:
            violations.append(
                (filepath, cls, f"TRACKED BUT {cls.value}: {filepath}")
            )

    return violations


def get_classification_report(workspace_root: str) -> str:
    """Generate a human-readable classification report for all tracked files."""
    result = subprocess.run(
        ["git", "ls-files", "--cached"],
        capture_output=True,
        text=True,
        cwd=workspace_root,
    )
    lines = [
        "=" * 70,
        " FILE CLASSIFICATION REPORT",
        "=" * 70,
        "",
    ]
    counts = {FileClass.PUBLIC: 0, FileClass.DEVELOPER_ONLY: 0, FileClass.NEVER_TRACK: 0}

    for filepath in sorted(result.stdout.strip().split("\n")):
        filepath = filepath.strip()
        if not filepath:
            continue
        cls = classify_file(filepath)
        counts[cls] += 1
        icon = {"PUBLIC": "✅", "DEVELOPER_ONLY": "⚠️", "NEVER_TRACK": "🚫"}[cls.value]
        lines.append(f"  {icon} [{cls.value:15s}] {filepath}")

    lines.extend([
        "",
        "-" * 70,
        f"  PUBLIC:         {counts[FileClass.PUBLIC]}",
        f"  DEVELOPER_ONLY: {counts[FileClass.DEVELOPER_ONLY]}",
        f"  NEVER_TRACK:    {counts[FileClass.NEVER_TRACK]}",
        "=" * 70,
    ])

    return "\n".join(lines)
