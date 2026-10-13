"""Tests for the File Classification Engine.

Ensures the classifier correctly identifies:
- PUBLIC files (production code)
- DEVELOPER_ONLY files (internal artifacts)
- NEVER_TRACK files (PDFs, binaries, secrets)
"""

from agent_poi.core.file_classifier import classify_file, FileClass


class TestFileClassifierPublicFiles:
    """Production files that SHOULD be pushed to GitHub."""

    def test_python_source_files(self):
        assert classify_file("agent_poi/core/taint_tracker.py") == FileClass.PUBLIC

    def test_test_files(self):
        assert classify_file("tests/test_facade.py") == FileClass.PUBLIC

    def test_readme(self):
        assert classify_file("README.md") == FileClass.PUBLIC

    def test_license(self):
        assert classify_file("LICENSE") == FileClass.PUBLIC

    def test_pyproject(self):
        assert classify_file("pyproject.toml") == FileClass.PUBLIC

    def test_requirements(self):
        assert classify_file("requirements.txt") == FileClass.PUBLIC

    def test_ci_workflow(self):
        assert classify_file(".github/workflows/ci.yml") == FileClass.PUBLIC

    def test_gitignore(self):
        assert classify_file(".gitignore") == FileClass.PUBLIC

    def test_architecture_doc(self):
        assert classify_file("docs/ARCHITECTURE.md") == FileClass.PUBLIC

    def test_architecture_figures(self):
        assert classify_file("docs/figures/architecture.jpg") == FileClass.PUBLIC


class TestFileClassifierNeverTrack:
    """Files that must NEVER enter git history."""

    def test_pdf_papers(self):
        assert classify_file("docs/papers/01_abdelnabi2026_ai_agents_always_fall.pdf") == FileClass.NEVER_TRACK

    def test_any_pdf(self):
        assert classify_file("some/random/paper.pdf") == FileClass.NEVER_TRACK

    def test_mistakes_ledger(self):
        assert classify_file("MISTAKES_LEDGER.md") == FileClass.NEVER_TRACK

    def test_project_ledger(self):
        assert classify_file("PROJECT_LEDGER.md") == FileClass.NEVER_TRACK

    def test_agents_md(self):
        assert classify_file("AGENTS.md") == FileClass.NEVER_TRACK

    def test_everything_claude_code(self):
        assert classify_file("everything-claude-code/agents/architect.md") == FileClass.NEVER_TRACK

    def test_dot_agents(self):
        assert classify_file(".agents/swe_1/output.md") == FileClass.NEVER_TRACK

    def test_venv(self):
        assert classify_file(".venv/lib/python3.12/site.py") == FileClass.NEVER_TRACK

    def test_pyc_files(self):
        assert classify_file("agent_poi/__pycache__/facade.cpython-312.pyc") == FileClass.NEVER_TRACK

    def test_env_file(self):
        assert classify_file(".env") == FileClass.NEVER_TRACK

    def test_uv_lock(self):
        assert classify_file("uv.lock") == FileClass.NEVER_TRACK

    def test_pareto_png(self):
        assert classify_file("docs/pareto_frontier.png") == FileClass.NEVER_TRACK


class TestFileClassifierDeveloperOnly:
    """Files for local development only — not pushed."""

    def test_survey_doc(self):
        assert classify_file("docs/SURVEY_AND_PAPERS.md") == FileClass.DEVELOPER_ONLY

    def test_research_novelty(self):
        assert classify_file("docs/RESEARCH_NOVELTY_LEDGER.md") == FileClass.DEVELOPER_ONLY

    def test_config_yaml(self):
        assert classify_file("config.yaml") == FileClass.DEVELOPER_ONLY

    def test_latex_paper(self):
        assert classify_file("paper/sections/04_architecture.tex") == FileClass.DEVELOPER_ONLY

    def test_paper_bib(self):
        assert classify_file("paper/references.bib") == FileClass.DEVELOPER_ONLY

    def test_build_paper_pipeline(self):
        assert classify_file("scripts/build_paper_pipeline.py") == FileClass.DEVELOPER_ONLY

    def test_benchmarking_code_quarantine(self):
        assert classify_file("agent_poi/evaluation/advanced_experiments.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("agent_poi/evaluation/deepteam_redteam.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("agent_poi/research/worktree_runner.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("scripts/run_worktree_redteam.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("tests/test_advanced_experiments.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("tests/test_deepteam_redteam.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("tests/test_worktree_runner.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("scripts/run_gemini_onetime_probe.py") == FileClass.DEVELOPER_ONLY
        assert classify_file("tests/test_gemini_probe.py") == FileClass.DEVELOPER_ONLY


class TestFileClassifierDefaultBehavior:
    """Unknown files should default to DEVELOPER_ONLY (fail-closed)."""

    def test_unknown_file(self):
        assert classify_file("random_notes.txt") == FileClass.DEVELOPER_ONLY

    def test_unknown_markdown(self):
        assert classify_file("INTERNAL_NOTES.md") == FileClass.DEVELOPER_ONLY

    def test_worktree_quarantine(self):
        assert classify_file(".worktrees/wt-exp-001/file.py") == FileClass.NEVER_TRACK
        assert classify_file("worktrees/wt-exp-001/file.py") == FileClass.NEVER_TRACK
        assert classify_file("data/redteam_results/EXP-01.json") == FileClass.NEVER_TRACK
