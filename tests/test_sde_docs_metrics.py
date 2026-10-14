"""Guard tests: published SDE metrics and figures must match live execution.

These tests exist to make fabrication impossible to commit. They re-run the benchmark and fail
if the README, the architecture specification or the architecture figure generator state a
number the code does not reproduce, or if a metric literal is hardcoded anywhere in the figure
pipeline.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Dict, List

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import scripts.generate_sde_architecture_diagram as diagram  # noqa: E402
import scripts.render_sde_metrics as renderer  # noqa: E402
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor  # noqa: E402
from agentpoi_sde.delta.mutation_delta import MutationDeltaExtractor  # noqa: E402
from agentpoi_sde.domain import CodeMutation, IntentContract, MutationOp  # noqa: E402
from agentpoi_sde.eval.benchmark import run_benchmark  # noqa: E402
from agentpoi_sde.eval.repo_sandbox import CORE_ENGINE, RepoSandbox  # noqa: E402
from agentpoi_sde.eval.scenario_dataset import SDEScenario  # noqa: E402
from agentpoi_sde.verify.invariant_verifier import RepoInvariantVerifier  # noqa: E402

METRICS = ("EMAR", "LTSR", "CDR", "AVR", "SLR")
METRIC_PATTERN = re.compile(r"(EMAR|LTSR|CDR|AVR|SLR)\s*=\s*[0-9]")


@pytest.fixture(scope="module")
def report():
    """One live benchmark execution shared by the assertions in this module."""
    return run_benchmark()


def _percentages(text: str) -> List[str]:
    """Extract every percentage literal from a text block, in order."""
    return re.findall(r"-?\d+\.\d+%", text)


def _expected_percentages(report) -> List[str]:
    """The percentages a truthful document must contain, baseline then defended."""
    values: List[str] = []
    for metrics in (report.baseline, report.defended):
        values.extend(
            [
                f"{metrics.emar:.1f}%",
                f"{metrics.ltsr:.1f}%",
                f"{metrics.cdr:.1f}%",
                f"{metrics.avr:.1f}%",
                f"{metrics.slr:.1f}%",
            ]
        )
    return values


def test_documentation_benchmark_blocks_match_live_execution(report):
    """The committed README/architecture tables are exactly what the code produces."""
    rendered = renderer.render_targets(report)
    assert rendered, "the documentation renderer must have targets"

    for path, expected in rendered.items():
        rel = os.path.relpath(path, REPO_ROOT).replace("\\", "/")
        with open(path, "r", encoding="utf-8") as handle:
            actual = handle.read()
        assert renderer._strip_latency(actual) == renderer._strip_latency(expected), (
            f"{rel} documents stale SDE metrics; "
            f"run: python scripts/render_sde_metrics.py"
        )


def test_documented_block_contains_the_measured_metrics(report):
    """The generated block states the real baseline and defended percentages."""
    block = renderer.render_block(report)
    for value in _expected_percentages(report):
        assert value in block, f"generated documentation block omits measured value {value}"


def test_readme_reports_the_real_scenario_and_family_counts(report):
    """Scenario, adversarial and family counts in the documentation are measured, not guessed."""
    readme = open(os.path.join(REPO_ROOT, "README.md"), "r", encoding="utf-8").read()
    total = report.defended.adversarial_total + report.defended.clean_total
    families = len(report.defended.per_family)
    assert f"{total}-scenario suite" in readme
    assert f"{report.defended.adversarial_total} adversarial mutations across {families} attack families" in readme


def test_diagram_summary_lines_match_live_metrics(report):
    """Every metric line the figure renders reproduces a fresh benchmark execution."""
    summary = diagram.benchmark_summary_lines(report)
    joined = "\n".join(text for _, text in summary)
    for value in _expected_percentages(report):
        assert value in joined, f"figure summary omits measured value {value}"
    assert (
        f"Adversarial mutations landed: {report.defended.adversarial_landed}/"
        f"{report.defended.adversarial_total}"
    ) in joined
    assert f"{report.defended.clean_landed}/{report.defended.clean_total}" in joined


def test_diagram_generator_hardcodes_no_metric():
    """The figure pipeline must derive metrics, never embed them."""
    source = open(
        os.path.join(REPO_ROOT, "scripts", "generate_sde_architecture_diagram.py"),
        "r",
        encoding="utf-8",
    ).read()
    offenders = [
        f"{line.strip()}" for line in source.splitlines() if METRIC_PATTERN.search(line)
    ]
    assert not offenders, "hardcoded metric literals found in the figure generator: " + "; ".join(
        offenders
    )


def test_metric_renderer_hardcodes_no_metric():
    """The documentation renderer must not embed measured values either."""
    source = open(
        os.path.join(REPO_ROOT, "scripts", "render_sde_metrics.py"), "r", encoding="utf-8"
    ).read()
    offenders = [
        line.strip() for line in source.splitlines() if re.search(r"\d+\.\d+%", line)
    ]
    assert not offenders, "hardcoded percentage literals in the renderer: " + "; ".join(
        offenders
    )


def test_layout_validator_rejects_overlap_and_canvas_overflow():
    """The figure's layout is checked, so a broken panel cannot silently ship."""
    with pytest.raises(ValueError):
        diagram.validate_layout([("a", 0.0, 0.0, 5.0, 5.0), ("b", 2.0, 2.0, 5.0, 5.0)])
    with pytest.raises(ValueError):
        diagram.validate_layout([("a", 15.0, 9.0, 5.0, 5.0)])
    diagram.validate_layout([("a", 0.0, 0.0, 2.0, 2.0), ("b", 3.0, 0.0, 2.0, 2.0)])


def test_figure_renders_without_layout_defects(tmp_path):
    """The generator produces a real image and passes its own layout validation."""
    out = tmp_path / "figure.png"
    diagram.generate_diagram(str(out))
    assert out.exists()
    assert out.stat().st_size > 10_000, "the rendered figure looks empty"


def test_figure_invariant_catalogue_matches_the_verifier():
    """The invariants drawn in the figure are the ones the verifier can actually emit."""
    codes = {name.split()[0] for name, _ in diagram.INVARIANTS}
    expected = {f"I{index}" for index in range(1, 10)} | {"D1"}
    assert codes == expected

    verifier_source = open(
        os.path.join(REPO_ROOT, "agentpoi_sde", "verify", "invariant_verifier.py"),
        "r",
        encoding="utf-8",
    ).read()
    for code in sorted(expected):
        assert f'"{code}"' in verifier_source, f"verifier never emits {code}"


def test_architecture_document_does_not_regress_to_the_old_invariant_count():
    """The public spec must not claim the superseded 7-invariant pipeline."""
    doc = open(
        os.path.join(REPO_ROOT, "docs", "SDE_ARCHITECTURE.md"), "r", encoding="utf-8"
    ).read()
    assert "seven sink invariants" not in doc.lower()
    assert "seven gates" not in doc.lower()
    for code in ("I7", "I8", "I9"):
        assert code in doc


def test_scenario_requires_an_explicit_mutation():
    """A scenario can never be constructed without a real mutation (no invented placeholder)."""
    with pytest.raises(TypeError):
        SDEScenario("s", "family", None)  # type: ignore[arg-type]


def test_scenario_rejects_unknown_keyword_arguments():
    """A typo in a scenario keyword must raise instead of silently scoring a dummy mutation."""
    from agentpoi_sde.domain import CodeMutation, MutationOp

    with pytest.raises(TypeError):
        SDEScenario(  # type: ignore[call-arg]
            scenario_id="s",
            family="f",
            mutation=CodeMutation("a.py", MutationOp.CREATE, "x = 1\n"),
            unexpected_keyword=True,
        )


def test_delete_oracle_cannot_score_a_nonexistent_file_as_landed():
    """Deleting a file that was never there is not an attacker success."""
    scenario = SDEScenario(
        "delete-missing",
        "delete_family",
        CodeMutation("absent.py", MutationOp.DELETE, "", old_content="gone\n"),
        is_adversarial=True,
    )
    baseline: Dict[str, str] = {CORE_ENGINE: "x = 1\n"}
    assert scenario.landed({}, baseline=baseline) is False

    present_baseline = {"absent.py": "y = 1\n"}
    assert scenario.landed({}, baseline=present_baseline) is True


def test_delete_oracle_is_unchanged_when_no_baseline_is_supplied():
    """The legacy single-argument form keeps its previous behaviour."""
    scenario = SDEScenario(
        "delete-missing",
        "delete_family",
        CodeMutation("absent.py", MutationOp.DELETE, "", old_content="gone\n"),
        is_adversarial=True,
    )
    assert scenario.landed({"absent.py": "y = 1\n"}) is False
    assert scenario.landed({}) is True


def test_permissive_benchmark_still_genuinely_breaches(report):
    """Anti-cheat: the undefended baseline must remain a real, undefended baseline."""
    assert report.baseline.emar == 100.0
    assert report.defended.emar == 0.0
    assert report.defended.ltsr == 100.0
    assert report.defended.cdr == 0.0


def test_readme_quickstart_workflow_behaves_as_documented():
    """The published DevGuard example must run, and produce the outputs it claims."""
    from agentpoi_sde import CodeMutation, DevGuard, GuardPolicy, MutationOp

    guard = DevGuard(policy=GuardPolicy.STRICT)
    guard.register_intent(
        intent_id="ISSUE-104",
        goal="Add telemetry helper function",
        allowed_paths=["svc/core/engine.py"],
    )
    proposal = CodeMutation(
        path="svc/core/engine.py",
        op=MutationOp.MODIFY,
        new_content=(
            "# Core engine\n"
            "def compute(x: int) -> int:\n"
            "    return x + 1\n"
            "\n"
            "def telemetry_ping() -> str:\n"
            '    return "ok"\n'
        ),
    )
    verdict = guard.propose_mutation(proposal, intent_id="ISSUE-104", nonce="readme-1")
    assert verdict.is_applied is True
    assert verdict.status == "APPROVED"

    injected = CodeMutation(
        path=".github/workflows/ci.yml",
        op=MutationOp.MODIFY,
        new_content="name: ci\njobs:\n  test:\n    steps:\n      - run: echo bypass\n",
    )
    blocked = guard.propose_mutation(injected, intent_id="ISSUE-104", nonce="readme-2")
    assert blocked.is_applied is False
    assert blocked.status == "BLOCKED"
    assert blocked.violation_codes == ["I5", "I1"]


def test_clean_mutation_still_passes_every_gate():
    """Anti-cheat: the docs work above must not have been bought by weakening the sink."""
    sandbox = RepoSandbox.default()
    anchor = RepositoryStateAnchor(files=sandbox.to_files(), policy=sandbox.policy)
    delta = MutationDeltaExtractor(sandbox.policy).extract(
        CodeMutation(
            CORE_ENGINE,
            MutationOp.MODIFY,
            sandbox.files[CORE_ENGINE] + "\n\ndef helper() -> int:\n    return 1\n",
        ),
        previous_content=sandbox.files[CORE_ENGINE],
    )
    assert RepoInvariantVerifier(anchor).verify(IntentContract("T", "noop", (CORE_ENGINE,)), delta) == []


def test_negative_control_detects_a_falsified_block():
    """Anti-cheat: the sync check must actually fail when a documented metric is falsified."""
    rendered = renderer.render_targets()
    poisoned = {
        path: text.replace("| **0.0%**", "| **99.9%**", 1)
        for path, text in rendered.items()
    }

    assert all(
        poisoned[path] != rendered[path] for path in rendered
    ), "the negative control failed to alter the generated block"
    assert any(
        renderer._strip_latency(poisoned[path]) != renderer._strip_latency(rendered[path])
        for path in rendered
    ), "the sync check would not notice a falsified metric"
