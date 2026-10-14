#!/usr/bin/env python3
"""Generate the AgentPOI-SDE architecture figure from the platform's live behaviour.

Nothing in this figure is hardcoded: the benchmark card is rendered from a fresh
``agentpoi_sde.eval.benchmark.run_benchmark()`` execution over the current repository, and the
invariant/component inventory is the catalogue the verifier actually implements. If the
platform changes, the figure either changes with it or ``tests/test_sde_docs_metrics.py``
fails.

Produces: docs/sde_architecture_diagram.png
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional, Sequence, Tuple

# Configure a writable cache directory for matplotlib in sandboxes.
os.environ.setdefault(
    "MPLCONFIGDIR", os.path.join(os.path.dirname(__file__), "..", ".venv", ".matplotlib")
)

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agentpoi_sde.eval.benchmark import BenchmarkReport, run_benchmark  # noqa: E402

# Paper colour palette (arXiv-style figure guidelines).
C = {
    "bg": "#FFFFFF",
    "t0": "#4080F0", "t0d": "#2456B0", "t0f": "#EAF1FC",   # Blue: ingestion
    "t1": "#001050", "t1d": "#000830", "t1f": "#F0F4FC",   # Navy: anchor R0
    "t2": "#7B5EC6", "t2d": "#5A3FA0", "t2f": "#F2EFFB",   # Violet: delta
    "t3": "#D25C5C", "t3d": "#A83A3A", "t3f": "#FCEAEA",   # Rose: invariants
    "t4": "#2C93A8", "t4d": "#1E6E80", "t4f": "#E5F4F7",   # Teal: provenance & graph
    "t5": "#30A050", "t5d": "#1F7A3A", "t5f": "#E6F6EB",   # Green: sink
    "adv": "#E04030", "advf": "#FDEAE8",                   # Adversarial / advisory
    "warn": "#8A6500", "warnf": "#FFF8E7",
    "border": "#2C3E50",
    "text": "#1A2530",
    "subtext": "#4A5568",
}

# The sink invariants the verifier implements (see docs/SDE_ARCHITECTURE.md §3).
INVARIANTS: Tuple[Tuple[str, str], ...] = (
    ("I1 Policy Integrity", "T2 context cannot mutate CI / agent policy files"),
    ("I2 Test Integrity", "No test deletion, skip or assertion weakening"),
    ("I3 Secret & Egress", "No new credentials or unallow-listed egress host"),
    ("I4 Arch Layering", "No forbidden import edge, cycle or layer inversion"),
    ("I5 Blast Radius", "Every mutated path must sit inside declared intent I"),
    ("I6 Dependency Provenance", "New imports must be anchored or allow-listed"),
    ("I7 Syntax Integrity", "Unparsable Python is refused, never skipped"),
    ("I8 Schema Consensus", "Frontend calls must match backend route contracts"),
    ("I9 Working-Part Immutability", "Protected working files need an explicit grant"),
    ("D1 Design ADR Gate", "Executable ADRs reject contradicting mutations"),
)


def validate_layout(
    panels: Sequence[Tuple[str, float, float, float, float]],
    xlim: Tuple[float, float] = (0.0, 16.0),
    ylim: Tuple[float, float] = (0.0, 10.0),
) -> None:
    """Fail loudly if a figure panel escapes the canvas or overlaps another panel.

    The figure is generated, so its layout is a property that can be checked rather than
    eyeballed: a panel that overruns the canvas or collides with a neighbour raises here
    instead of shipping a broken figure.
    """
    for name, x, y, w, h in panels:
        if x < xlim[0] or y < ylim[0] or x + w > xlim[1] or y + h > ylim[1]:
            raise ValueError(f"panel {name!r} escapes the canvas: {(x, y, w, h)}")

    for index, (name, x, y, w, h) in enumerate(panels):
        for other, ox, oy, ow, oh in panels[index + 1:]:
            overlap_x = min(x + w, ox + ow) - max(x, ox)
            overlap_y = min(y + h, oy + oh) - max(y, oy)
            if overlap_x > 1e-9 and overlap_y > 1e-9:
                raise ValueError(f"panels {name!r} and {other!r} overlap")


def draw_box(ax, x, y, w, h, fill, border, r=0.015, lw=1.2, ls="-", zorder=2):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        facecolor=fill, edgecolor=border, linewidth=lw, linestyle=ls, zorder=zorder,
    )
    ax.add_patch(box)
    return box


def draw_arrow(ax, p1, p2, color="#2C3E50", lw=1.5, ls="-", zorder=3):
    arrow = FancyArrowPatch(
        p1, p2,
        arrowstyle="-|>", mutation_scale=14,
        color=color, linewidth=lw, linestyle=ls, zorder=zorder,
    )
    ax.add_patch(arrow)
    return arrow


def draw_title(ax, x, y, text, color, size=11.0):
    ax.text(x, y, text, fontsize=size, fontweight="bold", color=color, family="sans-serif")


def draw_bullets(ax, x, y_top, rows: Sequence[str], color, size=8.6, step=0.34):
    """Draw a list of bullet lines downward from ``y_top``."""
    for index, row in enumerate(rows):
        ax.text(x, y_top - index * step, f"• {row}", fontsize=size, color=color, family="sans-serif")


def metric_line(label: str, metrics) -> str:
    """Render one benchmark row as monospace text (mirrors ``SDEMetrics``)."""
    return (
        f"{label}  EMAR = {metrics.emar:6.1f}%  |  LTSR = {metrics.ltsr:6.1f}%  |  "
        f"CDR = {metrics.cdr:5.1f}%  |  AVR = {metrics.avr:5.1f}%  |  SLR = {metrics.slr:5.1f}%"
    )


def benchmark_summary_lines(report: Optional[BenchmarkReport] = None) -> List[Tuple[str, str]]:
    """Return the benchmark card as (style, text) pairs, computed from a live run.

    Rendering and verification share this function, so the figure can never state a metric
    that a fresh execution does not reproduce.
    """
    report = report or run_benchmark()
    baseline, defended = report.baseline, report.defended
    total = defended.adversarial_total + defended.clean_total
    families = len(defended.per_family)
    blocked = defended.adversarial_total - defended.adversarial_landed
    return [
        (
            "head",
            "Empirical Benchmark — computed live from this repository against the "
            "defence-independent state-diff oracle",
        ),
        (
            "note",
            f"Scenario suite: {total} scenarios = {defended.adversarial_total} adversarial "
            f"({families} attack families) + {defended.clean_total} legitimate engineering tasks",
        ),
        ("baseline", metric_line("Undefended (permissive) :", baseline)),
        ("defended", metric_line("AgentPOI-SDE (fail-closed):", defended)),
        (
            "note",
            f"Adversarial mutations landed: {defended.adversarial_landed}/"
            f"{defended.adversarial_total} ({blocked} blocked)  ·  Legitimate tasks preserved: "
            f"{defended.clean_landed}/{defended.clean_total}",
        ),
        (
            "note",
            "Every figure above is recomputed when this figure is generated; no value is "
            "hardcoded and CI regenerates the benchmark on each run.",
        ),
    ]


def generate_diagram(output_path: str, report: Optional[BenchmarkReport] = None) -> None:
    """Render the architecture figure, reading all metrics from a live benchmark run."""
    summary = benchmark_summary_lines(report)

    fig = plt.figure(figsize=(16, 10), dpi=300)
    ax = fig.add_subplot(111)
    ax.set_facecolor(C["bg"])
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")

    panels: List[Tuple[str, float, float, float, float]] = []

    def panel(name, x, y, w, h, fill, border, lw=1.2, ls="-"):
        """Draw a panel and register it for layout validation."""
        draw_box(ax, x, y, w, h, fill, border, lw=lw, ls=ls)
        panels.append((name, x, y, w, h))

    # -- title -------------------------------------------------------------------
    ax.text(
        8.0, 9.62, "AgentPOI-SDE — Fail-Closed Repository Invariant Verification (RIV)",
        fontsize=17, fontweight="bold", color=C["text"], ha="center", family="sans-serif",
    )
    ax.text(
        8.0, 9.28,
        "Deterministic three-way match:  Intent Contract I  ↔  Repository State Anchor R0  "
        "↔  Mutation Delta Δ",
        fontsize=10.5, color=C["subtext"], ha="center", family="sans-serif", style="italic",
    )

    # -- Tier 0: tripartite ingestion --------------------------------------------
    panel("tier0-ingestion", 0.5, 7.05, 4.4, 1.85, C["t0f"], C["t0d"], lw=1.4)
    draw_title(ax, 0.7, 8.62, "Tier 0 — Tripartite Ingestion (Trust Tiering)", C["t0d"], 10.5)
    ax.text(0.7, 8.26, "• T0 Verified: authenticated task prompt / issue = I", fontsize=8.6, color=C["text"])
    ax.text(0.7, 7.90, "• T1 Committed: repository ground truth = R0", fontsize=8.6, color=C["text"])
    ax.text(0.7, 7.54, "• T2 Untrusted: web, MCP, PRs, tool output, memory", fontsize=8.6, color=C["adv"])

    # -- Tier 1: intent shield ----------------------------------------------------
    panel("tier1-intent-shield", 0.5, 4.85, 4.4, 1.75, C["t0f"], C["t0d"], lw=1.2)
    draw_title(ax, 0.7, 6.32, "Tier 1 — Intent Shield", C["t0d"], 10.5)
    draw_bullets(ax, 0.7, 5.96, [
        "Imperative-divergence screening of context",
        "Injection markers flagged before reasoning",
        "T0 obligations bound to the mutation sink",
    ], C["text"])

    # -- Advisory LLM (untrusted proposal source) --------------------------------
    panel("advisory-llm", 0.5, 2.65, 4.4, 1.75, C["warnf"], C["warn"], lw=1.2, ls="--")
    draw_title(ax, 0.7, 4.12, "Advisory LLM Reasoning (pluggable)", C["warn"], 10.5)
    draw_bullets(ax, 0.7, 3.76, [
        "OpenRouter-compatible API or deterministic provider",
        "Output is strictly an UNTRUSTED mutation proposal",
        "Fail-closed: error / no key / unparsable → 0 proposals",
    ], C["text"])

    # -- Tier 2: repository state anchor R0 --------------------------------------
    panel("tier2-anchor", 5.3, 7.05, 5.1, 1.85, C["t1f"], C["t1"], lw=1.8)
    draw_title(ax, 5.5, 8.62, "Tier 2 — Repository State Anchor ℛ₀", C["t1"], 10.5)
    draw_bullets(ax, 5.5, 8.26, [
        "Content-addressed git tree OID (SHA-256 manifest)",
        "AST symbol table + import graph, cycle detection",
        "Lockfile dependencies, layered architecture policy",
        "Executable ADRs (D1) + working-part registry (I9)",
    ], C["text"], step=0.30)

    # -- Tier 3: mutation delta ---------------------------------------------------
    panel("tier3-delta", 5.3, 4.85, 5.1, 1.75, C["t2f"], C["t2d"], lw=1.4)
    draw_title(ax, 5.5, 6.32, "Tier 3 — Mutation Delta Δ(edit)", C["t2d"], 10.5)
    draw_bullets(ax, 5.5, 5.96, [
        "Fail-closed unified diff parser (path containment)",
        "Syntax pre-parse (ast.parse) + patch hash",
        "Import delta, secret tokens, egress endpoints",
        "Cross-stack call/route contract extraction",
    ], C["text"], step=0.30)

    # -- Tier 4: invariant verification ------------------------------------------
    panel("tier4-invariants", 10.8, 3.30, 4.7, 5.60, C["t3f"], C["t3d"], lw=1.8)
    draw_title(ax, 11.0, 8.62, "Tier 4 — Invariant Gates (I1–I9 + D1)", C["t3d"], 10.5)
    for index, (name, desc) in enumerate(INVARIANTS):
        yy = 8.22 - index * 0.50
        ax.text(11.0, yy, f"• {name}", fontsize=8.0, fontweight="bold", color=C["t3d"])
        ax.text(11.15, yy - 0.21, desc, fontsize=7.2, color=C["subtext"])

    # -- Tier 5: provenance, capability and the cryptographic graph --------------
    panel("tier5-provenance", 5.3, 2.65, 5.1, 1.75, C["t4f"], C["t4d"], lw=1.4)
    draw_title(ax, 5.5, 4.12, "Tier 5 — Provenance P, Capability κ, Freshness", C["t4d"], 10.5)
    draw_bullets(ax, 5.5, 3.76, [
        "SHA-256 hash-chained lineage DAG per context node",
        "Non-bypassable CapabilityScope tokens + nonce freshness",
        "Merkle knowledge graph + architectural ledger (what/how/why)",
    ], C["text"], step=0.30)

    # -- Tier 6: fail-closed sink -------------------------------------------------
    panel("tier6-sink", 0.5, 0.55, 4.4, 1.85, C["t5f"], C["t5d"], lw=1.8)
    draw_title(ax, 0.7, 2.12, "Tier 6 — Fail-Closed Sink & Public API", C["t5d"], 10.5)
    draw_bullets(ax, 0.7, 1.76, [
        "DevGuard.propose_mutation() — public facade",
        "CLI: agentpoi-sde anchor | check-diff | benchmark",
        "APPROVED (exit 0) else BLOCKED (exit 1) + quarantine",
    ], C["t5d"], step=0.30)

    # -- benchmark card (live values) --------------------------------------------
    panel("benchmark-card", 5.3, 0.55, 10.2, 1.85, "#F8FAFC", C["border"], lw=1.2)
    y = 2.16
    for style, text in summary:
        if style == "head":
            ax.text(5.5, y, text, fontsize=9.0, fontweight="bold", color=C["text"])
            y -= 0.30
        elif style == "note":
            ax.text(5.5, y, text, fontsize=7.6, color=C["subtext"], style="italic")
            y -= 0.27
        else:
            colour = C["adv"] if style == "baseline" else C["t5d"]
            ax.text(5.5, y, text, fontsize=8.0, family="monospace", color=colour)
            y -= 0.30

    validate_layout(panels)

    # -- dataflow arrows ----------------------------------------------------------
    draw_arrow(ax, (2.70, 7.05), (2.70, 6.60), color=C["t0d"])       # T0  -> shield
    draw_arrow(ax, (4.90, 7.97), (5.30, 7.97), color=C["t0d"])       # T0  -> anchor
    draw_arrow(ax, (4.90, 5.72), (5.30, 5.72), color=C["t0d"])       # shield -> delta
    draw_arrow(ax, (7.85, 7.05), (7.85, 6.60), color=C["t1"])        # anchor -> delta
    draw_arrow(ax, (4.90, 4.40), (5.60, 4.85), color=C["warn"])      # advisory -> delta
    draw_arrow(ax, (10.40, 5.72), (10.80, 5.72), color=C["t2d"])     # delta -> invariants
    draw_arrow(ax, (10.80, 3.60), (10.40, 3.60), color=C["t4d"])     # invariants -> provenance
    draw_arrow(ax, (5.30, 3.30), (4.90, 2.40), color=C["t5d"])       # provenance -> sink

    plt.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated SDE architecture diagram at: {output_path}")
    for _, line in summary:
        print(f"  {line}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point: optionally takes an explicit output path."""
    args = list(argv if argv is not None else sys.argv[1:])
    out = args[0] if args else os.path.join(REPO_ROOT, "docs", "sde_architecture_diagram.png")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    generate_diagram(os.path.abspath(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
