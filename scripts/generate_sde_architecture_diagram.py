#!/usr/bin/env python3
"""Generate publication-grade AgentPOI-SDE Architecture Diagram in arXiv paper style.

Produces: docs/sde_architecture_diagram.png
"""
from __future__ import annotations

import os
import sys

# Configure writable cache directory for matplotlib in sandbox
os.environ.setdefault("MPLCONFIGDIR", os.path.join(os.path.dirname(__file__), "..", ".venv", ".matplotlib"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

# Measured paper color palette (matching arXiv figure guidelines)
C = {
    "bg": "#FFFFFF",
    # Tier accents
    "t0": "#4080F0", "t0d": "#2456B0", "t0f": "#EAF1FC",   # Blue: Intent & Ingestion
    "t1": "#001050", "t1d": "#000830", "t1f": "#F0F4FC",   # Navy: State Anchor R0
    "t2": "#7B5EC6", "t2d": "#5A3FA0", "t2f": "#F2EFFB",   # Violet: Delta Extraction
    "t3": "#D25C5C", "t3d": "#A83A3A", "t3f": "#FCEAEA",   # Rose: Invariant Verification
    "t4": "#2C93A8", "t4d": "#1E6E80", "t4f": "#E5F4F7",   # Teal: Provenance & Scope
    "t5": "#30A050", "t5d": "#1F7A3A", "t5f": "#E6F6EB",   # Green: Fail-Closed Sink
    "adv": "#E04030", "advf": "#FDEAE8",                   # Adversarial
    "border": "#2C3E50",
    "text": "#1A2530",
    "subtext": "#4A5568",
}


def draw_box(ax, x, y, w, h, fill, border, r=0.015, lw=1.2, ls="-", zorder=2):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        facecolor=fill, edgecolor=border, linewidth=lw, linestyle=ls, zorder=zorder
    )
    ax.add_patch(box)
    return box


def draw_arrow(ax, p1, p2, color="#2C3E50", lw=1.5, ls="-", zorder=3):
    arrow = FancyArrowPatch(
        p1, p2,
        arrowstyle="-|>",
        mutation_scale=14,
        color=color,
        linewidth=lw,
        linestyle=ls,
        zorder=zorder
    )
    ax.add_patch(arrow)
    return arrow


def generate_diagram(output_path: str) -> None:
    fig = plt.figure(figsize=(16, 10), dpi=300)
    ax = fig.add_subplot(111)
    ax.set_facecolor(C["bg"])
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")

    # Title Banner
    ax.text(8.0, 9.6, "AgentPOI-SDE: Fail-Closed Repository Invariant Verification (RIV)",
            fontsize=18, fontweight="bold", color=C["text"], ha="center", fontfamily="sans-serif")
    ax.text(8.0, 9.25, "Deterministic Three-Way Match: Intent Contract I <-> Repository State Anchor R0 <-> Mutation Delta Δ",
            fontsize=11, color=C["subtext"], ha="center", fontfamily="sans-serif", style="italic")

    # Tier 0: Ingestion & Tripartite Input Sources
    draw_box(ax, 0.6, 7.1, 4.4, 1.8, C["t0f"], C["t0d"], lw=1.4)
    ax.text(0.8, 8.6, "Tier 0: Untrusted Tripartite Context Ingestion", fontsize=11, fontweight="bold", color=C["t0d"])
    ax.text(0.8, 8.25, "• T0 (Verified Prompt): Authenticated user issue/task I", fontsize=9, color=C["text"])
    ax.text(0.8, 7.85, "• T1 (Committed State): Repository tree R0 (Git tree OID)", fontsize=9, color=C["text"])
    ax.text(0.8, 7.45, "• T2 (Untrusted Context): Web, MCP outputs, PRs, comments", fontsize=9, color=C["adv"])

    # Advisory LLM Reasoning Engine (Untrusted Proposals)
    draw_box(ax, 0.6, 5.0, 4.4, 1.6, "#FFF8E7", "#C99700", lw=1.2, ls="--")
    ax.text(0.8, 6.25, "Advisory LLM Reasoning Core (Pluggable)", fontsize=11, fontweight="bold", color="#8A6500")
    ax.text(0.8, 5.85, "• Pluggable API (OpenRouter, local script)", fontsize=9, color=C["text"])
    ax.text(0.8, 5.50, "• Output treated strictly as UNTRUSTED proposal", fontsize=9, color=C["text"])
    ax.text(0.8, 5.15, "• Fail-closed fallback: 0 proposals on error", fontsize=9, color="#8A6500")

    # Tier 1: Ground Truth Anchor R0
    draw_box(ax, 5.8, 7.1, 4.6, 1.8, C["t1f"], C["t1"], lw=1.8)
    ax.text(6.0, 8.6, "Tier 1: Content-Addressed State Anchor (R0)", fontsize=11, fontweight="bold", color=C["t1"])
    ax.text(6.0, 8.25, "• Content-Addressed Git Tree OID (SHA-256)", fontsize=9, color=C["text"])
    ax.text(6.0, 7.85, "• AST Symbol Table & Direct/Relative Import Graph", fontsize=9, color=C["text"])
    ax.text(6.0, 7.45, "• Lockfile Dependencies & Layered Architecture Policy", fontsize=9, color=C["text"])

    # Tier 2: Mutation Delta Extractor
    draw_box(ax, 5.8, 5.0, 4.6, 1.6, C["t2f"], C["t2d"], lw=1.4)
    ax.text(6.0, 6.25, "Tier 2: Mutation Delta Extractor Δ(edit)", fontsize=11, fontweight="bold", color=C["t2d"])
    ax.text(6.0, 5.85, "• Fail-closed unified diff parser (path containment)", fontsize=9, color=C["text"])
    ax.text(6.0, 5.50, "• Syntax pre-parse (ast.parse) & patch hash", fontsize=9, color=C["text"])
    ax.text(6.0, 5.15, "• Import delta, secret tokens, egress endpoints", fontsize=9, color=C["text"])

    # Tier 3: Invariant Verification Matrix (I1-I7 & D1)
    draw_box(ax, 11.2, 3.8, 4.3, 5.1, C["t3f"], C["t3d"], lw=1.8)
    ax.text(11.4, 8.6, "Tier 3: The Seven Invariant Gates", fontsize=11, fontweight="bold", color=C["t3d"])
    invariants = [
        ("I1 Policy Integrity", "Protect CI, AGENTS.md, rules from T2"),
        ("I2 Test Integrity", "Prohibit test skipping or assertion deletes"),
        ("I3 Secret & Egress", "Regex scan without word boundary flaws"),
        ("I4 Arch Layering", "Zero forbidden import edges or layer bypass"),
        ("I5 Blast Radius", "Strict containment within declared intent I"),
        ("I6 Dependency Prov.", "Prohibit unverified package imports"),
        ("I7 Syntax Integrity", "Fail-closed rejection of unparsable ASTs"),
        ("D1 Design ADR Gate", "Synthesized ADR architectural consistency"),
    ]
    for idx, (inv, desc) in enumerate(invariants):
        yy = 8.15 - (idx * 0.52)
        ax.text(11.4, yy, f"• {inv}:", fontsize=8.5, fontweight="bold", color=C["t3d"])
        ax.text(11.6, yy - 0.22, desc, fontsize=7.8, color=C["subtext"])

    # Tier 4: Provenance DAG & Capability Scope
    draw_box(ax, 5.8, 2.5, 4.6, 1.9, C["t4f"], C["t4d"], lw=1.4)
    ax.text(6.0, 4.05, "Tier 4: Provenance DAG & Capability Tokens", fontsize=11, fontweight="bold", color=C["t4d"])
    ax.text(6.0, 3.65, "• Hash-chained SHA-256 DAG tracking context lineage", fontsize=9, color=C["text"])
    ax.text(6.0, 3.30, "• Non-bypassable CapabilityScope tokens κ", fontsize=9, color=C["text"])
    ax.text(6.0, 2.95, "• Nonce freshness store preventing replay attacks", fontsize=9, color=C["text"])

    # Tier 5: Fail-Closed Sink & Developer Facade
    draw_box(ax, 0.6, 2.5, 4.4, 1.9, C["t5f"], C["t5d"], lw=1.8)
    ax.text(0.8, 4.05, "Tier 5: Fail-Closed Sink & Public Facade", fontsize=11, fontweight="bold", color=C["t5d"])
    ax.text(0.8, 3.65, "• Public Facade: DevGuard.propose_mutation()", fontsize=9, color=C["text"])
    ax.text(0.8, 3.30, "• CLI Tooling: agentpoi-sde (anchor/check-diff)", fontsize=9, color=C["text"])
    ax.text(0.8, 2.95, "• Outcome: APPROVED (Exit 0) or BLOCKED (Exit 1)", fontsize=9, fontweight="bold", color=C["t5d"])

    # Bottom Metrics Card: Dynamic Benchmark Oracles
    draw_box(ax, 0.6, 0.4, 14.9, 1.6, "#F8FAFC", C["border"], lw=1.2)
    ax.text(0.8, 1.65, "Empirical Benchmark Validation (Simulated Execution Against Defense-Independent State-Diff Oracle)",
            fontsize=10.5, fontweight="bold", color=C["text"])
    ax.text(0.8, 1.25,
            "Baseline (Undefended):  EMAR = 100.0%  |  LTSR = 100.0%  |  CDR = 0.0%  |  AVR = 6.2%  |  SLR = 6.2%  |  Latency = 1.79 ms",
            fontsize=9.2, fontfamily="monospace", color=C["adv"])
    ax.text(0.8, 0.85,
            "AgentPOI-SDE (Defended): EMAR =   0.0%  |  LTSR = 100.0%  |  CDR = 0.0%  |  AVR = 0.0%  |  SLR = 0.0%  |  Latency = 3.94 ms",
            fontsize=9.2, fontfamily="monospace", color=C["t5d"], fontweight="bold")
    ax.text(0.8, 0.55,
            "Result: 100% of adversarial evasion attacks blocked fail-closed; 100% of legitimate engineering tasks preserved without disruption.",
            fontsize=8.5, color=C["subtext"], style="italic")

    # Dataflow Arrows
    draw_arrow(ax, (2.8, 7.1), (2.8, 6.6), color=C["t0d"])      # T0 -> LLM
    draw_arrow(ax, (5.0, 7.9), (5.8, 7.9), color=C["t0d"])      # T0 -> Anchor R0
    draw_arrow(ax, (5.0, 5.8), (5.8, 5.8), color="#8A6500")     # LLM -> Delta
    draw_arrow(ax, (8.1, 7.1), (8.1, 6.6), color=C["t1"])       # Anchor -> Delta
    draw_arrow(ax, (10.4, 5.8), (11.2, 5.8), color=C["t2d"])    # Delta -> Invariants
    draw_arrow(ax, (13.3, 3.8), (10.4, 3.3), color=C["t3d"])    # Invariants -> Provenance
    draw_arrow(ax, (5.8, 3.3), (5.0, 3.3), color=C["t4d"])      # Provenance -> Fail-Closed Sink

    plt.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated SDE architecture diagram at: {output_path}")


if __name__ == "__main__":
    out = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "sde_architecture_diagram.png"))
    generate_diagram(out)
