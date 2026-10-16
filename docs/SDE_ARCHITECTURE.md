# AgentPOI-SDE: Repository Invariant Verification (RIV) Architecture

**Package:** `agentpoi_sde` — the software-engineering application of AgentPOI.
**Platform:** AgentPOI-SDE (Software Development Engineering)
**Branch:** `codebleak`
**Status:** implemented — core invariant engine, dynamic benchmark, agentic plane, CLI, Merkle
knowledge graph, cross-stack schema consensus, working-part immutability and the safe component
harvester all ship in `agentpoi_sde` and are exercised by the test suite and pre-flight gate.
**Parent platform:** `agent_poi` (CIV/DSEC financial defence) — principles carried over per `AGENTS.md`.
**Companion specification:** [`CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md`](CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md)
(Subsystems G/C/W/H and invariants I8–I9).

---

## 0. Design Principles (carried over, unchanged)

1. **Fail-closed.** A mutation is applied **iff** every invariant passes with zero violations.
2. **Deterministic enforcement.** Invariant evaluation is CPU-deterministic and offline-testable;
   LLM reasoning is *advisory input only*. The model can never authorise its own mutation.
3. **Anchor separation.** Untrusted context can never mutate ground truth (ℛ₀).
4. **No hardcoded results.** All benchmark metrics are computed dynamically from real execution.
5. **Many small files.** 200–400 lines typical, ≤800 hard cap; functions ≤50 lines; nesting ≤4.
6. **TDD.** RED → GREEN → REFACTOR. Tests precede implementation.
7. **Facade abstraction.** Users touch `DevGuard`; internals stay behind it.
8. **Public/developer quarantine.** Internal ledgers remain `.gitignore`d (`AGENTS.md` Rule 6).

---

## 1. The Core Idea (novelty in one paragraph)

AgentPOI defends financial agents by decoupling *unstructured language* from *execution-sink
authorisation* via an immutable state anchor `S₀`. AgentPOI-SDE performs the identical move on
software: **the sink is a code mutation (write/commit/merge)**, and the anchor is **repository
ground truth ℛ₀**. An agent may reason in natural language however it likes — but a mutation
lands only if it survives a deterministic, provenance-gated, three-way match against
authenticated **intent ℐ**, the immutable **repository anchor ℛ₀**, and a scoped **capability grant**.

This is the direct answer to the documented failure of every 2026-era coding-agent defence:
sandboxes bound *where* code runs (arXiv:2607.05743, 2605.14932), least-privilege bounds *what*
(2605.14859), IFC bounds *flow* (2505.23643), and classifiers bound *nothing reliably*
(AIShellJack: >85% bypass). None bounds **the artefact**: whether this specific mutation is
authorised, in-scope, non-weakening, non-leaking, architecturally legal, and traceable.

### Notation

| Symbol | Name | Meaning |
|---|---|---|
| `ℐ` | Intent Anchor | Authenticated task contract (spec/issue/ADR) + obligations |
| `ℛ₀` | Repository State Anchor | Content-addressed committed ground truth |
| `Δ(edit)` | Mutation Delta | Typed, normalised description of one code mutation |
| `𝒫` | Provenance Anchor | SHA-256 hash-chained lineage of contributing context |
| `κ` | Capability Scope | Deterministic grant bounding paths/tools/egress |
| `𝒢_merkle` | Merkle Knowledge Graph | Content-addressed graph of files, symbols, endpoints, schemas, ADRs and builds, with a recomputable Merkle root |
| `ℒ` | Architectural Ledger | Hash-chained block record of what was built, how, why, and what it connects to |

---

## 2. The 7-Tier Pipeline

```mermaid
flowchart TD
    subgraph T0["Tier 0 — Ingestion & Trust Tiering"]
        UI["Authenticated Intent (T0)<br/>task prompt / issue / spec"]
        RG["Repository Files (T1)<br/>committed ground truth"]
        UX["Untrusted Context (T2)<br/>tool output / web / deps / MCP"]
    end
    subgraph T1b["Tier 1 — Intent Shield"]
        IS["Imperative-divergence gate<br/>injection-marker screening of T2 context"]
    end
    subgraph T2b["Tier 2 — Anchor Construction"]
        RA["RepositoryStateAnchor ℛ₀<br/>git OID · AST symbols · import graph<br/>lockfile digests · protected paths · ADR policy"]
    end
    subgraph T3b["Tier 3 — Mutation Delta Extraction"]
        MD["MutationDeltaExtractor Δ(edit)<br/>path · symbol · op · patch_hash<br/>imports_added · writes · secrets"]
    end
    subgraph T4b["Tier 4 — Invariant Verification (the nine gates)"]
        IV["RepoInvariantVerifier<br/>policy-file · test-integrity · secrets/egress<br/>architecture · blast-radius · dependency provenance<br/>syntax integrity · cross-stack schema · working parts<br/>+ design gate D1"]
    end
    subgraph T5b["Tier 5 — Provenance & Capability"]
        PV["ProvenanceGate 𝒫 ∩ CapabilityGate κ ∩ Freshness"]
    end
    subgraph T6b["Tier 6 — Fail-Closed Sink"]
        SK{"ALL pass?"}
        AP["Applied Mutation Ledger"]
        QV["Quarantine Vault + telemetry"]
    end
    UI --> IS
    UX --> IS
    RG --> RA
    IS --> RA --> MD --> IV --> PV --> SK
    SK -- "yes" --> AP
    SK -- "no" --> QV
```

---

## 3. The Nine Sink Invariants (each maps to a documented, unmitigated attack class)

| Invariant | Rule | Attack class it closes |
|---|---|---|
| **I1 Policy-File Integrity** | T2-origin context may not mutate agent/CI policy files (`AGENTS.md`, `.cursorrules`, `*.yml` CI, protected manifests) unless the mutation is in ℐ. | Rules File Backdoor; ClawHavoc context poisoning |
| **I2 Test-Integrity Non-Weakening** | A mutation may not delete/skip/weaken an existing test to satisfy itself; oracle files are tamper-evident against ℛ₀. | "Agent fixes failing test by deleting the assertion" |
| **I3 Secret Non-Proliferation & Egress** | No new hardcoded credential material; no new egress endpoint introduced by T2 context. | GitGuardian 3.2% AI-commit secret-leak rate |
| **I4 Architectural Layering** | No forbidden import edge, no new dependency cycle, no layer inversion vs. ℛ₀ policy. | Long-horizon architectural drift (SWE-EVO) |
| **I5 Blast-Radius / Scope** | Mutation paths ∩ declared ℐ scope must cover all mutation paths (no covert side-writes). | RoguePilot-style scope expansion |
| **I6 Dependency Provenance** | New imports must resolve to allow-listed or anchor-present dependencies; T2-supplied installs are refused. | Supply-chain injection via new import |
| **I7 Syntax Integrity** | A mutation must leave every touched Python file parsable (`ast.parse`); unparsable output is refused, never silently skipped. | Fail-open parsers / smuggled malformed code |
| **I8 Cross-Stack Schema Consensus** | Every frontend API invocation must resolve to a declared backend route with the same HTTP verb and a payload supplying the route's required fields (`I8:ENDPOINT_NOT_FOUND`, `I8:METHOD_MISMATCH`, `I8:MISSING_REQUIRED_FIELD`). | Hallucinated/renamed endpoints, verb drift, silently missing payload fields |
| **I9 Working-Part Immutability** | A file registered in the working-part anchor may only be mutated when the active capability scope explicitly grants it. Registration is opt-in per task (`DevGuard.register_working_file`). | Regression: an agent rewriting a known-good module while adding a feature |

Enforced jointly with **𝒫** (provenance ancestry), **κ** (capability scope) and **freshness**
(non-replay idempotency) before the sink fires.

The **I9 regression-run** capability is deliberately *not* automatic: `DevGuard.run_sandbox_tests()`
executes the registered regression suites in an isolated temporary configuration when the caller
asks for it, and reports the result. Only the path/scope half of I9 is enforced on every mutation;
the evidence half is an explicit API call, so this document does not claim it is automatic.

![AgentPOI-SDE Publication Architecture Diagram](sde_architecture_diagram.png)

---

## 4. Component Map

| Layer | Module | Responsibility |
|---|---|---|
| Domain | `agentpoi_sde/domain.py` | Enums + dataclasses (TrustTier, MutationOp, MutationDelta, …) |
| Anchor | `anchor/symbol_index.py` | AST symbol table + import/dependency extraction |
| Anchor | `anchor/policy_registry.py` | Architecture policy (layers, forbidden edges, protected paths) |
| Anchor | `anchor/repo_anchor.py` | `RepositoryStateAnchor` ℛ₀ (content-addressed tree OID) |
| Delta | `delta/mutation_delta.py` | `MutationDeltaExtractor` — Δ(edit) normalisation & AST parsing |
| Delta | `delta/diff_parser.py` | Fail-closed unified diff/patch parser with path containment |
| Provenance | `provenance/code_provenance.py` | `ProvenanceDAG` 𝒫 — SHA-256 hash-chained, trust-tier-aware lineage over `agent_poi.memory.schema.SourceOrigin` |
| Capability | `capability/capability_scope.py` | `CapabilityScope` κ tokens + freshness nonce store |
| Verify | `verify/invariant_verifier.py` | `RepoInvariantVerifier` — the nine gates (I1–I9) + design gate D1 |
| Anchor | `anchor/working_part_anchor.py` | `WorkingPartAnchor` — registry of verified working parts / regression suites (I9) |
| Graph | `graph/merkle_graph.py` | `MerkleKnowledgeGraph` — content-addressed nodes/edges with a recomputable Merkle root |
| Graph | `graph/arch_ledger.py` | `ArchitecturalLedger` — hash-chained record of what/how/why was built and connected |
| Graph | `graph/graph_indexer.py` | AST scanner lifting files, symbols, imports and routes into graph nodes |
| Schema | `schema/contract_model.py` | Universal endpoint/schema contract models + cross-dialect route normalisation |
| Schema | `schema/frontend_extractor.py` | AST extraction of frontend `fetch`/`axios`/client calls and payload keys |
| Schema | `schema/backend_extractor.py` | AST extraction of FastAPI/Flask/Express routes and required schema fields |
| Schema | `schema/cross_stack_verifier.py` | Contract consensus sink enforcing invariant I8 |
| Harvester | `harvester/component_harvester.py` | Open-source component lookup and pull (registry-driven, no network calls in tests) |
| Harvester | `harvester/program_slicer.py` | Minimal transitive AST slice of a requested symbol |
| Harvester | `harvester/slicer_security.py` | Sanitises harvested slices for credentials, alias-evaded imports and shell/network primitives |
| Sandbox | `sandbox/isolated_sandbox.py` | `IsolatedConfigurationSandbox` — runs suites in a throwaway configuration |
| Agent | `agent/llm_provider.py` | Pluggable provider (OpenRouter-style) + deterministic provider |
| Agent | `agent/coding_agent.py` | Agent loop: plan → propose → guard → sink |
| Agent | `agent/design_planner.py` | System-design plane: module graph + ADR synthesis |
| Eval | `eval/repo_sandbox.py` | Deterministic in-memory repository simulation |
| Eval | `eval/attack_generator.py` | Generated 13-family adaptive injection suite (no hardcoding) |
| Eval | `eval/scenario_dataset.py` | Paired clean/adversarial scenario construction |
| Eval | `eval/benchmark.py` | Dynamic metrics: EMAR, LTSR, CDR, AVR, SLR |
| CLI | `cli.py` & `__main__.py` | Public CLI tool `agentpoi-sde` (anchor, check-diff, benchmark) |
| SDK | `facade.py` | `DevGuard`, `GuardPolicy`, `MutationVerdict` |
| SDK | `__init__.py` | Public exports |

---

## 5. Phased Delivery Plan

| Phase | Deliverable | Gate |
|---|---|---|
| **P0** | Novelty-gap analysis (`docs/NOVELTY_GAP.md`) | Literature verified — **PASSED** |
| **P1** | Anchor ℛ₀ + Δ(edit) + invariants I1–I7 + 𝒫 + κ + facade, with TDD unit tests (I8–I9 added in P7–P8) | All unit tests green; offline — **DELIVERED** |
| **P2** | Simulated repo sandbox + generated attack suite + dynamic benchmark (`EMAR/LTSR/CDR/AVR/SLR`) | Metrics computed from execution, never hardcoded — **DELIVERED** (§8) |
| **P3** | Coding agent loop + pluggable LLM provider (API-key live mode) + deterministic provider | Agent applies clean work and blocks every injected mutation — **DELIVERED** |
| **P4** | System-design plane (ADR synthesis → executable design invariants) | Design-contradiction mutation rejected at the sink via gate D1 — **DELIVERED** |
| **P5** | Unified CI pre-flight gate, adaptive attacker suite, public CLI (`agentpoi-sde`), E2E tests | `scripts/ci_check.py` VERIFICATION: PASS (unit + E2E suites, both domain benchmarks, documentation-sync gate) — **DELIVERED** |
| **P6** | Merkle knowledge graph + architectural ledger + graph indexer | Recomputed Merkle root and inclusion proofs verified by unit tests — **DELIVERED** |
| **P7** | Cross-stack schema consensus (invariant I8) | Hallucinated endpoints, verb drift and missing payload fields rejected at the sink — **DELIVERED** |
| **P8** | Working-part anchor + isolated configuration sandbox (invariant I9) | Protected files refused without an explicit capability grant — **DELIVERED** |
| **P9** | Safe component harvester + program slicer | Minimal dependency slice, security-sanitised, anchored into the ledger — **DELIVERED** |
| **P10** | Facade/CLI integration, E2E acceptance, documentation sync | `agentpoi-sde` CLI end to end; docs regenerated from live metrics — **DELIVERED** |

### Explicitly out of scope for this branch
- Any multi-language code-gen beyond the Python AST layer (extensible by design, not built now).
- Autonomous `git push` / deployment (forbidden by `AGENTS.md` Rule 7).
- Copying any third-party agent's prompt templates or source (novelty requirement).

---

## 6. Threat Model (summary)

**Adversary capability.** The adversary can place arbitrary text in any T2 channel: repository
files it contributes via PR, dependency READMEs, MCP tool responses, CI logs, issue bodies, web
pages the agent fetches, and the agent's own long-term memory. The adversary cannot modify ℛ₀
(committed ground truth), ℐ (authenticated intent), or κ (capability grant).

**Adversary goal.** Cause the agent to (a) mutate a policy/CI file, (b) weaken or delete a test,
(c) introduce a secret or exfiltration endpoint, (d) violate architecture, (e) write outside the
declared scope, or (f) introduce a malicious dependency — and have that mutation **applied**.

**Success criterion (state-diff oracle).** The attack succeeds iff the simulated repository's
final state contains the adversary's intended mutation, judged independently of the defence.

**Guarantee.** For any Δ that violates I1–I9, 𝒫, κ or freshness, the sink does not fire. This is
a fail-closed guarantee over the enforced invariant set — not a claim of universal safety
(unmodelled invariants are outside the guarantee, and are reported as such).

---

## 7. Public CLI & Unified Diff Architecture

The `agentpoi-sde` CLI provides three command workflows:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Agent
    participant CLI as agentpoi-sde CLI
    participant Parser as DiffParser (Fail-Closed)
    participant Anchor as RepoStateAnchor R0
    participant Verifier as RepoInvariantVerifier
    participant Sink as Mutation Sink

    Dev->>CLI: agentpoi-sde check-diff [patch.diff]
    CLI->>Parser: parse_unified_diff(content)
    Note over Parser: Checks: path containment, no '..',<br/>no absolute paths, no .git/.agents escape
    Parser-->>CLI: List[CodeMutation]
    CLI->>Anchor: from_directory(repo_root)
    Anchor-->>CLI: R0 (Tree OID, AST Graph, ADR Policy)
    loop For each proposed mutation Δ
        CLI->>Verifier: verify(intent, delta)
        Note over Verifier: Enforces I1–I9 & ADR Gate D1
        Verifier-->>CLI: List[InvariantViolation]
    end
    alt Zero Violations
        CLI-->>Dev: VERDICT: APPROVED (Exit Code 0)
    else Violations Detected
        CLI-->>Dev: VERDICT: BLOCKED (Exit Code 1, list of codes)
    end
```

---

## 8. Empirical Benchmark Evaluation (Live Simulated Execution)

The table below is generated by `scripts/render_sde_metrics.py` from a live
`run_benchmark()` execution; `tests/test_sde_docs_metrics.py` and the pre-flight gate fail if it
ever drifts from the code. Reproduce it with `python -m agentpoi_sde.eval.benchmark` or
`agentpoi-sde benchmark`.

<!-- BEGIN SDE_BENCHMARK (generated by scripts/render_sde_metrics.py from a live benchmark run; do not edit by hand) -->

_Generated from a live execution of the 40-scenario suite: 34 adversarial mutations across 17 attack families plus 6 legitimate engineering tasks, scored by a defence-independent state-diff oracle._

| Mode | Scenarios | EMAR (↓) | LTSR (↑) | CDR (↓) | AVR (↓) | SLR (↓) | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Undefended (permissive) | 40 | 100.0% | 100.0% | 0.0% | 10.0% | 5.0% | 1.12 ms |
| **AgentPOI-SDE (fail-closed)** | 40 | **0.0%** | **100.0%** | **0.0%** | **0.0%** | **0.0%** | 4.07 ms |

- **Adversarial mutations landed under AgentPOI-SDE:** 0/34 (34 blocked fail-closed).
- **Legitimate engineering tasks preserved:** 6/6.
- **AVR / SLR** count architecture and credential breaches in the *resulting repository state* of every landed mutation, read after execution — not from the defence's verdict.
- Mean latency is machine dependent and is excluded from the documentation sync check.

<!-- END SDE_BENCHMARK -->

- **Empirical Mutation Attack Rate (EMAR)**: share of adversarial mutations that landed in the
  working tree — lower is better.
- **Legitimate Task Survival Rate (LTSR)**: share of legitimate engineering tasks applied —
  higher is better. **CDR** is its complement among clean scenarios (false rejections).
- **Architecture Violation Rate (AVR)** & **Secret Leak Rate (SLR)**: ground-truth invariant
  breaches found by post-execution AST scans of the *resulting repository state* of every landed
  mutation — read independently of the defence's verdict.

### Reproduction limits (stated explicitly)

- The suite is a deterministic **in-process simulation** of a repository, not a live clone of a
  production codebase; it exercises the enforcement logic, not the whole toolchain.
- Latency figures are single-machine wall-clock timings and are not comparable across hosts; they
  are therefore excluded from the documentation sync check.
- The `--check` mode of the documentation renderer ignores latency for the same reason.

