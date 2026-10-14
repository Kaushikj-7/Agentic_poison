# Contributor & Development Guide: File Classification & Architecture Boundaries

This document formalizes the repository structure, abstraction boundaries and file classification
policy for contributors to **AgentPOI-SDE** on branch `codebleak`.

## 1. Scope of this branch

Branch `codebleak` hosts the **autonomous software-engineering (coding-agent) domain**:

- **Package:** `agentpoi_sde` — anchor construction, mutation delta extraction, the invariant
  engine (I1–I9 + design gate D1), provenance, capability scopes, the Merkle knowledge graph,
  cross-stack schema consensus, the safe harvester, the sandbox runner and the evaluation harness.
- **Public facade:** `agentpoi_sde.DevGuard` (`facade.py`).
- **CLI:** `agentpoi-sde` (`anchor`, `check-diff`, `benchmark`, `graph`, `cross-stack`, `harvest`,
  `sandbox`).
- **Specification:** [`SDE_ARCHITECTURE.md`](SDE_ARCHITECTURE.md) and
  [`CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md`](CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md).

The only shared surface with the sibling financial-domain package is the context-origin enum
`agent_poi.memory.schema.SourceOrigin`, which supplies the trust-tier vocabulary (`T0`
authenticated intent, `T1` repository ground truth, `T2` untrusted context) used by the provenance
DAG and the scenario dataset.

## 2. Abstraction Boundary Principles

- **Public SDK consumption:** users and application engineers interact with the framework via the
  top-level facade (`DevGuard`, `GuardPolicy`), typed domain objects (`CodeMutation`, `MutationOp`,
  `MutationVerdict`) and typed exceptions (`PolicyFileIntegrityError`, `TestIntegrityError`,
  `SecretProliferationError`, `ArchitectureViolationError`, `BlastRadiusError`,
  `DependencyProvenanceError`, `SyntaxIntegrityError`, `UntrustedProvenanceError`,
  `CapabilityScopeError`, `ReplayDetectedError`).
- **Internal mechanics encapsulation:** unified-diff parsing and path containment, AST symbol and
  import indexing, invariant evaluation, Merkle graph construction, capability tokens and the
  freshness nonce store, and harvester slicing/sanitisation remain behind clean interfaces.
- **Scaffolding isolation:** internal agent personas, development ledgers, experimental scratchpads
  and prompt-engineering templates must remain isolated from consumer distributions and must never
  be tracked in git.

## 3. File Classification Matrix

The repository maintains an explicit boundary between **Consumer Distribution Artifacts**
(packaged and distributed) and **Internal Developer Scaffolding** (strictly ignored via
`.gitignore`):

| Scope | Path / Pattern | Purpose | Audience | Distribution / Git Status |
| :--- | :--- | :--- | :--- | :--- |
| **Public SDK** | `agentpoi_sde/facade.py` | High-level `DevGuard` facade, `GuardPolicy`, `MutationVerdict` | All end-users & integrators | Distributed via pip / Tracked in Git |
| **Public SDK** | `agentpoi_sde/anchor/`, `agentpoi_sde/delta/` | ℛ₀ anchor construction, AST symbol/import indexing, mutation delta extraction | SDK & security researchers | Distributed via pip / Tracked in Git |
| **Public SDK** | `agentpoi_sde/verify/invariant_verifier.py` | Invariant engine (I1–I9) + executable design gate (D1) | SDK & security researchers | Distributed via pip / Tracked in Git |
| **Public SDK** | `agentpoi_sde/provenance/`, `agentpoi_sde/capability/` | Provenance DAG 𝒫, capability scope κ and freshness store | SDK integrators | Distributed via pip / Tracked in Git |
| **Public SDK** | `agentpoi_sde/graph/`, `agentpoi_sde/schema/` | Merkle knowledge graph, architectural ledger, cross-stack contract verification | SDK integrators | Distributed via pip / Tracked in Git |
| **Public SDK** | `agentpoi_sde/harvester/`, `agentpoi_sde/sandbox/`, `agentpoi_sde/agent/` | Safe component harvesting/slicing, isolated sandbox execution, agent loop & providers | SDK integrators | Distributed via pip / Tracked in Git |
| **Public Benchmark** | `agentpoi_sde/eval/` | Adaptive adversarial suite, repo sandbox and dynamic metrics | Evaluators & auditors | Distributed / Tracked in Git |
| **Public Tests** | `tests/` (incl. `tests/e2e/`) | Unit, integration and opaque-box acceptance suites | CI/CD & open-source contributors | Tracked in Git |
| **Public Docs** | `docs/` | SDE architecture, cryptographic graph specification, novelty gap analysis | Open-source community | Tracked in Git |
| **Public Packaging** | `pyproject.toml`, `requirements.txt`, `LICENSE` | Packaging, dependencies and MIT license | Python Packaging Index (PyPI) | Tracked in Git |
| **Internal Governance** | `AGENTS.md` | Persona behavioural invariants & TDD rules | Autonomous agent pair programmers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `PROJECT_LEDGER.md` | Milestone tracking and decision log | Core maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `MISTAKES_LEDGER.md` | Post-mortem analysis of failed approaches | Core maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `TEST_READY.md`, `docs/MONITORING_AGENT.md` | Test-readiness notes, supervisory agent specification | Multi-agent harness | **Strictly Ignored (`.gitignore`)** |
| **Internal Scaffolding** | `everything-claude-code/`, `.agents/` | Private prompt workflows & templates | Internal agent harness | **Strictly Ignored (`.gitignore`)** |
| **Local Artifacts** | `logs/`, `scratch/`, `local_audit/`, `legacy/`, `.pytest_cache/` | Local logs, caches and audit campaigns | Local machine | **Strictly Ignored (`.gitignore`)** |

## 4. Git Workflow & PR Invariants

1. **Branching strategy:** this domain is developed on `codebleak`; the sibling financial domain
   proceeds on its own branches and is not documented here.
2. **Author identity:** all commits must be attributed to the user identity:
   ```bash
   git config user.name "Kaushik"
   git config user.email "kaushikj2005@gmail.com"
   ```
3. **No unapproved pushes:** pushing to a remote (`git push origin ...`) requires explicit
   confirmation from the repository owner. Stage, commit and verify locally first.
4. **Pre-flight verification:** run `python scripts/ci_check.py` before requesting review. The gate
   covers Python syntax, the secrets audit, the unit suite, the dynamic AgentPOI-SDE benchmark,
   documentation-metrics sync, working-tree cleanliness, ledger status and the code-principles
   audit; it also re-runs the inherited financial-domain benchmark, which this branch does not
   modify.
5. **Generated documentation is never hand-edited:** the benchmark block in `README.md` and
   `docs/SDE_ARCHITECTURE.md` is produced by `scripts/render_sde_metrics.py` from a live
   `run_benchmark()` execution. Run it (or `--check` to verify) instead of typing numbers.
