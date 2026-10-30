# Contributor & Development Guide: Multi-Domain Isolation & Architecture Boundaries

This document formalizes the repository structure, abstraction boundaries, and file classification policy across all three isolated application domains supported by the **AgentPOI** framework.

---

## 1. Multi-Domain Invariant Scope & Isolation

The platform supports three formally isolated application domains:

1. **Software-Engineering Agent Defense (`agentpoi_sde`)**:
   - **Scope**: Repository Invariant Verification (RIV), immutable state anchors ($\mathcal{R}_0$), AST symbol indexing, nine sink invariants (I1–I9), executable design gate (D1), Merkle knowledge graph, cross-stack schema consensus, and autonomous agent runner with atomic rollback.
   - **Public Facade**: `agentpoi_sde.DevGuard` (`facade.py`).
   - **CLI**: `agentpoi-sde` (`anchor`, `check-diff`, `benchmark`, `graph`, `cross-stack`, `harvest`, `sandbox`, `run`).
   - **Architecture Specifications**: [`SDE_ARCHITECTURE.md`](SDE_ARCHITECTURE.md) and [`CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md`](CRYPTOGRAPHIC_GRAPH_ARCHITECTURE.md).

2. **Zero-Host-Execution Vulnerability & Malicious Code Scanner (`agentpoi_scan`)**:
   - **Scope**: Inverted Anthropic `oss-scanner` model. Strict zero host execution (target code is never compiled, run, or imported). Detects legacy vulnerabilities (PHP SQLi, unescaped `exec()`, unsafe `unserialize()`, webshell backdoors), agentic repository snapshots (Langflow unsafe PyTorch/YAML deserialization, autorun surfaces, prompt injection), advisory multi-tier OpenRouter free-model cascade (`nvidia/nemotron-3.5-lightning:free`, `google/gemma-4-31b-it:free`, `qwen/qwen-2.5-coder-32b-instruct:free`), DEC-105 fail-closed veto resistance, and Stored XSS-defended Streamlit dashboard.
   - **Public Entrypoints**: `agentpoi_scan.pipeline.ScanPipeline`, `agentpoi_scan.report.store.ScanStore`.
   - **CLI**: `agentpoi-scan` (`run`, `dashboard`).
   - **Architecture Specification**: [`SCANNER_DASHBOARD_ARCHITECTURE.md`](SCANNER_DASHBOARD_ARCHITECTURE.md).

3. **Financial & Transactional Agent Defense (`agent_poi`)**:
   - **Scope**: Contextual Invariant Verification (CIV), immutable state anchor ($\mathcal{S}_0$), wire disbursements, invoice verification, escrow settlement, and ledger reconciliation.
   - **Public Facade**: `agent_poi.FinancialGuard` (`facade.py`).
   - **Architecture Specification**: Embedded in core module specifications.

---

## 2. Abstraction Boundary Principles

- **Public SDK Consumption**: Users and integrators interact exclusively through high-level facades (`DevGuard`, `FinancialGuard`, `ScanPipeline`), typed domain objects (`CodeMutation`, `Finding`, `Scorecard`), and typed exceptions (`PolicyFileIntegrityError`, `TestIntegrityError`, `SecretProliferationError`, `SyntaxIntegrityError`).
- **Internal Mechanics Encapsulation**: AST parsers, regex extractors, SQLite persistence, rate-limiting token buckets, and cryptographic hash chain evaluators remain fully encapsulated behind public facades.
- **Strict Domain Isolation**: Configuration loaders, test suites, and core modules across domains must not bleed configuration (e.g. `scanner_config.yaml` and `sde_config.yaml` must never inherit financial `config.yaml`).
- **Scaffolding Isolation (Rule 6)**: Internal developer artifacts (prompt templates, agent personas, mistakes ledgers, project ledgers, and scratchpads) must remain permanently quarantined via `.gitignore` and must never be tracked in Git.

---

## 3. File Classification Matrix

The repository strictly enforces the boundary between **Consumer Distribution Artifacts** (packaged and distributed) and **Internal Developer Scaffolding** (quarantined via `.gitignore`):

| Scope | Path / Pattern | Purpose | Audience | Distribution / Git Status |
| :--- | :--- | :--- | :--- | :--- |
| **Public SDK (SDE)** | `agentpoi_sde/facade.py` | High-level `DevGuard` facade, `GuardPolicy`, `MutationVerdict` | All end-users & integrators | Distributed via pip / Tracked in Git |
| **Public SDK (SDE)** | `agentpoi_sde/anchor/`, `agentpoi_sde/delta/` | $\mathcal{R}_0$ anchor construction, AST symbol indexing, mutation deltas | SDK & security researchers | Distributed via pip / Tracked in Git |
| **Public SDK (SDE)** | `agentpoi_sde/verify/` | Invariant engine (I1–I9) + executable design gate (D1) | SDK & security researchers | Distributed via pip / Tracked in Git |
| **Public SDK (SDE)** | `agentpoi_sde/graph/`, `agentpoi_sde/schema/` | Merkle knowledge graph, architectural ledger, schema consensus | SDK integrators | Distributed via pip / Tracked in Git |
| **Public SDK (Scan)** | `agentpoi_scan/pipeline.py`, `agentpoi_scan/scan/` | Zero-execution scan pipeline, AST & regex sinks (PHP, Python, Autorun) | All end-users & auditors | Distributed via pip / Tracked in Git |
| **Public SDK (Scan)** | `agentpoi_scan/agents/llm_bridge.py` | Multi-tier OpenRouter free-model cascade & rate limits | Security researchers | Distributed via pip / Tracked in Git |
| **Public SDK (Scan)** | `agentpoi_scan/report/store.py` | SQLite ScanStore persistence and SARIF 2.1.0 generation | All end-users & integrators | Distributed via pip / Tracked in Git |
| **Public UI (Scan)** | `agentpoi_scan/ui/dashboard.py`, `render.py` | Hardened Streamlit dashboard with Stored XSS defense | Security auditors & analysts | Distributed via pip / Tracked in Git |
| **Public Benchmarks**| `agentpoi_sde/eval/`, `tests/fixtures/` | SDE adaptive suite, synthetic legacy PHP & Langflow fixtures | Evaluators & auditors | Distributed / Tracked in Git |
| **Public Tests** | `tests/` (incl. `tests/e2e/`) | Unit, integration, and opaque-box acceptance suites | CI/CD & contributors | Tracked in Git |
| **Public Docs** | `docs/`, `README.md` | Architecture specs, formal threat models, API guides | Open-source community | Tracked in Git |
| **Public Packaging** | `pyproject.toml`, `LICENSE` | Package definitions and MIT license | PyPI / GitHub | Tracked in Git |
| **Internal Governance** | `AGENTS.md` | Persona behavioral invariants & TDD rules | Autonomous agent pair programmers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `PROJECT_LEDGER.md` | Milestone tracking and decision log | Core maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `MISTAKES_LEDGER.md` | Post-mortem analysis of failed approaches | Core maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `TEST_READY.md`, `TEST_INFRA.md` | Test attestations and environment notes | Multi-agent harness | **Strictly Ignored (`.gitignore`)** |
| **Internal Scaffolding** | `everything-claude-code/`, `.agents/` | Private prompt workflows & agent swarm logs | Internal agent harness | **Strictly Ignored (`.gitignore`)** |
| **Local Artifacts** | `logs/`, `scratch/`, `local_audit/`, `.pytest_cache/` | Local logs, caches, and test artifacts | Local machine | **Strictly Ignored (`.gitignore`)** |

---

## 4. Git Workflow & Contribution Invariants

1. **Branching Strategy**:
   - `main`: Clean, production-grade releases.
   - `agentpoi-scan-dashboard`: Zero-host-execution vulnerability scanner, OpenRouter free bridge, and Streamlit dashboard.
   - `codebleak`: Autonomous software-engineering agent domain (`agentpoi_sde`).
   - `dev/financial-core`: Financial transaction agent domain (`agent_poi`).
2. **Author Identity Invariant (Rule 7)**:
   All commits must be strictly attributed to the repository owner:
   ```bash
   git config user.name "Kaushik"
   git config user.email "kaushikj2005@gmail.com"
   ```
3. **Zero Autonomous Pushes**:
   Pushing to remote repositories (`git push origin ...`) requires explicit, interactive user authorization. Stage, commit, and verify locally first.
4. **Pre-Flight CI Verification**:
   Prior to submitting a pull request, run the unified verification runner:
   ```bash
   python scripts/ci_check.py --allow-dirty
   ```
   The gate validates:
   - Python syntax compilation across all 4 package roots (`agent_poi`, `agentpoi_sde`, `agentpoi_scan`, `tests`).
   - Automated secret audit across all code files (0 hardcoded secrets).
   - Automated unit test suite execution (1,107 passed).
   - Dynamic benchmark execution (SDE dynamic benchmark: `EMAR=0.0%`, `LTSR=100.0%`).
   - Working tree cleanliness and ledger integrity.
