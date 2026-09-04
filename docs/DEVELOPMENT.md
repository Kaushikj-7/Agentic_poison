# Contributor & Development Guide: File Classification & Architecture Boundaries

This document formalizes the repository structure, abstraction boundaries, and file classification policies for AgentPOI contributors.

## 1. Abstraction Boundary Principles

AgentPOI adheres to the strict encapsulation standards seen in industry platforms (Anthropic Claude Code, OpenClaw, CrewAI):
- **Public SDK Consumption**: Users and application engineers must interact with the framework exclusively via the top-level facade (`agent_poi.FinancialGuard`), typed policies (`SecurityPolicy`), verdicts (`GuardVerdict`), and typed exceptions (`FinancialSecurityError`, `UnauthorizedPayeeError`, etc.).
- **Internal Mechanics Encapsulation**: Low-level parsing (`FinancialDeltaExtractor`), cryptographic lineage hashing (`AuthGraphDAG`), and heuristic verification (`ContextualInvariantVerifier`) are decoupled and maintained behind clean interfaces.
- **Scaffolding Isolation**: Internal agent personas, development ledgers, experimental scratchpads, and prompt engineering templates must remain isolated from consumer distributions and must never be tracked in git.

---

## 2. File Classification Matrix

The repository maintains an explicit boundary between **Consumer Distribution Artifacts** (packaged and distributed to developers) and **Internal Developer Scaffolding** (strictly ignored via `.gitignore`):

| Scope | Path / Pattern | Purpose | Audience | Distribution / Git Status |
| :--- | :--- | :--- | :--- | :--- |
| **Public SDK** | `agent_poi/facade.py` | High-level `FinancialGuard` facade | All End-Users & Integrators | Distributed via pip / Tracked in Git |
| **Public SDK** | `agent_poi/financial/` | State anchor $\mathcal{S}_0$, invariant verifier, delta extractor | Financial Workflow Integrators | Distributed via pip / Tracked in Git |
| **Public SDK** | `agent_poi/core/` | `TaskShieldGate`, `AuthGraphDAG`, CI decomposer | Security Researchers & Core SDK | Distributed via pip / Tracked in Git |
| **Public SDK** | `agent_poi/memory/` | Memory firewall & quarantine vault | Long-term Memory Systems | Distributed via pip / Tracked in Git |
| **Public Benchmark** | `agent_poi/financial/eval/` | 60-scenario ground-truth evaluation suite | Evaluators & Auditors | Distributed / Tracked in Git |
| **Public Tests** | `tests/` | 47 automated unit & integration tests | CI/CD & Open-Source Contributors | Tracked in Git |
| **Public Docs** | `docs/` | Formal architecture, math formulation, methodology | Open-Source Community | Tracked in Git |
| **Public Packaging** | `pyproject.toml`, `requirements.txt`, `LICENSE` | Standard packaging and MIT license | Python Packaging Index (PyPI) | Tracked in Git |
| **Internal Governance** | `AGENTS.md` | Persona behavioral invariants & TDD rules | Autonomous Agent Pair Programmers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `PROJECT_LEDGER.md` | Milestone tracking & decision log (DEC-xxx) | Core Maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `MISTAKES_LEDGER.md` | Post-mortem analysis of failed approaches | Core Maintainers | **Strictly Ignored (`.gitignore`)** |
| **Internal Governance** | `docs/MONITORING_AGENT.md` | Supervisory agent orchestrator specification | Multi-Agent Harness | **Strictly Ignored (`.gitignore`)** |
| **Internal Scaffolding** | `everything-claude-code/` | Private prompt workflows & templates | Internal Agent Harness | **Strictly Ignored (`.gitignore`)** |
| **Local Artifacts** | `logs/`, `scratch/`, `.pytest_cache/` | Test logs and temporary run caches | Local Machine | **Strictly Ignored (`.gitignore`)** |

---

## 3. Git Workflow & PR Invariants

1. **Branching Strategy**: Core domain development proceeds on feature branches (`dev/financial-core`).
2. **Author Identity**: All commits must be attributed to the user identity:
   ```bash
   git config user.name "Kaushik"
   git config user.email "kaushikj2005@gmail.com"
   ```
3. **No Unapproved Pushes**: Pushes to remote repositories (`git push origin ...`) require explicit confirmation from the repository owner.
4. **Pre-Flight Verification**: Run `python scripts/ci_check.py` locally before requesting PR review. All 5 gates (Syntax, Secrets, Unit Tests, Benchmark Invariant, Ledger) must pass.
