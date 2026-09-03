# Codebase Mistakes & Invariant Violations Ledger

**Monitored Repository:** `agent_poi`  
**Monitoring Agent:** `codebase_monitor` (Strictly Read-Only Auditor)  
**Worker Agent:** `Antigravity` (Main Agent)  
**Status:** 🛑 **BLOCKED** (2 Critical, 5 High, 5 Medium, 2 Low issues pending resolution)  
**Last Audit Date:** 2026-09-03  

---

## Executive Summary Matrix

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total Open | Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **[SYNTAX]** | 0 | 0 | 2 | 1 | **3** | OPEN |
| **[METHODOLOGY]** | 0 | 1 | 2 | 0 | **3** | OPEN |
| **[ARCHITECTURE]** | 0 | 2 | 0 | 1 | **3** | OPEN |
| **[INPUT_OUTPUT]** | 2 | 2 | 0 | 0 | **4** | OPEN |
| **[CORRECTNESS_DRIFT]** | 0 | 0 | 1 | 0 | **1** | OPEN |
| **TOTAL** | **2** | **5** | **5** | **2** | **14** | **BLOCKED** |

---

## Active Mistake Entries

### [MISTAKE-01] [SYNTAX] Built-in `any` Function Used as Typing Annotation
- **Severity**: MEDIUM
- **Category**: SYNTAX
- **Location**: [`agent_poi/financial/state_anchor.py:L95,L152`](file:///E:/agent_poi/agent_poi/financial/state_anchor.py#L95-L152)
- **Broken Invariant**: Typing contract integrity. `Dict[str, any]` uses Python built-in `any()` instead of `typing.Any`.
- **Status**: OPEN
- **Worker Remediation**: Import `Any` from `typing` and update type annotations.
- **Verification**: `python -c "import ast; ast.parse(open('agent_poi/financial/state_anchor.py').read())"` & mypy typecheck.

---

### [MISTAKE-02] [SYNTAX] Unbound Local Variable Scoping Hazard for `civ_res`
- **Severity**: MEDIUM
- **Category**: SYNTAX
- **Location**: [`agent_poi/financial/financial_agent.py:L179-L181`](file:///E:/agent_poi/agent_poi/financial/financial_agent.py#L179-L181)
- **Broken Invariant**: Variable declaration scoping. `civ_res` is conditionally assigned inside `if self.enable_civ:`, remaining uninitialized when `enable_civ=False`.
- **Status**: OPEN
- **Worker Remediation**: Pre-initialize `civ_res: Optional[InvariantVerificationResult] = None` before branching.
- **Verification**: `pytest tests/test_financial_invariants.py -v`.

---

### [MISTAKE-03] [SYNTAX] Dead / Unused Imports Across Core, Financial, and Evaluation Modules
- **Severity**: LOW
- **Category**: SYNTAX
- **Location**: [`state_anchor.py`](file:///E:/agent_poi/agent_poi/financial/state_anchor.py), [`delta_extractor.py`](file:///E:/agent_poi/agent_poi/financial/delta_extractor.py), [`financial_benchmark.py`](file:///E:/agent_poi/agent_poi/financial/eval/financial_benchmark.py), [`alignment_gate.py`](file:///E:/agent_poi/agent_poi/core/alignment_gate.py), [`trust_scorer.py`](file:///E:/agent_poi/agent_poi/core/trust_scorer.py), [`llm_provider.py`](file:///E:/agent_poi/agent_poi/agent/llm_provider.py), [`adaptive_mutator.py`](file:///E:/agent_poi/agent_poi/attacks/tier2_adaptive/adaptive_mutator.py), [`benchmark_runner.py`](file:///E:/agent_poi/agent_poi/evaluation/benchmark_runner.py), [`pareto_sweeper.py`](file:///E:/agent_poi/agent_poi/evaluation/pareto_sweeper.py)
- **Broken Invariant**: Clean code hygiene and minimal dependency footprint.
- **Status**: OPEN
- **Worker Remediation**: Remove unreferenced imports across identified modules.
- **Verification**: `flake8 agent_poi/` / zero import warnings.

---

### [MISTAKE-04] [METHODOLOGY] Zero Unit Test Coverage for Adversarial Attack Suite
- **Severity**: MEDIUM
- **Category**: METHODOLOGY
- **Location**: [`agent_poi/attacks/`](file:///E:/agent_poi/agent_poi/attacks)
- **Broken Invariant**: `everything-claude-code` TDD & 80%+ test coverage constraint. `agent_poi/attacks/` has 0 dedicated test suites in `tests/`.
- **Status**: OPEN
- **Worker Remediation**: Create `tests/test_attacks.py` testing static attacks, adaptive mutators, and judge loops.
- **Verification**: `pytest tests/test_attacks.py -v` (100% passing).

---

### [MISTAKE-05] [METHODOLOGY] Dead Root Configuration (`config.yaml`) & Parameter Drift
- **Severity**: HIGH
- **Category**: METHODOLOGY
- **Location**: [`config.yaml`](file:///E:/agent_poi/config.yaml#L1-L45)
- **Broken Invariant**: Single source of truth. Runtime defaults in `CIDecomposer` and `TaskShieldGate` have drifted from `config.yaml`, and `config.yaml` is never loaded at runtime.
- **Status**: OPEN
- **Worker Remediation**: Implement unified config loader (`agent_poi/core/config_loader.py`) and synchronize calibrated weights.
- **Verification**: Create `tests/test_config_sync.py` asserting loaded defaults match `config.yaml`.

---

### [MISTAKE-06] [METHODOLOGY] Multi-Domain Sprawl in Evaluation Dataset & Mock Tools
- **Severity**: MEDIUM
- **Category**: METHODOLOGY
- **Location**: [`agent_poi/evaluation/dataset.py`](file:///E:/agent_poi/agent_poi/evaluation/dataset.py#L48-L158), [`agent_poi/agent/mock_tools.py`](file:///E:/agent_poi/agent_poi/agent/mock_tools.py#L45-L69)
- **Broken Invariant**: Single-Domain Focus Constraint (`AGENTS.md` Rule 2). Generic database, email, and calendar scenarios sprawl outside the financial agent boundary.
- **Status**: OPEN
- **Worker Remediation**: Align evaluation datasets and mock tools exclusively with autonomous transactional & financial operations.
- **Verification**: `pytest tests/test_benchmark.py -v`.

---

### [MISTAKE-07] [ARCHITECTURE] Many Small Files Principle Violation (`financial_dataset.py` > 800 Lines)
- **Severity**: HIGH
- **Category**: ARCHITECTURE
- **Location**: [`agent_poi/financial/eval/financial_dataset.py`](file:///E:/agent_poi/agent_poi/financial/eval/financial_dataset.py) (853 lines)
- **Broken Invariant**: Many Small Files Principle (200–400 lines typical, max 800).
- **Status**: OPEN
- **Worker Remediation**: Decompose into `scenarios_clean.py`, `scenarios_adversarial.py`, and thin aggregator `financial_dataset.py`.
- **Verification**: Line count verification ($\le 800$ lines per file) and `pytest tests/test_unbiased_benchmark.py -v`.

---

### [MISTAKE-08] [ARCHITECTURE] Function Granularity Principle Violation (> 50 Lines)
- **Severity**: HIGH
- **Category**: ARCHITECTURE
- **Location**: 11 functions across [`financial_agent.py`](file:///E:/agent_poi/agent_poi/financial/financial_agent.py#L121), [`financial_benchmark.py`](file:///E:/agent_poi/agent_poi/financial/eval/financial_benchmark.py#L48), [`invariant_verifier.py`](file:///E:/agent_poi/agent_poi/financial/invariant_verifier.py#L38), [`memory_firewall.py`](file:///E:/agent_poi/agent_poi/memory/memory_firewall.py#L55), [`delta_extractor.py`](file:///E:/agent_poi/agent_poi/financial/delta_extractor.py#L55), etc.
- **Broken Invariant**: Function length constraint $\le 50$ lines and nesting $\le 4$ levels.
- **Status**: OPEN
- **Worker Remediation**: Decompose complex functions into clean private helper methods.
- **Verification**: Linting check confirming function line lengths $\le 50$.

---

### [MISTAKE-09] [ARCHITECTURE] Public API Inconsistency in `agent_poi/core/__init__.py`
- **Severity**: LOW
- **Category**: ARCHITECTURE
- **Location**: [`agent_poi/core/__init__.py:L1-L9`](file:///E:/agent_poi/agent_poi/core/__init__.py#L1-L9)
- **Broken Invariant**: Encapsulation and export completeness. `TaskShieldGate`, `AuthGraphDAG`, and `AuthGraphNode` omitted from `__all__`.
- **Status**: OPEN
- **Worker Remediation**: Add exports to `__all__`.
- **Verification**: `python -c "from agent_poi.core import TaskShieldGate, AuthGraphDAG"`.

---

### [MISTAKE-10] [INPUT_OUTPUT] Missing Boundary Sanitization on Disbursement Amounts (Zero / Negative / NaN)
- **Severity**: HIGH
- **Category**: INPUT_OUTPUT
- **Location**: [`agent_poi/financial/state_anchor.py:L105-L143`](file:///E:/agent_poi/agent_poi/financial/state_anchor.py#L105-L143), [`agent_poi/financial/invariant_verifier.py:L69-L80`](file:///E:/agent_poi/agent_poi/financial/invariant_verifier.py#L69-L80)
- **Broken Invariant**: Epistemic Invariant Validation. Amounts must be strictly positive real numbers ($0 < a < \infty$). Non-positive amounts or NaN bypass ceiling limits.
- **Status**: OPEN
- **Worker Remediation**: Add `amount <= 0 or math.isnan(amount) or math.isinf(amount)` invariant checks.
- **Verification**: New unit tests in `tests/test_financial_invariants.py`.

---

### [MISTAKE-11] [INPUT_OUTPUT] Critical Amount Truncation Vulnerability in `AMOUNT_PATTERNS` Regex
- **Severity**: CRITICAL
- **Category**: INPUT_OUTPUT
- **Location**: [`agent_poi/financial/delta_extractor.py:L35-L39`](file:///E:/agent_poi/agent_poi/financial/delta_extractor.py#L35-L39)
- **Broken Invariant**: Strict Input Sanitization. Unformatted numbers $\ge \$1,000$ (e.g. `$95000`) truncate to first 3 digits (`$950.0`), allowing invariant ceiling bypass.
- **Status**: OPEN
- **Worker Remediation**: Fix regex pattern to support non-comma numbers without digit truncation.
- **Verification**: Add TDD unit test extracting `$95000` confirming exact float `95000.0`.

---

### [MISTAKE-12] [INPUT_OUTPUT] Execution Sink Provenance Bypass via Default `contributing_node_ids=None`
- **Severity**: CRITICAL
- **Category**: INPUT_OUTPUT
- **Location**: [`agent_poi/financial/financial_agent.py:L65-L83`](file:///E:/agent_poi/agent_poi/financial/financial_agent.py#L65-L83)
- **Broken Invariant**: Sink Authorization Invariant. Calling `process_disbursement` with `contributing_node_ids=None` skips cryptographic provenance validation.
- **Status**: OPEN
- **Worker Remediation**: Reject execution sink if `contributing_node_ids` is missing when `enable_civ` is True.
- **Verification**: TDD test in `tests/test_authgraph.py` asserting rejection when `contributing_node_ids=None`.

---

### [MISTAKE-13] [INPUT_OUTPUT] In-Place DAG Mutation of Untrusted Origin to Authorized Root
- **Severity**: HIGH
- **Category**: INPUT_OUTPUT
- **Location**: [`agent_poi/financial/financial_agent.py:L178-L181`](file:///E:/agent_poi/agent_poi/financial/financial_agent.py#L178-L181)
- **Broken Invariant**: Cryptographic provenance integrity. Nodes with `SourceOrigin.UNTRUSTED_WEB` must not be dynamically mutated into `is_authorized_root = True`.
- **Status**: OPEN
- **Worker Remediation**: Retain untrusted provenance on context nodes; validate sinks via verified anchor root links.
- **Verification**: Assert `context_node.is_authorized_root == False` throughout task processing in `tests/test_authgraph.py`.

---

### [MISTAKE-14] [CORRECTNESS_DRIFT] Synthetic Mock Illusions & Fragile Heuristics in `MockLLMProvider` and `MockToolManager`
- **Severity**: MEDIUM
- **Category**: CORRECTNESS_DRIFT
- **Location**: [`agent_poi/agent/llm_provider.py:L36-L70`](file:///E:/agent_poi/agent_poi/agent/llm_provider.py#L36-L70), [`agent_poi/agent/mock_tools.py:L80-L95`](file:///E:/agent_poi/agent_poi/agent/mock_tools.py#L80-L95)
- **Broken Invariant**: Rigorous & Unbiased Evaluation Standard (`AGENTS.md` Rule 4). Hardcoded string triggers and `amount > 500` rule produce artificial benchmark biases.
- **Status**: OPEN
- **Worker Remediation**: Anchor tool execution to verified registry rather than static thresholds.
- **Verification**: Run `pytest tests/test_benchmark.py -v`.
