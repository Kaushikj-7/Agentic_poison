# Workspace Behavioral Rules & Invariants: agent_poi

## 1. Mandatory everything-claude-code Methodology
All coding, refactoring, agent behavior, and artifacts in this workspace must strictly follow the instructions, techniques, and agent personas defined in `everything-claude-code/`:
- **Planning (`/plan`)**: Restate requirements, break down into phases, assess risks, estimate complexity, and wait for explicit confirmation before touching any code.
- **TDD Workflow (`/tdd`)**: Scaffold interfaces -> Write failing tests first (RED) -> Implement minimal code to pass (GREEN) -> Refactor (REFACTOR). Maintain 80%+ test coverage.
- **Architecture (`architect`)**: Follow the Many Small Files principle (200–400 lines typical, max 800), high cohesion, low coupling, and explicit trade-off documentation.
- **Security (`security-reviewer`)**: Strict input sanitization, epistemic invariant validation, and zero hardcoded secrets.
- **Code Review (`code-reviewer`)**: Group issues by priority (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`). Keep functions under 50 lines and nesting under 4 levels.
- **Verification (`/verify`)**: Standard report format:
  ```text
  VERIFICATION: [PASS/FAIL]
  Build:    [OK/FAIL]
  Syntax:   [OK/X errors]
  Tests:    [X/Y passed, Z% coverage]
  Security: [OK/X issues]
  Ledger:   [UPDATED]
  Ready for PR: [YES/NO]
  ```

## 2. Single-Domain Focus Constraint
- Keep research, implementation, and benchmarking strictly focused on the **Autonomous Financial & Transactional Agent** domain (wire disbursements, invoice verification, escrow settlement, and ledger reconciliation).
- Do not scale to multi-agent networks or secondary domains until the single-domain Contextual Invariant Verification (CIV) defense is proven working, efficient, and thoroughly vetted.

## 3. Continuous Ledger Maintenance
- Maintain `PROJECT_LEDGER.md` in the workspace root after every turn.
- Track milestones, architectural choices (DEC-xxx), planned vs. built components, and dynamic benchmark metrics (RUN-xxx).

## 4. Rigorous & Unbiased Evaluation Standard
- All benchmark metrics (`ASR-Exec`, `LDSR`, `CDR`) must be computed dynamically from actual execution against ground-truth datasets.
- No hardcoded test passes, synthetic mock illusions, or biased reporting. If an attack succeeds, report it honestly without masking.

## 5. Zero-Hardware Offline Execution
- All models, evaluators, vector stores, and test harnesses must execute 100% locally on standard CPU without requiring external GPU hardware or an active Ollama daemon.
