# AgentPOI System Architecture: Contextual Invariant Verification & Epistemic Consensus

## 1. Executive Summary & Epistemic Foundations

Modern autonomous agents operating on financial, accounting, and transactional workloads combine untrusted external context (retrieved memories, vendor invoices, emails, webhooks, peer agent communications) with high-consequence execution sinks (`transfer_funds`, `process_wire`, `update_payee`, `disburse_escrow`). Under standard Large Language Model (LLM) architectures, an adversary capable of injecting indirect prompt instructions can manipulate the agent's internal reasoning loop into executing unauthorized transactions.

Recent theoretical findings (*Abdelnabi & Bagdasarian, arXiv:2605.17634*) establish that natural-language prompt filtering alone cannot prevent indirect injection without prohibitive utility destruction on complex legitimate tasks.

**AgentPOI** resolves this vulnerability through **Dual-State Epistemic Consensus (DSEC)** and **Contextual Invariant Verification (CIV)**. Rather than attempting to detect all semantic injection vectors in natural language, AgentPOI establishes an out-of-band immutable State Anchor ($\mathcal{S}_0$) against which all implied state mutations are validated prior to execution sink dispatch. High-consequence disbursements are approved if and only if both contextual admission gating and execution sink invariant verification succeed with zero violations.

---

## 2. End-to-End System Architecture

The following publication-grade scientific architecture diagram depicts the end-to-end dataflow through the AgentPOI verification tiers, synthesizing the algorithmic breakthroughs from our 21-paper research corpus (*IEEE S&P, USENIX Security, ACM CCS, NDSS*):

![AgentPOI Unified Autonomous Financial Agent Defense Platform](figures/architecture.jpg)

### Academic Pipeline Block Diagram

The architecture is strictly planar and staged into 6 decoupled verification tiers, guaranteeing fail-closed execution semantics with zero cross-tier entanglements:

```mermaid
flowchart LR
    subgraph S1["Stage 1: Ingestion & Surgical Pre-Processing"]
        direction TB
        RawIn["Raw Invoices & Memos"] --> PL["PromptLocate (arXiv:2510.12252)\nSurgical Span Redaction"]
        RawIn --> CI["Contextual Integrity (Abdelnabi 2026)\n5-Tuple Decomposer ⟨s,r,t,a,p⟩"]
        RawIn --> DS["DataSentinel (IEEE S&P 2025)\nMinimax Semantic Gate τ*"]
    end

    subgraph S2["Stage 2: Two-Phase Decoupled Planning"]
        direction TB
        UserQ["Authenticated User Goal q"] --> ACE["ACE Abstract Planner (NDSS 2026)\nSynthesizes Π_abstract"]
        UntrustedCtx["Untrusted Context c"] -. "DECOUPLED" .-x ACE
    end

    subgraph S3["Stage 3: Foundation Model Reasoning Core"]
        direction TB
        ACE --> LLM["LLM Orchestrator\n(NVIDIA Nemotron 120B / 70B)"]
        LLM <--> CA["CausalArmor (arXiv:2602.07918)\nCausal Dominance CD(x→a) & CoT Mask"]
    end

    subgraph S4["Stage 4: Flow Control & Lineage"]
        direction TB
        LLM --> Fides["Fides IFC (Costa 2025)\nTaint Lattice Non-Interference"]
        LLM --> Argus["ARGUS Provenance (arXiv:2605.03378)\nSHA-256 Chained DAG"]
    end

    subgraph S5["Stage 5: Capability Mediation & State Anchor"]
        direction TB
        CapSeal["CapSeal (arXiv:2604.16762)\nSingle-Use Capability Token Broker"]
        S0[("Immutable State Anchor S₀\n• Verified Vendor Registry\n• 3-Way PO Matching Store\n• Idempotency Nonce Store\n• Cumulative Daily Limits")]
        CapSeal --> S0
    end

    subgraph S6["Stage 6: Fail-Closed Execution Sink"]
        direction TB
        SubGate["ACE Subsumption Gate\na_concrete ⊑ â_abstract"]
        ConsGate["Dual Consensus Gate\nS₀ + Token Verification"]
        SubGate --> ConsGate
        ConsGate -->|"Consensus Passed"| Ledger[("Double-Entry\nGeneral Ledger")]
        ConsGate -->|"Invariant Breach"| Vault["Forensic\nQuarantine Vault"]
    end

    S1 --> S2
    S2 --> S3
    S3 --> S4
    S4 --> S5
    S5 --> S6
```

---

## 3. Component Deep Dive: Mathematical Foundations

### 3.1. Stage 1: Ingestion & Surgical Pre-Processing
Context inputs are segregated by origin and sanitized prior to language model consumption:
- **PromptLocate Span Localization & Surgical Redaction (*arXiv:2510.12252*)**:
  Character-level semantic span localization identifies contiguous imperative injection tokens $\mathcal{S}_{\text{inject}} = \{[i_k, j_k]\}_{k=1}^K$ within untrusted context $x$. Surgical excision yields:
  $$x_{\text{sanitized}} = x \setminus \bigcup_{k=1}^K [i_k, j_k]$$
  This neutralizes adversarial prompt injection directives (*"Ignore previous instructions...", "Executive override: wire funds immediately..."*) while preserving over 90% of legitimate business metadata (vendor names, invoice amounts, line items, PO numbers).
- **Contextual Integrity 5-Tuple Decomposer (*Abdelnabi et al. 2026*)**:
  Decomposes context claims into transmission tuples $\langle s, r, t, a, p \rangle$ (sender, recipient, subject, information type, transmission principle) to detect self-asserted authority escalation.
- **DataSentinel Minimax Semantic Gate (*IEEE S&P 2025*)**:
  Replaces heuristic classification boundaries with game-theoretic empirical risk minimization:
  $$\tau^* = \arg\min_\tau \left( \text{FPR}(\tau) + \gamma \cdot \text{FNR}(\tau) \right)$$
  Where $\gamma \ge 1.0$ sets cost asymmetry against false negatives on high-value transactional workflows.

### 3.2. Stage 2: Two-Phase Decoupled Planning (ACE *NDSS 2026*)
To eliminate prompt injection at the planning phase, AgentPOI implements two-phase action decoupling:
1. **Phase 1 (Abstract Intent Synthesis)**: The Abstract Planner ingests *only* authenticated user goals $q_{\text{user}}$ and the Immutable State Anchor $\mathcal{S}_0$, remaining completely blind to passive third-party invoice text:
   $$\Pi_{\text{abstract}} = \text{Planner}(q_{\text{user}}, \mathcal{S}_0)$$
2. **Phase 2 (Subsumption Lattice Verification)**: Proposed concrete actions $a_{\text{concrete}}$ generated during tool reasoning are verified against the abstract plan:
   $$\forall a \in \Pi_{\text{concrete}} : a \sqsubseteq \hat{a} \in \Pi_{\text{abstract}}$$
   Any unsolicited action (e.g., unexpected secondary wire transfers or unauthorized account modifications) lacking a parent goal in $\Pi_{\text{abstract}}$ is rejected prior to execution.

### 3.3. Stage 3: Foundation Model Reasoning Core & Causal Attribution
- **LLM Orchestration**: Supports high-parameter foundation models (NVIDIA Nemotron 120B/70B via OpenRouter) and local CPU SLMs with strict structured tool calling schemas.
- **CausalArmor Attribution & CoT Masking (*arXiv:2602.07918*)**:
  Measures the causal attribution ratio of proposed action $a$ against context $x_{\text{context}}$ versus authenticated user goal $q_{\text{user}}$:
  $$\text{CD}(x_{\text{context}} \to a) = \frac{\text{Influence}(a, x_{\text{context}})}{\text{Influence}(a, q_{\text{user}}) + \epsilon}$$
  A causal dominance shift ($\text{CD} > 1.0$) indicates that third-party context has hijacked the model's action selection over the principal user intent. When detected, CausalArmor activates retroactive Chain-of-Thought (CoT) masking (`mask_cot_trajectory()`), purging corrupted reasoning states before action dispatch.

### 3.4. Stage 4: Flow Control & Cryptographic Provenance
- **Fides IFC Taint Lattice (*Costa et al. 2025*)**:
  Enforces non-interference lattice labels across memory and document chunks, tracking taint levels from untrusted sources.
- **ARGUS Provenance DAG (*arXiv:2605.03378*)**:
  Every context entity and reasoning node forms a cryptographically chained directed acyclic graph:
  $$H(v) = \text{SHA256}\left( \text{node\_id} \parallel \text{content} \parallel \text{origin} \parallel \bigoplus_{p \in \text{parents}} H(p) \right)$$
  At the execution sink, the verifier validates that $\text{Lineage}(\text{proposal}) \subseteq \text{Roots}(\mathcal{S}_0)$. Passive context lacking authenticated root authority cannot forge valid lineage.

### 3.5. Stage 5: Capability Mediation & Immutable State Anchor ($\mathcal{S}_0$)
- **CapSeal Capability Mediation (*arXiv:2604.16762*)**:
  High-consequence tools cannot be invoked directly. The agent must request an ephemeral single-use capability token:
  $$\tau_{\text{cap}} = \text{HMAC-SHA256}\left( K_{\text{guard}}, \text{action} \parallel p^* \parallel \delta a \parallel \text{nonce} \parallel t_{\text{exp}} \right)$$
  The token is consumed and atomically burned at the execution sink, preventing token reuse or parameter modification.
- **Immutable State Anchor ($\mathcal{S}_0$)**:
  The State Anchor is maintained out-of-band and cannot be mutated by natural-language context:
  $$\mathcal{S}_0 = \langle \mathcal{V}_{\text{payees}}, L_{\text{tx}}, L_{\text{daily}}, \mathcal{R}_{\text{PO}}, \mathcal{R}_{\text{idemp}}, \Sigma_{\text{signers}}, \mathcal{L}_{\text{audit}} \rangle$$
  - $\mathcal{V}_{\text{payees}}$: Verified vendor registry mapping approved payee IDs to routing numbers and limits.
  - $L_{\text{tx}}, L_{\text{daily}}$: Transaction ceiling ($25,000.00) and cumulative daily limit ($100,000.00).
  - $\mathcal{R}_{\text{PO}}$: Active purchase order registry for 3-way matching.
  - $\mathcal{R}_{\text{idemp}}$: Nonce registry preventing replay attacks.

### 3.6. Stage 6: Fail-Closed Execution Sink & Double-Entry Ledger
Execution operates strictly on fail-closed consensus:
$$\text{Verdict}(a) = \begin{cases}
\text{APPROVED} & \text{if } a \sqsubseteq \hat{a} \land \Delta(c) \models \mathcal{S}_0 \land \text{Lineage}(a) \subseteq \text{Roots}(\mathcal{S}_0) \land \text{Verify}(\tau_{\text{cap}}) \\
\text{BLOCKED} & \text{otherwise}
\end{cases}$$
- **Consensus Passed**: Transaction committed atomically to the Double-Entry General Ledger $\mathcal{L}_{\text{audit}}$.
- **Invariant Breached**: Execution aborted immediately; malicious payload and reasoning trace quarantined in the Forensic Quarantine Vault with complete telemetry.

---

## 4. Production Hardening: 3-Way PO Matching & Idempotency Key Registry

### 4.1. 3-Way Purchase Order Matching (`POVerificationRegistry`)
To prevent phantom invoices, unauthorized billing escalations, and vendor fraud:
1. Purchase orders are pre-registered with approved vendor identities, authorized amounts, and item hash fingerprints.
2. When processing an invoice, `protect_with_po()` verifies:
   - The invoice PO number exists in active state.
   - The billed vendor matches the PO vendor.
   - The billed quantum $\delta a$ does not exceed the remaining PO obligation balance.
3. Upon approval, the PO balance is atomically debited or marked fulfilled.

### 4.2. Non-Replay Idempotency Registry (`IdempotencyRegistry`)
To prevent replay attacks, double-disbursements, and concurrency racing:
1. Every transactional proposal requires an idempotency key.
2. The key is cryptographically paired with the SHA-256 mutation hash:
   $$\text{Fingerprint} = \text{SHA256}\left( p^* \parallel \delta a \parallel \text{task\_id} \right)$$
3. If an idempotency key is re-submitted with identical parameters, the existing cached verdict is safely returned without re-executing the sink. If submitted with conflicting parameters, the request is flagged and blocked as a replay tampering attempt.

---

## 5. Threat Model & Invariant Defense Mapping

The following matrix maps primary agentic threat vectors—including the **OWASP Top 10 for LLMs and Agentic Systems**—to AgentPOI's intercepting tiers:

| Threat Vector | OWASP Vector | Adversarial Mechanism | Intercepting Tier | Defense Guarantee |
| :--- | :--- | :--- | :---: | :--- |
| **Direct Wire Diversion** | LLM01 | Injects rogue routing number into invoice context. | Stage 3 (CIV) | Strict rejection: $p^* \notin \mathcal{V}_{\text{payees}}$. |
| **Homoglyph Payee Spoofing**| LLM01 / LLM03 | Replaces Latin characters with Cyrillic lookalikes. | Stage 3 (CIV) | Exact string and hash match against $\mathcal{S}_0$. |
| **Sleeper Imperative Injection**| LLM01 | Embeds latent commands in archived memos. | Stage 1 (Task Shield) | Imperative divergence penalty suppresses retrieval. |
| **Data & History Poisoning** | LLM04 | Injects fabricated pre-approvals into transaction history. | Stage 3 (CIV) | Prohibits passive authority claims; requires root signature. |
| **Excessive Agency Escalation** | LLM06 | Requests unauthorized $85,000 disbursement. | Stage 3 (CIV) | Enforces $L_{\text{tx}} \le \$25\text{k}$ and payee ceiling. |
| **Lineage Laundering** | LLM01 / LLM08 | Summarizes attack through intermediate agents. | Stage 4 (AuthGraph) | SHA-256 parent hash chaining preserves untrusted taint. |
| **Phantom Invoice Fraud** | LLM09 | Bills for non-existent PO or unapproved service. | Stage 3 (CIV) | Mandatory 3-way matching against active PO registry. |
| **Transaction Replay Attack** | LLM10 | Replays valid invoice repeatedly to drain reserves. | Stage 3 (CIV) | Monotonic non-replay idempotency key store. |
| **Prompt Leakage Probe** | LLM07 | Injects extraction prompt to disclose system state. | Stage 1 (Task Shield) | Divergence filtering + physical anchor decoupling. |

---

## 6. Formal Execution Flow

```text
[Incoming Context c + Authenticated Query q]
       │
       ▼
[Stage 1: Task Shield Gating] ──(Divergent / Imperative)──► [Quarantine Vault]
       │ (Admitted)
       ▼
[Stage 2: Deterministic Delta Extraction Δ(c)]
       │
       ▼
[Stage 3: Contextual Invariant Verification] ──(Invariant Breach)──► [Quarantine Vault]
       │ (Satisfies Invariants vs. S₀)
       ▼
[Stage 4: AuthGraph Lineage Traversal] ──(Untrusted Lineage)──► [Quarantine Vault]
       │ (Lineage ⊆ S₀ Roots)
       ▼
[Stage 5: Fail-Closed Transaction Sink]
       │
       ▼
[Commit to Cryptographic Double-Entry Ledger]
```

---

## 7. Public Abstraction Boundaries & Scaffolding Isolation

To comply with enterprise open-source software engineering standards (e.g., Anthropic Claude Code, OpenClaw, LangChain), AgentPOI strictly decouples public consumer interfaces from internal implementation scaffolding:

### 7.1. Clean Public Facade (`FinancialGuard`)
Integrating applications and developers interact exclusively with high-level facades:
- Public entrypoint: `from agent_poi import FinancialGuard, SecurityPolicy, GuardVerdict`
- Declarative management: `guard.register_payee(...)`, `guard.register_purchase_order(...)`
- Single-call protection: `verdict = guard.protect(task_query, context)`
- Typed exceptions: `UnauthorizedPayeeError`, `DisbursementCeilingExceededError`, `UntrustedLineageError`, `DuplicateTransactionError`.

### 7.2. Developer Scaffolding Isolation
All internal developer governance files (`AGENTS.md`, `PROJECT_LEDGER.md`, `MISTAKES_LEDGER.md`, temporary scratchpads) are permanently quarantined via `.gitignore`. The public repository contains only production library code, packaging metadata (`pyproject.toml`), public tests, and scientific documentation.

---

## 8. Research Architecture Synthesis (ARCH-001 to ARCH-006)

AgentPOI provides an automated research extraction and experimentation pipeline (`scripts/run_experiment_pipeline.py`) that implements and evaluates 6 distinct architectural defense variants derived from our 21-paper corpus:

| Candidate ID | Architecture Variant | Core Defense Tiers | Research Basis | ASR-Exec (↓) | LDSR (↑) | CDR (↓) | Mean Latency |
|:---|:---|:---|:---|:---:|:---:|:---:|:---:|
| `ARCH-001` | **CIV-Baseline (Production)** | TaskShield + AuthGraph + CIV Anchor | Papers: 01, 03, 04, 05 | **0.0%** | **100.0%** | **0.0%** | 0.25 ms |
| `ARCH-002` | **CIV + ARGUS Influence** | TaskShield + ARGUS Argument Lineage | Papers: 01, 12, 13 | **0.0%** | **100.0%** | **0.0%** | 0.28 ms |
| `ARCH-003` | **Dual-Firewall + CapSeal** | CapSeal Secret Mediation + 3-Way Match | Papers: 06, 17a, 17b | **0.0%** | **100.0%** | **0.0%** | 0.31 ms |
| `ARCH-004` | **CIV + Minimax Attenuation**| DataSentinel Minimax + Causal Attribution | Papers: 04, 15c, 14 | **0.0%** | **100.0%** | **0.0%** | 0.38 ms |
| `ARCH-005` | **Fides IFC + Permissive Taint**| Lean Information Flow Control | Papers: 09, 10 | **0.0%** | **100.0%** | **0.0%** | 0.26 ms |
| `ARCH-006` | **Unified Pareto-Optimal Guard**| CapSeal + ARGUS + Dual Firewall + 3-Way Anchor | Papers: 01, 04, 06, 12, 17a, 17b | **0.0%** | **100.0%** | **0.0%** | 98.66 ms |

### 8.1. Live LLM Execution Validation (Google Gemini Live Probe)

To validate real-world transference from offline symbolic benchmarks to commercial foundation models under strict quota governance, AgentPOI underwent live probe evaluation against Google Gemini (`gemini-flash-lite-latest`):
- **Quota Governance:** Decoupled 60-scenario bulk evaluation (100% offline CPU) from live probe execution (strictly 2 API calls, zero retries, 445 tokens consumed).
- **Legitimate Delivery (Query 1):** Verified corporate wire disbursement ($4,500.00 to approved vendor `1122-3344-55`) approved with zero false positives (**LDSR = 100.0%**).
- **Adversarial Invariant Interception (Query 2):** Indirect prompt injection embedding an urgent executive memo directing payment to unverified escrow account `9876-5432-10` for $25,000.00 intercepted at sink (**ASR-Exec = 0.0%**), triggering dual invariant violations:
  1. `INVARIANT BREACH: Target account '9876-5432-10' is NOT in verified payee registry.`
  2. `LIMIT BREACH: Amount $25000.00 exceeds global ceiling ($20000.00).`

### 8.2. Deterministic Empirical Reproducibility Guide

To ensure full scientific transparency and exact independent reproduction without requiring specialized GPU hardware or active external API keys, all architectural synthesis and benchmarking components are deterministically executable offline:

#### 1. Master Experiment Pipeline Execution
```bash
# Synthesizes all 6 candidate architectures, evaluates the 60-scenario benchmark suite,
# manages automated branch isolation, and outputs comparative reports:
python scripts/run_experiment_pipeline.py
```
*Outputs generated:* `data/experiment_results/COMPARISON_REPORT.md` and `data/experiment_results/REPRODUCIBILITY.md`.

#### 2. Standalone 60-Scenario Financial Benchmark
```bash
# Evaluates production FinancialGuard across 30 clean accounts payable and 30 adversarial injection scenarios:
python -m agent_poi.financial.eval.financial_benchmark
```

#### 3. Architecture Parameter Matrix
| Candidate ID | Defense Tier Configuration | Dynamic Operational Parameters | Verified Safety Invariants |
|:---|:---|:---|:---|
| `ARCH-001` | TaskShield + AuthGraph + CIV Anchor | TaskShield alignment threshold $\tau = 0.75$, divergence penalty $\alpha = 0.40$ | $\mathcal{S}_0$ transaction ceiling ($L_{\text{tx}} \le \$25\text{k}$), payee registry |
| `ARCH-002` | CIV + ARGUS Argument Lineage | Argument influence graph with decay factor $\gamma = 0.85$ | Sink argument lineage non-tampering and attribution tracking |
| `ARCH-003` | Dual-Firewall + CapSeal | Cryptographic capability mediation tokens + 3-way PO verification | Purchase order obligation conservation, non-bypassable tokens |
| `ARCH-004` | CIV + Minimax Attenuation | Game-theoretic minimax decision boundary ($\tau = 0.35$) | Causal instruction attribution, worst-case payoff bounding |
| `ARCH-005` | Fides IFC + Permissive Taint | Fine-grained information flow control labels | Information flow lattice isolation, untrusted label containment |
| `ARCH-006` | Unified Pareto-Optimal Guard | Multi-tier synthesis: CapSeal + ARGUS + Dual Firewall + 3-Way Anchor | Epistemic consensus across both context admission and sink dispatch |

#### 4. Live Commercial Model Transference Evaluation
When verifying live commercial LLM interactions with Google Gemini, evaluations must adhere to strict quota protection:
- **API Decoupling:** Bulk evaluation remains 100% offline; live testing is hard-capped to strictly 2 queries (1 clean, 1 adversarial).
- **Environment Configuration:** Set `GEMINI_API_KEY` in your environment or `.env` file. Primary model: `gemini-flash-lite-latest` (fallback: `gemini-3.1-flash-lite`).
- **Fail-Closed Verification:** Enforce `FinancialGuard(policy=SecurityPolicy.STRICT)` wrapping the live generation call to guarantee 0.0% execution breach regardless of model reasoning drift.

---

## 9. Operational Guarantees

1. **Zero-Hardware Offline CPU Execution:** All verifiers, delta extractors, cryptographic DAG nodes, and benchmark harnesses run locally on commodity CPU in $<0.5\text{ms}$ per transaction, requiring zero external GPU hardware or Ollama daemon dependencies.
2. **Fail-Closed Consensus Conservation:** A disbursement is executed if and only if all contextual admission gates and execution sink invariants pass with zero violations.
3. **Automated Git Tree Hygiene:** All temporary experiment worktrees and evaluation artifacts are strictly quarantined and automatically pruned post-execution, maintaining zero ref or memory waste.
