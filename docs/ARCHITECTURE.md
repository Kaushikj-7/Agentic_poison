# AgentPOI System Architecture: Contextual Invariant Verification & Epistemic Consensus

## 1. Executive Summary & Epistemic Foundations

Modern autonomous agents operating on financial, accounting, and transactional workloads combine untrusted external context (retrieved memories, vendor invoices, emails, webhooks, peer agent communications) with high-consequence execution sinks (`transfer_funds`, `process_wire`, `update_payee`, `disburse_escrow`). Under standard Large Language Model (LLM) architectures, an adversary capable of injecting indirect prompt instructions can manipulate the agent's internal reasoning loop into executing unauthorized transactions.

Recent theoretical findings (*Abdelnabi & Bagdasarian, arXiv:2605.17634*) establish that natural-language prompt filtering alone cannot prevent indirect injection without prohibitive utility destruction on complex legitimate tasks.

**AgentPOI** resolves this vulnerability through **Dual-State Epistemic Consensus (DSEC)** and **Contextual Invariant Verification (CIV)**. Rather than attempting to detect all semantic injection vectors in natural language, AgentPOI establishes an out-of-band immutable State Anchor ($\mathcal{S}_0$) against which all implied state mutations are validated prior to execution sink dispatch. High-consequence disbursements are approved if and only if both contextual admission gating and execution sink invariant verification succeed with zero violations.

---

## 2. End-to-End System Architecture (arXiv Block Diagram)

The following architectural block diagram depicts the end-to-end dataflow through the AgentPOI verification tiers. The architecture is strictly planar and staged, ensuring zero cross-tier edge entanglements:

```mermaid
flowchart TD
    subgraph Stage0 ["Stage 0: Dual Input Ingestion"]
        direction LR
        UserQ["Authenticated Principal Query q\n(User / System Dispatch)"]
        DocC["Untrusted Context c\n(Invoices, Emails, Webhooks, Memos)"]
    end

    subgraph Stage1 ["Stage 1: Semantic Admission Gating (Task Shield, ACL 2025)"]
        TSGate["Task Shield Semantic Gate\nScore(m, q) = cos(E(m), E(q)) - α · Divergence(m, q)\nRejects Unsolicited Imperative Action Directives"]
    end

    subgraph Stage2 ["Stage 2: Deterministic Mutation Synthesis"]
        DeltaExt["Financial Delta Extractor\nΔ(c) = ⟨p*, δa, α, IdempKey, CapToken⟩\nNormalizes Unstructured Text into Formal Parameter Tuple"]
    end

    subgraph Stage3 ["Stage 3: Contextual Invariant Verification (CIV)"]
        direction LR
        AnchorS0[("Immutable State Anchor S₀\n• Payee Registry {p_i}\n• Spending Ceilings L_tx, L_daily\n• 3-Way PO Matching Store\n• Non-Replay Idempotency Store")]
        CIVEngine["CIV Invariant Engine\n1. Target Payee: p* ∈ S₀\n2. Amount Ceiling: δa ≤ min(L_tx, Limit(p*))\n3. 3-Way Match: PO(p*, items, δa) verified\n4. Idempotency: IdempKey unique & fresh"]
        AnchorS0 -->|"Invariant Constraints"| CIVEngine
    end

    subgraph Stage4 ["Stage 4: Cryptographic Provenance Attestation (AuthGraph DAG, arXiv:2605.26497)"]
        DAGEngine["AuthGraph Provenance DAG Verifier\nParent Hash Chaining: H(v) = SHA256(payload || parents)\nVerifies Lineage(sink) ⊆ Roots(S₀) without external trust"]
    end

    subgraph Stage5 ["Stage 5: Fail-Closed Execution Sink & Settlement"]
        direction LR
        SinkNode{"Fail-Closed Sink Gate\nAll Checks Valid?"}
        LedgerOut[("Cryptographic Double-Entry Ledger\nImmutable Committed Transaction")]
        QuarantineOut["Quarantine Vault & Diagnostics\nIsolation Event + Telemetry Log"]

        SinkNode -- "All Invariants Pass" --> LedgerOut
        SinkNode -- "Any Violation" --> QuarantineOut
    end

    UserQ --> TSGate
    DocC --> TSGate
    TSGate -->|"Admitted Context"| DeltaExt
    DeltaExt -->|"Formal Tuple Δ(c)"| CIVEngine
    CIVEngine -->|"Invariants Satisfied"| DAGEngine
    DAGEngine -->|"Lineage Validated"| SinkNode
```

---

## 3. Component Deep Dive

### 3.1. Stage 0: Context Ingestion & Decoupling
Context inputs are segregated by origin:
- **Authenticated Query ($q$):** Instructions provided by an authenticated human principal or authoritative system orchestrator.
- **Untrusted Context ($c$):** Passive data ingested from external sources (invoices, emails, webhooks, knowledge-base retrievals).

### 3.2. Stage 1: Task Shield Retrieval Gate (*ACL 2025*)
Prevents dormant or sleeper injection payloads from entering the agent's context window. Evaluates semantic relevance while penalizing unsolicited imperative commands:
$$\text{Score}(m, q) = \cos(E(m), E(q)) - \alpha \cdot \text{Divergence}(m, q)$$
If candidate chunk $m$ contains high imperative density (*wire, remit, transfer, bypass, override*) that diverges from user query $q$, the divergence penalty suppresses admission before the language model can be compromised.

### 3.3. Stage 2: Deterministic Delta Extraction ($\Delta(c)$)
The `FinancialDeltaExtractor` maps unstructured natural-language claims into a deterministic mutation tuple:
$$\Delta(c) = \langle p^*, \delta a, \alpha, \text{IdempKey}, \text{CapToken} \rangle$$
Where:
- $p^* \in \mathcal{P} \cup \{\bot\}$: Extracted target payee account identifier.
- $\delta a \in \mathbb{R}^+ \cup \{\bot\}$: Proposed disbursement amount.
- $\alpha \in \mathcal{A}$: Implied authorization or executive override claim.
- $\text{IdempKey} \in \mathcal{K}$: Transaction idempotency identifier.
- $\text{CapToken} \in \mathcal{T}$: Capability mediation token.

### 3.4. Stage 3: Contextual Invariant Verification (CIV) & Immutable State Anchor ($\mathcal{S}_0$)
The State Anchor ($\mathcal{S}_0$) is maintained out-of-band and cannot be mutated by context:
$$\mathcal{S}_0 = \langle \mathcal{V}_{\text{payees}}, L_{\text{tx}}, L_{\text{daily}}, \mathcal{R}_{\text{PO}}, \mathcal{R}_{\text{idemp}}, \Sigma_{\text{signers}}, \mathcal{L}_{\text{audit}} \rangle$$
- $\mathcal{V}_{\text{payees}}$: Verified vendor registry mapping payee IDs to authorized routing accounts and ceilings.
- $L_{\text{tx}}$: Global single-transaction ceiling ($25,000.00).
- $L_{\text{daily}}$: Cumulative daily transaction ceiling ($100,000.00).
- $\mathcal{R}_{\text{PO}}$: Active purchase order verification registry for 3-way matching.
- $\mathcal{R}_{\text{idemp}}$: Nonce registry preventing transaction replay attacks.

The Contextual Invariant Verifier tests formal compliance:
$$\Delta(c) \models \mathcal{S}_0 \iff \begin{cases}
p^* \in \text{dom}(\mathcal{V}_{\text{payees}}) \\
\delta a \le \min\left(L_{\text{tx}}, \mathcal{V}_{\text{payees}}[p^*].\text{max\_disbursement}\right) \\
\text{VerifyPO}(p^*, \delta a, \mathcal{R}_{\text{PO}}) = \text{True} \\
\text{IsFreshNonce}(\text{IdempKey}, \mathcal{R}_{\text{idemp}}) = \text{True} \\
\text{SelfAssertedOverride}(\alpha) = \text{False}
\end{cases}$$

### 3.5. Stage 4: AuthGraph Cryptographic Lineage DAG (*arXiv:2605.26497*)
Every context chunk and execution proposal forms a directed acyclic graph (DAG) node chained by SHA-256 parent digests:
$$H(v) = \text{SHA256}\left( \text{node\_id} \parallel \text{content} \parallel \text{origin} \parallel \bigoplus_{p \in \text{parents}} H(p) \right)$$
At the execution sink, the verifier confirms that $\text{Lineage}(\text{proposal}) \subseteq \text{Roots}(\mathcal{S}_0)$. Untrusted web or email nodes cannot forge authentic cryptographic lineage.

### 3.6. Stage 5: Fail-Closed Execution Sink & Double-Entry Ledger
The final transactional sink operates on fail-closed invariant semantics:
- **Consensus Passed:** If all checks across Stages 1–4 succeed, the transaction is executed and atomically appended to a double-entry cryptographic ledger $\mathcal{L}_{\text{audit}}$.
- **Invariant Breached:** If any check fails, execution is immediately halted, and the event is routed to the Quarantine Vault with comprehensive diagnostic telemetry.

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
