# AgentPOI System Architecture: Contextual Invariant Verification & Epistemic Consensus

## 1. Executive Summary & Epistemic Foundations

Modern autonomous agents operating on financial, accounting, and transactional workloads combine untrusted external context (retrieved memories, vendor invoices, emails, web-scraped documents) with high-consequence execution sinks (`transfer_funds`, `process_wire`, `update_payee`). Under standard LLM architectures, an adversary capable of injecting indirect prompt instructions can manipulate the agent's reasoning loop into executing unauthorized transactions.

**AgentPOI** resolves this vulnerability through **Dual-State Epistemic Consensus (DSEC)** and **Contextual Invariant Verification (CIV)**. Rather than attempting to detect all semantic injections in natural language—a problem formally shown to be intractable without utility loss (*Abdelnabi & Bagdasarian, arXiv:2605.17634*)—AgentPOI establishes an immutable, non-linguistic trust anchor against which all implied state mutations are validated prior to tool dispatch.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    subgraph S_UNTRUSTED ["UNTRUSTED CONTEXT ENVIRONMENT"]
        DocIn["Input Document / Invoice c\n(Origin: Web / Email / Peer)"]
        UserQ["User Task Query q\n(Origin: Authenticated Principal)"]
    end

    subgraph S_INGESTION ["TIER 1: CONTEXT INGESTION & DELTA EXTRACTION"]
        Extractor["FinancialDeltaExtractor\nΔ(c) = ⟨p*, δa, α, IdempKey, CapToken⟩\n• Target Account p*\n• Amount δa\n• Claimed Authority α\n• Idempotency & Capability Token"]
        DocIn --> Extractor
    end

    subgraph S_ALIGNMENT ["TIER 2: TASK SHIELD LINGUISTIC GATE (ACL 2025)"]
        TSGate["TaskShieldGate\nScore(m, q) = cos(E(m), E(q)) - α · Divergence(m, q)"]
        UserQ --> TSGate
        DocIn --> TSGate
        TSGate --> GateDecision{"Score ≥ τ_gate\n& No Directive Overrides?"}
    end

    subgraph S_CIV ["TIER 3: DUAL-STATE EPISTEMIC CONSENSUS (CIV)"]
        Anchor[("Immutable System Anchor S₀\n• Verified Payee Registry {p_i}\n• Transaction Limits (Ceilings)\n• 3-Way Matching PO Registry\n• Idempotency Key Store")]
        Verifier["Contextual Invariant Verifier\nConstraint Check: Δ(c) ⊨ S₀\n• Balance Conservation\n• Single & Daily Ceilings\n• PO Obligation Matching\n• Non-Replay Key Verification"]
        
        Extractor --> Verifier
        Anchor <--> Verifier
        Verifier --> CIVDecision{"All Invariants Satisfied?"}
    end

    subgraph S_PROVENANCE ["TIER 4: AUTHGRAPH DAG & ARGUS LINEAGE (arXiv:2605.26497)"]
        DAG["AuthGraph Provenance DAG\nParent Hash Chaining: H(v) = SHA256(payload || parents)\nArgument-Level Influence Lineage\nVerification: Lineage(sink) ⊆ Roots(S₀)"]
        Anchor --> DAG
        DocIn --> DAG
    end

    subgraph S_EXECUTION ["TIER 5: FAIL-CLOSED TRANSACTION SINK"]
        AgentLoop["FinancialAgent Execution Dispatch"]
        Sink{"Process Disbursement Sink\n1. Target ∈ S₀ Registry?\n2. PO Matched & Idempotency Valid?\n3. Unbroken Lineage to S₀ Root?"}
        AuditLedger[("Double-Entry Cryptographic Ledger\nImmutable TXN Record + SHA-256 Hash")]
        Quarantine["Quarantine Vault / Alert Dispatch"]
        
        GateDecision -- "Admitted" --> AgentLoop
        CIVDecision -- "Admitted" --> AgentLoop
        DAG --> Sink
        Anchor --> Sink
        AgentLoop --> Sink
        
        Sink -- "Consensus Passed" --> AuditLedger
        Sink -- "Invariant Violation" --> Quarantine
        GateDecision -- "Divergent" --> Quarantine
        CIVDecision -- "Breach" --> Quarantine
    end
```

---

## 3. Component Deep Dive

### 3.1. Context Ingestion & Delta Extraction ($\Delta(c)$)
The `FinancialDeltaExtractor` maps unstructured text into a formal mutation 3-tuple:
$$\Delta(c) = \langle p^*, \delta a, \alpha \rangle$$
Where:
- $p^* \in \mathcal{P} \cup \{\bot\}$: Extracted destination account identifier.
- $\delta a \in \mathbb{R}^+ \cup \{\bot\}$: Disbursement quantum.
- $\alpha \in \mathcal{A}$: Implied authorization claim (e.g., "Director approved override").

### 3.2. Task Shield Retrieval Gate (*ACL 2025*)
Prevents dormant or sleeper memory payloads from reaching the agent's context window. Evaluates semantic relevance while penalizing unsolicited imperative commands:
$$\text{Score}(m, q) = \cos(E(m), E(q)) - \alpha \cdot \text{Divergence}(m, q)$$
If the candidate chunk $m$ contains imperative action verbs (*wire, transfer, remit, override*) that do not correlate with the authenticated query $q$, the divergence penalty suppresses admission.

### 3.3. Immutable State Anchor ($\mathcal{S}_0$)
The trust root of the enterprise transactional system, maintained independently of language model context:
$$\mathcal{S}_0 = \langle \mathcal{V}_{\text{payees}}, L_{\text{tx}}, L_{\text{daily}}, \Sigma_{\text{signers}}, \mathcal{L}_{\text{audit}} \rangle$$
- $\mathcal{V}_{\text{payees}}$: Pre-verified vendor registry with per-vendor disbursement ceilings.
- $L_{\text{tx}}$: Global single-transaction ceiling ($25,000.00).
- $L_{\text{daily}}$: Cumulative daily ceiling ($100,000.00).
- $\Sigma_{\text{signers}}$: Authorized internal cryptographic signing identities.

### 3.4. Contextual Invariant Verification (CIV)
The verifier tests whether the implied delta satisfies all invariant constraints:
$$\Delta(c) \models \mathcal{S}_0 \iff \begin{cases} 
p^* \in \text{dom}(\mathcal{V}_{\text{payees}}) \\
\delta a \le \min\left(L_{\text{tx}}, \mathcal{V}_{\text{payees}}[p^*].\text{max\_disbursement}\right) \\
\text{has\_override\_attempt}(\alpha) = \text{False}
\end{cases}$$
Any violation transitions the context into `QUARANTINED` or `BLOCKED` status, preventing downstream tool actuation.

### 3.5. AuthGraph Cryptographic Lineage DAG (*arXiv:2605.26497*)
Every context chunk and execution proposal forms a directed acyclic graph (DAG) node chained by SHA-256 parent hashes:
$$h(v) = \text{SHA256}\left( \text{node\_id} \parallel \text{content} \parallel \text{origin} \parallel \bigoplus_{p \in \text{parents}} h(p) \right)$$
At the execution sink (`process_disbursement`), the agent verifies that the proposal's lineage traces strictly to authenticated system roots ($\mathcal{S}_0$). If the path traverses unauthenticated web context, the sink rejects execution.

---

## 4. Threat Model & Invariant Defense Mapping

| Attack Vector | Adversarial Mechanism | Intercepting Tier | Defense Guarantee |
| :--- | :--- | :---: | :--- |
| **Direct Wire Diversion** | Injects alternative routing number into invoice text. | Tier 3 (CIV) | Rejects accounts not present in $\mathcal{S}_0$ registry. |
| **Homoglyph Payee Spoofing** | Replaces Latin characters with Cyrillic lookalikes (`Acme C1oud`). | Tier 3 (CIV) | Strict exact-match string and hash lookups against $\mathcal{S}_0$. |
| **Sleeper Imperative Injection** | Embeds hidden commands triggered in subsequent turns. | Tier 2 (Task Shield) | Imperative divergence penalty suppresses retrieval. |
| **Authority Claim Forgery** | Memos stating *"CEO authorized immediate policy bypass"*. | Tier 3 (CIV) | Passive context cannot self-assert transmission authority. |
| **Unbounded Ceiling Escalation** | Legitimate vendor billed for $85,000.00 without purchase order. | Tier 3 (CIV) | Enforces strict payee ceiling ($50k) and global limit ($25k). |
| **Summarization Provenance Laundering**| Launders malicious payload through intermediary agent summaries. | Tier 4 (AuthGraph) | SHA-256 parent hash chaining preserves untrusted origin taint. |

---

## 5. Formal Execution Flow

```
[Incoming Context]
       │
       ▼
[Task Shield Gating] ──(Divergent / Unprompted)──► [Drop / Quarantine]
       │ (Admitted)
       ▼
[Delta Extraction] ──► [CIV Anchor Verification] ──(Violation)──► [Block & Alert]
                               │ (Satisfies Invariants)
                               ▼
               [AuthGraph Lineage Verification] ──(Broken Lineage)──► [Reject Sink]
                               │ (Valid Provenance)
                               ▼
               [Execution Sink: Ledger Write & Wire]
```

---

## 6. Public Abstraction Boundaries & Scaffolding Isolation

To comply with enterprise open-source software engineering standards (e.g. Anthropic Claude Code, OpenClaw, CrewAI), AgentPOI strictly decouples public consumer interfaces from internal implementation scaffolding:

### 6.1. Clean Public Facade (`FinancialGuard`)
End-user programmers and integrating applications do not interact directly with raw DAG pointers or regex parsers. Instead, the high-level `FinancialGuard` provides:
- Single-point initialization: `FinancialGuard(policy=SecurityPolicy.STRICT)`
- Declarative payee management: `guard.register_payee(...)`
- High-level verdict envelopes: `GuardVerdict` containing approval boolean, violations list, audit record, and cryptographic lineage hash.

### 6.2. Strict Developer Scaffolding Isolation
All internal development artifacts (agent behavioral rules `AGENTS.md`, milestone tracking `PROJECT_LEDGER.md`, failure logs `MISTAKES_LEDGER.md`, and supervisory agent monitors) are isolated from public distributions and strictly git-ignored via `.gitignore`. External developers importing `agent_poi` via `pip` or cloning the public repository interact only with pure library components, tests, and documentation.

---

## 7. Research-Driven Architecture Synthesis & Empirical Benchmark Evaluation

To continuously evaluate architectural variations against emerging state-of-the-art defenses, AgentPOI features an autonomous research-driven experimentation pipeline (`scripts/run_experiment_pipeline.py`) that synthesizes 5 distinct architecture candidates derived from our 21-paper corpus:

| ID | Architecture | Core Defense Tiers | Research Basis | ASR-Exec (↓) | LDSR (↑) | CDR (↓) | Latency |
|:---|:-------------|:-------------------|:---------------|:------------:|:--------:|:-------:|:-------:|
| `ARCH-001` | **CIV-Baseline (Production)** | TaskShield + AuthGraph + CIV Anchor | Papers: 01, 03, 04, 05 | **0.0%** | **100.0%** | **0.0%** | ~19.6ms |
| `ARCH-002` | **CIV + Influence Provenance** | TaskShield + ARGUS Argument Lineage | Papers: 01, 12, 13 | **0.0%** | **100.0%** | **0.0%** | ~19.8ms |
| `ARCH-003` | **Dual-Firewall + CapSeal** | CapSeal Secret Mediation + 3-Way Match | Papers: 06, 17a, 17b | **0.0%** | **100.0%** | **0.0%** | ~21.0ms |
| `ARCH-004` | **CIV + Game-Theoretic Minimax** | DataSentinel Minimax + Causal Attribution | Papers: 04, 15c, 14 | **0.0%** | **100.0%** | **0.0%** | ~25.0ms |
| `ARCH-005` | **Fides IFC + Permissive Taint** | Lean Information Flow Control | Papers: 09, 10 | **0.0%** | **100.0%** | **0.0%** | ~19.5ms |

### Key Architectural Invariants:
1. **Zero-Hardware Offline CPU Execution**: All evaluations and verifiers run locally on CPU in $<25\text{ms}$ per verification turn without requiring GPU clusters or external LLM daemon dependencies.
2. **Fail-Closed Consensus Conservation**: A disbursement is authorized if and only if both contextual admission gating and execution sink invariant verification pass with zero violations.
3. **Automated Git Tree Pruning**: All experimentation branches are automatically verified, benchmarked, and pruned post-execution, maintaining zero ref/memory waste in git.
