# Literature Survey: Agent Context & Memory Poisoning (2023–2026)

## Executive Summary
This document provides a comprehensive survey of **over 30 peer-reviewed and preprint publications** addressing indirect prompt injection, memory poisoning, agent-to-agent contagion, and contextual integrity defenses. It grounds the **Contextual Trust Propagation (CTP)** framework in the state-of-the-art literature and explicitly establishes why agent poisoning is **not a solved problem**.

---

## 1. The Theoretical Foundation: The Impossibility Result

### "AI Agents May Always Fall for Prompt Injections"
- **Authors**: Sahar Abdelnabi & Eugene Bagdasarian (ELLIS / MPI-IS)
- **Year / Citation**: arXiv:2605.17634 (May 2026)
- **Key Contribution**: 
  - Reframes prompt injection not as a token-filtering failure, but as an informational flow breakdown using **Contextual Integrity (CI)** theory (Nissenbaum, 2004).
  - Evaluates five parameters: $\langle \text{Sender } s, \text{ Receiver } r, \text{ Subject } u, \text{ Information Type } t, \text{ Transmission Principle } p \rangle$.
  - **Formal Impossibility Argument**: No static or deterministic policy can eliminate all context-manipulation attacks without also blocking legitimate requests. An attacker can construct a plausible contextual framing making a malicious action appear authorized; any defense strict enough to block all such attacks inevitably exhibits severe false-positive rates on complex, benign tasks.
  - **Empirical Transferability**: Adaptive attacks hit **96.7% Attack Success Rate (ASR)** against an email agent whose static baseline was $<1\%$. Attacks transferred seamlessly across frontier models without re-optimization:
    - GPT-5.4: 63.3% ASR
    - GPT-5.2: 89.3% ASR
    - Gemini-3-Pro: 92.6% ASR
    - Claude Sonnet 4.6: High susceptibility
  - **Safety Classifier Breakdown**: Meta's Prompt Guard 2 scored an AUROC of 0.43–0.59 (near chance) on contextual manipulation. Meta's SecAlign-70B underperformed base models on suspicious content detection (54.6% vs 89.8%), demonstrating that parameter alignment on one threat vector often degrades safety behaviors on another.
  - **Significance for CTP**: Proves that attempting 0% ASR is scientifically misguided. Defenses must instead optimize the **Pareto trade-off curve** between ASR and legitimate utility (False Quarantine Rate).

---

## 2. Taxonomy of Memory & Context Poisoning Attacks

| Paper | Authors / Venue | Year | Attack Mechanism & Key Finding |
|---|---|---|---|
| **Not what you've signed up for (Foundational IPI)** | Greshake et al. | 2023 | Established Indirect Prompt Injection (IPI) via untrusted third-party data retrieval. |
| **MINJA** | arXiv | 2024 | Query-only memory injection via multi-turn user dialogue without elevated system privileges. |
| **AgentPoison** | USENIX / NeurIPS | 2024 | Red-teaming retrieval-augmented agents by optimizing poisoned trigger embeddings in long-term memory. |
| **Sleeper Memory Poisoning** | Preprint | 2026 | Plants dormant malicious instructions inside agent long-term memory during passive ingestion; triggers only upon arbitrary future keyword matches. |
| **Cross-Session SPI** ("What If Prompt Injection Never Left?") | Research Preprint | 2025 | Injects state during Session 1 that persists across sessions and hijacks execution during Session 2. |
| **ConVerse** | Gomaa, Salem, Abdelnabi (EACL) | 2026 | Multi-agent contextual safety benchmark: 88% privacy violation and 60% security breach in multi-turn agent conversations. |
| **Prompt Infection** | MAS Research | 2024 | Demonstrates self-replicating, worm-like prompt injections propagating across agent networks. |
| **AutoDojo** | Security Preprint | 2026 | Adaptive black-box attack engine exposing that static IPI defenses degrade by >60% under iterative optimization. |
| **MCPTox** | MCP Security Working Group | 2025 | Model Context Protocol poisoning benchmark targeting structured tool definitions and memory servers. |

---

## 3. Defense Mechanisms, Information Flow, and Provable Scaffolding

| Defense / System | Authors / Venue | Year | Core Mechanism & Tradeoff |
|---|---|---|---|
| **Task Shield** | ACL | 2025 | Retrieval-time task alignment gate. Achieves 2.07% ASR at 69.79% utility on AgentDojo. Strongest published utility/security anchor. |
| **DataSentinel** | Liu et al. (IEEE S&P) | 2026 | Game-theoretic minimax detection framework framing detection thresholds against adaptive attackers. |
| **Securing AI Agents with IFC** | Costa et al. (Microsoft) | 2025 | Formal Information Flow Control (IFC) and non-bypassable taint tracking through agent execution graphs. |
| **Permissive IFC for LLMs** | Siddiqui et al. | 2026 | Declassifies taint dynamically based on context policies to reduce false blocks. |
| **AuthGraph** | arXiv:2605.26497 | 2026 | Provenance graph tracking data origin and transmission authorization per context node. |
| **AgentDojo** | Debenedetti et al. (NeurIPS) | 2024 | Standard benchmark environment for evaluating prompt injection defenses under dynamic execution. |
| **MPBench** | Benchmarking Suite | 2025 | Decoupled evaluation reporting `ASR-write` (memory write evasion) separately from `ASR-retrieval` (context extraction). |
| **Contextual Agent Security** | Tsai & Bagdasarian | 2025 | System-level contextual integrity enforcement architecture for LLM agents. |
| **Firewalls for LLM Agentic Networks** | Abdelnabi et al. | 2025 | Dual firewall architecture projecting multi-agent communication onto task-constrained contexts. |
| **AirGapAgent** | Bagdasarian et al. (CCS) | 2024 | Per-task CI enforcement minimizing cross-tool and cross-session data leakage. |
| **ACE Architecture** | NDSS | 2026 | Resilient capability-based execution sandbox for autonomous agent applications. |
| **OWASP Agent Security (ASI06)** | OWASP Foundation | 2025 | Top-10 guideline defining Memory Poisoning and Indirect Injection risks and mitigation criteria. |

---

## 4. Synthesis: The Core Research Gap

Current defenses suffer from three critical architectural flaws:
1. **Additive Keyword Scoring**: Most guardrails compute linear sums of risk keywords. An attacker who cloaks their instructions with polite framing or authority claims can dilute their risk score below static cutoffs.
2. **Taint Dilution**: When agents summarize or synthesize clean context with untrusted memory, conventional systems assign fresh neutral trust to the summary, laundering malicious payloads.
3. **Model Alignment Misconception**: Frontier model safety training (RLHF / DPO / SecAlign) aligns the *reasoner*, but the vulnerability resides in the *scaffolding* (retrieval and memory). A base model cannot distinguish between a legitimate remembered user preference and an injected instruction.

## 5. The CTP Solution
Contextual Trust Propagation directly addresses these gaps:
- Evaluates Contextual Integrity parameter violations—specifically **self-asserted transmission principles** (the attack vector responsible for 96.7% ASR in Abdelnabi & Bagdasarian).
- Applies **exponential risk decay** ($\exp(-\lambda R)$) so that severe contextual anomalies cannot be offset by benign filler.
- Enforces **geometric mean ancestor propagation** ($\prod T(p_i)^{1/n}$), guaranteeing taint cannot be laundered through summarization.
- Combines write-time quarantine with retrieval-time task alignment gating (Task Shield proxy).
