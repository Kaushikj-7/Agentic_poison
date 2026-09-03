# System Architecture: CTP Agent Poisoning Defense

## Overview

The **Contextual Trust Propagation (CTP)** framework defends autonomous LLM agents against context and memory poisoning across the entire lifecycle: from write-time ingestion to retrieval-time conditioning and tool execution.

```
+--------------------------------------------------------------------------------+
|                             USER / EXTERNAL WORLD                              |
+--------------------------------------------------------------------------------+
                                       │
                   [Write Action]      │      [User Query / Task]
                                       ▼
       +───────────────────────────────────────────────────────────+
       |                  LAYER 1: WRITE-TIME FIREWALL             |
       |                                                           |
       |   1. CI Parameter Decomposer (5-Tuple Context Analysis)   |
       |   2. Self-Asserted Authorization & Directive Detector     |
       |   3. Provenance DAG & Multiplicative CTP Trust Scorer     |
       +───────────────────────────────────────────────────────────+
                                       │
                      T(c) >= tau ?    ├───────── [ T(c) < tau ] ──► QUARANTINE VAULT
                                       ▼                             (Isolated & Logged)
       +───────────────────────────────────────────────────────────+
       |               LAYER 2: SECURE MEMORY REPOSITORY           |
       |                                                           |
       |   • ChromaDB / In-Memory Scikit Vector Store              |
       |   • Complete Provenance Metadata & Lineage Graph          |
       +───────────────────────────────────────────────────────────+
                                       │
                        k-NN Candidate Retrieval
                                       ▼
       +───────────────────────────────────────────────────────────+
       |               LAYER 3: RETRIEVAL-TIME ALIGNMENT GATE      |
       |                                                           |
       |   • Task Shield Semantic Alignment Proxy                  |
       |   • Task-Memory Divergence Penalty                        |
       |   • Sanitized Context Window Assembly                     |
       +───────────────────────────────────────────────────────────+
                                       │
                             Sanitized Context
                                       ▼
       +───────────────────────────────────────────────────────────+
       |               LAYER 4: AGENT SCAFFOLDING & TOOLS          |
       |                                                           |
       |   • Agent Policy Loop (LangGraph / Stateful Runner)       |
       |   • Pluggable LLM: Deterministic Mock or Local Ollama     |
       |   • Sensitive Mock Tools with Audit Trapping              |
       |     (send_email, delete_record, transfer_funds)           |
       +───────────────────────────────────────────────────────────+
                                       │
                                       ▼
                          [Execution Audit & Metrics]
```

---

## 4-Layer Defense Scaffolding

### Layer 1: Write-Time Memory Firewall
Every context item (user memory, agent note, tool observation, or web-scraped document) is intercepted before insertion into the long-term memory store.
- **CI Decomposer**: Analyzes the contextual integrity 5-tuple $\langle s, r, u, t, p \rangle$. Specifically extracts whether the item asserts an authorization principle.
- **Taint Tracker**: Traverses the provenance graph to determine ancestor trust.
- **Decision Engine**:
  - $T(c) \ge \tau$: Stored in active memory.
  - $\tau_{\text{crit}} \le T(c) < \tau$: Quarantined in isolated partition for audit.
  - $T(c) < \tau_{\text{crit}}$: Blocked and dropped.

### Layer 2: Secure Vector Storage
Stores active memories with embedded trust scores and parent references. Supports:
- **ChromaDB**: For production local persistence.
- **Fallback In-Memory Vector Store**: Zero-dependency TF-IDF / Cosine Similarity vector store for instant, self-contained evaluation on any machine.

### Layer 3: Retrieval-Time Task Alignment Gate
Prevents dormant/sleeper memory payloads from hijacking execution even if they somehow bypassed write-time filters:
- Computes cosine similarity between active task $q$ and candidate memory $c$.
- Detects divergence where memory attempts to redirect the agent to invoke high-impact actions unprompted by the user.

### Layer 4: Safe Execution Runtime & Mock Tools
Executes agent reasoning and tool actions.
- **Mock Tools**:
  - `send_email(to, subject, body)`
  - `delete_record(table, id)`
  - `transfer_funds(to_account, amount)`
  Every invocation is logged with parameters and authorization status for rigorous, automated ASR-exec verification without safety hazards.
- **Dual Execution Engine**:
  - `MockLLMProvider`: Deterministic, zero-cost, runs on any laptop CPU in milliseconds.
  - `OllamaProvider`: Connects to local `llama3.2:3b` or `qwen2.5:3b` for human-in-the-loop chat demos.
