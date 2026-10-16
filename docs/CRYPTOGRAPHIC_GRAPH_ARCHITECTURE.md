# AgentPOI-SDE: Cryptographic Knowledge Graph & Cross-Stack Contract Architecture

**Document version:** 1.0.0
**Status:** implemented (Subsystems G/C/W/H ship in `agentpoi_sde`; verified by the unit suite
and the pre-flight gate).
**Domain:** Autonomous Software Engineering (`agentpoi_sde`)
**Theoretical anchors:** Merkle trees and hash chains, program slicing (Weiser 1984), contract-first
full-stack consensus (OpenAPI 3.1), epistemic state anchoring (AgentPOI DSEC).
**Companion specification:** [`SDE_ARCHITECTURE.md`](SDE_ARCHITECTURE.md) (the I1–I9 sink
governance gate this document extends).

---

## 1. Executive Summary & Problem Formulation

Modern autonomous coding agents exhibit four critical failure modes when building software systems:
1. **Epistemic Drift & History Amnesia:** Agents do not maintain an immutable, tamper-evident cryptographic record of *what* they built, *how* they built it, *why* they built it, and *which components* they connected. Context window truncation leads to repeated mistakes, architectural drift, and accidental regressions.
2. **Cross-Stack Disconnection (Frontend-Backend Drift):** Agents frequently hallucinate API endpoints, mismatch request/response schemas, scramble HTTP verbs, or miss query parameters when connecting frontend clients to backend routers.
3. **Destruction of Working Features (Regression Vulnerability):** In the process of adding new features or fixing bugs, agents inadvertently mutate or break existing, working parts of the codebase because they lack cryptographic boundaries separating working modules from active mutation zones.
4. **High Token Bloat & Small-Model Inefficiency:** Generating entire libraries, algorithms, or boilerplate from scratch requires massive context windows and giant frontier models. Small language models (SLMs) struggle with boilerplate hallucination and context dilution.

To solve these failure modes deterministically, **AgentPOI-SDE** introduces five core architectural subsystems:
- **Subsystem G (Merkle Knowledge Graph & ArchLedger):** An append-only, content-addressed cryptographic Directed Acyclic Graph ($\mathcal{G}_{merkle}$) that tracks all symbols, API endpoints, schema contracts, call relationships, and build provenance with SHA-256 Merkle root anchoring.
- **Subsystem C (Cross-Stack Contract & Schema Verifier):** AST-driven bidirectional contract validation between frontend client calls (e.g. `fetch`, `axios`, typed hooks) and backend routes (FastAPI, Flask, Express, Pydantic schemas) enforcing Invariant I8 (Schema Consensus).
- **Subsystem W (Working-Part Anchor & Non-Regression Gate):** Cryptographic immutability anchors for verified working modules and isolated sandbox test configurations enforcing Invariant I9 (Working Part Immutability).
- **Subsystem H (Safe Component Harvester & Program Slicer):** Deterministic AST-level program slicing that searches open-source repositories, extracts the minimal transitive dependency slice for a needed component, sanitizes it against injections/credentials, and anchors it into the project.
- **Subsystem S (Semantic Armor & Anti-Dilution Defense):** Taint-tracked context filtering ensuring untrusted external documentation, issue comments, or poisoned code comments cannot dilute or alter the agent's architectural memory or type schemas.

![AgentPOI-SDE Subsystems Architecture: Merkle Knowledge Graph, Cross-Stack Verifier, Working-Part Anchor, and Safe Harvester](architecture_diagram.png)

---

## 2. Mathematical & Cryptographic Formulation

### 2.1 The Merkle Architectural Knowledge Graph $\mathcal{G}_{merkle}$
We define the Merkle Knowledge Graph as a tuple:
$$\mathcal{G}_{merkle} = \langle \mathcal{V}, \mathcal{E}, \mathcal{H}, R_M \rangle$$
Where:
- $\mathcal{V} = \{v_1, v_2, \dots, v_n\}$ is the set of architectural nodes. Each node $v_i = \langle \text{id}, \text{type}, \text{payload}, h(v_i) \rangle$, where $\text{type} \in \{\text{FILE}, \text{SYMBOL}, \text{ENDPOINT}, \text{SCHEMA}, \text{DECISION}, \text{COMPONENT}, \text{BUILD}\}$.
- $\mathcal{E} \subseteq \mathcal{V} \times \mathcal{V} \times \mathcal{T}_{edge}$ is the set of directed, typed edges, where $\mathcal{T}_{edge} \in \{\text{CALLS}, \text{IMPLEMENTS}, \text{IMPORTS}, \text{CONNECTS\_TO}, \text{CONSTRAINS}, \text{EXTRACTED\_FROM}\}$.
- $\mathcal{H}: \mathcal{V} \cup \mathcal{E} \to \{0, 1\}^{256}$ is the cryptographic hashing function (SHA-256).
- $R_M = \text{MerkleRoot}(\mathcal{V}, \mathcal{E})$ is the root hash of the complete graph state.

For any node $v_i$:
$$h(v_i) = \text{SHA256}\Big(\text{id} \mathbin{\Vert} \text{type} \mathbin{\Vert} \text{CanonicalJSON}(\text{payload}) \mathbin{\Vert} \sum_{u \in \text{Parents}(v_i)} h(u) \Big)$$

Every agent state transition produces a new ledger block $B_k = \langle k, B_{k-1}.hash, R_{M, k}, \Delta_k, \text{timestamp}, \text{signature} \rangle$. Any historical tampering breaks the hash chain:
$$B_k.hash = \text{SHA256}(B_k.k \mathbin{\Vert} B_{k-1}.hash \mathbin{\Vert} B_k.R_M \mathbin{\Vert} \text{CanonicalJSON}(B_k.\Delta))$$

### 2.2 Cross-Stack Schema Invariant (Invariant I8)
Let $\mathcal{F}_{calls} = \{f_1, f_2, \dots, f_m\}$ be the set of frontend API invocations extracted via AST analysis:
$$f_j = \langle \text{method}, \text{path\_template}, \text{query\_params}, \text{body\_schema}, \text{response\_schema} \rangle$$
Let $\mathcal{B}_{routes} = \{b_1, b_2, \dots, b_p\}$ be the set of backend router endpoints extracted via AST analysis:
$$b_k = \langle \text{method}, \text{path\_template}, \text{query\_params}, \text{body\_schema}, \text{response\_schema} \rangle$$

The Cross-Stack Invariant predicate is satisfied if and only if:
$$\forall f_j \in \mathcal{F}_{calls}, \exists b_k \in \mathcal{B}_{routes} \text{ such that:}$$
$$\begin{cases}
f_j.\text{method} = b_k.\text{method} \\
\text{NormalizePath}(f_j.\text{path}) = \text{NormalizePath}(b_k.\text{path}) \\
f_j.\text{query\_params} \subseteq b_k.\text{query\_params} \\
\text{SchemaCompatible}(f_j.\text{body\_schema}, b_k.\text{body\_schema}) = \text{True}
\end{cases}$$
If any $f_j$ fails this predicate, the mutation is rejected with invariant code `I8` and one of
the violation codes the verifier actually emits:

| Condition | Violation code |
|---|---|
| No backend route matches the normalised path | `I8:ENDPOINT_NOT_FOUND` |
| Path matches but the HTTP verb does not | `I8:METHOD_MISMATCH` |
| Required request fields are absent from the call payload | `I8:MISSING_REQUIRED_FIELD` |

### 2.3 Working-Part Immutability Invariant (Invariant I9)
Let $\mathcal{W}_{working} \subset \mathcal{V}_{files}$ be the set of verified working files and regression tests anchored in $\mathcal{R}_0$.
Let $\mathcal{C}_{scope} = \langle \text{allowed\_paths}, \text{allowed\_symbols}, \text{token\_id} \rangle$ be the agent's capability scope for the active task.
Let $\Delta = \text{MutationDelta}(P)$.

Invariant I9 holds if and only if:
$$\forall \text{file } f \in \text{ModifiedFiles}(\Delta): f \in \mathcal{C}_{scope}.\text{allowed\_paths} \quad \land \quad f \notin \mathcal{W}_{working} \setminus \mathcal{C}_{scope}.\text{allowed\_paths}$$
**What is enforced automatically, and what is not.** The path/scope half of I9 above is enforced on
every mutation: a registered working file is refused unless the active capability scope grants it
(`I9` in `RepoInvariantVerifier.check_working_parts`). The evidence half — running the registered
regression suites in an isolated configuration and rejecting on a non-zero exit status — is an
explicit call (`DevGuard.run_sandbox_tests`), which returns a `SandboxExecutionResult`. It is not
wired into the automatic sink, and this specification deliberately does not claim that it is.

### 2.4 Minimal Program Slicing $\text{Slice}(C, s)$
Given an open-source component or module $C$ and target symbol $s$:
$$\text{Slice}(C, s) = \text{TransitiveDependencies}(s) \cap \text{AST}(C)$$
All extraneous declarations, demo drivers, unit test harnesses, and credential variables are pruned. The slice is verified through a sandbox compilation gate before being introduced into the project repository.

---

## 3. Implementation Phases & Architecture

### Phase P6: Cryptographic Knowledge Graph & Merkle Ledger
- `agentpoi_sde/graph/merkle_graph.py`: Append-only Merkle DAG data structures, node/edge hashing, root computation, proof verification.
- `agentpoi_sde/graph/arch_ledger.py`: Block-chained architectural ledger tracking what was built, how it was built, why, and connections.
- `agentpoi_sde/graph/graph_indexer.py`: AST-driven repo scanner extracting functions, classes, imports, and API routes into graph nodes/edges.

### Phase P7: Cross-Stack Interface & Schema Consensus Verifier
- `agentpoi_sde/schema/contract_model.py`: Universal endpoint and schema contract representations (methods, paths, query, body, responses).
- `agentpoi_sde/schema/frontend_extractor.py`: AST parser for frontend fetch/axios/client requests (detecting URL patterns, verbs, body payloads).
- `agentpoi_sde/schema/backend_extractor.py`: AST parser for backend route definitions (FastAPI `@app.get/post`, Flask routes, Express routers).
- `agentpoi_sde/schema/cross_stack_verifier.py`: Verification sink computing schema delta and enforcing Invariant I8.

### Phase P8: Working-Part Anchor & Isolated Configuration Sandbox
- `agentpoi_sde/anchor/working_part_anchor.py`: Cryptographic boundary registry tracking verified working parts and regression suites.
- `agentpoi_sde/sandbox/isolated_sandbox.py`: Isolated worktree/scratch test runner executing end-to-end tests in clean configuration.
- `agentpoi_sde/verify/invariant_verifier.py`: Extending verifier with Invariants I8 and I9.

### Phase P9: Open-Source Component Harvester & Program Slicer
- `agentpoi_sde/harvester/component_harvester.py`: Query OSS components, retrieve source code, locate matching functions/classes.
- `agentpoi_sde/harvester/program_slicer.py`: AST backward and forward dependency slicing extracting minimal self-contained units.
- `agentpoi_sde/harvester/slicer_security.py`: Sanitizing harvested slices (credential scanning, shell command / dynamic import / backdoor checks).

### Phase P10: Public Facade, CLI Integration, E2E Acceptance & Verification
- `agentpoi_sde/facade.py`: Expose unified methods on `DevGuard`.
- `agentpoi_sde/cli.py`: Console commands for graph verification, cross-stack audit, component harvesting, and isolated sandbox tests.
- Unit, integration and opaque-box end-to-end test suites, plus the documentation-sync gate that
  fails the build if a published metric drifts from live execution (`scripts/render_sde_metrics.py --check`).
- Documentation updates and Project Ledger recording.

### Delivery status

All of P6–P10 are implemented; the module list above is the shipped layout, and the phase headings
are retained here as the design record rather than as a to-do list.
