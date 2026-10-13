# Research Novelty & Literature Gap Analysis: AgentPOI-SDE

**Project:** AgentPOI-SDE — Fail-Closed Software Engineering Agent Platform
**Branch:** `codebleak`
**Phase:** Phase 0 Gate Deliverable
**Date:** 2026-10-13
**Status:** Gate Passed — literature verified against live arXiv/ACL/CSA sources

---

## 1. Executive Summary

This document establishes the formal research novelty gap for **AgentPOI-SDE**, the
software-engineering application of the AgentPOI defence platform. A structured literature
and industry-advisory search was conducted across arXiv, ACL Anthology, the Cloud Security
Alliance AI Safety Labs, and vendor security advisories (NVIDIA, Palo Alto Unit 42,
Invariant Labs, Snyk) targeting four axes:

1. Indirect prompt injection against **agentic coding assistants**;
2. **Supply-chain** compromise of agent context/skill/rules files;
3. **Least-privilege / sandboxing / information-flow control** for tool-using agents;
4. **Deterministic verification** of machine-generated code and architecture.

Every citation below corresponds to an artefact observed in live search results during this
Phase 0 sweep. No synthetic or hallucinated references are included.

**Headline finding.** The threat is not hypothetical: the 2025–2026 record contains 24 CVEs
across 10 AI development environments (IDEsaster), quantitative ASR up to 83.4% on a
production coding assistant (AIShellJack), and the first marketplace-scale malicious
skill/context-file campaigns (ClawHavoc, ToxicSkills). Yet **every published defence is either
permissive-by-construction (sandboxing, least privilege) or probabilistic (classifiers,
LLM judges)**. No prior work enforces a **deterministic, provenance-gated invariant check on
the code-mutation sink itself**, and no prior work treats *repository ground truth* as an
immutable epistemic anchor that untrusted context can never mutate.

---

## 2. Structured Literature Survey & Closest Prior Work

### 2.1 Attack surface — agentic coding assistants

| Citation / Source | Scope & Methodology | Key Findings | What Remains Unaddressed (The Gap) |
|---|---|---|---|
| **Prompt Injection Attacks on Agentic Coding Assistants**<br>*arXiv:2601.17548 (Jan 2026)* | Systematic taxonomy of injection vectors specific to coding agents (Claude Code, Copilot, Cursor, skill-based architectures). | Formalises lifecycle phases P1 (entry) → P2 (**persistence**), including **Rules File Backdoor**: modifying agent configuration to persist across sessions and forks. | Taxonomy and red-teaming only. Proposes no deterministic enforcement of a write/merge sink; persistence is described, not structurally prevented. |
| **IDEsaster** (Ari Marzouk, Dec 2025)<br>CSA research note 2026-04-03 | 30+ vulnerabilities, 24 CVEs, 10 AI-integrated dev environments. | 100% of tested tools exploitable. `CVE-2025-53773` (Copilot auto-approve → RCE, CVSS 7.8), `CVE-2025-54130` (Cursor settings overwrite → RCE), `CVE-2025-61260` (Codex CLI command injection), `CVE-2025-54794/54795` (Claude Code path bypass, command injection). | Each CVE is patched individually. No architectural invariant that makes the *class* impossible — the payload is a file the agent reads, and the sink is a config/tool write. |
| **AIShellJack**<br>*arXiv:2509.22040* | 314 payloads mapped to 70 MITRE ATT&CK techniques against production coding tools. | Cursor Auto Mode **83.4%** ASR; Cursor+Claude-4 69.1%; Copilot+Claude-4 52.2%. **Published defences bypassed >85%** under adaptive attack. | Confirms probabilistic defences fail under adaptive attackers; does not propose a non-probabilistic sink gate. |
| **RoguePilot** (Orca Security, Feb 2026) | GitHub Issue → Codespace → token exfiltration, zero special privileges. | Injection in hidden HTML comments of an Issue is ingested as context; agent exfiltrates `GITHUB_TOKEN`; repository takeover. | Demonstrates that *issue text* is a trusted instruction channel. No provenance separation of authenticated intent vs. ingested content. |
| **Rules File Backdoor** (Pillar Security, Mar 2025) | `.cursorrules` / `.github/copilot-instructions.md` carrying invisible Unicode (zero-width joiners, bidi markers). | Injected instructions invisible to human review, fully legible to models; can suppress the agent's own activity logs; **survive forking**. | GitHub added a warning banner. The structural problem — config files are treated as trusted instruction sources — persists. |
| **ClawHavoc / ToxicSkills** (Koi Security, Snyk, CrowdStrike, Antiy CERT; 2026) | Registry-scale malicious agent skills (`SKILL.md`, `CLAUDE.md`, `AGENTS.md`, memory files). | 341 → ≥824 confirmed malicious skills; AMOS infostealer + reverse shells; agents execute these files with full terminal/filesystem privilege. | No integrity/provenance gate on context files; trust is granted by *location*, not by cryptographic lineage. |

### 2.2 Defences — sandboxing, least privilege, information-flow control

| Citation / Source | Scope & Methodology | Strengths | What Remains Unaddressed (The Gap) |
|---|---|---|---|
| **Isolation, Access Control, and TOCTOU in AI Coding Agents**<br>*arXiv:2607.05743 (Jul 2026)* | Analyses isolation/access-control/TOCTOU flaws in coding agents that read repos and run shell commands. | Identifies the exact failure mode our sink closes: the *check* and the *use* are separated by an untrusted window. | Diagnoses; does not provide a formal invariant set or an executable fail-closed sink. |
| **Do Coding Agents Understand Least-Privilege?**<br>*arXiv:2605.14859 (May 2026)* | Evaluates whether agents can self-restrict to least-privilege tool/path grants. | Shows agents *can* be prompted toward least privilege, but compliance is unreliable. | Relies on model compliance — probabilistic. Our **capability scope token** is enforced deterministically outside the model. |
| **Toward Securing AI Agents Like Operating Systems**<br>*arXiv:2605.14932 (May 2026)* | OS-analogy security model for agents (isolation, mediation, privilege). | Provides the conceptual frame: agents need a kernel-like mediation layer. | Conceptual/positional; no concrete invariant engine for *code mutations* or repository anchors. |
| **Fides**<br>*arXiv:2505.23643 (Microsoft Research)* | Non-bypassable Information-Flow Control via dynamic taint lattices + HIDE primitives; proves non-interference. | Formally strong; the gold standard for IFC. | High integration cost; taint-only — **no domain semantic invariants** (does not know what a layer violation, a weakened test, or a leaked secret *is*). |
| **ShieldMCP**<br>*ACL 2026 Industry Track* | Runtime threat taxonomy + mediation for the MCP tool layer. | Reduces tool-poisoning ASR 74% → <9%, indirect injection 47% → <6%. | Scoped to the MCP transport layer; not to code-artefact invariants or repository ground truth. |
| **MCP-ITP**<br>*arXiv:2603.22489 (Mar 2026)* | Automated **implicit tool poisoning** generation via tool metadata. | Shows metadata (not just output) is an injection channel. | Attack framework; no sink-side invariant defence. |
| **Abdelnabi & Bagdasarian**<br>*arXiv:2605.17634* | Proves impossibility of robust instruction/data separation by natural-language prompt filtering. | The theoretical licence for non-linguistic enforcement. | Proves the negative; provides no constructive sink architecture. |

### 2.3 Grounding — verification, architecture integrity, repo context

| Citation / Source | Relevance to AgentPOI-SDE |
|---|---|
| **From Code to Contract** (*arXiv:2602.00180*, Jan 2026) | Spec-driven development: specification as source of truth. Our **Intent Anchor ℐ** is a machine-checkable form of this. |
| **Property-Generated Solver** (*arXiv:2506.18315*) | Property-based testing to validate LLM output; motivates our **test-integrity invariant** (tests are an oracle, so they must be tamper-evident). |
| **SWE-bench Verified / SWE-EVO** (*arXiv:2512.18470*) | The de-facto utility benchmarks. SWE-EVO shows ~3× collapse on long-horizon evolution tasks — motivating blast-radius and architecture invariants. |
| **Prometheus** (*arXiv:2507.19942*) and **Codebase-Memory** (*arXiv:2603.27277*) | Memory-centric / Tree-Sitter knowledge-graph navigation. Our **Repository Anchor ℛ₀** is a *content-addressed, deterministic* symbol/import snapshot in this lineage, but used for enforcement rather than retrieval. |
| **AgentDojo** (*arXiv:2406.13352*) / **InjecAgent** (*arXiv:2403.02691*) / **MINJA** (*arXiv:2503.03704*) | Agentic injection + memory-poisoning benchmarks; the parents of our **SDE scenario suite** and cross-session persistence track. |
| **ArchUnit / dependency-cruiser / archprint** (industry) | Enforce architecture by test. We lift architecture rules out of the test suite and into the **fail-closed sink**, so a violation cannot be merged. |

---

## 3. Contribution Verification & Go / No-Go Decisions

### C1 — Repository State Anchor (ℛ₀) as an immutable epistemic anchor — **GO (Novel)**
A content-addressed snapshot of *committed ground truth*: git tree OID, AST symbol table,
import/dependency graph, lockfile digests, protected-path manifest, declared architecture
policy. Untrusted context (repo files, tool output, web docs, dependency READMEs, MCP
responses) can never mutate ℛ₀. Overlap: ArchUnit/dependency-cruiser enforce architecture
inside tests; Codebase-Memory builds a graph for *retrieval*. **Neither uses repository ground
truth as an anchor against which agent mutations are authoritatively judged.**

### C2 — Mutation Delta Algebra Δ(edit) + Three-Way Engineering Match — **GO (Novel)**
Every agent action normalises to a typed tuple ⟨path, symbol, op, patch_hash, imports_added,
writes, secrets, capability, provenance⟩. Authorisation requires the **three-way match**
`Intent ℐ ↔ Anchor ℛ₀ ↔ Mutation Δ` — the engineering analogue of the 3-way PO match.
Overlap: diff/patch tooling and linters exist, but no prior work formalises a mutation *algebra*
whose terms must be jointly satisfied by an authenticated intent and an immutable anchor.

### C3 — Fail-Closed Mutation Sink with structural invariants — **GO (Novel)**
The sink applies a mutation **iff** all invariants hold, each of which maps to a *documented,
currently-unmitigated* attack class:
- **Policy-File Integrity** → Rules File Backdoor / ClawHavoc context poisoning.
- **Test-Integrity Non-Weakening** → agent "fixing" a failing test by deleting it (unaddressed in every defence above).
- **Secret Non-Proliferation & Egress Confinement** → GitGuardian 3.2% AI-commit leak rate.
- **Architectural Layering / No-New-Cycles** → architectural drift under long-horizon agents (SWE-EVO).
- **Blast-Radius / Blast-Radius Minimality** → RoguePilot-style covert scope expansion.
- **Dependency Provenance** → supply-chain injection via new imports.
- **Provenance Ancestry (𝒫)** → Fides-style IFC, but domain-aware and cheap.
- **Capability Scope** → deterministic least-privilege that does not depend on model compliance.
- **Non-Replay Idempotency** → repeated/duplicated edits and TOCTOU re-application.
Overlap: each component exists in isolation (ShieldMCP, Fides, ArchUnit, capability systems).
**No single architecture composes them into one deterministic, fail-closed gate on code mutation**,
and none anchors them to repository ground truth.

### C4 — Poisoned-Repository Benchmark with a state-diff oracle — **GO (Novel)**
A deterministic, simulatable repo sandbox whose success criterion is the **resulting repository
state diff**, computed independently of the defence (no defence-shaped oracle). Includes a
cross-session persistence track and an adaptive attacker. Metrics computed dynamically:
EMAR (execution mutation attack rate ↓), LTSR (legitimate task success ↑), CDR (clean
disruption ↓), AVR (architecture violation rate ↓), SLR (secret-leak rate ↓).
Overlap: AgentDojo/InjecAgent are generic-tool; SWE-bench is utility-only and adversarial-free;
SWE-EVO is utility-only. **No state-based, provenance-aware adversarial coding-agent benchmark exists.**

### C5 — System-Design Plane (ADR synthesis + design invariants) — **GO (Novel, scoped)**
A design planner emits module graphs and Architecture Decision Records that become *executable*
invariants in ℛ₀, so a later code mutation that contradicts a design decision is rejected at the
sink. Overlap: spec-driven development (arXiv:2602.00180) treats specs as source of truth but
does not enforce them at a sink.

---

## 4. Phase 0 Gate Conclusion

All five contributions are confirmed novel against the verified state of the art. The literature
establishes (a) that the attack class is real and severe, (b) that existing defences are
probabilistic or permissive-by-construction, and (c) that no prior work provides a deterministic,
provenance-gated, repository-anchored invariant check on the code-mutation sink.

**Phase 0 Gate Status: PASSED.** Proceeding to Phase 1 implementation on branch `codebleak`.

---

## 5. Verification Method for This Gate

- Every arXiv identifier above was returned by a live search during this sweep.
- CVE identifiers and the IDEsaster campaign are drawn from the Cloud Security Alliance research
  note *"AI Coding Assistants as Attack Surface: Code, Skills, and Secrets"* (2026-04-03), which
  enumerates the CVE table reproduced in §2.1.
- ClawHavoc / ToxicSkills figures are drawn from Koi Security, Snyk, CrowdStrike and Antiy CERT
  reporting as summarised in the same CSA note.
- Third-party quantitative claims (e.g. AIShellJack ASR, ShieldMCP reductions) are **cited, not
  reproduced**; AgentPOI-SDE reports only metrics it computes itself, dynamically, per
  `AGENTS.md` Rule 4.
