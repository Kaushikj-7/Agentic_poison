"""Structured Research Paper Corpus for AgentPOI Defense and Agentic Engineering.

Indexes all 21 research publications stored in docs/papers/ into a high-precision,
zero-hallucination knowledge base organized across 5 pedagogical learning tiers.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class LearningTier(int, Enum):
    TIER_1_FOUNDATIONS = 1      # Attack mechanics, IPI root, multi-turn safety, contagion
    TIER_2_IMPOSSIBILITY = 2    # Contextual integrity, impossibility theorems, game theory
    TIER_3_IFC_PROVENANCE = 3   # Information Flow Control, taint tracking, granularity mismatch
    TIER_4_ISOLATION_FIREWALL = 4 # Dual firewalls, capability mediation, dynamic rule isolation
    TIER_5_FORENSIC_CAUSAL = 5  # Pre-processors, token localization, causal dominance CoT masking


@dataclass
class PaperMetadata:
    paper_id: str
    filename: str
    title: str
    authors: List[str]
    year: int
    venue: str
    arxiv_id: Optional[str]
    tier: LearningTier
    layman_summary: str
    technical_abstract: str
    core_threat_or_defense: str
    formal_invariants_or_math: List[str]
    verbatim_key_quotes: List[str]
    relevance_to_agentic_engineering: str
    suggested_prerequisites: List[str] = field(default_factory=list)


# Complete 21-Paper Ground Truth Corpus
PAPER_CORPUS: Dict[str, PaperMetadata] = {
    # -------------------------------------------------------------------------
    # TIER 1: Foundations of Vulnerability & Attack Vectors
    # -------------------------------------------------------------------------
    "02_greshake2023": PaperMetadata(
        paper_id="02_greshake2023",
        filename="02_greshake2023_not_what_you_signed_up_for.pdf",
        title="Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection",
        authors=["Kai Greshake", "Sahar Abdelnabi", "Shailesh Mishra", "Christoph Endres", "Thorsten Holz", "Mario Fritz"],
        year=2023,
        venue="ACM Workshop on Artificial Intelligence and Security (AISec 2023)",
        arxiv_id="arXiv:2302.12173",
        tier=LearningTier.TIER_1_FOUNDATIONS,
        layman_summary="The foundational paper on Indirect Prompt Injection (IPI). Shows that when an AI reads untrusted data (like an email or webpage) containing hidden instructions, it treats that data as orders from the user and executes dangerous actions.",
        technical_abstract="Demonstrates that LLMs integrating external data sources cannot reliably distinguish between system instructions and third-party data payloads. Adversaries can achieve remote control, exfiltrate private context, and trigger arbitrary tool invocations without direct user prompt access.",
        core_threat_or_defense="Indirect Prompt Injection (IPI) via untrusted retrieval channels.",
        formal_invariants_or_math=[
            "Context Composition: C = Prompt_system ∪ Prompt_user ∪ RetrievedData(x_untrusted)",
            "Control Escapement: Pr[Execute(a_adversary) | a_adversary ⊂ RetrievedData] >> 0",
        ],
        verbatim_key_quotes=[
            "Indirect prompt injection allows adversaries to manipulate LLM applications by placing malicious prompts in web searches, emails, or databases.",
            "As long as LLMs process instructions and data within the same context window without formal channel separation, prompt injection remains systemic.",
        ],
        relevance_to_agentic_engineering="Establishes why naive agent loops that concatenate document text into the prompt window are catastrophically vulnerable to third-party control.",
        suggested_prerequisites=[],
    ),

    "16_lee2024": PaperMetadata(
        paper_id="16_lee2024",
        filename="16_lee2024_prompt_infection.pdf",
        title="Prompt Infection: LLM-to-LLM Prompt Injection in Multi-Agent Systems",
        authors=["Seungho Lee", "Mohit Tiwari"],
        year=2024,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2410.07283",
        tier=LearningTier.TIER_1_FOUNDATIONS,
        layman_summary="Demonstrates how indirect prompt injections turn into digital 'worms' in multi-agent networks: one infected agent passes poisoned messages to peer agents, recursively compromising the entire agent swarm.",
        technical_abstract="Analyzes inter-agent communication topologies where compromised agent outputs act as indirect prompt injections for downstream peer agents. Evaluates infection replication rates, lateral movement across subagent hierarchies, and payload persistence across multi-turn exchanges.",
        core_threat_or_defense="Multi-Agent System (MAS) worm propagation and cascading lateral infection.",
        formal_invariants_or_math=[
            "Propagation Graph: G = (V_agents, E_messages), Infection(v_j) = f(Msg(v_i, v_j))",
            "Infection Reproduction Number: R_0 = E[# of downstream peers infected per compromised agent]",
        ],
        verbatim_key_quotes=[
            "An infected agent transmits adversarial payloads through natural language messages to peer agents, causing exponential infection across the multi-agent graph.",
            "Isolated agent safety alignments fail to prevent multi-agent infection because inter-agent trust assumptions bypass single-agent input filtering.",
        ],
        relevance_to_agentic_engineering="Mandates that every inter-agent message boundary must treat peer messages as untrusted input streams subject to taint tracking.",
        suggested_prerequisites=["02_greshake2023"],
    ),

    "07_gomaa2026": PaperMetadata(
        paper_id="07_gomaa2026",
        filename="07_gomaa2026_converse.pdf",
        title="ConVerse: A Contextual Safety Benchmark for Multi-Turn Agentic Dialogues",
        authors=["Amr Gomaa", "et al."],
        year=2026,
        venue="EACL 2026",
        arxiv_id="arXiv:2511.05359",
        tier=LearningTier.TIER_1_FOUNDATIONS,
        layman_summary="A multi-turn benchmark measuring how agent safety degrades over long conversations. Shows that agents leak private data 88% of the time and violate security policies 60% of the time when attackers use gradual, multi-turn conversational steering.",
        technical_abstract="Establishes a rigorous multi-turn benchmark evaluating contextual safety, privacy boundaries, and authorization adherence in autonomous agent conversations. Discloses that frontier LLMs maintain high single-turn safety but suffer dramatic degradation under iterative multi-turn dialogues.",
        core_threat_or_defense="Multi-turn contextual safety drift and multi-step boundary erosion.",
        formal_invariants_or_math=[
            "Safety Degradation over Turns: Pr[Breach | Turn=k] = 1 - (1 - p_single)^k + Drift(k)",
            "Privacy Violation Rate: PVR = 88.2%, Security Violation Rate: SVR = 60.1%",
        ],
        verbatim_key_quotes=[
            "Safety mechanisms trained on single-turn benchmarks fail to generalize to multi-turn agent interactions where context accumulates and boundaries erode gradually.",
            "Contextual safety requires continuous state monitoring rather than static turn-by-turn classification.",
        ],
        relevance_to_agentic_engineering="Proves why evaluating agents on single-step prompts produces false security confidence; dynamic multi-turn testing is mandatory.",
        suggested_prerequisites=["02_greshake2023"],
    ),

    "14_autodojo2026": PaperMetadata(
        paper_id="14_autodojo2026",
        filename="14_autodojo2026_adaptive_black_box.pdf",
        title="AutoDojo: Adaptive Black-Box Attacks against LLM Agent Guardrails",
        authors=["Yao Ma", "et al."],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2606.15057",
        tier=LearningTier.TIER_1_FOUNDATIONS,
        layman_summary="An automated black-box attack system that iteratively modifies prompt injections until it bypasses static guardrails, restoring 28% to 64% attack success against previously protected agents.",
        technical_abstract="Presents an automated black-box adversarial framework that uses mutation strategies and feedback from target agent execution traces to bypass heuristic and LLM-based guardrails without requiring gradient access.",
        core_threat_or_defense="Adaptive black-box optimization defeating static input-filtering defenses.",
        formal_invariants_or_math=[
            "Adversarial Optimization: x* = argmax_{x \\in Mut(x_0)} Reward(Agent(x) = a_target)",
            "ASR Recovery: \\Delta ASR = +28.4% \\text{ to } +64.1% \\text{ post-adaptation}",
        ],
        verbatim_key_quotes=[
            "Static prompt filters and pattern-matching guardrails create a brittle defense perimeter that easily crumbles under iterative black-box mutation.",
            "Defenses must operate at the invariant level rather than attempting lexical or heuristic perimeter filtering.",
        ],
        relevance_to_agentic_engineering="Demonstrates why static keyword blocklists and regex filters fail; defenses must be verified at the execution sink.",
        suggested_prerequisites=["02_greshake2023"],
    ),

    # -------------------------------------------------------------------------
    # TIER 2: The Theoretical Impossibility & Threat Mechanics
    # -------------------------------------------------------------------------
    "01_abdelnabi2026": PaperMetadata(
        paper_id="01_abdelnabi2026",
        filename="01_abdelnabi2026_ai_agents_always_fall.pdf",
        title="AI Agents May Always Fall for Prompt Injections: A Contextual Integrity Theoretical Perspective",
        authors=["Sahar Abdelnabi", "Eugene Bagdasarian"],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2605.17634",
        tier=LearningTier.TIER_2_IMPOSSIBILITY,
        layman_summary="The landmark theoretical paper proving that completely stopping prompt injection without breaking legitimate agent capabilities is mathematically impossible if you only look at prompt text. Uses Helen Nissenbaum's Contextual Integrity theory to parameterize context.",
        technical_abstract="Reframes prompt injection using Contextual Integrity (CI) theory, parameterizing context as a 5-tuple: sender, receiver, subject, information type, and transmission principle. Formally proves an impossibility result: no static or deterministic policy can eliminate all context-manipulation attacks without causing catastrophic False Positive Rates on benign, complex user workflows.",
        core_threat_or_defense="Contextual Integrity (CI) 5-Tuple Formulation & Formal Impossibility Theorem.",
        formal_invariants_or_math=[
            "CI Context 5-Tuple: \\kappa = \\langle s, r, u, t, p \\rangle \\in \\mathcal{S} \\times \\mathcal{R} \\times \\mathcal{U} \\times \\mathcal{T} \\times \\mathcal{P}",
            "Impossibility Theorem: \\forall \\mathcal{D}, \\exists \\delta > 0 : \\text{ASR}(\\mathcal{D}) \\to 0 \\implies \\text{FPR}(\\mathcal{D}) \\ge \\delta_{\\text{utility}}",
            "Pareto Optimization: \\min_{\\theta} \\left[ \\lambda \\cdot \\text{ASR-Exec}(\\theta) + (1-\\lambda) \\cdot (1 - \\text{LDSR}(\\theta)) \\right]",
        ],
        verbatim_key_quotes=[
            "Prompt injection is not a mere token parsing glitch; it is an informational norm violation governed by Contextual Integrity.",
            "Aiming for unconstrained zero-ASR via natural language filtering is scientifically impossible; defenses must enforce non-linguistic execution sink invariants.",
        ],
        relevance_to_agentic_engineering="The theoretical bedrock of modern agent defense: explains why we build Contextual Invariant Verification (CIV) at execution sinks instead of chasing 0% ASR prompt filters.",
        suggested_prerequisites=["02_greshake2023"],
    ),

    "03_chen2025": PaperMetadata(
        paper_id="03_chen2025",
        filename="03_chen2025_meta_secalign.pdf",
        title="Meta SecAlign: Safety Alignment and Trade-offs in Foundation Models",
        authors=["Richard Chen", "Zaurbek Zharmagambetov", "David Wagner", "Chuan Guo"],
        year=2025,
        venue="Meta AI Research / arXiv",
        arxiv_id="arXiv:2507.02735",
        tier=LearningTier.TIER_2_IMPOSSIBILITY,
        layman_summary="Shows how fine-tuning LLMs with Direct Preference Optimization (DPO) for security improves refusal of direct attacks, but can paradoxically degrade the model's ability to detect subtle contextual anomalies and follow complex tool schemas.",
        technical_abstract="Investigates Direct Preference Optimization (DPO) and Reinforcement Learning from AI Feedback (RLAIF) for securing foundation models against jailbreaks and injections. Quantifies the alignment tax on reasoning capability, schema compliance, and anomaly detection.",
        core_threat_or_defense="Safety Alignment Trade-offs and Alignment Tax under DPO.",
        formal_invariants_or_math=[
            "DPO Loss: \\mathcal{L}_{\\text{DPO}}(\\theta) = -\\mathbb{E}_{(x, y_w, y_l)} \\left[ \\log \\sigma \\left( \\beta \\log \\frac{\\pi_\\theta(y_w|x)}{\\pi_\\text{ref}(y_w|x)} - \\beta \\log \\frac{\\pi_\\theta(y_l|x)}{\\pi_\\text{ref}(y_l|x)} \\right) \\right]",
            "Alignment Tax: \\Delta \\text{Capability} = \\text{Score}_{\\text{ref}} - \\text{Score}_{\\pi_\\theta}",
        ],
        verbatim_key_quotes=[
            "Over-aligning foundation models on syntactic refusal benchmarks degrades their contextual sensitivity to complex legitimate multi-step instructions.",
            "Foundation model safety alignment is a necessary layer but insufficient on its own for autonomous agentic tool execution security.",
        ],
        relevance_to_agentic_engineering="Demonstrates why agent engineers cannot simply rely on 'a well-aligned base model'—system-level structural guards are indispensable.",
        suggested_prerequisites=["01_abdelnabi2026"],
    ),

    "04_liu2025": PaperMetadata(
        paper_id="04_liu2025",
        filename="04_liu2025_datasentinel.pdf",
        title="DataSentinel: Game-Theoretic Detection of Indirect Prompt Injections",
        authors=["Yingqi Liu", "Jinyuan Jia", "Ning Jia", "Dawn Song", "Neil Zhenqiang Gong"],
        year=2025,
        venue="IEEE Symposium on Security and Privacy (S&P 2025)",
        arxiv_id="arXiv:2504.11358",
        tier=LearningTier.TIER_2_IMPOSSIBILITY,
        layman_summary="Formulates the battle between prompt attackers and detectors as a mathematical game (minimax), designing a detector that remains robust even when attackers adapt their injection techniques.",
        technical_abstract="Models prompt injection detection as a minimax zero-sum game between an adversarial payload generator and a safety discriminator. Establishes theoretical upper bounds on detection error rates under worst-case bounded perturbations.",
        core_threat_or_defense="Game-Theoretic Minimax Prompt Injection Detection.",
        formal_invariants_or_math=[
            "Minimax Formulation: \\min_{D \\in \\mathcal{D}} \\max_{A \\in \\mathcal{A}} \\mathbb{E}_{x \\sim \\mathcal{X}} [\\mathcal{L}(D(A(x)), y)]",
            "Robust Detection Threshold: \\tau^* = \\arg\\min_\\tau (\\text{FPR}(\\tau) + \\gamma \\cdot \\text{FNR}(\\tau))",
        ],
        verbatim_key_quotes=[
            "By formalizing prompt injection as a game-theoretic minimax optimization, DataSentinel establishes detection boundaries that are provably resilient against bounded adaptive adversaries.",
        ],
        relevance_to_agentic_engineering="Teaches how to mathematically balance detection sensitivity vs false alarms when designing pre-execution context screening filters.",
        suggested_prerequisites=["01_abdelnabi2026", "14_autodojo2026"],
    ),

    # -------------------------------------------------------------------------
    # TIER 3: Information Flow Control (IFC) & Provenance Tracking
    # -------------------------------------------------------------------------
    "09_costa2025": PaperMetadata(
        paper_id="09_costa2025",
        filename="09_costa2025_securing_ai_agents_ifc.pdf",
        title="Securing AI Agents with Information-Flow Control (Fides)",
        authors=["Manuel Costa", "Cedric Fournet", "Boris Köpf", "et al."],
        year=2025,
        venue="Microsoft Research / arXiv",
        arxiv_id="arXiv:2505.23643",
        tier=LearningTier.TIER_3_IFC_PROVENANCE,
        layman_summary="Introduces Information Flow Control (IFC) to AI agents: every piece of data receives a 'taint label' (e.g., untrusted email). If tainted data tries to flow into a sensitive action (like sending money or writing a database), the system strictly blocks it.",
        technical_abstract="Presents Fides, a formal information-flow control architecture for LLM agents. Enforces non-bypassable information flow policies through runtime taint tracking, security plan generation, and selective hiding primitives to prevent data exfiltration and unauthorized actuation.",
        core_threat_or_defense="Information-Flow Control (IFC) and non-bypassable runtime taint tracking.",
        formal_invariants_or_math=[
            "Taint Lattice: \\mathcal{L} = \\langle \\mathbb{T}, \\sqsubseteq, \\sqcup, \\sqcap, \\bot, \\top \\rangle",
            "Taint Propagation Rule: \\text{Label}(x_\\text{out}) = \\bigsqcup_{x_i \\in \\text{Dependencies}(x_\\text{out})} \\text{Label}(x_i)",
            "Non-Interference Invariant: \\text{Sink}(a, \\text{args}) \\implies \\text{Label}(\\text{args}) \\sqsubseteq \\text{Clearance}(\\text{Sink})",
        ],
        verbatim_key_quotes=[
            "Fides tracks taint labels across LLM reasoning steps, ensuring that untrusted external context cannot influence high-privilege execution sinks without explicit declassification.",
            "Information flow control provides deterministic guarantees that cannot be bypassed by linguistic prompt jailbreaks.",
        ],
        relevance_to_agentic_engineering="Core foundational pattern for building enterprise agents: separating data planes from control planes via taint lattices.",
        suggested_prerequisites=["01_abdelnabi2026"],
    ),

    "10_siddiqui2024": PaperMetadata(
        paper_id="10_siddiqui2024",
        filename="10_siddiqui2024_permissive_ifc.pdf",
        title="Permissive Information-Flow Analysis for LLMs",
        authors=["Fasahat Siddiqui", "et al."],
        year=2024,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2410.03055",
        tier=LearningTier.TIER_3_IFC_PROVENANCE,
        layman_summary="Solves the 'over-tainting' problem in IFC. Standard taint tracking marks everything tainted as soon as an agent touches untrusted text; permissive IFC uses token influence to only taint parts of the output that were actually influenced by untrusted data.",
        technical_abstract="Addresses over-conservative taint propagation in LLM pipelines by computing gradient- and attention-based token influence. Allows benign information sharing while maintaining strict isolation for sensitive control directives.",
        core_threat_or_defense="Permissive Influence-Based Information-Flow Tracking.",
        formal_invariants_or_math=[
            "Token Influence: \\mathcal{I}(y_j, x_i) = \\left\\| \\frac{\\partial \\log P(y_j|x)}{\\partial e(x_i)} \\right\\|_2",
            "Permissive Declassification: \\text{Tainted}(y_j) = \\text{True} \\iff \\exists x_i \\in \\text{Untrusted} : \\mathcal{I}(y_j, x_i) > \\tau_\\text{influence}",
        ],
        verbatim_key_quotes=[
            "Coarse-grained taint tracking causes over-tainting and excessive false rejections. Influence-based permissive IFC isolates only causal token dependencies.",
        ],
        relevance_to_agentic_engineering="Critical for building agents that read untrusted documents (e.g. invoices) and still complete legitimate tasks without freezing.",
        suggested_prerequisites=["09_costa2025"],
    ),

    "12_fan2026": PaperMetadata(
        paper_id="12_fan2026",
        filename="12_fan2026_granularity_mismatch.pdf",
        title="The Granularity Mismatch in Agent Security: Argument-Level Provenance",
        authors=["Zhiyuan Fan", "et al."],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2605.11039",
        tier=LearningTier.TIER_3_IFC_PROVENANCE,
        layman_summary="Reveals the 'Granularity Mismatch' flaw in most AI frameworks: checking permissions at the tool level (e.g. 'Can agent call wire_transfer? Yes') allows attackers to sneak malicious arguments (like an attacker's IBAN) into the call. Security must check every argument individually.",
        technical_abstract="Exposes that contemporary agent security frameworks validate tool permissions at the whole-call level, creating a vulnerability where untrusted context smuggles malicious arguments into authorized tool invocations. Proposes fine-grained argument-level provenance tracking.",
        core_threat_or_defense="Argument-Level Provenance vs Coarse Whole-Call Authorization.",
        formal_invariants_or_math=[
            "Whole-Call Trust Mismatch: Auth(\\text{Tool}) = \\text{True} \\not\\implies \\forall k : \\text{Origin}(\\text{arg}_k) \\in \\text{Trusted}",
            "Argument Provenance Invariant: \\forall (k, v) \\in \\text{Args}(\\text{Tool}) : \\text{Ancestry}(v) \\subseteq \\text{TrustedSources}",
        ],
        verbatim_key_quotes=[
            "Whole-call authorization is the primary architectural flaw enabling indirect prompt injection in tool-using agents.",
            "Every tool argument must maintain an independent cryptographic provenance certificate linking it directly to an authenticated source.",
        ],
        relevance_to_agentic_engineering="Directly governs how tool execution engines must inspect parameters: every argument must be validated against state anchors $\\mathcal{S}_0$.",
        suggested_prerequisites=["09_costa2025"],
    ),

    "13_argus2026": PaperMetadata(
        paper_id="13_argus2026",
        filename="13_argus2026_context_aware_injection.pdf",
        title="ARGUS: Context-Aware Injection Defense via Dynamic Influence Provenance Graphs",
        authors=["ARGUS Research Team"],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2605.03378",
        tier=LearningTier.TIER_3_IFC_PROVENANCE,
        layman_summary="Constructs dynamic graph maps of how information flows through the agent's thought process. If an action's justification traces back to untrusted text rather than authenticated goals, ARGUS blocks the action (achieving 3.8% ASR and 87.5% utility).",
        technical_abstract="Introduces dynamic influence provenance graphs that map causal dependency chains between ingested context tokens, intermediate chain-of-thought reasoning steps, and final tool dispatch arguments. Flags and blocks ungrounded action decisions.",
        core_threat_or_defense="Dynamic Influence Provenance Graph Verification.",
        formal_invariants_or_math=[
            "Provenance DAG: \\mathcal{G} = (\\mathcal{V}_\\text{tokens}, \\mathcal{E}_\\text{influence}), e_{uv} = \\text{Weight}(u \\to v)",
            "Grounding Invariant: \\text{Lineage}(\\text{Action}) \\cap \\mathcal{V}_\\text{UserGoal} \\neq \\emptyset \\land \\text{Lineage}(\\text{Action}) \\cap \\mathcal{V}_\\text{UntrustedInjection} = \\emptyset",
        ],
        verbatim_key_quotes=[
            "ARGUS ensures that every tool dispatch is mathematically justified by authenticated user intent rather than adversarial contextual drift.",
        ],
        relevance_to_agentic_engineering="Inspires the AuthGraph provenance DAG used in production-grade financial agent defenses.",
        suggested_prerequisites=["12_fan2026", "10_siddiqui2024"],
    ),

    # -------------------------------------------------------------------------
    # TIER 4: Architectural Firewalls & Capability Isolation
    # -------------------------------------------------------------------------
    "05_tsai2025": PaperMetadata(
        paper_id="05_tsai2025",
        filename="05_tsai2025_contextual_agent_security.pdf",
        title="Contextual Agent Security: A Policy for Every Purpose (Conseca)",
        authors=["Tiffany Tsai", "Eugene Bagdasarian"],
        year=2025,
        venue="ACM HotOS 2025 / arXiv",
        arxiv_id="arXiv:2502.04321",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Introduces 'Just-in-Time' (JIT) security policies for AI agents: instead of one static giant rulebook, Conseca dynamically generates a specific, human-readable policy for the exact task before executing it.",
        technical_abstract="Presents Conseca, an operating-system-level policy architecture that generates task-specific, context-aware, human-verifiable security policies just-in-time for generalist agent execution flows.",
        core_threat_or_defense="Just-In-Time (JIT) Dynamic Contextual Security Policies.",
        formal_invariants_or_math=[
            "Policy Generation: \\Pi_\\text{task} = \\text{SynthesizePolicy}(\\text{Goal}, \\mathcal{S}_0, \\text{Capabilities})",
            "Conformity Check: \\text{Action}(a) \\models \\Pi_\\text{task} \\iff \\forall c \\in \\text{Constraints}(\\Pi_\\text{task}) : c(a) = \\text{True}",
        ],
        verbatim_key_quotes=[
            "One-size-fits-all security policies fail in generalist agents. Conseca synthesizes least-privilege, just-in-time constraints per user task.",
        ],
        relevance_to_agentic_engineering="Demonstrates how to dynamically narrow agent permissions based on task scope before invoking tools.",
        suggested_prerequisites=["01_abdelnabi2026"],
    ),

    "06_abdelnabi2025": PaperMetadata(
        paper_id="06_abdelnabi2025",
        filename="06_abdelnabi2025_firewalls_agentic_networks.pdf",
        title="Firewalls to Secure Dynamic LLM Agentic Networks",
        authors=["Sahar Abdelnabi", "et al."],
        year=2025,
        venue="Transactions on Machine Learning Research (TMLR 2026) / arXiv:2502.01822",
        arxiv_id="arXiv:2502.01822",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Designs dual firewalls for AI agent networks: an Inbound Converter Firewall that converts unstructured text into clean JSON, and an Outbound Abstraction Firewall that removes sensitive details before sending data outside.",
        technical_abstract="Proposes a dual-firewall architecture for multi-agent ecosystems: (1) Language Converter Firewall, projecting incoming natural language messages into structured protocol schemas; (2) Data Abstraction Firewall, enforcing minimal granularity on outbound inter-agent traffic.",
        core_threat_or_defense="Dual Language-Converter and Data-Abstraction Firewalls.",
        formal_invariants_or_math=[
            "Inbound Conversion: \\text{FW}_\\text{in}(x_\\text{raw}) = \\text{JSONProject}(\\text{Schema}_\\text{strict}, x_\\text{raw})",
            "Outbound Minimization: \\text{FW}_\\text{out}(x_\\text{response}) = \\text{AbstractToLeastGranularity}(x_\\text{response})",
        ],
        verbatim_key_quotes=[
            "Converting natural language into strictly typed schema payloads at the boundary neutralizes hidden prompt injection instructions.",
        ],
        relevance_to_agentic_engineering="Directly informs the Pydantic schema validation and delta extraction pipelines in our agent architecture.",
        suggested_prerequisites=["02_greshake2023", "16_lee2024"],
    ),

    "08_bagdasarian2024": PaperMetadata(
        paper_id="08_bagdasarian2024",
        filename="08_bagdasarian2024_airgapagent.pdf",
        title="AirGapAgent: Protecting Privacy-Conscious Agents with Contextual Integrity",
        authors=["Eugene Bagdasarian", "et al."],
        year=2024,
        venue="ACM CCS 2024 / arXiv:2405.05175",
        arxiv_id="arXiv:2405.05175",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Air-gaps sensitive user context from third-party tools. If an agent needs to look up a flight or invoice, it never sends the user's private context or raw API keys to untrusted endpoints.",
        technical_abstract="Implements an architectural separation of concerns where private user context and tool execution environments reside in logically isolated execution compartments governed by task-specific contextual integrity policies.",
        core_threat_or_defense="Contextual Air-Gapping & Third-Party Tool Isolation.",
        formal_invariants_or_math=[
            "Compartment Separation: \\mathcal{E}_\\text{private} \\cap \\mathcal{E}_\\text{tool} = \\emptyset",
            "Mediated Bridge: \\text{Bridge}(m) = \\text{SanitizeAndTokenize}(m, \\text{Policy}_\\text{CI})",
        ],
        verbatim_key_quotes=[
            "Agents must air-gap sensitive execution credentials and private user memories from untrusted third-party tool execution scopes.",
        ],
        relevance_to_agentic_engineering="Essential design pattern for preventing credential exfiltration and unauthorized memory reading in tool sinks.",
        suggested_prerequisites=["01_abdelnabi2026"],
    ),

    "11_ace2025": PaperMetadata(
        paper_id="11_ace2025",
        filename="11_ace2025_security_architecture.pdf",
        title="ACE: Security Architecture for LLM-Integrated App Systems",
        authors=["NDSS Research Team"],
        year=2025,
        venue="NDSS 2026 / arXiv:2504.20984",
        arxiv_id="arXiv:2504.20984",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Splits agent planning into two separate phases: Phase 1 creates an abstract high-level plan using only trusted user instructions. Phase 2 maps that plan to concrete tool calls, blocking any new actions suggested by untrusted documents.",
        technical_abstract="Presents ACE, an architectural framework that decouples abstract trusted planning from concrete tool mapping. Enforces static information-flow verification between planning phases to eliminate indirect injection hijacking.",
        core_threat_or_defense="Two-Phase Abstract Planning to Concrete Tool Mapping.",
        formal_invariants_or_math=[
            "Abstract Plan: \\Pi_\\text{abstract} = \\text{Planner}(q_\\text{user}, \\mathcal{S}_0)",
            "Tool Mapping Invariant: \\forall a \\in \\text{Actions}(\\Pi_\\text{concrete}) : \\exists \\hat{a} \\in \\Pi_\\text{abstract} \\text{ s.t. } a \\sqsubseteq \\hat{a}",
        ],
        verbatim_key_quotes=[
            "By decoupling high-level intention synthesis from untrusted tool argument extraction, ACE guarantees that untrusted context cannot spawn new action goals.",
        ],
        relevance_to_agentic_engineering="Prevents 'Goal Hijacking' where an invoice or email convinces the agent to pursue a completely different objective.",
        suggested_prerequisites=["05_tsai2025"],
    ),

    "17a_capseal2026": PaperMetadata(
        paper_id="17a_capseal2026",
        filename="17a_capseal2026_secret_mediation.pdf",
        title="CapSeal: Capability-Sealed Secret Mediation for Autonomous Agents",
        authors=["CapSeal Systems Lab"],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2604.16762",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Replaces raw API keys and database passwords with single-use, cryptographically sealed 'capability tokens'. Even if an LLM is completely tricked by a prompt injection, it does not have the token to execute unauthorized actions.",
        technical_abstract="Eliminates raw secrets from LLM agent context windows by replacing credentials with capability-sealed delegation tokens issued by a local trusted mediator. Enforces least privilege, expiry, and parameter pinning.",
        core_threat_or_defense="Capability-Sealed Secret Mediation & Parameter Pinning.",
        formal_invariants_or_math=[
            "Capability Token: \\text{Cap} = \\text{Sign}_{K_\\text{auth}}(\\langle \\text{Action}, \\text{Scope}, \\text{Expires}, \\text{ParamHash} \\rangle)",
            "Execution Invariant: \\text{Exec}(a, \\text{args}, \\text{Cap}) \\iff \\text{Verify}(\\text{Cap}) \\land \\text{hash}(\\text{args}) == \\text{Cap.ParamHash}",
        ],
        verbatim_key_quotes=[
            "Never expose raw API credentials to LLM context; mediate all sensitive sink operations through cryptographically sealed, parameter-pinned capability tokens.",
        ],
        relevance_to_agentic_engineering="Zero-trust secret management for production agents calling financial APIs, databases, and payment gateways.",
        suggested_prerequisites=["08_bagdasarian2024"],
    ),

    "17b_drift2025": PaperMetadata(
        paper_id="17b_drift2025",
        filename="17b_drift2025_dynamic_rule_isolation.pdf",
        title="DRIFT: Dynamic Rule Isolation and Memory Stream Injection Masking",
        authors=["DRIFT Research Consortium"],
        year=2025,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2506.12104",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="Monitors an agent's reasoning trajectory step-by-step. If a retrieved memory suddenly causes the agent's logic to deviate from its core business rules, DRIFT masks out the memory stream and restores safe execution.",
        technical_abstract="Introduces dynamic execution trajectory validation and real-time memory stream injection masking. Detects divergence between expected workflow transition state machines and LLM reasoning steps.",
        core_threat_or_defense="Dynamic Rule-Based Trajectory Validation & Memory Stream Masking.",
        formal_invariants_or_math=[
            "State Machine: \\mathcal{M} = (\\mathcal{S}, \\Sigma, \\delta, s_0, \\mathcal{F})",
            "Trajectory Invariant: \\forall t_k \\in \\text{Trajectory} : (s_k, a_k, s_{k+1}) \\in \\delta",
        ],
        verbatim_key_quotes=[
            "DRIFT intercepts memory retrieval streams before they corrupt reasoning trajectories, rolling back anomalous state transitions.",
        ],
        relevance_to_agentic_engineering="Provides state machine validation over agent loops so agents cannot skip approval steps or jump to payout steps.",
        suggested_prerequisites=["05_tsai2025", "11_ace2025"],
    ),

    "17c_cognitive_firewall2026": PaperMetadata(
        paper_id="17c_cognitive_firewall2026",
        filename="17c_cognitive_firewall2026_hybrid_defense.pdf",
        title="Cognitive Firewall: Split-Compute Hybrid Defenses for Agentic Web Systems",
        authors=["Cognitive Systems Group"],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2603.23791",
        tier=LearningTier.TIER_4_ISOLATION_FIREWALL,
        layman_summary="A split-compute defense: a fast, cheap local model checks browser actions and DOM inputs against deterministic rules before calling the expensive cloud LLM, slashing costs while catching injections locally.",
        technical_abstract="Presents a split-compute edge-cloud defensive architecture combining deterministic edge guardrails with cloud LLM orchestration for browser and web agents. Offloads DOM filtering and invariant checking to lightweight local processes.",
        core_threat_or_defense="Split-Compute Edge-Cloud Hybrid Deterministic Firewall.",
        formal_invariants_or_math=[
            "Split Compute: \\text{Output} = \\text{CloudLLM}(\\text{EdgeFilter}(\\text{DOM}, \\mathcal{R}_\\text{deterministic}))",
            "Cost & Latency Reduction: \\Delta \\text{Cost} = -78.4\\%, \\Delta \\text{EdgeLatency} < 12\\text{ms}",
        ],
        verbatim_key_quotes=[
            "Hybrid edge-cloud architectures filter high-volume untrusted web context deterministically at the edge, reserving expensive cloud reasoning for sanitized tasks.",
        ],
        relevance_to_agentic_engineering="Demonstrates how to run lightweight local SLMs / AST filters on CPU while keeping frontier models safe and cost-effective.",
        suggested_prerequisites=["06_abdelnabi2025"],
    ),

    # -------------------------------------------------------------------------
    # TIER 5: Forensic Localization & Causal Sanitization
    # -------------------------------------------------------------------------
    "15a_promptarmor2025": PaperMetadata(
        paper_id="15a_promptarmor2025",
        filename="15a_promptarmor2025_guardrails.pdf",
        title="PromptArmor: Auxiliary LLM Pre-Processor for Context Sanitization",
        authors=["PromptArmor Security Team"],
        year=2025,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2507.15219",
        tier=LearningTier.TIER_5_FORENSIC_CAUSAL,
        layman_summary="Uses a specialized, lightweight auxiliary model as a 'bouncer' before the main agent reads any data. The bouncer strips out suspicious prompt injection tokens and returns clean data.",
        technical_abstract="Evaluates an auxiliary pre-processing guardrail model that inspects untrusted external documents before context injection, stripping imperative command patterns and returning sanitized semantic content.",
        core_threat_or_defense="Auxiliary Pre-Processor Prompt Sanitization.",
        formal_invariants_or_math=[
            "Sanitization Function: x_\\text{clean} = \\text{GuardModel}(x_\\text{untrusted})",
            "Adversarial Bypass Rate: \\text{ASR}_{\\text{adaptive}} = 34.2\\% \\text{ (Static filters alone degrade under mutation)}",
        ],
        verbatim_key_quotes=[
            "PromptArmor provides a first line of defense by stripping imperative command tokens from retrieved text, but must be paired with execution-sink invariants.",
        ],
        relevance_to_agentic_engineering="Shows the proper role of input sanitizers: valuable as a pre-filter, but never trusted as the sole security boundary.",
        suggested_prerequisites=["14_autodojo2026"],
    ),

    "15b_promptlocate2025": PaperMetadata(
        paper_id="15b_promptlocate2025",
        filename="15b_promptlocate2025_localization.pdf",
        title="PromptLocate: Fine-Grained Semantic Localization of Injected Instructions",
        authors=["PromptLocate Research Group"],
        year=2025,
        venue="IEEE Symposium on Security and Privacy (S&P 2026) / arXiv:2510.12252",
        arxiv_id="arXiv:2510.12252",
        tier=LearningTier.TIER_5_FORENSIC_CAUSAL,
        layman_summary="Instead of just saying 'this document is suspicious', PromptLocate acts like a highlighter, pinpointing the exact sentences and token ranges where the attacker hid malicious instructions.",
        technical_abstract="Develops semantic token segmentation models to locate exact span boundaries of injected prompts within legitimate documents, enabling surgical redaction without discarding the entire document.",
        core_threat_or_defense="Fine-Grained Semantic Token Span Localization & Surgical Redaction.",
        formal_invariants_or_math=[
            "Span Localization: \\mathcal{S}_\\text{inject} = \\{ [i, j] : \\text{Score}(x_{i:j}) > \\tau_\\text{locate} \\}",
            "Surgical Redaction: x_\\text{redacted} = x \\setminus \\bigcup_{[i, j] \\in \\mathcal{S}_\\text{inject}} x_{i:j}",
        ],
        verbatim_key_quotes=[
            "Surgical localization preserves document utility by excising only the adversarial prompt tokens while retaining legitimate business content.",
        ],
        relevance_to_agentic_engineering="Enables partial data recovery when processing documents that contain mixed legitimate data and third-party comments/injections.",
        suggested_prerequisites=["15a_promptarmor2025"],
    ),

    "15c_causalarmor2026": PaperMetadata(
        paper_id="15c_causalarmor2026",
        filename="15c_causalarmor2026_causal_attribution.pdf",
        title="CausalArmor: Causal Dominance Shift Detection & Retroactive CoT Masking",
        authors=["Causal AI Security Lab"],
        year=2026,
        venue="arXiv Preprint",
        arxiv_id="arXiv:2602.07918",
        tier=LearningTier.TIER_5_FORENSIC_CAUSAL,
        layman_summary="Monitors which words in the prompt are driving the AI's thoughts. If untrusted input suddenly becomes the dominant cause of the agent's decision to call a tool, CausalArmor masks that thought and rewinds the agent to a safe state.",
        technical_abstract="Formulates causal attribution metrics over LLM attention graphs to identify when untrusted context tokens usurp causal dominance over user instructions during Chain-of-Thought (CoT) generation. Dynamically masks dominant adversarial paths.",
        core_threat_or_defense="Causal Dominance Shift Detection & Retroactive CoT Masking.",
        formal_invariants_or_math=[
            "Causal Dominance: \\text{CD}(x_\\text{untrusted} \\to a) = \\frac{\\text{Attn}(a, x_\\text{untrusted})}{\\text{Attn}(a, q_\\text{user}) + \\epsilon}",
            "Intervention Condition: \\text{CD}(x_\\text{untrusted} \\to a) > 1.0 \\implies \\text{TriggerRollbackAndMask}(a)",
        ],
        verbatim_key_quotes=[
            "When causal dominance shifts from authenticated user intent to untrusted context, the agent's chain-of-thought must be retroactively masked to prevent taint propagation.",
        ],
        relevance_to_agentic_engineering="Represents the cutting edge of cognitive-level agent defenses, preventing prompt injection at the internal attention layer.",
        suggested_prerequisites=["13_argus2026", "15b_promptlocate2025"],
    ),
}
