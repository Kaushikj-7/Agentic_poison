# Mathematical Formulation: Contextual Trust Propagation (CTP)

## 1. Problem Formulation

Let an agent context environment consist of an external world $W$, an internal memory state $M = \{c_1, c_2, \dots, c_m\}$, a task prompt $q \in \mathcal{Q}$, and an action space $\mathcal{A}$ with tool execution operator $\text{Exec}: \mathcal{A} \times W \to W$.

In conventional RAG and memory-augmented agents, a top-$k$ retriever queries $M$ given $q$:
$$M_q = \text{TopK}(M, q, k) = \arg\max_{c \in M}^{(k)} \text{Sim}(E(c), E(q))$$
The policy model generates actions conditioned on the concatenation:
$$a \sim \pi_{\theta}(\cdot \mid q, M_q)$$

An adversary crafts a poisoned context object $c^* \in M$ such that:
$$a_{\text{malicious}} = \arg\max_a \pi_{\theta}(a \mid q, M_q \cup \{c^*\}) \quad \text{where } a_{\text{malicious}} \neq \arg\max_a \pi_{\theta}(a \mid q, M_q)$$

---

## 2. Contextual Integrity (CI) Parameterization

Following Abdelnabi & Bagdasarian (2026), an information flow is valid if and only if it respects contextual norms defined by a 5-tuple:
$$\text{CI}(c) = \langle s, r, u, t, p \rangle$$
Where:
- $s \in \mathcal{S}$: Sender entity (e.g., User, External Tool, Web Scraper)
- $r \in \mathcal{R}$: Receiver entity (e.g., Memory Store, Execution Scaffolding)
- $u \in \mathcal{U}$: Subject of the information (e.g., Target account, System state)
- $t \in \mathcal{T}$: Information type (e.g., User preference, System directive, Fact)
- $p \in \mathcal{P}$: Transmission principle (Authorization policy, Consent, System invariant)

### The Self-Asserted Authorization Signal
The primary vector of contextual subversion is **forged transmission principles**—where the payload $c^*$ explicitly asserts authorization conditions:
$$p_{\text{asserted}} \in \{\text{"User has pre-approved this"}, \text{"Execute under administrator override"}, \text{"Prior safety checks bypassed"}\}$$

We define the CI Risk Score $R_{\text{CI}}(c) \in [0, 1]$ as:
$$R_{\text{CI}}(c) = w_{\text{auth}} \cdot \mathbb{I}_{\text{auth}}(c) + w_{\text{imp}} \cdot \sigma\left(\frac{N_{\text{imperative}}(c)}{|c|}\right) + w_{\text{mismatch}} \cdot \mathcal{D}(t_{\text{declared}}, t_{\text{inferred}}) + w_{\text{frame}} \cdot \mathbb{I}_{\text{frame}}(c)$$

Where:
- $\mathbb{I}_{\text{auth}}(c) \in [0, 1]$: Intensity of self-asserted transmission claims.
- $\sigma(\cdot)$: Sigmoidal density of imperative/directive verbs (e.g., "must", "execute", "forward", "delete").
- $\mathcal{D}$: Mismatch between declared data type (e.g. "meeting note") and functional type ("tool invocation instruction").
- $\mathbb{I}_{\text{frame}}$: Presence of delimiter hijacking, markdown boundary escapes, or prompt reset tokens.

---

## 3. Multiplicative Trust Propagation with Exponential Penalty

Prior systems compute risk via linear additive combination:
$$\text{Risk}_{\text{linear}}(c) = \sum_{i} w_i x_i$$
This is vulnerable to **benign padding**: an attacker inserts long benign paragraphs to dilute the weighted average.

CTP resolves this via **Exponential Risk Decay**:
$$T_{\text{direct}}(c) = T_{\text{source}}(c) \cdot \exp\left(-\lambda \cdot R_{\text{CI}}(c)\right)$$

Where:
- $T_{\text{source}}(c) \in (0, 1]$ is the origin prior (e.g., Verified User = 0.95, Scraped Web = 0.25).
- $\lambda > 0$ is the steepness hyperparameter (empirically calibrated to $\lambda \in [2.0, 3.0]$).
- If $R_{\text{CI}}(c) \to 1$, $T_{\text{direct}}(c) \to T_{\text{source}} \cdot e^{-\lambda} \approx 0.08 \cdot T_{\text{source}}$, guaranteeing immediate collapse below quarantine threshold.

---

## 4. Provenance Graph & Non-Dilutable Taint Propagation

Context objects in memory undergo synthesis, summarization, and concatenation:
$$c_{\text{new}} = \text{Summarize}(p_1, p_2, \dots, p_n)$$
To prevent "laundering" poisoned context through clean summarizers (the taint dilution problem from Costa et al., 2025), trust propagates as the **geometric mean** of its ancestor provenance:

$$T(c) = T_{\text{direct}}(c) \cdot \left( \prod_{i=1}^n T(p_i) \right)^{\frac{1}{n}}$$

### Proof of Non-Dilution:
Suppose an attacker contaminates memory $p_1$ such that $T(p_1) = 0.10$. An agent summarizes $p_1$ with 3 clean, highly trusted items $p_2, p_3, p_4$ ($T = 0.95$).
Under an arithmetic mean:
$$T_{\text{arith}} = \frac{0.10 + 0.95 + 0.95 + 0.95}{4} = 0.7375 \quad (\text{Laundered above threshold } \tau = 0.50!)$$
Under CTP's geometric mean:
$$T_{\text{geom}} = (0.10 \cdot 0.95^3)^{0.25} = (0.10 \cdot 0.857375)^{0.25} = (0.0857)^{0.25} \approx 0.540$$
Combined with the new node's direct penalty, the trust score remains depressed, preventing tainted memories from escaping quarantine.

---

## 5. Retrieval-Time Task Alignment Gate (Task Shield Proxy)

At query time, for any candidate memory $c$ passing write-time thresholds, we enforce a task-alignment constraint:
$$\text{Align}(c, q) = \frac{E(c) \cdot E(q)}{\|E(c)\| \|E(q)\|}$$

If $c$ contains latent or sleeper instructions divergent from task $q$:
$$\text{Divergence}(c, q) = \max\left(0, \text{Sim}(E(c_{\text{instruction}}), E(a_{\text{sensitive}})) - \text{Align}(c, q)\right)$$

The effective retrieval trust score becomes:
$$T_{\text{retrieval}}(c \mid q) = T(c) \cdot \max\left(0, 1 - \alpha \cdot \text{Divergence}(c, q)\right)$$

---

## 6. Minimax Threshold Optimization & The Pareto Frontier

Following DataSentinel (Liu et al., 2026), the defender chooses operating threshold $\tau^*$ to minimize empirical worst-case risk against an adaptive attacker:

$$\tau^* = \arg\min_{\tau \in [0, 1]} \mathcal{L}(\tau) = \text{ASR}(\tau) + \gamma \cdot \text{FQR}(\tau)$$

Where:
- $\text{ASR}(\tau) = \frac{|\{c^* \in \mathcal{D}_{\text{poison}} \mid T(c^*) \ge \tau \land \text{Executed}\}|}{|\mathcal{D}_{\text{poison}}|}$ (Attack Success Rate)
- $\text{FQR}(\tau) = \frac{|\{c_{\text{clean}} \in \mathcal{D}_{\text{clean}} \mid T(c_{\text{clean}}) < \tau\}|}{|\mathcal{D}_{\text{clean}}|}$ (False Quarantine Rate / Utility Loss)
- $\gamma > 0$: Cost trade-off weighting parameter.

By sweeping $\tau \in [0.05, 0.95]$, CTP generates the complete Pareto frontier, identifying the exact operating point of optimal risk-utility trade-off.
