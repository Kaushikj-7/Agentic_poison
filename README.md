# Contextual Trust Propagation (CTP): Agent Poisoning Defense Framework

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Grounded: arXiv:2605.17634](https://img.shields.io/badge/Grounded-arXiv%3A2605.17634-b31b1b.svg)](https://arxiv.org/abs/2605.17634)
[![Zero-Cost Execution](https://img.shields.io/badge/Execution-100%25%20Offline%20CPU-brightgreen.svg)]()

> **"AI Agents May Always Fall for Prompt Injections"** (*Abdelnabi & Bagdasarian, ELLIS / MPI-IS, arXiv:2605.17634, May 2026*):  
> Context manipulation and memory poisoning are **formally impossible to eliminate completely without utility degradation**. Rather than promising 0% ASR, robust defense requires optimizing the **Pareto trade-off curve** between Attack Success Rate (ASR) and legitimate utility preservation (False Quarantine Rate).

---

## Key Features

1. **Theoretical Grounding**: Built directly upon Contextual Integrity (CI) theory, detecting the `#1` attack signal identified by recent literature: **self-asserted transmission principles** (which achieved 96.7% ASR across frontier models in recent studies).
2. **Contextual Trust Propagation (CTP)**:
   $$T(c) = T_{\text{source}}(c) \cdot \exp(-\lambda \cdot R_{\text{CI}}(c)) \cdot \left( \prod_{i=1}^n T(p_i) \right)^{\frac{1}{n}}$$
   - **Exponential Penalty**: Red flags cause rapid exponential trust collapse, preventing benign text dilution.
   - **Non-Dilutable Taint**: Geometric mean ancestor propagation guarantees tainted sources cannot be laundered through summarization.
3. **Retrieval-Time Task Alignment Gate**: Lightweight, zero-cost semantic alignment proxy (*Task Shield, ACL 2025*) intercepting divergent sleeper directives before they reach the agent's context window.
4. **100% Offline & Zero API Cost**: Runs on any CPU in milliseconds using local embeddings and deterministic mock scaffolding. Optional plug for local Ollama (`llama3.2:3b`).
5. **Interactive Streamlit Security Dashboard**: Live agent chat, real-time memory monitor, attack injection lab, and interactive Pareto curve generator.

---

## Quick Start

### 1. Installation
```powershell
pip install -r requirements.txt
```

### 2. Run Test Suite
```powershell
pytest tests/ -v
```

### 3. Run Benchmark Ablation Study
```powershell
python -m agent_poi.evaluation.benchmark_runner
```

### 4. Generate Pareto Trade-Off Frontier Plot
```powershell
python -m agent_poi.evaluation.pareto_sweeper
```

### 5. Launch Interactive Streamlit Dashboard
```powershell
streamlit run agent_poi/ui/app.py
```

---

## Literature Survey & Documentation

- [Literature Survey: 30+ Papers & Connections](docs/SURVEY_AND_PAPERS.md)
- [Mathematical Formulation & Taint Non-Dilution Proof](docs/MATHEMATICAL_FORMULATION.md)
- [System Architecture (4 Defense Layers)](docs/ARCHITECTURE.md)
- [Benchmark Methodology & Paired Ground-Truth](docs/BENCHMARK_METHODOLOGY.md)
- [Pareto Frontier Visualization](docs/pareto_frontier.png)
