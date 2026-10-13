"""Educational Module 3: Low-Cost Small Language Models (SLMs) on CPU.

Demonstrates:
1. Running 1B-3B SLMs locally on standard CPU with zero GPU cost.
2. Grammar-constrained JSON decoding to eliminate parsing failures and hallucinations.
3. Hybrid architecture: Fast local SLM for extraction + Deterministic Invariant Verifier.
"""

import re
from agent_poi.education.foundational_agent_loop import ActionType, AgentAction


class SmallModelCPURunner:
    """Simulates a quantized (Q4_K_M) Small Language Model (SLM) running on CPU.

    Key Benefits of SLMs for Agentic Systems:
    - Zero GPU Requirement: Runs smoothly on standard multi-core laptop CPUs.
    - Low Latency: 40-70 tokens/sec for 1B-3B parameter models.
    - Zero Cloud Cost: No per-token API billing.
    - Privacy & Isolation: Untrusted documents never leave the local machine.
    """

    def __init__(self, model_name: str = "qwen2.5-3b-instruct-q4_k_m"):
        self.model_name = model_name

    def generate_constrained_action(
        self,
        task_query: str,
        context_document: str,
    ) -> AgentAction:
        """Extracts structured agent actions using deterministic regex-grammar constraints.

        In production, tools like llama.cpp (GBNF grammars) or Outlines enforce
        that the SLM output strictly adheres to the JSON schema token-by-token.
        """
        # Look for invoice numbers
        inv_match = re.search(r"(?:invoice|inv)[\s#:]*([A-Za-z0-9-]+)", context_document, re.IGNORECASE)
        # Look for dollar amounts
        amt_match = re.search(r"\$\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?)", context_document)
        # Look for account / routing IDs
        acc_match = re.search(r"(?:account|iban|acct)[\s#:]*([A-Za-z0-9-]+)", context_document, re.IGNORECASE)

        if "wire" in task_query.lower() or "pay" in task_query.lower() or "transfer" in task_query.lower():
            if acc_match and amt_match:
                clean_amt = float(amt_match.group(1).replace(",", ""))
                return AgentAction(
                    thought_trace=f"Extracted payment directive: Pay ${clean_amt:.2f} to account {acc_match.group(1)}.",
                    action_type=ActionType.TOOL_CALL,
                    tool_name="process_disbursement",
                    tool_arguments={
                        "target_account": acc_match.group(1),
                        "amount": clean_amt,
                        "invoice_id": inv_match.group(1) if inv_match else "INV-UNKNOWN",
                    },
                    epistemic_justification=f"Context document contains payment instructions for {acc_match.group(1)}.",
                )

        if inv_match:
            return AgentAction(
                thought_trace=f"Found invoice {inv_match.group(1)}. Querying ledger database.",
                action_type=ActionType.TOOL_CALL,
                tool_name="read_invoice",
                tool_arguments={"invoice_id": inv_match.group(1)},
            )

        return AgentAction(
            thought_trace="No actionable financial directives found in context.",
            action_type=ActionType.FINISH,
            epistemic_justification="Task goal satisfied without further tool dispatch.",
        )
