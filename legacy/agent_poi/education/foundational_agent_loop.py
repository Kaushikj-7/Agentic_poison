"""Educational Module 1: Foundational Agent Loop Architecture from Scratch.

Teaches the core ReAct (Reason + Act + Observe) state machine, formal Pydantic
schemas, tool registration, execution sandboxing, and fault/exception handling.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Types of actions an agentic system can initiate."""
    TOOL_CALL = "tool_call"
    FINISH = "finish"
    ASK_USER = "ask_user"


class AgentAction(BaseModel):
    """Strict structured output produced by an agent reasoning step."""
    thought_trace: str = Field(
        ...,
        description="Internal step-by-step reasoning explaining why this action is chosen.",
    )
    action_type: ActionType = Field(
        ...,
        description="The category of action to take.",
    )
    tool_name: Optional[str] = Field(
        None,
        description="Exact registered name of the tool to invoke.",
    )
    tool_arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value arguments matching the target tool signature.",
    )
    epistemic_justification: Optional[str] = Field(
        None,
        description="Citation or rationale anchoring this action to authenticated user intent.",
    )


class AgentObservation(BaseModel):
    """Structured result returned from a tool execution back to the agent reasoning loop."""
    tool_name: str
    status: str  # "SUCCESS", "ERROR", "TIMEOUT", "BLOCKED"
    output: Any
    error_message: Optional[str] = None
    execution_latency_ms: float = 0.0


class AgentExecutionState(BaseModel):
    """State trajectory tracking the agent's multi-step execution."""
    task_goal: str
    step_count: int = 0
    max_steps: int = 10
    history: List[Dict[str, Any]] = Field(default_factory=list)
    is_finished: bool = False
    final_answer: Optional[str] = None
    caught_errors: List[str] = Field(default_factory=list)


class BaseTool(ABC):
    """Base interface for all agentic tools."""

    name: str
    description: str

    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        """Return the JSON schema definition for tool arguments."""
        pass

    @abstractmethod
    def execute(self, **kwargs: Any) -> Any:
        """Execute the tool deterministically with provided keyword arguments."""
        pass


class ToolRegistry:
    """Registry maintaining available tools and performing input schema validation."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool in the catalog."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        """Retrieve a tool by name."""
        return self._tools.get(name)

    def list_tool_definitions(self) -> List[Dict[str, Any]]:
        """List all tool schemas for model system prompt injection."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "schema": tool.get_schema(),
            }
            for tool in self._tools.values()
        ]


class SimpleReActAgent:
    """Educational implementation of a deterministic ReAct agent loop."""

    def __init__(
        self,
        registry: ToolRegistry,
        model_inference_fn: Optional[Callable[[str, List[Dict[str, Any]]], AgentAction]] = None,
        max_steps: int = 6,
    ):
        self.registry = registry
        self.inference_fn = model_inference_fn or self._default_mock_inference
        self.max_steps = max_steps

    def _default_mock_inference(self, prompt: str, history: List[Dict[str, Any]]) -> AgentAction:
        """Fallback mock inference demonstrating action transitions."""
        step = len(history)
        if step == 0:
            return AgentAction(
                thought_trace="I need to look up the invoice details before proceeding.",
                action_type=ActionType.TOOL_CALL,
                tool_name="read_invoice",
                tool_arguments={"invoice_id": "INV-2026-001"},
            )
        return AgentAction(
            thought_trace="Invoice verified. Task completed successfully.",
            action_type=ActionType.FINISH,
            epistemic_justification="Verified invoice matches vendor registration.",
        )

    def step(self, state: AgentExecutionState) -> AgentExecutionState:
        """Execute a single ReAct step (Reason -> Act -> Observe)."""
        if state.is_finished or state.step_count >= state.max_steps:
            state.is_finished = True
            return state

        state.step_count += 1

        # 1. REASON: Generate structured action proposal
        try:
            action = self.inference_fn(state.task_goal, state.history)
        except Exception as e:
            err = f"Inference error during step {state.step_count}: {str(e)}"
            state.caught_errors.append(err)
            state.history.append({"role": "system", "content": err})
            return state

        # 2. ACT & OBSERVE: Handle finish or tool dispatch
        if action.action_type == ActionType.FINISH:
            state.is_finished = True
            state.final_answer = action.thought_trace
            state.history.append({
                "role": "agent_finish",
                "thought": action.thought_trace,
                "justification": action.epistemic_justification,
            })
            return state

        if action.action_type == ActionType.TOOL_CALL:
            tool_name = action.tool_name
            tool = self.registry.get(tool_name) if tool_name else None

            # Exception Handling: Hallucinated / Unregistered Tool
            if not tool:
                obs = AgentObservation(
                    tool_name=tool_name or "unknown",
                    status="ERROR",
                    output=None,
                    error_message=f"Tool '{tool_name}' is not registered in ToolRegistry.",
                )
                state.caught_errors.append(obs.error_message)
            else:
                # Execution with parameter fault handling
                try:
                    res = tool.execute(**action.tool_arguments)
                    obs = AgentObservation(
                        tool_name=tool.name,
                        status="SUCCESS",
                        output=res,
                    )
                except TypeError as te:
                    obs = AgentObservation(
                        tool_name=tool.name,
                        status="ERROR",
                        output=None,
                        error_message=f"Argument mismatch for tool '{tool.name}': {str(te)}",
                    )
                    state.caught_errors.append(obs.error_message)
                except Exception as ex:
                    obs = AgentObservation(
                        tool_name=tool.name,
                        status="ERROR",
                        output=None,
                        error_message=f"Execution runtime failure: {str(ex)}",
                    )
                    state.caught_errors.append(obs.error_message)

            # Append action & observation to trajectory
            state.history.append({
                "role": "agent_action",
                "action": action.model_dump(),
                "observation": obs.model_dump(),
            })

        return state

    def run(self, task_goal: str) -> AgentExecutionState:
        """Execute the agent loop until completion or step ceiling."""
        state = AgentExecutionState(task_goal=task_goal, max_steps=self.max_steps)
        while not state.is_finished and state.step_count < state.max_steps:
            state = self.step(state)
        return state
