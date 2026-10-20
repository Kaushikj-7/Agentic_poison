"""Rigid Pydantic v2 schemas for AgentPOI-SDE MCP tools.

Enforces strict type validation and forbids unexpected/extra arguments
at the gateway boundary before tool execution.
"""

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentpoi_sde.mcp.gateway import check_path_string, extract_diff_paths

# ---------------------------------------------------------------------------
# Tool 1: sde_ast_search
# ---------------------------------------------------------------------------

class ASTSearchInput(BaseModel):
    """Input parameters for searching AST symbols and dependency edges."""

    model_config = ConfigDict(extra="forbid", strict=True)

    query: Optional[str] = Field(
        default=None,
        description="Case-insensitive substring query matching symbol names",
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Optional repository-relative path to scope the search",
    )
    symbol_type: Literal["all", "function", "class"] = Field(
        default="all",
        description="Filter results by symbol kind ('all', 'function', 'class')",
    )
    include_dependencies: bool = Field(
        default=False,
        description="Whether to include internal and external import dependency maps",
    )

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            err = check_path_string(v)
            if err:
                raise ValueError(err)
        return v


class SymbolMatch(BaseModel):
    """A matched top-level AST symbol within a repository file."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(..., description="Symbol identifier name")
    kind: Literal["function", "class"] = Field(..., description="Symbol kind")
    file_path: str = Field(..., description="Repository-relative file path")
    module: str = Field(..., description="Dotted module identifier")


class ASTSearchOutput(BaseModel):
    """Output payload from an AST symbol search."""

    model_config = ConfigDict(extra="forbid", strict=True)

    matches: List[SymbolMatch] = Field(
        default_factory=list,
        description="List of matching symbol items",
    )
    total_matches: int = Field(
        default=0,
        description="Total number of matched symbols",
    )
    dependencies: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="Map of file path to imported target paths if requested",
    )


# ---------------------------------------------------------------------------
# Tool 2: sde_harvest_component
# ---------------------------------------------------------------------------

class ComponentHarvestInput(BaseModel):
    """Input parameters for safely slicing and harvesting a reusable component."""

    model_config = ConfigDict(extra="forbid", strict=True)

    file_path: str = Field(
        ...,
        description="Repository-relative path of the source file containing the symbol",
    )
    symbol_name: str = Field(
        ...,
        description="Top-level function or class identifier to slice and isolate",
    )
    source_code: Optional[str] = Field(
        default=None,
        description="Optional explicit source code override (defaults to repository content)",
    )

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        err = check_path_string(v)
        if err:
            raise ValueError(err)
        return v


class ComponentHarvestOutput(BaseModel):
    """Output payload from safe component harvesting."""

    model_config = ConfigDict(extra="forbid", strict=True)

    symbol_name: str = Field(..., description="Isolated symbol identifier")
    file_path: str = Field(..., description="Repository-relative path of source")
    sliced_code: str = Field(..., description="Isolated Python source code of the component")
    content_hash: str = Field(..., description="SHA-256 digest of sliced code")
    is_approved: bool = Field(..., description="True if component passed static security gates")
    retained_symbols: List[str] = Field(
        default_factory=list,
        description="Top-level symbols retained during backward slicing",
    )
    pruned_symbols: List[str] = Field(
        default_factory=list,
        description="Top-level symbols pruned during backward slicing",
    )
    security_violations: List[str] = Field(
        default_factory=list,
        description="List of security screening violation messages if any",
    )
    error: Optional[str] = Field(
        default=None,
        description="Diagnostic error message if harvesting failed",
    )


# ---------------------------------------------------------------------------
# Tool 3: sde_propose_mutation
# ---------------------------------------------------------------------------

class MutationProposalInput(BaseModel):
    """Input parameters for proposing a code mutation or unified diff patch."""

    model_config = ConfigDict(extra="forbid", strict=True)

    intent_id: str = Field(
        ...,
        description="Authenticated task intent contract identifier (Tier T0 provenance root)",
    )
    path: Optional[str] = Field(
        default=None,
        description="Repository-relative target file path (required if diff is omitted)",
    )
    op: Optional[Literal["create", "modify", "delete"]] = Field(
        default=None,
        description="Operation kind ('create', 'modify', 'delete') (required if diff is omitted)",
    )
    new_content: Optional[str] = Field(
        default=None,
        description="Complete replacement content for create or modify operations",
    )
    diff: Optional[str] = Field(
        default=None,
        description="Alternative unified diff string proposing one or more file mutations",
    )
    dry_run: bool = Field(
        default=False,
        description="If True, evaluates invariants without applying mutations to workspace",
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            err = check_path_string(v)
            if err:
                raise ValueError(err)
        return v

    @field_validator("diff")
    @classmethod
    def validate_diff(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            diff_paths = extract_diff_paths(v)
            for p in diff_paths:
                err = check_path_string(p)
                if err:
                    raise ValueError(f"Path traversal in diff header: {err}")
        return v

    @model_validator(mode="after")
    def validate_mutation_target(self) -> "MutationProposalInput":
        """Ensure either diff or both path and op are provided."""
        if not self.diff and (not self.path or not self.op):
            raise ValueError(
                "Either 'diff' or both 'path' and 'op' must be provided."
            )
        return self



class MutationVerdictItem(BaseModel):
    """Per-file verdict item for a proposed mutation."""

    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(..., description="Target file path")
    op: str = Field(..., description="Mutation operation applied or evaluated")
    is_applied: bool = Field(..., description="True if mutation was approved and written")
    status: str = Field(..., description="Evaluation status ('APPROVED', 'BLOCKED', etc.)")
    violation_codes: List[str] = Field(
        default_factory=list,
        description="List of violated invariant codes (e.g. ['I1', 'I2'])",
    )
    violations: List[str] = Field(
        default_factory=list,
        description="Human-readable violation descriptions",
    )
    patch_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 digest of the evaluated mutation patch",
    )


class MutationProposalOutput(BaseModel):
    """Output payload from mutation evaluation and gating."""

    model_config = ConfigDict(extra="forbid", strict=True)

    verdicts: List[MutationVerdictItem] = Field(
        default_factory=list,
        description="List of verdicts for all evaluated mutations",
    )
    overall_approved: bool = Field(
        default=False,
        description="True if all proposed mutations were approved",
    )
    working_tree_oid: str = Field(
        default="",
        description="Cryptographic tree OID of repository state after evaluation",
    )
    intent_id: str = Field(
        default="",
        description="Matching intent identifier",
    )


# ---------------------------------------------------------------------------
# Tool 4: sde_run_tests
# ---------------------------------------------------------------------------

class TestRunnerInput(BaseModel):
    """Input parameters for running pytest in the verification sink."""

    __test__ = False
    model_config = ConfigDict(extra="forbid", strict=True)

    test_paths: List[str] = Field(
        ...,
        description="List of repository-relative test file paths or directory targets",
    )
    isolated: bool = Field(
        default=True,
        description="Execute in an isolated temporary directory to prevent workspace pollution",
    )
    timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=120,
        description="Maximum execution timeout in seconds (1 to 120)",
    )
    expression: Optional[str] = Field(
        default=None,
        description="Optional pytest -k keyword filter expression",
    )

    @field_validator("test_paths")
    @classmethod
    def validate_test_paths(cls, v: List[str]) -> List[str]:
        for p in v:
            err = check_path_string(p)
            if err:
                raise ValueError(err)
        return v


class TestFailureItem(BaseModel):
    """Structured details of a failed test case."""

    __test__ = False
    model_config = ConfigDict(extra="forbid", strict=True)

    test_id: str = Field(..., description="Full test node identifier")
    message: str = Field(..., description="Failure summary or assertion message")
    traceback: str = Field(..., description="Captured failure traceback text")


class TestRunnerOutput(BaseModel):
    """Output payload from test suite execution."""

    __test__ = False
    model_config = ConfigDict(extra="forbid", strict=True)

    success: bool = Field(..., description="True if pytest exited with code 0")
    exit_code: int = Field(..., description="Subprocess return code")
    passed_count: int = Field(default=0, description="Number of passed tests")
    failed_count: int = Field(default=0, description="Number of failed tests")
    skipped_count: int = Field(default=0, description="Number of skipped tests")
    duration_seconds: float = Field(default=0.0, description="Test run duration in seconds")
    output: str = Field(default="", description="Captured stdout and stderr")
    failures: List[TestFailureItem] = Field(
        default_factory=list,
        description="Detailed list of test failures",
    )

