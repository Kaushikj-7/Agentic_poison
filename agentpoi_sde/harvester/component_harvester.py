"""Open-source component harvester and safe ingestion pipeline."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from agentpoi_sde.harvester.program_slicer import ProgramSlicer
from agentpoi_sde.harvester.slicer_security import (
    SlicerSecurityResult,
    SlicerSecurityValidator,
)


@dataclass(frozen=True)
class HarvestedComponent:
    """A sliced, sanitized, content-addressed software component."""

    name: str
    repo_name: str
    file_path: str
    target_symbol: str
    sliced_code: str
    content_hash: str
    security_verdict: SlicerSecurityResult
    is_approved: bool
    retained_symbols: List[str] = field(default_factory=list)
    pruned_symbols: List[str] = field(default_factory=list)
    error: Optional[str] = None


class LocalComponentRegistry:
    """In-memory or local catalog of indexed open-source component sources."""

    def __init__(self) -> None:
        self._sources: Dict[Tuple[str, str], str] = {}  # (repo, path) -> code

    def register(self, repo_name: str, file_path: str, source_code: str) -> None:
        """Registers source code for a repository file."""
        self._sources[(repo_name, file_path.replace("\\", "/"))] = source_code

    def get_source(self, repo_name: str, file_path: str) -> Optional[str]:
        """Retrieves registered source code."""
        return self._sources.get((repo_name, file_path.replace("\\", "/")))

    def _match_symbols_in_code(
        self, repo: str, path: str, code: str, query: str
    ) -> List[Tuple[str, str, str]]:
        """Extracts matching function and class names from Python code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        q = query.lower()
        return [
            (repo, path, node.name)
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and q in node.name.lower()
        ]

    def search_symbols(self, query: str) -> List[Tuple[str, str, str]]:
        """Finds matching symbols containing query across indexed sources."""
        matches: List[Tuple[str, str, str]] = []
        for (repo, path), code in self._sources.items():
            matches.extend(self._match_symbols_in_code(repo, path, code, query))
        return matches


class ComponentHarvester:
    """Safe component harvesting pipeline: query -> retrieve -> slice -> screen -> verify."""

    def __init__(
        self,
        registry: Optional[LocalComponentRegistry] = None,
        slicer: Optional[ProgramSlicer] = None,
        security_validator: Optional[SlicerSecurityValidator] = None,
    ) -> None:
        self.registry = registry or LocalComponentRegistry()
        self.slicer = slicer or ProgramSlicer()
        self.security_validator = security_validator or SlicerSecurityValidator()

    def harvest(
        self,
        repo_name: str,
        file_path: str,
        target_symbol: str,
        source_code: Optional[str] = None,
    ) -> HarvestedComponent:
        """Safely harvests and isolates target_symbol from repo source."""
        code = source_code or self.registry.get_source(repo_name, file_path)
        if not code:
            return self._build_error_component(
                repo_name, file_path, target_symbol, f"Source not found for {repo_name}/{file_path}"
            )

        slice_result = self.slicer.slice_symbol(code, target_symbol)
        if not slice_result.is_valid:
            return self._build_error_component(
                repo_name, file_path, target_symbol, slice_result.error or "Slicing failed"
            )

        security_verdict = self.security_validator.validate(slice_result.sliced_code)
        if not security_verdict.is_safe:
            return HarvestedComponent(
                name=f"{repo_name}:{target_symbol}",
                repo_name=repo_name,
                file_path=file_path,
                target_symbol=target_symbol,
                sliced_code=slice_result.sliced_code,
                content_hash=self._hash(slice_result.sliced_code),
                security_verdict=security_verdict,
                is_approved=False,
                retained_symbols=slice_result.retained_symbols,
                pruned_symbols=slice_result.pruned_symbols,
                error=f"Security check failed: {'; '.join(security_verdict.violations)}",
            )

        return HarvestedComponent(
            name=f"{repo_name}:{target_symbol}",
            repo_name=repo_name,
            file_path=file_path,
            target_symbol=target_symbol,
            sliced_code=slice_result.sliced_code,
            content_hash=self._hash(slice_result.sliced_code),
            security_verdict=security_verdict,
            is_approved=True,
            retained_symbols=slice_result.retained_symbols,
            pruned_symbols=slice_result.pruned_symbols,
        )

    def _hash(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _build_error_component(
        self, repo_name: str, file_path: str, target_symbol: str, error_msg: str
    ) -> HarvestedComponent:
        empty_sec = SlicerSecurityResult(is_safe=False, violations=[error_msg])
        return HarvestedComponent(
            name=f"{repo_name}:{target_symbol}",
            repo_name=repo_name,
            file_path=file_path,
            target_symbol=target_symbol,
            sliced_code="",
            content_hash="",
            security_verdict=empty_sec,
            is_approved=False,
            error=error_msg,
        )
