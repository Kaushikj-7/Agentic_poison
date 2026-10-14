"""Deterministic AST-based backward program slicer extracting minimal self-contained units."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class SliceResult:
    """Outcome of program slicing operation on a target symbol."""

    target_symbol: str
    sliced_code: str
    retained_symbols: List[str] = field(default_factory=list)
    pruned_symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    is_valid: bool = True
    error: Optional[str] = None


class ProgramSlicer:
    """Extracts minimal transitive dependency slices for target functions or classes."""

    def slice_symbol(self, source_code: str, target_symbol: str) -> SliceResult:
        """Extracts minimal self-contained slice of source_code for target_symbol."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return SliceResult(
                target_symbol=target_symbol,
                sliced_code="",
                is_valid=False,
                error=f"Syntax error in source: {exc}",
            )

        top_defs, import_nodes, all_syms = self._index_top_level(tree)
        if target_symbol not in top_defs:
            return SliceResult(
                target_symbol=target_symbol,
                sliced_code="",
                is_valid=False,
                error=f"Target symbol '{target_symbol}' not found in source.",
            )

        needed_syms, needed_imports = self._compute_dependencies(target_symbol, top_defs, import_nodes)
        retained_nodes = self._build_retained_nodes(tree, needed_syms, needed_imports)

        new_module = ast.Module(body=retained_nodes, type_ignores=[])
        ast.fix_missing_locations(new_module)
        sliced_code = ast.unparse(new_module)

        try:
            ast.parse(sliced_code)
        except SyntaxError as exc:
            return SliceResult(
                target_symbol=target_symbol,
                sliced_code=sliced_code,
                is_valid=False,
                error=f"Unparsed slice failed verification: {exc}",
            )

        pruned_syms = [s for s in all_syms if s not in needed_syms]
        return SliceResult(
            target_symbol=target_symbol,
            sliced_code=sliced_code,
            retained_symbols=sorted(needed_syms),
            pruned_symbols=sorted(pruned_syms),
            dependencies=sorted(s for s in needed_syms if s != target_symbol),
            is_valid=True,
        )

    def _index_assign(
        self, node: ast.Assign | ast.AnnAssign, top_defs: Dict[str, ast.AST], all_syms: List[str]
    ) -> None:
        """Helper to index assignment targets."""
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                top_defs[target.id] = node
                all_syms.append(target.id)

    def _index_top_level(
        self, tree: ast.Module
    ) -> Tuple[Dict[str, ast.AST], List[ast.AST], List[str]]:
        """Indexes top-level definitions, imports, and symbol names."""
        top_defs: Dict[str, ast.AST] = {}
        import_nodes: List[ast.AST] = []
        all_syms: List[str] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                top_defs[node.name] = node
                all_syms.append(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                import_nodes.append(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._index_assign(node, top_defs, all_syms)

        return top_defs, import_nodes, all_syms

    def _compute_dependencies(
        self,
        target_symbol: str,
        top_defs: Dict[str, ast.AST],
        import_nodes: List[ast.AST],
    ) -> Tuple[Set[str], Set[ast.AST]]:
        """Computes transitive closure of dependencies for target_symbol."""
        import_map = self._build_import_map(import_nodes)
        needed_syms: Set[str] = {target_symbol}
        needed_imports: Set[ast.AST] = set()

        # Always preserve __future__ imports if present
        for imp in import_nodes:
            if isinstance(imp, ast.ImportFrom) and imp.module == "__future__":
                needed_imports.add(imp)

        queue: List[str] = [target_symbol]
        while queue:
            current = queue.pop(0)
            node = top_defs.get(current)
            if not node:
                continue

            referenced_names = self._extract_referenced_names(node)
            for name in referenced_names:
                if name in top_defs and name not in needed_syms:
                    needed_syms.add(name)
                    queue.append(name)
                elif name in import_map:
                    needed_imports.add(import_map[name])

        return needed_syms, needed_imports

    def _build_import_map(self, import_nodes: List[ast.AST]) -> Dict[str, ast.AST]:
        """Maps exposed import names/aliases to their respective import AST nodes."""
        mapping: Dict[str, ast.AST] = {}
        for imp in import_nodes:
            if isinstance(imp, ast.Import):
                for alias in imp.names:
                    name = alias.asname or alias.name.split(".")[0]
                    mapping[name] = imp
            elif isinstance(imp, ast.ImportFrom):
                for alias in imp.names:
                    name = alias.asname or alias.name
                    mapping[name] = imp
        return mapping

    def _extract_referenced_names(self, node: ast.AST) -> Set[str]:
        """Extracts all variable and function names referenced within node."""
        refs: Set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                refs.add(child.id)
            elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                refs.add(child.value.id)
        return refs

    def _should_retain_node(
        self, node: ast.AST, needed_syms: Set[str], needed_imports: Set[ast.AST]
    ) -> bool:
        """Determines whether an AST statement node should be retained in the slice."""
        if node in needed_imports:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return node.name in needed_syms
        if isinstance(node, ast.Assign):
            return any(isinstance(t, ast.Name) and t.id in needed_syms for t in node.targets)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            return node.target.id in needed_syms
        return False

    def _build_retained_nodes(
        self,
        tree: ast.Module,
        needed_syms: Set[str],
        needed_imports: Set[ast.AST],
    ) -> List[ast.AST]:
        """Filters module body retaining only needed imports and definitions."""
        return [
            node for node in tree.body
            if self._should_retain_node(node, needed_syms, needed_imports)
        ]
