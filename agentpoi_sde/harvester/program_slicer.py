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

        is_method_slice = "." in target_symbol
        pruned_class_symbols: List[str] = []
        replaced_defs: Dict[str, ast.AST] = {}
        root_symbol = target_symbol

        if is_method_slice:
            class_name, method_name = target_symbol.split(".", 1)
            if class_name not in top_defs:
                return SliceResult(
                    target_symbol=target_symbol,
                    sliced_code="",
                    is_valid=False,
                    error=f"Target symbol '{target_symbol}' not found in source.",
                )
            class_node = top_defs[class_name]
            if not isinstance(class_node, ast.ClassDef):
                return SliceResult(
                    target_symbol=target_symbol,
                    sliced_code="",
                    is_valid=False,
                    error=f"Target symbol parent '{class_name}' is not a class.",
                )

            class_methods: Dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
            for item in class_node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_methods[item.name] = item

            if method_name not in class_methods:
                return SliceResult(
                    target_symbol=target_symbol,
                    sliced_code="",
                    is_valid=False,
                    error=f"Method '{method_name}' not found in class '{class_name}'.",
                )

            methods_queue = [method_name]
            if "__init__" in class_methods and "__init__" not in methods_queue:
                methods_queue.append("__init__")
            if "__new__" in class_methods and "__new__" not in methods_queue:
                methods_queue.append("__new__")

            retained_class_methods: Set[str] = set(methods_queue)
            while methods_queue:
                curr_m = methods_queue.pop(0)
                m_node = class_methods[curr_m]
                m_refs = self._extract_referenced_names(m_node)
                for r in m_refs:
                    if r in class_methods and r not in retained_class_methods:
                        retained_class_methods.add(r)
                        methods_queue.append(r)

            for m_name in class_methods:
                if m_name not in retained_class_methods:
                    pruned_class_symbols.append(m_name)

            new_class_body: List[ast.AST] = []
            for item in class_node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name in retained_class_methods:
                        new_class_body.append(item)
                else:
                    new_class_body.append(item)

            type_params = getattr(class_node, "type_params", [])
            retained_class_node = ast.ClassDef(
                name=class_node.name,
                bases=class_node.bases,
                keywords=class_node.keywords,
                body=new_class_body,
                decorator_list=class_node.decorator_list,
                type_params=type_params,
            )
            ast.copy_location(retained_class_node, class_node)
            replaced_defs[class_name] = retained_class_node
            top_defs[class_name] = retained_class_node
            root_symbol = class_name
        else:
            if target_symbol not in top_defs:
                return SliceResult(
                    target_symbol=target_symbol,
                    sliced_code="",
                    is_valid=False,
                    error=f"Target symbol '{target_symbol}' not found in source.",
                )

        needed_syms, needed_imports = self._compute_dependencies(root_symbol, top_defs, import_nodes)
        retained_nodes = self._build_retained_nodes(tree, needed_syms, needed_imports, replaced_defs)

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
        pruned_syms.extend(pruned_class_symbols)
        retained_sym_list = set(needed_syms)
        if is_method_slice:
            retained_sym_list.add(target_symbol)

        return SliceResult(
            target_symbol=target_symbol,
            sliced_code=sliced_code,
            retained_symbols=sorted(retained_sym_list),
            pruned_symbols=sorted(set(pruned_syms)),
            dependencies=sorted(s for s in needed_syms if s != root_symbol),
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
                    needed_syms.add(name)

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
        replaced_defs: Optional[Dict[str, ast.AST]] = None,
    ) -> List[ast.AST]:
        """Filters module body retaining only needed imports and definitions."""
        retained: List[ast.AST] = []
        replaced_defs = replaced_defs or {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                if node in needed_imports:
                    if node.module == "__future__":
                        retained.append(node)
                    else:
                        filtered_aliases = [
                            alias
                            for alias in node.names
                            if (alias.asname or alias.name) in needed_syms
                        ]
                        if filtered_aliases:
                            new_imp = ast.ImportFrom(
                                module=node.module,
                                names=filtered_aliases,
                                level=node.level,
                            )
                            ast.copy_location(new_imp, node)
                            retained.append(new_imp)
            elif isinstance(node, ast.Import):
                if node in needed_imports:
                    filtered_aliases = [
                        alias
                        for alias in node.names
                        if (alias.asname or alias.name.split(".")[0]) in needed_syms
                    ]
                    if filtered_aliases:
                        new_imp = ast.Import(names=filtered_aliases)
                        ast.copy_location(new_imp, node)
                        retained.append(new_imp)
            elif isinstance(node, ast.ClassDef) and node.name in replaced_defs:
                retained.append(replaced_defs[node.name])
            elif self._should_retain_node(node, needed_syms, needed_imports):
                retained.append(node)
        return retained
