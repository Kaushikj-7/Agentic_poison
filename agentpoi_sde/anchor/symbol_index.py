"""AST-based symbol index and import graph for the repository anchor.

Builds a deterministic, content-derived view of a Python repository: module names,
top-level symbols, and resolved internal import edges. This is the structural half of
the Repository State Anchor (R0) and is intentionally pure (no I/O, no network).
"""

import ast
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set


def module_name_from_path(path: str) -> str:
    """Map a repository-relative file path to a dotted Python module name."""
    normalised = path.replace("\\", "/")
    if normalised.endswith(".py"):
        normalised = normalised[: -len(".py")]
    if normalised.endswith("/__init__"):
        normalised = normalised[: -len("/__init__")]
    return ".".join(seg for seg in normalised.split("/") if seg and seg != ".")


def resolve_relative(
    base_module: str,
    level: int,
    module: Optional[str],
    is_package: bool = False,
) -> str:
    """Resolve an import to an absolute dotted target.

    ``level == 0`` marks an absolute import (``import a.b`` / ``from a.b import c``), which
    must be returned verbatim. For relative imports ``level`` components are trimmed from the
    containing module; because a package (``__init__.py``) *is* level 1, one fewer component
    is trimmed in that case.
    """
    if level <= 0:
        return module or ""
    parts = base_module.split(".") if base_module else []
    trim = level - 1 if is_package else level
    if trim > 0:
        parts = parts[: len(parts) - trim] if len(parts) >= trim else []
    if module:
        parts = parts + module.split(".")
    return ".".join(parts)


def extract_imports(source: str, module_name: str, is_package: bool = False) -> Set[str]:
    """Extract the set of absolute dotted import targets referenced by ``source``."""
    tree = ast.parse(source)
    imports: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = resolve_relative(module_name, node.level, node.module, is_package)
            for alias in node.names:
                if alias.name == "*":
                    if base:
                        imports.add(base)
                    continue
                imports.add(f"{base}.{alias.name}" if base else alias.name)
    return imports


def extract_symbols(source: str) -> Dict[str, str]:
    """Extract top-level symbol names and their kind (``function`` / ``class``)."""
    tree = ast.parse(source)
    symbols: Dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols[node.name] = "function"
        elif isinstance(node, ast.ClassDef):
            symbols[node.name] = "class"
    return symbols


@dataclass
class FileSymbols:
    """Parsed structural facts about one repository file."""

    path: str
    module: str
    imports: Set[str] = field(default_factory=set)
    symbols: Dict[str, str] = field(default_factory=dict)
    parse_error: bool = False


class SymbolIndex:
    """Deterministic symbol table + import graph over a set of repository files."""

    def __init__(self) -> None:
        self.files: Dict[str, FileSymbols] = {}
        self._module_to_path: Dict[str, str] = {}

    def build(self, files: Dict[str, str]) -> "SymbolIndex":
        """Index every ``*.py`` file in ``files`` (path -> source content)."""
        self.files = {}
        self._module_to_path = {}
        for path in sorted(files):
            if not path.endswith(".py"):
                continue
            source = files[path]
            module = module_name_from_path(path)
            entry = FileSymbols(path=path, module=module)
            try:
                entry.imports = extract_imports(
                    source, module, is_package=path.endswith("__init__.py")
                )
                entry.symbols = extract_symbols(source)
            except SyntaxError:
                entry.parse_error = True
            self.files[path] = entry
            self._module_to_path[module] = path
        return self

    def module_to_path(self) -> Dict[str, str]:
        """Return the module-name -> path mapping."""
        return dict(self._module_to_path)

    def resolve_import(self, dotted: str) -> Optional[str]:
        """Resolve a dotted import to an internal file path, if it is internal."""
        parts = dotted.split(".")
        while parts:
            candidate = ".".join(parts)
            if candidate in self._module_to_path:
                return self._module_to_path[candidate]
            parts.pop()
        return None

    def internal_edges(self) -> Dict[str, Set[str]]:
        """Return the internal import graph as path -> set of imported paths."""
        edges: Dict[str, Set[str]] = {path: set() for path in self.files}
        for path, entry in self.files.items():
            for dotted in entry.imports:
                target = self.resolve_import(dotted)
                if target and target != path:
                    edges[path].add(target)
        return edges

    def external_imports(self) -> Set[str]:
        """Return top-level names imported from outside the repository."""
        external: Set[str] = set()
        for entry in self.files.values():
            for dotted in entry.imports:
                if self.resolve_import(dotted) is None:
                    external.add(dotted.split(".")[0])
        return external

    def all_symbols(self) -> Dict[str, List[str]]:
        """Return path -> sorted top-level symbol names."""
        return {path: sorted(entry.symbols) for path, entry in self.files.items()}


def would_create_cycle(edges: Dict[str, Set[str]], src: str, dst: str) -> bool:
    """Return True if adding edge ``src -> dst`` would introduce a dependency cycle."""
    if src == dst:
        return True
    stack = [dst]
    seen: Set[str] = set()
    while stack:
        node = stack.pop()
        if node == src:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(edges.get(node, ()))
    return False


def find_cycles(edges: Dict[str, Set[str]]) -> List[List[str]]:
    """Return a deterministic list of detected dependency cycles (each a node path)."""
    cycles: List[List[str]] = []
    colour: Dict[str, int] = {}
    stack: List[str] = []

    def visit(node: str) -> None:
        colour[node] = 1
        stack.append(node)
        for neighbour in sorted(edges.get(node, ())):
            state = colour.get(neighbour, 0)
            if state == 1:
                idx = stack.index(neighbour)
                cycles.append(stack[idx:] + [neighbour])
            elif state == 0:
                visit(neighbour)
        stack.pop()
        colour[node] = 2

    for node in sorted(edges):
        if colour.get(node, 0) == 0:
            visit(node)
    return cycles


def path_exists_in(files: Iterable[str], candidate: str) -> bool:
    """Return True if ``candidate`` is present in the given file collection."""
    return candidate in set(files)
