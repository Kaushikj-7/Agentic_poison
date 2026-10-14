"""AST-driven repository indexer that builds the Merkle Knowledge Graph."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set

from agentpoi_sde.graph.merkle_graph import EdgeType, MerkleGraph, NodeType


class GraphIndexer:
    """Extracts symbols, classes, and calls from source files into a MerkleGraph."""

    def __init__(self) -> None:
        pass

    def index_file(self, file_path: Path, relative_to: Optional[Path] = None) -> MerkleGraph:
        """Indexes a single Python file into a MerkleGraph."""
        graph = MerkleGraph()
        rel_path = file_path.relative_to(relative_to) if relative_to else file_path
        rel_str = str(rel_path).replace("\\", "/")

        source_code = file_path.read_text(encoding="utf-8")
        self._index_source(graph, rel_str, source_code)
        return graph

    def index_source(self, graph: MerkleGraph, rel_path: str, source_code: str) -> None:
        """Indexes source code string into an existing graph."""
        self._index_source(graph, rel_path, source_code)

    def _index_source(self, graph: MerkleGraph, rel_str: str, source_code: str) -> None:
        """Parses AST and registers file, class, function nodes, and call edges."""
        file_node_id = f"file:{rel_str}"
        graph.add_node(file_node_id, NodeType.FILE, {"path": rel_str, "size": len(source_code)})

        try:
            tree = ast.parse(source_code, filename=rel_str)
        except SyntaxError:
            # File failed parsing - register error state
            graph.add_node(f"error:{rel_str}", NodeType.BUILD, {"syntax_error": True})
            return

        self._walk_ast(graph, tree, file_node_id, rel_str)

    def _walk_ast(self, graph: MerkleGraph, tree: ast.AST, file_node_id: str, rel_str: str) -> None:
        """Walks top-level AST nodes to extract classes, functions, and relationships."""
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef):
                self._index_function(graph, node, file_node_id, rel_str)
            elif isinstance(node, ast.AsyncFunctionDef):
                self._index_function(graph, node, file_node_id, rel_str)
            elif isinstance(node, ast.ClassDef):
                self._index_class(graph, node, file_node_id, rel_str)

    def _index_function(
        self, graph: MerkleGraph, fn: ast.FunctionDef | ast.AsyncFunctionDef, file_node_id: str, rel_str: str
    ) -> None:
        """Registers a function symbol node and attaches to its file."""
        sym_id = f"sym:{rel_str}:{fn.name}"
        args = [arg.arg for arg in fn.args.args]
        return_annot = ast.unparse(fn.returns) if fn.returns else None

        graph.add_node(
            sym_id,
            NodeType.SYMBOL,
            {"name": fn.name, "args": args, "returns": return_annot, "line": fn.lineno},
        )
        graph.add_edge(file_node_id, sym_id, EdgeType.IMPLEMENTS)

    def _index_class(self, graph: MerkleGraph, cls: ast.ClassDef, file_node_id: str, rel_str: str) -> None:
        """Registers a class symbol node and its member methods."""
        class_id = f"sym:{rel_str}:{cls.name}"
        bases = [ast.unparse(b) for b in cls.bases]

        graph.add_node(class_id, NodeType.SYMBOL, {"name": cls.name, "bases": bases, "line": cls.lineno})
        graph.add_edge(file_node_id, class_id, EdgeType.IMPLEMENTS)

        for item in cls.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_id = f"sym:{rel_str}:{cls.name}.{item.name}"
                args = [arg.arg for arg in item.args.args]
                graph.add_node(
                    method_id,
                    NodeType.SYMBOL,
                    {"name": f"{cls.name}.{item.name}", "args": args, "line": item.lineno},
                )
                graph.add_edge(class_id, method_id, EdgeType.IMPLEMENTS)
