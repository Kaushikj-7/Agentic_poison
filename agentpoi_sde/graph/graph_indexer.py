"""AST-driven repository indexer that builds the Merkle Knowledge Graph."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from agentpoi_sde.graph.merkle_graph import EdgeType, MerkleGraph, MerkleNode, NodeType

HTTP_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


class GraphIndexer:
    """Extracts symbols, classes, routes, schemas, and calls from source files into a MerkleGraph."""

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
        """Parses AST and registers file, class, function, endpoint, and schema nodes."""
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
        """Walks top-level AST nodes to extract classes, schemas, functions, endpoints, and relationships."""
        # First pass: index classes and schemas so endpoints can link to schemas
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                self._index_class(graph, node, file_node_id, rel_str)

        # Second pass: index functions and endpoints
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._index_function(graph, node, file_node_id, rel_str)

    def _index_function(
        self, graph: MerkleGraph, fn: ast.FunctionDef | ast.AsyncFunctionDef, file_node_id: str, rel_str: str
    ) -> None:
        """Registers a function symbol node, extracts route endpoints, and attaches to its file."""
        sym_id = f"sym:{rel_str}:{fn.name}"
        args = [arg.arg for arg in fn.args.args]
        return_annot = ast.unparse(fn.returns) if fn.returns else None

        graph.add_node(
            sym_id,
            NodeType.SYMBOL,
            {"name": fn.name, "args": args, "returns": return_annot, "line": fn.lineno},
        )
        graph.add_edge(file_node_id, sym_id, EdgeType.IMPLEMENTS)

        # Extract route endpoints from function decorators
        self._extract_route_endpoints(graph, fn, sym_id, file_node_id, rel_str)

    def _index_class(self, graph: MerkleGraph, cls: ast.ClassDef, file_node_id: str, rel_str: str) -> None:
        """Registers a class symbol node, member methods, and schema if dataclass/pydantic."""
        class_id = f"sym:{rel_str}:{cls.name}"
        bases = [ast.unparse(b) for b in cls.bases]

        graph.add_node(class_id, NodeType.SYMBOL, {"name": cls.name, "bases": bases, "line": cls.lineno})
        graph.add_edge(file_node_id, class_id, EdgeType.IMPLEMENTS)

        # Inspect if class is a Pydantic model or Dataclass (NodeType.SCHEMA)
        is_dataclass = any(
            (isinstance(d, ast.Name) and d.id == "dataclass")
            or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
            or (
                isinstance(d, ast.Call)
                and (
                    (isinstance(d.func, ast.Name) and d.func.id == "dataclass")
                    or (isinstance(d.func, ast.Attribute) and d.func.attr == "dataclass")
                )
            )
            for d in cls.decorator_list
        )

        is_pydantic = any(
            "BaseModel" in base
            or "Schema" in base
            or base == "Model"
            or base.endswith(".BaseModel")
            for base in bases
        )

        fields: Dict[str, str] = {}
        for item in cls.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id
                field_type = ast.unparse(item.annotation) if item.annotation else "Any"
                fields[field_name] = field_type
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        fields[target.id] = "Any"

        if is_dataclass or is_pydantic or (fields and ("Model" in cls.name or "Schema" in cls.name)):
            schema_id = f"schema:{rel_str}:{cls.name}" if rel_str else f"schema:{cls.name}"
            graph.add_node(
                schema_id,
                NodeType.SCHEMA,
                {
                    "name": cls.name,
                    "fields": fields,
                    "field_names": list(fields.keys()),
                    "line": cls.lineno,
                    "file": rel_str,
                    "is_dataclass": is_dataclass,
                    "is_pydantic": is_pydantic,
                },
            )
            graph.add_edge(file_node_id, schema_id, EdgeType.IMPLEMENTS)
            graph.add_edge(class_id, schema_id, EdgeType.IMPLEMENTS)

        # Index member methods
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
                # Check for routes on methods
                self._extract_route_endpoints(graph, item, method_id, file_node_id, rel_str)

    def _extract_route_endpoints(
        self,
        graph: MerkleGraph,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        sym_id: str,
        file_node_id: str,
        rel_str: str,
    ) -> None:
        """Inspects function decorators for REST route definitions (@app.get, @router.post, etc.)."""
        for deco in fn.decorator_list:
            if not isinstance(deco, ast.Call):
                continue

            routes_found: List[Tuple[str, str]] = []  # list of (method, path)

            # Case 1: @app.get('/path'), @router.post('/path')
            if isinstance(deco.func, ast.Attribute):
                attr_name = deco.func.attr.upper()
                if attr_name in HTTP_METHODS:
                    if deco.args and isinstance(deco.args[0], ast.Constant) and isinstance(deco.args[0].value, str):
                        routes_found.append((attr_name, deco.args[0].value))
                elif deco.func.attr == "route":
                    # Case 2: Flask-style @app.route('/path', methods=['GET', 'POST'])
                    if deco.args and isinstance(deco.args[0], ast.Constant) and isinstance(deco.args[0].value, str):
                        path = deco.args[0].value
                        methods = ["GET"]
                        for kw in deco.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                parsed_methods = []
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and str(elt.value).upper() in HTTP_METHODS:
                                        parsed_methods.append(str(elt.value).upper())
                                if parsed_methods:
                                    methods = parsed_methods
                        for m in methods:
                            routes_found.append((m, path))

            # Register each extracted route as NodeType.ENDPOINT
            for method, path in routes_found:
                endpoint_id = f"endpoint:{rel_str}:{method}:{path}" if rel_str else f"endpoint:{method}:{path}"
                graph.add_node(
                    endpoint_id,
                    NodeType.ENDPOINT,
                    {
                        "path": path,
                        "method": method,
                        "line": fn.lineno,
                        "file": rel_str,
                        "handler": fn.name,
                    },
                )
                # Link ENDPOINT to handler SYMBOL
                graph.add_edge(endpoint_id, sym_id, EdgeType.CONNECTS_TO)
                graph.add_edge(endpoint_id, sym_id, EdgeType.CALLS)
                # Link FILE to ENDPOINT
                graph.add_edge(file_node_id, endpoint_id, EdgeType.IMPLEMENTS)

                # Link ENDPOINT to any referenced SCHEMAs in function arguments
                for arg in fn.args.args:
                    if arg.annotation:
                        type_name = ast.unparse(arg.annotation)
                        schema_node_id = f"schema:{rel_str}:{type_name}"
                        if graph.get_node(schema_node_id):
                            graph.add_edge(endpoint_id, schema_node_id, EdgeType.CONNECTS_TO)

    def register_decision(
        self,
        graph: MerkleGraph,
        decision_id: str,
        description: str,
        touched_files: Optional[List[str]] = None,
        touched_symbols: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MerkleNode:
        """Registers a NodeType.DECISION node with linkages to touched files and symbols."""
        node_id = decision_id if decision_id.startswith("decision:") else f"decision:{decision_id}"
        files = touched_files or []
        symbols = touched_symbols or []

        payload: Dict[str, Any] = {
            "decision_id": decision_id,
            "description": description,
            "touched_files": list(files),
            "touched_symbols": list(symbols),
        }
        if metadata:
            payload.update(metadata)

        node = graph.add_node(node_id, NodeType.DECISION, payload)

        for file_path in files:
            file_node_id = file_path if file_path.startswith("file:") else f"file:{file_path}"
            if file_node_id not in graph._nodes:
                graph.add_node(file_node_id, NodeType.FILE, {"path": file_path})
            graph.add_edge(node_id, file_node_id, EdgeType.CONSTRAINS)

        for sym in symbols:
            sym_node_id = sym if sym.startswith("sym:") else f"sym:{sym}"
            if sym_node_id not in graph._nodes:
                graph.add_node(sym_node_id, NodeType.SYMBOL, {"name": sym})
            graph.add_edge(node_id, sym_node_id, EdgeType.CONSTRAINS)

        return node

    def get_endpoints(self, graph: MerkleGraph) -> List[MerkleNode]:
        """Returns all ENDPOINT nodes in the graph."""
        return [n for n in graph._nodes.values() if n.node_type == NodeType.ENDPOINT]

    def get_schemas(self, graph: MerkleGraph) -> List[MerkleNode]:
        """Returns all SCHEMA nodes in the graph."""
        return [n for n in graph._nodes.values() if n.node_type == NodeType.SCHEMA]

    def get_decisions(self, graph: MerkleGraph) -> List[MerkleNode]:
        """Returns all DECISION nodes in the graph."""
        return [n for n in graph._nodes.values() if n.node_type == NodeType.DECISION]
