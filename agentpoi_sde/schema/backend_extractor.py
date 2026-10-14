"""Extractor for backend server route definitions and Pydantic schemas."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set

from agentpoi_sde.schema.contract_model import BackendRoute, HTTPMethod


class BackendRouteExtractor:
    """Extracts route endpoints and required request schema fields from Python code."""

    def __init__(self) -> None:
        pass

    def extract_routes(self, file_path: str, source_code: str) -> List[BackendRoute]:
        """Parses Python source AST to find FastAPI and Flask route handlers."""
        routes: List[BackendRoute] = []
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return routes

        # First pass: map Pydantic model names to their fields
        models = self._extract_pydantic_models(tree)

        # Second pass: extract route decorators
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_route_decorators(node, models, file_path, routes)

        return routes

    def _extract_pydantic_models(self, tree: ast.AST) -> Dict[str, List[str]]:
        """Maps Pydantic BaseModel subclasses to their declared fields."""
        models: Dict[str, List[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                fields: List[str] = []
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        fields.append(item.target.id)
                if fields:
                    models[node.name] = fields
        return models

    def _check_route_decorators(
        self,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        models: Dict[str, List[str]],
        file_path: str,
        routes: List[BackendRoute],
    ) -> None:
        """Inspects function decorators for route definitions."""
        for deco in fn.decorator_list:
            if not isinstance(deco, ast.Call):
                continue

            # Handles @app.get('/path'), @router.post('/path')
            if isinstance(deco.func, ast.Attribute):
                attr_name = deco.func.attr.upper()
                if attr_name in HTTPMethod.__members__:
                    self._create_route_from_call(deco, HTTPMethod[attr_name], fn, models, file_path, routes)
                elif deco.func.attr == "route":
                    self._create_flask_route(deco, fn, models, file_path, routes)

    def _create_route_from_call(
        self,
        call: ast.Call,
        method: HTTPMethod,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        models: Dict[str, List[str]],
        file_path: str,
        routes: List[BackendRoute],
    ) -> None:
        """Constructs a BackendRoute from an AST call node."""
        if not call.args:
            return
        path_arg = call.args[0]
        if not isinstance(path_arg, ast.Constant) or not isinstance(path_arg.value, str):
            return

        path_template = path_arg.value
        required_fields = self._resolve_function_fields(fn, models)

        routes.append(
            BackendRoute(
                method=method,
                path_template=path_template,
                required_fields=required_fields,
                file_path=file_path,
                line=fn.lineno,
            )
        )

    def _create_flask_route(
        self,
        call: ast.Call,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        models: Dict[str, List[str]],
        file_path: str,
        routes: List[BackendRoute],
    ) -> None:
        """Handles Flask @app.route('/path', methods=['GET', 'POST'])."""
        if not call.args or not isinstance(call.args[0], ast.Constant):
            return
        path_template = str(call.args[0].value)

        methods = [HTTPMethod.GET]
        for kw in call.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                parsed_methods: List[HTTPMethod] = []
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).upper() in HTTPMethod.__members__:
                        parsed_methods.append(HTTPMethod[str(elt.value).upper()])
                if parsed_methods:
                    methods = parsed_methods

        required_fields = self._resolve_function_fields(fn, models)
        for m in methods:
            routes.append(
                BackendRoute(
                    method=m,
                    path_template=path_template,
                    required_fields=required_fields,
                    file_path=file_path,
                    line=fn.lineno,
                )
            )

    def _resolve_function_fields(
        self, fn: ast.FunctionDef | ast.AsyncFunctionDef, models: Dict[str, List[str]]
    ) -> List[str]:
        """Resolves required schema fields by checking parameter type annotations."""
        fields: List[str] = []
        for arg in fn.args.args:
            if arg.annotation and isinstance(arg.annotation, ast.Name):
                type_name = arg.annotation.id
                if type_name in models:
                    fields.extend(models[type_name])
        return fields
