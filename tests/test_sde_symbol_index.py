"""Tests for the AST symbol index: import resolution, edges, and cycle detection."""

from agentpoi_sde.anchor.symbol_index import (
    SymbolIndex,
    extract_imports,
    find_cycles,
    module_name_from_path,
    resolve_relative,
    would_create_cycle,
)


def test_module_name_from_path():
    assert module_name_from_path("svc/core/engine.py") == "svc.core.engine"
    assert module_name_from_path("svc/core/__init__.py") == "svc.core"
    assert module_name_from_path("svc\\api\\routes.py") == "svc.api.routes"


def test_absolute_imports_are_not_prefixed_with_containing_module():
    # Regression: a level-0 import must be returned verbatim, never prefixed.
    assert resolve_relative("svc.core.engine", 0, "svc.api.routes") == "svc.api.routes"
    assert resolve_relative("svc.core.engine", 0, "requests") == "requests"
    assert resolve_relative("svc.core.engine", 0, None) == ""


def test_relative_imports_trim_correctly():
    assert resolve_relative("svc.core.engine", 1, "config") == "svc.core.config"
    assert resolve_relative("svc.core.engine", 2, "data") == "svc.data"
    # A package (__init__.py) *is* level 1, so one fewer component is trimmed.
    assert resolve_relative("svc.core", 1, "engine", is_package=True) == "svc.core.engine"
    assert resolve_relative("svc.core", 2, "x", is_package=True) == "svc.x"


def test_extract_imports_mixes_internal_relative_and_external():
    source = "import os\nfrom svc.api.routes import handle_health\nfrom . import config\n"
    imports = extract_imports(source, "svc.core.engine")
    assert "os" in imports
    assert "svc.api.routes.handle_health" in imports
    assert "svc.core.config" in imports


def test_symbol_index_builds_internal_edges():
    files = {
        "svc/__init__.py": "",
        "svc/core/__init__.py": "",
        "svc/api/__init__.py": "",
        "svc/core/engine.py": "def f():\n    return 1\n",
        "svc/api/routes.py": "from svc.core.engine import f\n",
    }
    index = SymbolIndex().build(files)
    edges = index.internal_edges()
    assert edges["svc/api/routes.py"] == {"svc/core/engine.py"}
    assert edges["svc/core/engine.py"] == set()


def test_symbol_index_records_parse_errors_without_raising():
    index = SymbolIndex().build({"bad.py": "def broken(:\n"})
    assert index.files["bad.py"].parse_error is True


def test_would_create_cycle_and_find_cycles():
    edges = {"a": {"b"}, "b": {"c"}, "c": set()}
    assert would_create_cycle(edges, "c", "a") is True
    assert would_create_cycle(edges, "b", "c") is False
    assert would_create_cycle(edges, "a", "a") is True
    cycles = find_cycles({"a": {"b"}, "b": {"a"}})
    assert cycles, "expected a cycle to be detected"
    assert set(cycles[0]) == {"a", "b"}
