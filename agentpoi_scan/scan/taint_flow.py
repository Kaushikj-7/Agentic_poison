"""Taint-flow adapter — traces untrusted input into dangerous sinks, statically.

The value a scanner adds over a per-line regex is *reachability*: the report
should say "this request parameter arrives at ``os.system``", not merely "this
file calls ``os.system``". This adapter performs a small, conservative
intra-procedural dataflow analysis:

* Python: real ``ast`` walk. Assignments propagate taint; f-strings, ``+``
  concatenation and ``.format`` inherit it; sinks are matched by qualified name.
* JavaScript/TypeScript: line-level flow over ``req.*``/``location.*`` sources
  assigned to local variables, then used at a shell/eval/SQL sink.

PHP is intentionally not covered here: ``legacy_patterns`` already performs the
equivalent superglobal-to-sink analysis for PHP. Nothing is imported, compiled
or executed — only parsed.
"""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "taint_flow"

MAX_FINDINGS_PER_FILE = 50

# name -> (human description, severity, vulnerability, maliciousness)
SINKS: Dict[str, Tuple[str, str, float, float]] = {
    "eval": ("evaluates input as code", "critical", 0.95, 0.35),
    "exec": ("executes input as code", "critical", 0.95, 0.35),
    "os.system": ("passes input to a shell", "critical", 0.9, 0.2),
    "os.popen": ("passes input to a shell", "critical", 0.9, 0.2),
    "subprocess.run": ("spawns a process with input", "high", 0.8, 0.1),
    "subprocess.Popen": ("spawns a process with input", "high", 0.8, 0.1),
    "subprocess.call": ("spawns a process with input", "high", 0.8, 0.1),
    "subprocess.check_output": ("spawns a process with input", "high", 0.8, 0.1),
    "pickle.loads": ("deserializes untrusted data", "critical", 0.85, 0.25),
    "pickle.load": ("deserializes untrusted data", "critical", 0.85, 0.25),
    "marshal.loads": ("deserializes untrusted data", "critical", 0.85, 0.25),
    "yaml.load": ("parses untrusted YAML with the unsafe loader", "high", 0.75, 0.15),
}

SQL_SINK = ("sql.execute", ("builds a SQL query from input", "high", 0.85, 0.1))

_JS_SOURCE = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:query|body|params|cookies|headers|file)\b"
    r"|\blocation\s*\.\s*(?:search|hash)\b"
    r"|\bprocess\s*\.\s*argv\b"
    r"|\bwindow\s*\.\s*name\b"
)
_JS_ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
_JS_SINK = re.compile(
    r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|eval|Function)\s*\("
    r"|\.\s*(?:query|execute)\s*\("
)
_JS_FUNCTION_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


def _qualified(node: ast.AST) -> str:
    """Dotted name for ``a.b.c`` expressions; empty for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _qualified(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return ""


def _sink_meta(func: ast.AST) -> Optional[Tuple[str, Tuple[str, str, float, float]]]:
    if isinstance(func, ast.Name):
        if func.id in ("eval", "exec"):
            return func.id, SINKS[func.id]
        return None
    qualified = _qualified(func)
    if not qualified:
        return None
    parts = qualified.split(".")
    dotted = ".".join(parts[-2:]) if len(parts) >= 2 else qualified
    if dotted in SINKS:
        return dotted, SINKS[dotted]
    if parts[-1] in {"execute", "executemany"}:
        return SQL_SINK
    return None


def _source_label(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Call):
        qualified = _qualified(node.func)
        if qualified in {"input", "raw_input"}:
            return "stdin input"
        if qualified in {"os.getenv", "os.environ.get"}:
            return "environment variable"
        lowered = qualified.lower()
        if "request" in lowered or lowered.startswith("req."):
            return "HTTP request input"
    if isinstance(node, ast.Subscript):
        base = _qualified(node.value)
        lowered = base.lower()
        if lowered in {"sys.argv"} or lowered.endswith(".argv"):
            return "command-line argument"
        if lowered == "os.environ" or lowered.startswith("os.environ."):
            return "environment variable"
        if "request" in lowered or lowered.startswith("req."):
            return "HTTP request input"
    return None


def _expr_label(node: ast.AST, tainted: Dict[str, str]) -> Optional[str]:
    """Returns the source label if the expression carries tainted data."""
    if isinstance(node, ast.Name):
        return tainted.get(node.id)
    label = _source_label(node)
    if label:
        return label
    for child in ast.iter_child_nodes(node):
        inherited = _expr_label(child, tainted)
        if inherited:
            return inherited
    return None


def _walk_local(node: ast.AST):
    """Walks an expression/statement without descending into nested scopes."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for child in ast.iter_child_nodes(current):
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            stack.append(child)


def _target_names(target: ast.AST) -> List[str]:
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


def _scan_block(
    statements: List[ast.stmt],
    tainted: Dict[str, str],
    lines: List[str],
    relpath: str,
    findings: List[Finding],
    seen: Set[Tuple[str, int]],
) -> None:
    local = dict(tainted)
    for stmt in statements:
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            return

        for node in _walk_local(stmt):
            if not isinstance(node, ast.Call):
                continue
            meta = _sink_meta(node.func)
            if meta is None:
                continue
            sink_name, (description, severity, vulnerability, maliciousness) = meta
            if not any(
                _expr_label(arg, local) for arg in node.args
            ) and not _expr_label(node.func, local):
                continue
            label = next(
                (found for found in (_expr_label(arg, local) for arg in node.args) if found),
                None,
            ) or _expr_label(node.func, local)
            lineno = int(getattr(node, "lineno", None) or getattr(stmt, "lineno", 1))
            if (sink_name, lineno) in seen:
                continue
            seen.add((sink_name, lineno))
            snippet = lines[lineno - 1].strip()[:300] if 0 < lineno <= len(lines) else ""
            findings.append(
                Finding(
                    file=relpath,
                    lines=[lineno],
                    category="sast",
                    severity=severity,
                    title=f"tainted input reaches {sink_name}",
                    detail=(
                        f"Untrusted {label or 'data'} flows into {sink_name}(), which "
                        f"{description}; the value is controlled outside the program"
                    ),
                    scanner=SCANNER_NAME,
                    confidence=0.85,
                    maliciousness=maliciousness,
                    vulnerability=vulnerability,
                    snippet=snippet,
                    evidence=[
                        {
                            "kind": "dataflow",
                            "source": label or "unknown",
                            "sink": sink_name,
                            "line": lineno,
                        }
                    ],
                )
            )

        if isinstance(stmt, ast.Assign):
            label = _expr_label(stmt.value, local)
            for target in stmt.targets:
                for name in _target_names(target):
                    if label:
                        local[name] = label
                    else:
                        local.pop(name, None)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            label = _expr_label(stmt.value, local)
            for name in _target_names(stmt.target):
                if label:
                    local[name] = label
                else:
                    local.pop(name, None)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            label = _expr_label(stmt.value, local) or local.get(stmt.target.id)
            if label:
                local[stmt.target.id] = label

        # Nested scopes start untainted: a parameter is not automatically user input.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _scan_block(stmt.body, {}, lines, relpath, findings, seen)
            continue
        for field_name in ("body", "orelse", "finalbody"):
            block = getattr(stmt, field_name, None)
            if isinstance(block, list) and block:
                _scan_block(block, dict(local), lines, relpath, findings, seen)
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                _scan_block(handler.body, dict(local), lines, relpath, findings, seen)


class TaintFlowScanner:
    """Links untrusted input to code-execution, deserialization and SQL sinks."""

    name = SCANNER_NAME

    def run(self, context: ScanContext) -> ScanResult:
        findings: List[Finding] = []
        for relpath in context.file_index:
            suffix = PurePosixPath(relpath).suffix.lower()
            if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx"}:
                continue
            text = context.read_text(relpath)
            if not text:
                continue
            if suffix == ".py":
                findings.extend(self._scan_python(relpath, text))
            else:
                findings.extend(self._scan_javascript(relpath, text))
        return ScanResult(scanner=SCANNER_NAME, findings=findings)

    # -- Python ----------------------------------------------------------------
    def _scan_python(self, relpath: str, text: str) -> List[Finding]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        findings: List[Finding] = []
        _scan_block(tree.body, {}, text.splitlines(), relpath, findings, set())
        return findings

    # -- JavaScript / TypeScript ----------------------------------------------
    def _scan_javascript(self, relpath: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        tainted: Set[str] = set()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            for match in _JS_ASSIGN.finditer(line):
                variable, expression = match.group(1), match.group(2)
                if _JS_SOURCE.search(expression):
                    tainted.add(variable)
                elif not any(re.search(rf"\b{re.escape(name)}\b", expression) for name in tainted):
                    tainted.discard(variable)
            sink = _JS_SINK.search(line)
            if not sink:
                continue
            carries_taint = bool(_JS_SOURCE.search(line)) or any(
                re.search(rf"\b{re.escape(name)}\b", line) for name in tainted
            )
            if not carries_taint:
                continue
            sink_name = sink.group(0).split("(")[0].strip().lstrip(".")
            is_sql = sink_name in {"query", "execute"}
            findings.append(
                Finding(
                    file=relpath,
                    lines=[lineno],
                    category="sast",
                    severity="high" if is_sql else "critical",
                    title=f"tainted request input reaches {sink_name}",
                    detail=(
                        f"Untrusted HTTP request data flows into {sink_name}(), which "
                        f"{'builds a SQL query' if is_sql else 'runs code or a process'}"
                    ),
                    scanner=SCANNER_NAME,
                    confidence=0.8,
                    maliciousness=0.1,
                    vulnerability=0.85,
                    snippet=line.strip()[:300],
                    evidence=[
                        {
                            "kind": "dataflow",
                            "source": "HTTP request input",
                            "sink": sink_name,
                            "line": lineno,
                        }
                    ],
                )
            )
        return findings
