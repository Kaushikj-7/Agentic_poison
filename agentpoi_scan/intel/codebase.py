"""Static codebase intelligence for an untrusted repository snapshot.

Answers "what is this codebase?" before "is it dangerous?": which languages and
file roles exist, which dependency manifests are used and what they pull in,
which HTTP routes the application exposes, and which scripts/entrypoints run it.

All of it is read-only text/AST/regex parsing of an already-extracted snapshot.
No dependency is installed, no manifest is evaluated, no route is imported, and
nothing is executed. Numbers and paths are reported as *observations*, not
verdicts — verdicts come from the scanners.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from agentpoi_scan.scan.base import LoadError, ScanContext

MAX_DEPENDENCIES = 2000
MAX_ROUTES = 500
MAX_ENTRYPOINTS = 200

# -- languages and roles -------------------------------------------------------

LANGUAGE_BY_SUFFIX: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".php": "PHP",
    ".phtml": "PHP",
    ".rb": "Ruby",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".lua": "Lua",
    ".pl": "Perl",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".scala": "Scala",
}

SPECIAL_LANGUAGE_BY_NAME: Dict[str, str] = {
    "dockerfile": "Docker",
    "makefile": "Make",
    "gnumakefile": "Make",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
    "procfile": "Config",
}

VENDOR_DIRS = {
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "bower_components",
    "site-packages",
    ".venv",
    "venv",
}
GENERATED_DIRS = {"dist", "build", "out", "coverage", ".next", "target"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs"}
CI_DIRS = {".github", ".circleci", ".gitlab", ".buildkite", ".azure"}
CI_FILES = {
    ".travis.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "appveyor.yml",
    ".gitlab-ci.yml",
}
CONFIG_SUFFIXES = {
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".json",
    ".lock",
    ".env",
    ".properties",
    ".xml",
    ".gradle",
}


def classify_file_role(relpath: str) -> str:
    """Groups a snapshot path into a coarse operational role."""
    pure = PurePosixPath(relpath)
    parts = [p.lower() for p in pure.parts[:-1]]
    name = pure.name.lower()
    suffix = pure.suffix.lower()

    if any(part in VENDOR_DIRS for part in parts):
        return "vendor"
    if any(part in TEST_DIRS for part in parts) or name.startswith("test_") or (
        name.endswith(("_test.py", "_test.go", "_test.rb", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    ):
        return "test"
    if any(part in CI_DIRS for part in parts) or name in CI_FILES:
        return "ci"
    if "docs" in parts or "doc" in parts or suffix in {".md", ".rst", ".adoc"}:
        return "docs"
    if any(part in GENERATED_DIRS for part in parts):
        return "generated"
    if name in {"dockerfile", "makefile", "gnumakefile"} or suffix in CONFIG_SUFFIXES or name.startswith("requirements"):
        return "config"
    if name in SPECIAL_LANGUAGE_BY_NAME or suffix in LANGUAGE_BY_SUFFIX:
        return "source"
    return "other"


def _language_of(relpath: str) -> Optional[str]:
    pure = PurePosixPath(relpath)
    by_name = SPECIAL_LANGUAGE_BY_NAME.get(pure.name.lower())
    if by_name:
        return by_name
    return LANGUAGE_BY_SUFFIX.get(pure.suffix.lower())


# -- dependencies --------------------------------------------------------------

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)$")
_VCS_RE = re.compile(
    r"(?:git\+|hg\+|svn\+|bzr\+|https?://|git://|ssh://|github:|gitlab:|bitbucket:)",
    re.IGNORECASE,
)
_EXACT_PYPI_RE = re.compile(r"^===?\s*[0-9]")
_EXACT_NPM_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_EXACT_COMPOSER_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_EXACT_GEM_RE = re.compile(r"^=?\s*\d+\.\d+")


@dataclass
class Dependency:
    """One declared dependency, with the manifest line it came from."""

    name: str
    specifier: str
    ecosystem: str
    manifest: str
    line: int
    raw: str
    pinned: bool
    source: str = "registry"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "specifier": self.specifier,
            "ecosystem": self.ecosystem,
            "manifest": self.manifest,
            "line": self.line,
            "raw": self.raw,
            "pinned": self.pinned,
            "source": self.source,
        }


def _read(context: ScanContext, relpath: str) -> Optional[str]:
    try:
        return context.read_text(relpath)
    except (LoadError, OSError):
        return None


def _line_text(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:300]
    return ""


def _find_line(text: str, needle: str) -> int:
    for lineno, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return lineno
    return 1


def _classify_source(specifier: str) -> str:
    if _VCS_RE.search(specifier):
        return "vcs"
    if specifier.strip().startswith((".", "/", "file:", "path:", "link:", "workspace:")):
        return "path"
    return "registry"


def _is_pinned(specifier: str, ecosystem: str) -> bool:
    spec = specifier.strip()
    if not spec:
        return False
    if ecosystem == "pypi":
        return bool(_EXACT_PYPI_RE.match(spec))
    if ecosystem == "npm":
        return bool(_EXACT_NPM_RE.match(spec))
    if ecosystem == "composer":
        return bool(_EXACT_COMPOSER_RE.match(spec))
    if ecosystem == "rubygems":
        return bool(_EXACT_GEM_RE.match(spec))
    if ecosystem in {"gomod", "cargo"}:
        return True  # module resolution is lockfile-pinned by design
    return False


def _requirement_dep(spec: str, manifest: str, lineno: int, raw: str) -> Optional[Dependency]:
    line = spec.split(";", 1)[0].strip()
    if not line:
        return None
    source = _classify_source(line)
    if source != "registry":
        tail = line.rstrip("/").split("/")[-1]
        return Dependency(
            name=tail or line[:60],
            specifier=line,
            ecosystem="pypi",
            manifest=manifest,
            line=lineno,
            raw=raw[:300],
            pinned=False,
            source=source,
        )
    match = _REQ_NAME_RE.match(line)
    if not match:
        return None
    name, specifier = match.group(1), (match.group(2) or "").strip()
    if name.lower() in {"python", "pip", "setuptools", "wheel"} and not specifier:
        return None
    return Dependency(
        name=name,
        specifier=specifier,
        ecosystem="pypi",
        manifest=manifest,
        line=lineno,
        raw=raw[:300],
        pinned=_is_pinned(specifier, "pypi"),
        source=_classify_source(specifier),
    )


def _parse_requirements(relpath: str, text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            continue
        if stripped.startswith(("-e ", "--editable")):
            deps.append(
                Dependency(
                    name=stripped.split()[-1].rstrip("/").split("/")[-1] or stripped,
                    specifier=stripped,
                    ecosystem="pypi",
                    manifest=relpath,
                    line=lineno,
                    raw=raw.strip()[:300],
                    pinned=False,
                    source="vcs" if _VCS_RE.search(stripped) else "path",
                )
            )
            continue
        if stripped.startswith("-"):
            continue
        dep = _requirement_dep(stripped, relpath, lineno, raw)
        if dep is not None:
            deps.append(dep)
    return deps


def _parse_package_json(relpath: str, text: str) -> List[Dependency]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    deps: List[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            specifier = str(spec)
            lineno = _find_line(text, f'"{name}"')
            deps.append(
                Dependency(
                    name=str(name),
                    specifier=specifier,
                    ecosystem="npm",
                    manifest=relpath,
                    line=lineno,
                    raw=_line_text(text, lineno) or f"{name}: {specifier}",
                    pinned=_is_pinned(specifier, "npm"),
                    source=_classify_source(specifier),
                )
            )
    return deps


def _parse_pyproject(relpath: str, text: str) -> List[Dependency]:
    if tomllib is None:  # pragma: no cover - Python 3.10
        return _parse_pyproject_fallback(relpath, text)
    try:
        data = tomllib.loads(text)
    except (ValueError, AttributeError):
        return []
    deps: List[Dependency] = []
    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        lineno = _find_line(text, str(spec))
        dep = _requirement_dep(str(spec), relpath, lineno, _line_text(text, lineno) or str(spec))
        if dep is not None:
            deps.append(dep)
    for specs in (project.get("optional-dependencies") or {}).values():
        for spec in specs or []:
            lineno = _find_line(text, str(spec))
            dep = _requirement_dep(str(spec), relpath, lineno, _line_text(text, lineno) or str(spec))
            if dep is not None:
                deps.append(dep)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for name, spec in (poetry.get("dependencies") or {}).items():
        if str(name).lower() == "python":
            continue
        if isinstance(spec, dict):
            specifier = str(spec.get("version") or spec.get("git") or spec.get("path") or "")
            source = "vcs" if spec.get("git") else "path" if spec.get("path") else "registry"
        else:
            specifier = str(spec)
            source = _classify_source(specifier)
        lineno = _find_line(text, f'"{name}"')
        deps.append(
            Dependency(
                name=str(name),
                specifier=specifier,
                ecosystem="pypi",
                manifest=relpath,
                line=lineno,
                raw=_line_text(text, lineno) or f"{name} = {specifier}",
                pinned=_is_pinned(specifier, "pypi"),
                source=source,
            )
        )
    return deps


def _parse_pyproject_fallback(relpath: str, text: str) -> List[Dependency]:
    """Best-effort dependency extraction when ``tomllib`` is unavailable."""
    deps: List[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        match = re.match(r"""^\s*["']([A-Za-z0-9][\w.\-]*\[[^\]]*\]|[A-Za-z0-9][\w.\-]*)\s*([<>=!~^].*)["'],?\s*$""", raw)
        if not match:
            continue
        name, specifier = match.group(1), match.group(2).rstrip("\",").strip()
        deps.append(
            Dependency(
                name=name,
                specifier=specifier,
                ecosystem="pypi",
                manifest=relpath,
                line=lineno,
                raw=raw.strip()[:300],
                pinned=_is_pinned(specifier, "pypi"),
                source="registry",
            )
        )
    return deps


def _parse_composer(relpath: str, text: str) -> List[Dependency]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    deps: List[Dependency] = []
    for section in ("require", "require-dev"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            lowered = str(name).lower()
            if lowered == "php" or lowered.startswith("ext-") or lowered.startswith("lib-"):
                continue
            specifier = str(spec)
            lineno = _find_line(text, f'"{name}"')
            deps.append(
                Dependency(
                    name=str(name),
                    specifier=specifier,
                    ecosystem="composer",
                    manifest=relpath,
                    line=lineno,
                    raw=_line_text(text, lineno) or f"{name}: {specifier}",
                    pinned=_is_pinned(specifier, "composer"),
                    source=_classify_source(specifier),
                )
            )
    return deps


def _parse_go_mod(relpath: str, text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    in_require = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.split("//", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("require "):
            entry = stripped[len("require "):].strip()
        elif in_require:
            entry = stripped
        else:
            continue
        parts = entry.split()
        if len(parts) < 2:
            continue
        deps.append(
            Dependency(
                name=parts[0],
                specifier=parts[1],
                ecosystem="gomod",
                manifest=relpath,
                line=lineno,
                raw=raw.strip()[:300],
                pinned=True,
                source="registry",
            )
        )
    return deps


def _parse_gemfile(relpath: str, text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    pattern = re.compile(r"""^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.split("#", 1)[0]
        match = pattern.match(stripped)
        if not match:
            continue
        name, specifier = match.group(1), (match.group(2) or "").strip()
        source = "vcs" if _VCS_RE.search(stripped) else _classify_source(specifier)
        deps.append(
            Dependency(
                name=name,
                specifier=specifier,
                ecosystem="rubygems",
                manifest=relpath,
                line=lineno,
                raw=raw.strip()[:300],
                pinned=_is_pinned(specifier, "rubygems"),
                source=source,
            )
        )
    return deps


def _parse_cargo(relpath: str, text: str) -> List[Dependency]:
    if tomllib is None:  # pragma: no cover - Python 3.10
        return []
    try:
        data = tomllib.loads(text)
    except (ValueError, AttributeError):
        return []
    deps: List[Dependency] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(spec, dict):
                specifier = str(spec.get("version") or spec.get("git") or spec.get("path") or "")
                source = "vcs" if spec.get("git") else "path" if spec.get("path") else "registry"
            else:
                specifier = str(spec)
                source = _classify_source(specifier)
            lineno = _find_line(text, f'"{name}"')
            deps.append(
                Dependency(
                    name=str(name),
                    specifier=specifier,
                    ecosystem="cargo",
                    manifest=relpath,
                    line=lineno,
                    raw=_line_text(text, lineno) or f"{name} = {specifier}",
                    pinned=True,
                    source=source,
                )
            )
    return deps


def _manifest_ecosystem(relpath: str) -> Optional[str]:
    pure = PurePosixPath(relpath)
    name = pure.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi"
    if name == "pyproject.toml":
        return "pypi"
    if name == "package.json":
        return "npm"
    if name == "composer.json":
        return "composer"
    if name == "go.mod":
        return "gomod"
    if name == "gemfile":
        return "rubygems"
    if name == "cargo.toml":
        return "cargo"
    return None


def parse_dependencies(context: ScanContext) -> List[Dependency]:
    """Parses every supported dependency manifest in the snapshot (read-only)."""
    deps: List[Dependency] = []
    for relpath in context.file_index:
        if any(part.lower() in VENDOR_DIRS for part in PurePosixPath(relpath).parts[:-1]):
            continue
        ecosystem = _manifest_ecosystem(relpath)
        if ecosystem is None:
            continue
        text = _read(context, relpath)
        if not text:
            continue
        name = PurePosixPath(relpath).name.lower()
        if name.startswith("requirements"):
            parsed = _parse_requirements(relpath, text)
        elif name == "pyproject.toml":
            parsed = _parse_pyproject(relpath, text)
        elif name == "package.json":
            parsed = _parse_package_json(relpath, text)
        elif name == "composer.json":
            parsed = _parse_composer(relpath, text)
        elif name == "go.mod":
            parsed = _parse_go_mod(relpath, text)
        elif name == "gemfile":
            parsed = _parse_gemfile(relpath, text)
        elif name == "cargo.toml":
            parsed = _parse_cargo(relpath, text)
        else:
            parsed = []
        deps.extend(parsed)
        if len(deps) >= MAX_DEPENDENCIES:
            return deps[:MAX_DEPENDENCIES]
    return deps


# -- routes --------------------------------------------------------------------

_FLASK_ROUTE = re.compile(
    r"""@\s*[\w.]+\.route\(\s*["']([^"']+)["'](?:[^)]*?methods\s*=\s*\[([^\]]*)\])?"""
)
_FASTAPI_ROUTE = re.compile(r"""@\s*[\w.]+\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']""")
_DJANGO_ROUTE = re.compile(r"""^\s*(?:path|re_path|url)\(\s*r?["']([^"']*)["']""")
_EXPRESS_ROUTE = re.compile(
    r"""\b[\w$.]+\.(get|post|put|patch|delete|all|use)\(\s*["'](/[^"']*)["']"""
)
_LARAVEL_ROUTE = re.compile(r"""Route::(get|post|put|patch|delete|any|match)\(\s*["']([^"']+)["']""")
_GO_ROUTE = re.compile(r"""\bHandle(?:Func)?\(\s*["']([^"']+)["']""")


def _route(framework: str, method: str, path: str, relpath: str, lineno: int) -> Dict[str, Any]:
    return {
        "framework": framework,
        "method": method.upper(),
        "path": path,
        "file": relpath,
        "line": lineno,
    }


def detect_routes(context: ScanContext) -> List[Dict[str, Any]]:
    """Statically harvest HTTP route declarations (no framework import)."""
    routes: List[Dict[str, Any]] = []
    for relpath in context.file_index:
        suffix = PurePosixPath(relpath).suffix.lower()
        if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go"}:
            continue
        text = _read(context, relpath)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if suffix == ".py":
                match = _FLASK_ROUTE.search(line)
                if match:
                    methods = match.group(2) or "GET"
                    for method in re.findall(r"[A-Z]+", methods.upper()) or ["GET"]:
                        routes.append(_route("flask", method, match.group(1), relpath, lineno))
                match = _FASTAPI_ROUTE.search(line)
                if match:
                    routes.append(
                        _route("flask/fastapi", match.group(1), match.group(2), relpath, lineno)
                    )
                match = _DJANGO_ROUTE.search(line)
                if match:
                    routes.append(_route("django", "ANY", match.group(1), relpath, lineno))
            elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
                match = _EXPRESS_ROUTE.search(line)
                if match:
                    routes.append(_route("express", match.group(1), match.group(2), relpath, lineno))
            elif suffix == ".php":
                match = _LARAVEL_ROUTE.search(line)
                if match:
                    routes.append(_route("laravel", match.group(1), match.group(2), relpath, lineno))
            elif suffix == ".go":
                match = _GO_ROUTE.search(line)
                if match:
                    routes.append(_route("go-http", "ANY", match.group(1), relpath, lineno))
            if len(routes) >= MAX_ROUTES:
                return routes[:MAX_ROUTES]
    return routes


# -- scripts and entrypoints ---------------------------------------------------

_MAKE_TARGET = re.compile(r"^([A-Za-z0-9][\w.-]*)\s*:(?!=)")
_PROC_FILE = re.compile(r"^([A-Za-z0-9_-]+)\s*:\s*(.+)$")
_DOCKER_RUN = re.compile(r"^\s*(?:CMD|ENTRYPOINT)\s+(.+)$", re.IGNORECASE)


def detect_scripts(context: ScanContext) -> tuple[Dict[str, Dict[str, str]], List[str]]:
    """Returns declared run scripts per manifest plus the manifest inventory."""
    scripts: Dict[str, Dict[str, str]] = {}
    manifests: List[str] = []
    for relpath in context.file_index:
        ecosystem = _manifest_ecosystem(relpath)
        if ecosystem is not None:
            manifests.append(relpath)
        pure = PurePosixPath(relpath)
        name = pure.name.lower()
        text = _read(context, relpath) if name in {"package.json", "pyproject.toml", "makefile", "gnumakefile"} else None
        if not text:
            continue
        if name == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            block = (data or {}).get("scripts") if isinstance(data, dict) else None
            if isinstance(block, dict):
                scripts[relpath] = {str(k): str(v)[:200] for k, v in block.items()}
        elif name == "pyproject.toml" and tomllib is not None:
            try:
                data = tomllib.loads(text)
            except (ValueError, AttributeError):
                continue
            project_scripts = (data.get("project") or {}).get("scripts") or {}
            poetry_scripts = ((data.get("tool") or {}).get("poetry") or {}).get("scripts") or {}
            merged = {
                str(k): str(v)[:200]
                for block in (project_scripts, poetry_scripts)
                if isinstance(block, dict)
                for k, v in block.items()
            }
            if merged:
                scripts[relpath] = merged
        else:
            targets = {
                match.group(1): ""
                for line in text.splitlines()
                if (match := _MAKE_TARGET.match(line))
                and not match.group(1).startswith(".")
            }
            if targets:
                scripts[relpath] = targets
    return scripts, sorted(manifests)


def detect_entrypoints(context: ScanContext) -> List[Dict[str, Any]]:
    """Finds the places the repository says "run this" (declarative only)."""
    entrypoints: List[Dict[str, Any]] = []
    for relpath in context.file_index:
        pure = PurePosixPath(relpath)
        name = pure.name.lower()
        suffix = pure.suffix.lower()
        if name.startswith("dockerfile") or name.endswith(".dockerfile"):
            text = _read(context, relpath)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                match = _DOCKER_RUN.match(line)
                if match:
                    entrypoints.append(
                        {"file": relpath, "line": lineno, "kind": "dockerfile", "value": line.strip()[:200]}
                    )
        elif name == "procfile":
            text = _read(context, relpath)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                match = _PROC_FILE.match(line.strip())
                if match:
                    entrypoints.append(
                        {
                            "file": relpath,
                            "line": lineno,
                            "kind": f"procfile:{match.group(1)}",
                            "value": match.group(2)[:200],
                        }
                    )
        elif suffix in LANGUAGE_BY_SUFFIX or not suffix:
            text = _read(context, relpath)
            if not text:
                continue
            first_line = text.splitlines()[0] if text.splitlines() else ""
            if first_line.startswith("#!"):
                entrypoints.append(
                    {"file": relpath, "line": 1, "kind": "shebang", "value": first_line[:200]}
                )
        if len(entrypoints) >= MAX_ENTRYPOINTS:
            break
    return entrypoints[:MAX_ENTRYPOINTS]


# -- profile -------------------------------------------------------------------

@dataclass
class CodebaseProfile:
    """Read-only description of what a repository contains."""

    total_files: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    roles: Dict[str, int] = field(default_factory=dict)
    manifests: List[str] = field(default_factory=list)
    dependencies: List[Dependency] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    entrypoints: List[Dict[str, Any]] = field(default_factory=list)
    scripts: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def primary_language(self) -> str:
        if not self.languages:
            return "unknown"
        return max(self.languages.items(), key=lambda item: item[1])[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "primary_language": self.primary_language,
            "languages": dict(sorted(self.languages.items(), key=lambda kv: -kv[1])),
            "roles": dict(sorted(self.roles.items(), key=lambda kv: -kv[1])),
            "manifests": list(self.manifests),
            "dependency_count": len(self.dependencies),
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "route_count": len(self.routes),
            "routes": list(self.routes),
            "entrypoints": list(self.entrypoints),
            "scripts": {path: dict(names) for path, names in self.scripts.items()},
        }


def build_codebase_profile(context: ScanContext) -> CodebaseProfile:
    """Builds the full static profile for one extracted snapshot."""
    languages: Dict[str, int] = {}
    roles: Dict[str, int] = {}
    for relpath in context.file_index:
        language = _language_of(relpath)
        if language:
            languages[language] = languages.get(language, 0) + 1
        role = classify_file_role(relpath)
        roles[role] = roles.get(role, 0) + 1

    scripts, manifests = detect_scripts(context)
    return CodebaseProfile(
        total_files=len(context.file_index),
        languages=languages,
        roles=roles,
        manifests=manifests,
        dependencies=parse_dependencies(context),
        routes=detect_routes(context),
        entrypoints=detect_entrypoints(context),
        scripts=scripts,
    )
