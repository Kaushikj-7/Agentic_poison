"""Architecture policy registry and path classification predicates.

Holds the declarative architecture invariants (layer roots, forbidden edges, protected
paths, test markers) and the pure predicates used by the invariant verifier. The defaults
here describe a generic layered service repository; production users supply their own
policy via ``ArchitecturePolicy``.
"""

import ast
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

from agentpoi_sde.config_loader import get_protected_paths, get_test_markers
from agentpoi_sde.domain import ArchitecturePolicy

DEFAULT_LAYER_ROOTS: Dict[str, str] = {
    "core": "core",
    "domain": "domain",
    "api": "api",
}
DEFAULT_FORBIDDEN_EDGES: Tuple[Tuple[str, str], ...] = (
    ("core", "api"),
    ("domain", "api"),
)

# Credential material that must never appear in a mutation (I3).
# The name prefix is matched without a leading \b so SCREAMING_SNAKE constants such as
# ``DEPLOY_API_KEY`` are caught (a preceding ``_`` is a word character, so \b would fail).
SECRET_PATTERNS: Tuple[str, ...] = (
    r"(?i)[A-Za-z0-9_]*(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|"
    r"client[_-]?secret|password|passwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"AKIA[0-9A-Z]{16}",                       # AWS access key id
    r"sk-[A-Za-z0-9_\-]{16,}",                 # OpenAI-style key
    r"ghp_[A-Za-z0-9]{20,}",                   # GitHub personal access token
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",           # Slack token
    r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{16,}",
)

# Network endpoints referenced in code (for egress confinement, I3).
URL_PATTERN = r"https?://[^\s'\"<>)]+"

# Imperative verbs that a T2 payload uses to steer the agent (Intent Shield signal).
INJECTION_MARKERS: Tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard the above",
    "system override",
    "new instructions",
    "you must now",
    "do not tell",
    "without asking",
    "skip the tests",
    "disable the",
    "exfiltrate",
    "send the token",
    "curl ",
    "base64 -d",
    "rm -rf",
    "chmod +x",
    "hidden instruction",
    "assistant:",
    "note to ai",
    "note to the ai",
    "bypass invariants",
    "disable invariants",
)


def default_policy(
    layer_roots: Optional[dict] = None,
    forbidden_edges: Optional[Tuple[Tuple[str, str], ...]] = None,
) -> ArchitecturePolicy:
    """Build an ``ArchitecturePolicy`` with the platform's default protected/test patterns."""
    layers = layer_roots if layer_roots is not None else dict(DEFAULT_LAYER_ROOTS)
    edges = forbidden_edges if forbidden_edges is not None else tuple(DEFAULT_FORBIDDEN_EDGES)
    return ArchitecturePolicy(
        layer_roots=dict(layers),
        forbidden_edges=tuple(edges),
        protected_paths=tuple(get_protected_paths()),
        test_markers=tuple(get_test_markers()),
    )


def path_matches_any(path: str, patterns: Tuple[str, ...]) -> bool:
    """Return True when ``path`` matches any glob pattern (normalised to ``/``)."""
    norm = path.replace("\\", "/")
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        if fnmatch(norm, pat) or fnmatch(norm, pat.rstrip("/*")):
            return True
        # Allow "**/x" to also match a bare "x" at the repository root.
        if pat.startswith("**/") and fnmatch(norm, pat[3:]):
            return True
    return False


def is_policy_file(path: str, policy: ArchitecturePolicy) -> bool:
    """Return True when ``path`` is a protected agent/CI/policy artefact (I1)."""
    return path_matches_any(path, policy.protected_paths)


def is_test_file(path: str, policy: ArchitecturePolicy) -> bool:
    """Return True when ``path`` is part of the test oracle (I2)."""
    norm = path.replace("\\", "/")
    filename = norm.rsplit("/", 1)[-1]
    for marker in policy.test_markers:
        if marker.startswith("/") or marker.startswith("*"):
            continue
        if marker.endswith("/"):
            if f"/{marker}" in f"/{norm}":
                return True
        elif marker.endswith(".py"):
            if norm.endswith(marker) or filename.startswith(marker):
                return True
        elif filename.startswith(marker) or f"/{marker}" in f"/{norm}":
            return True
    return False


def forbidden_edge_reason(
    policy: ArchitecturePolicy,
    importer_path: str,
    imported_path: str,
) -> Optional[str]:
    """Return a human-readable reason when an import edge violates the policy."""
    importer_layer = policy.layer_of(importer_path)
    imported_layer = policy.layer_of(imported_path)
    if importer_layer is None or imported_layer is None:
        return None
    if (importer_layer, imported_layer) in policy.forbidden_edges:
        return (
            f"forbidden dependency edge: layer '{importer_layer}' must not import "
            f"layer '{imported_layer}' ('{importer_path}' -> '{imported_path}')"
        )
    return None


def collect_secret_signals(text: str) -> List[str]:
    """Return the distinct secret-like signals detected in ``text`` (I3)."""
    import re

    found: List[str] = []
    for pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            snippet = match.group(0)
            redacted = snippet[:24].split("=")[0].split(":")[0]
            if redacted not in found:
                found.append(redacted)
    return found


def _evaluate_ast_string_additions(source: str) -> List[str]:
    """Extract evaluated concatenated string values from AST additions."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    def _eval_const_str(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = _eval_const_str(node.left)
            right = _eval_const_str(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    results: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            val = _eval_const_str(node)
            if val is not None:
                results.append(val)
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    parts.append(part.value)
            if parts:
                results.append("".join(parts))
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                sep_val = _eval_const_str(node.func.value)
                args = list(node.args)
                if sep_val is None and isinstance(node.func.value, ast.Name) and node.func.value.id == "str":
                    if len(args) >= 2:
                        sep_val = _eval_const_str(args[0])
                        args = args[1:]
                if sep_val is not None and args:
                    arg0 = args[0]
                    if isinstance(arg0, (ast.List, ast.Tuple)):
                        parts = []
                        all_consts = True
                        for elt in arg0.elts:
                            elt_val = _eval_const_str(elt)
                            if elt_val is not None:
                                parts.append(elt_val)
                            else:
                                all_consts = False
                                break
                        if all_consts and parts:
                            results.append(sep_val.join(parts))
    return results


def collect_urls(text: str) -> List[str]:
    """Return the distinct URLs referenced in ``text`` (I3)."""
    import re

    urls = set(re.findall(URL_PATTERN, text))
    for concatenated_str in _evaluate_ast_string_additions(text):
        for matched in re.findall(URL_PATTERN, concatenated_str):
            urls.add(matched)
    return sorted(urls)


def injection_marker_hits(text: str) -> List[str]:
    """Return the distinct injection markers present in ``text`` (Intent Shield)."""
    lowered = text.lower()
    return [marker for marker in INJECTION_MARKERS if marker in lowered]
