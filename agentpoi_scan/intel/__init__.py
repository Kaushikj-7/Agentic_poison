"""Static codebase intelligence — languages, dependencies, routes, entrypoints.

Everything here is read-only parsing of an already-extracted snapshot. Nothing
is imported, installed, built or executed, and no file is copied out of the
ephemeral workspace.
"""

from agentpoi_scan.intel.codebase import (
    CodebaseProfile,
    Dependency,
    build_codebase_profile,
    classify_file_role,
    parse_dependencies,
)

__all__ = [
    "CodebaseProfile",
    "Dependency",
    "build_codebase_profile",
    "classify_file_role",
    "parse_dependencies",
]
