"""Pytest configuration and sandbox compatibility hooks."""

import os
import sys

# Ensure workspace root is in sys.path
workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)

# Patch os.stat for drive root permissions in sandboxed runner
_orig_stat = os.stat


def _safe_stat(path, *args, **kwargs):
    try:
        return _orig_stat(path, *args, **kwargs)
    except PermissionError:
        path_str = str(path).rstrip("\\/")
        if path_str in ("E:", "E:\\", "C:", "C:\\"):
            return _orig_stat(workspace_root)
        raise


os.stat = _safe_stat
