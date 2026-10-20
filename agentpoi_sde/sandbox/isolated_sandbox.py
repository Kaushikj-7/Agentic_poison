"""Isolated Configuration Sandbox for verifying features in separation from primary tree."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class SandboxExecutionResult:
    """Outcome of test execution inside isolated sandbox."""

    success: bool
    exit_code: int
    output: str
    feature_name: str


class IsolatedConfigurationSandbox:
    """Executes tests and builds in an isolated temporary directory to prevent pollution."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir

    def verify_slice_in_sandbox(
        self,
        sliced_code: str,
        target_symbol: str,
        timeout_seconds: int = 15,
    ) -> Tuple[bool, str]:
        """Verifies that sliced code imports cleanly and defines target_symbol in a network-isolated environment."""
        with tempfile.TemporaryDirectory(dir=self.base_dir) as tmp_dir_str:
            tmp_path = Path(tmp_dir_str)
            comp_path = tmp_path / "component.py"
            test_path = tmp_path / "test_component.py"

            comp_path.write_text(sliced_code, encoding="utf-8")

            test_script = f"""import sys
import socket
import _socket

# Install runtime network socket blocker
def _blocked_socket(*args, **kwargs):
    raise PermissionError("Network access disabled in isolated sandbox")

for mod in (socket, _socket):
    for attr in [
        "socket",
        "SocketType",
        "create_connection",
        "create_server",
        "socketpair",
        "fromfd",
        "fromshare",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "gethostname",
        "getnameinfo",
        "getprotobyname",
        "getservbyname",
        "getservbyport",
    ]:
        if hasattr(mod, attr):
            try:
                setattr(mod, attr, _blocked_socket)
            except Exception:
                pass

try:
    socket.SocketType.connect = _blocked_socket
    socket.SocketType.bind = _blocked_socket
    socket.SocketType.listen = _blocked_socket
    socket.SocketType.send = _blocked_socket
    socket.SocketType.recv = _blocked_socket
except Exception:
    pass

try:
    import component
except Exception as exc:
    print(f"IMPORT_ERROR: {{type(exc).__name__}}: {{exc}}", file=sys.stderr)
    sys.exit(1)

target = "{target_symbol}"
if "." in target:
    parts = target.split(".")
    obj = component
    for part in parts:
        if not hasattr(obj, part):
            print(f"SYMBOL_ERROR: Symbol '{{part}}' not found in '{{obj}}'", file=sys.stderr)
            sys.exit(2)
        obj = getattr(obj, part)
else:
    if not hasattr(component, target):
        print(f"SYMBOL_ERROR: Symbol '{{target}}' not found in component", file=sys.stderr)
        sys.exit(2)
    obj = getattr(component, target)

import inspect
if callable(obj) and not inspect.isclass(obj):
    try:
        sig = inspect.signature(obj)
        req_params = [
            p for p in sig.parameters.values()
            if p.default == inspect.Parameter.empty
            and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]
        if len(req_params) == 0:
            obj()
    except Exception as exc:
        print(f"CALL_ERROR: {{type(exc).__name__}}: {{exc}}", file=sys.stderr)
        sys.exit(3)

print("VERIFICATION_SUCCESS")
sys.exit(0)
"""
            test_path.write_text(test_script, encoding="utf-8")

            env = os.environ.copy()
            env["PYTHONPATH"] = str(tmp_path)

            cmd = [sys.executable, str(test_path)]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(tmp_path),
                    env=env,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                return False, f"Sandbox verification timed out after {timeout_seconds} seconds"
            except Exception as exc:
                return False, f"Subprocess execution error: {exc}"

            if proc.returncode == 0 and "VERIFICATION_SUCCESS" in proc.stdout:
                return True, "OK"

            err_msg = proc.stderr.strip() or proc.stdout.strip()
            return False, err_msg or f"Verification script exited with code {proc.returncode}"

    def run_test_in_isolation(
        self,
        feature_name: str,
        test_files: Dict[str, str],
        source_files: Dict[str, str],
        timeout_seconds: int = 30,
    ) -> SandboxExecutionResult:
        """Sets up isolated directory, writes sources/tests, and executes pytest."""
        with tempfile.TemporaryDirectory(dir=self.base_dir) as tmp_dir_str:
            tmp_path = Path(tmp_dir_str)
            self._write_files(tmp_path, source_files)
            self._write_files(tmp_path, test_files)

            return self._execute_pytest(tmp_path, feature_name, timeout_seconds)

    def _write_files(self, base_path: Path, files: Dict[str, str]) -> None:
        """Writes dictionary of relative path -> content to disk with containment check."""
        resolved_base = base_path.resolve()
        for rel_path, content in files.items():
            norm = rel_path.replace("\\", "/").strip()
            if norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":"):
                raise ValueError(f"Security error: absolute path rejected in sandbox: {rel_path}")
            dest = (base_path / rel_path).resolve()
            try:
                if not dest.is_relative_to(resolved_base):
                    raise ValueError(f"Security error: sandbox path traversal rejected: {rel_path}")
            except AttributeError:
                import os
                if os.path.commonpath([str(resolved_base), str(dest)]) != str(resolved_base):
                    raise ValueError(f"Security error: sandbox path traversal rejected: {rel_path}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

    def _execute_pytest(self, tmp_path: Path, feature_name: str, timeout: int) -> SandboxExecutionResult:
        """Executes pytest against the isolated directory."""
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(tmp_path),
            "-v",
            "--tb=short",
            "-o",
            f"cache_dir={tmp_path / '.pytest_cache'}",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(tmp_path),
                timeout=timeout,
            )
            output = proc.stdout + "\n" + proc.stderr
            return SandboxExecutionResult(
                success=(proc.returncode == 0),
                exit_code=proc.returncode,
                output=output,
                feature_name=feature_name,
            )
        except subprocess.TimeoutExpired:
            return SandboxExecutionResult(
                success=False,
                exit_code=124,
                output=f"Execution timed out after {timeout} seconds",
                feature_name=feature_name,
            )
