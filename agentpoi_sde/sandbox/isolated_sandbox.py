"""Isolated Configuration Sandbox for verifying features in separation from primary tree."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


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
        """Writes dictionary of relative path -> content to disk."""
        for rel_path, content in files.items():
            dest = base_path / rel_path
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
