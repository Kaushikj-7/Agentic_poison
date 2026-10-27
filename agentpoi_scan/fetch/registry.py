"""Scan target registry — OSS-Scanner-style ``project.yaml`` enrollment records.

One directory per target (``scan_registry/<name>/project.yaml``), validated the
way ``anthropics/oss-scanner``'s ``tools/validate.py`` validates enrollments,
minus the email/PGP keys we do not use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

import yaml

from agentpoi_scan.fetch.snapshot_client import parse_repo_slug


@dataclass
class ScanTarget:
    name: str
    repo_url: str
    branch: str = ""
    repo_slug: str = ""
    threat_model: str = ""
    disabled: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "repo_slug": self.repo_slug,
            "threat_model": self.threat_model,
            "disabled": self.disabled,
        }


@dataclass
class RegistryLoadResult:
    targets: List[ScanTarget] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _parse_project(name: str, payload: dict) -> Tuple[ScanTarget, List[str]]:
    errors: List[str] = []
    repo = payload.get("repo")
    if not repo or not isinstance(repo, str):
        errors.append(f"{name}: 'repo' is required")
        repo = ""
    slug = ""
    if repo:
        try:
            slug = parse_repo_slug(repo)
        except Exception as exc:  # noqa: BLE001 - registry validation reports all failures
            errors.append(f"{name}: invalid repo URL: {exc}")
    branch = ""
    if isinstance(repo, str) and "#branch:" in repo:
        repo, _, ref = repo.partition("#branch:")
        repo, branch = repo.strip(), ref.strip()
        try:
            slug = parse_repo_slug(repo)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: invalid repo URL: {exc}")
    threat_model = payload.get("threat_model") or ""
    if threat_model and not isinstance(threat_model, str):
        errors.append(f"{name}: 'threat_model' must be a path string")
    return (
        ScanTarget(
            name=name,
            repo_url=repo,
            branch=branch,
            repo_slug=slug,
            threat_model=threat_model,
            disabled=bool(payload.get("disabled", False)),
        ),
        errors,
    )


def load_scan_registry(registry_dir: str | Path) -> RegistryLoadResult:
    """Loads and validates every ``scan_registry/<name>/project.yaml``."""
    registry_dir = Path(registry_dir)
    result = RegistryLoadResult()
    if not registry_dir.is_dir():
        result.errors.append(f"registry directory not found: {registry_dir}")
        return result
    for project_yaml in sorted(registry_dir.glob("*/project.yaml")):
        name = project_yaml.parent.name
        try:
            payload = yaml.safe_load(project_yaml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            result.errors.append(f"{name}: invalid YAML: {exc}")
            continue
        if not isinstance(payload, dict):
            result.errors.append(f"{name}: project.yaml must be a mapping")
            continue
        target, errors = _parse_project(name, payload)
        result.errors.extend(errors)
        if not errors:
            result.targets.append(target)
    for orphan in sorted(registry_dir.glob("*/")):
        if not (orphan / "project.yaml").exists():
            result.errors.append(f"{orphan.name}: directory without project.yaml")
    return result


def write_project_template(registry_dir: str | Path, name: str, repo_url: str) -> Path:
    """Writes a starter ``project.yaml`` for a new scan target."""
    project_dir = Path(registry_dir) / name
    project_dir.mkdir(parents=True, exist_ok=True)
    path = project_dir / "project.yaml"
    payload = {
        "repo": repo_url,
        "primary_contact": "you@example.org",
        "disabled": False,
    }
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    return path
