"""Tests for agentpoi_scan.fetch.registry (OSS-Scanner-style enrollment records)."""

import yaml

from agentpoi_scan.fetch.registry import load_scan_registry, write_project_template


def _project_yaml(directory, name, payload):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name / "project.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_valid_registry(tmp_path):
    _project_yaml(tmp_path, "juice-shop", {"repo": "https://github.com/owner/shop", "disabled": False})
    _project_yaml(tmp_path, "dvwa", {"repo": "https://github.com/owner/dvwa#branch:master"})
    result = load_scan_registry(tmp_path)
    assert result.ok
    # glob order is deterministic: dvwa sorts before juice-shop
    by_name = sorted(result.targets, key=lambda t: t.name)
    assert [t.branch for t in by_name] == ["master", ""]
    assert by_name[0].repo_slug == "owner/dvwa"
    assert by_name[1].repo_slug == "owner/shop"


def test_missing_repo_is_a_validation_error(tmp_path):
    _project_yaml(tmp_path, "broken", {"primary_contact": "x@example.org"})
    result = load_scan_registry(tmp_path)
    assert not result.ok
    assert any("'repo' is required" in e for e in result.errors)


def test_non_github_repo_rejected(tmp_path):
    _project_yaml(tmp_path, "foreign", {"repo": "https://gitlab.com/a/b"})
    result = load_scan_registry(tmp_path)
    assert not result.ok
    assert any("gitlab" in e for e in result.errors)


def test_orphan_directory_reported(tmp_path):
    (tmp_path / "no-yaml").mkdir()
    result = load_scan_registry(tmp_path)
    assert any("without project.yaml" in e for e in result.errors)


def test_missing_registry_dir(tmp_path):
    result = load_scan_registry(tmp_path / "absent")
    assert not result.ok
    assert not result.targets


def test_write_project_template_roundtrip(tmp_path):
    path = write_project_template(tmp_path, "acme", "https://github.com/acme/acme")
    result = load_scan_registry(tmp_path)
    assert result.ok and path.exists()
    assert result.targets[0].repo_slug == "acme/acme"
