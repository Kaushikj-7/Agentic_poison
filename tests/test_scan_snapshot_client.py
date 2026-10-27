"""Offline (fake-session) tests for agentpoi_scan.fetch.snapshot_client."""

import pytest

from agentpoi_scan.fetch.snapshot_client import (
    SnapshotClient,
    SnapshotError,
    parse_repo_slug,
)


class _Response:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json = json_data
        self.content = content

    def json(self):
        return self._json


class _FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, timeout=30.0, allow_redirects=True):
        self.calls.append(url)
        return self.routes.get(url, _Response(status_code=404))


def test_parse_repo_slug_variants():
    assert parse_repo_slug("https://github.com/owner/repo") == "owner/repo"
    assert parse_repo_slug("https://github.com/owner/repo.git") == "owner/repo"
    assert parse_repo_slug("https://www.github.com/owner/repo/tree/main") == "owner/repo"
    assert parse_repo_slug("owner/repo") == "owner/repo"


def test_parse_repo_slug_rejects_non_github():
    with pytest.raises(SnapshotError, match="github.com"):
        parse_repo_slug("https://gitlab.com/owner/repo")
    with pytest.raises(SnapshotError, match="cannot parse"):
        parse_repo_slug("https://github.com/justonepart")


def test_resolve_commit_pins_a_sha():
    session = _FakeSession(
        {"https://api.github.com/repos/owner/repo/commits/main": _Response(json_data={"sha": "abc123"})}
    )
    client = SnapshotClient(session=session)
    assert client.resolve_commit("owner/repo", ref="main") == "abc123"


def test_fetch_downloads_tarball_for_pinned_sha(tmp_path):
    commit_url = "https://api.github.com/repos/owner/repo/commits/HEAD"
    tar_url = "https://api.github.com/repos/owner/repo/tarball/abc123def456"
    session = _FakeSession(
        {commit_url: _Response(json_data={"sha": "abc123def456"}), tar_url: _Response(content=b"tar-data")}
    )
    client = SnapshotClient(session=session)
    snapshot = client.fetch("https://github.com/owner/repo", dest_dir=tmp_path)
    assert snapshot.commit_sha == "abc123def456"
    assert snapshot.tarball_path.read_bytes() == b"tar-data"
    assert snapshot.repo == "owner/repo"
    # exactly two network calls, both read-only API calls: commits + tarball
    assert session.calls == [commit_url, tar_url]


def test_rate_limit_surfaces_github_token_hint():
    session = _FakeSession(
        {"https://api.github.com/repos/owner/repo/commits/HEAD": _Response(status_code=403)}
    )
    with pytest.raises(SnapshotError, match="GITHUB_TOKEN"):
        SnapshotClient(session=session).resolve_commit("owner/repo")


def test_404_raises_not_found():
    session = _FakeSession({})
    with pytest.raises(SnapshotError, match="not found"):
        SnapshotClient(session=session).resolve_commit("owner/repo")
