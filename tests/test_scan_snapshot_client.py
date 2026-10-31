"""Offline (fake-session) tests for agentpoi_scan.fetch.snapshot_client."""

import pytest

from agentpoi_scan.fetch.snapshot_client import (
    SnapshotClient,
    SnapshotError,
    parse_repo_branch,
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
        self.request_headers = []

    def get(self, url, timeout=30.0, allow_redirects=True, headers=None):
        self.calls.append(url)
        self.request_headers.append(headers or {})
        return self.routes.get(url, _Response(status_code=404))


def test_parse_repo_slug_variants():
    assert parse_repo_slug("https://github.com/owner/repo") == "owner/repo"
    assert parse_repo_slug("https://github.com/owner/repo.git") == "owner/repo"
    slug_with_branch = parse_repo_slug("https://www.github.com/owner/repo/tree/main")
    assert slug_with_branch == "owner/repo"
    assert slug_with_branch.branch == "main"
    assert parse_repo_slug("owner/repo") == "owner/repo"


def test_parse_repo_slug_extracts_nested_branch():
    url = "https://github.com/Kaushikj-7/Agentic_poison/tree/feat/repo-scan-workspace-report"
    slug = parse_repo_slug(url)
    assert slug == "Kaushikj-7/Agentic_poison"
    assert slug.branch == "feat/repo-scan-workspace-report"
    assert parse_repo_branch(url) == "feat/repo-scan-workspace-report"
    assert parse_repo_branch("https://github.com/owner/repo") is None


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


def test_github_token_is_sent_on_api_requests():
    session = _FakeSession({
        "https://api.github.com/repos/owner/repo/commits/HEAD": _Response(json_data={"sha": "abc123"}),
    })
    SnapshotClient(session=session, token="test-token").resolve_commit("owner/repo")
    assert session.request_headers[0]["Authorization"] == "Bearer test-token"
    assert session.request_headers[0]["Accept"] == "application/vnd.github+json"


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


def test_fetch_extracts_branch_from_tree_url(tmp_path):
    commit_url = "https://api.github.com/repos/owner/repo/commits/feat/cool-feature"
    tar_url = "https://api.github.com/repos/owner/repo/tarball/feedcafe1234"
    session = _FakeSession({
        commit_url: _Response(json_data={"sha": "feedcafe1234"}),
        tar_url: _Response(content=b"branch-tar-content"),
    })
    client = SnapshotClient(session=session)
    snapshot = client.fetch("https://github.com/owner/repo/tree/feat/cool-feature", dest_dir=tmp_path)
    assert snapshot.commit_sha == "feedcafe1234"
    assert snapshot.repo == "owner/repo"
    assert session.calls == [commit_url, tar_url]
