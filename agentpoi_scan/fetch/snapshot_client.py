"""Fetch a repository snapshot as a tarball at one pinned commit (Zone 1 only).

The only component with network access. Uses the GitHub API tarball endpoint
for a single resolved commit SHA — never a full clone — so no hooks, filters
or helpers from the target repository can ever execute. The HTTP layer is
injected (``session``) so tests run fully offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol
from urllib.parse import urlparse

DEFAULT_API = "https://api.github.com"


class HttpSession(Protocol):
    """Minimal requests-like session surface (for injection in tests)."""

    def get(self, url: str, timeout: float = 30.0, allow_redirects: bool = True):  # noqa: D102
        ...


class SnapshotError(Exception):
    pass


@dataclass
class Snapshot:
    tarball_path: Path
    commit_sha: str
    repo: str


def parse_repo_slug(repo_url: str) -> str:
    """Extracts 'owner/name' from a GitHub URL or bare ``owner/name`` slug."""
    url = repo_url.strip()
    if "//" not in url:
        # bare owner/name (or github.com/owner/name) — normalize with a scheme
        if "/" not in url:
            raise SnapshotError(f"cannot parse owner/name from: {repo_url!r}")
        if url.count("/") == 1 and "." not in url.split("/")[0]:
            return url
        url = f"https://{url}"
    parsed = urlparse(url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        raise SnapshotError(
            f"only github.com repositories are supported, got: {parsed.hostname}"
        )
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise SnapshotError(f"cannot parse owner/name from: {repo_url!r}")
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    return f"{owner}/{name}"


class SnapshotClient:
    """Downloads a repo tarball pinned to one commit SHA."""

    def __init__(
        self,
        api_base: str = DEFAULT_API,
        session: Optional[HttpSession] = None,
        token: Optional[str] = None,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.token = token
        if session is None:
            import requests

            session = requests.Session()
        self.session = session

    # -- internal -------------------------------------------------------------
    def _headers(self, accept: str) -> dict:
        headers = {"Accept": accept, "User-Agent": "agentpoi-scan/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get(self, url: str, accept: str):
        response = self.session.get(url, timeout=60.0, allow_redirects=True)
        if response.status_code == 401:
            raise SnapshotError("authentication failed (bad or expired token)")
        if response.status_code == 404:
            raise SnapshotError(f"not found: {url}")
        if response.status_code in (403, 429):
            raise SnapshotError("rate limited by the GitHub API; set GITHUB_TOKEN")
        if response.status_code != 200:
            raise SnapshotError(f"unexpected status {response.status_code} for {url}")
        return response

    # -- public ---------------------------------------------------------------
    def resolve_commit(self, repo_slug: str, ref: Optional[str] = None) -> str:
        """Resolves a branch/tag ref to a single commit SHA (defaults to HEAD)."""
        suffix = f"/commits/{ref}" if ref else "/commits/HEAD"
        url = f"{self.api_base}/repos/{repo_slug}{suffix}"
        data = self._get(url, "application/vnd.github+json").json()
        sha = data.get("sha")
        if not sha:
            raise SnapshotError("commit lookup returned no SHA")
        return sha

    def fetch(self, repo_url: str, ref: Optional[str] = None, dest_dir: Path | None = None) -> Snapshot:
        """Downloads the tarball for the resolved commit.

        No clone, no checkout: the result is a single tar file that must be
        passed through :func:`agentpoi_scan.fetch.safe_extract.extract_snapshot`
        before anything reads it.
        """
        slug = parse_repo_slug(repo_url)
        sha = self.resolve_commit(slug, ref=ref)
        dest_dir = Path(dest_dir or ".agentpoi_scan")
        dest_dir.mkdir(parents=True, exist_ok=True)
        url = f"{self.api_base}/repos/{slug}/tarball/{sha}"
        response = self._get(url, "application/vnd.github+json")
        tarball_path = dest_dir / f"{slug.replace('/', '__')}__{sha[:12]}.tar.gz"
        tarball_path.write_bytes(response.content)
        return Snapshot(tarball_path=tarball_path, commit_sha=sha, repo=slug)
