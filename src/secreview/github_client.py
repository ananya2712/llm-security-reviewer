"""Fetch pull requests and commits from the GitHub REST API.

For PRs and commits we request the `.diff` representation directly — exactly the
unified-diff text `diff.parse_diff` consumes. `fetch_file` pulls raw file
content at a ref (used by the eval curator to materialize the pre-fix file for
Semgrep). Auth is via `GITHUB_TOKEN` (optional for public repos).

Per PLAN's risk table, v1 does a single attempt with a clear error rather than
retries/rate-limit backoff.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
from pydantic import BaseModel

GITHUB_API = "https://api.github.com"
_DIFF_MEDIA_TYPE = "application/vnd.github.diff"
_JSON_MEDIA_TYPE = "application/vnd.github+json"
_RAW_MEDIA_TYPE = "application/vnd.github.raw"
_API_VERSION = "2022-11-28"

# "owner/repo#123"
_PR_SPEC = re.compile(r"^(?P<owner>[^/\s]+)/(?P<repo>[^/#\s]+)#(?P<number>\d+)$")
# "...github.com/owner/repo/pull/123..."
_PR_URL = re.compile(r"github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/pull/(?P<number>\d+)")
# "owner/repo@<sha>"
_COMMIT_SPEC = re.compile(r"^(?P<owner>[^/\s]+)/(?P<repo>[^/@\s]+)@(?P<sha>[0-9a-fA-F]{7,40})$")
# "...github.com/owner/repo/commit/<sha>..."
_COMMIT_URL = re.compile(
    r"github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})"
)


class GitHubError(RuntimeError):
    """A GitHub request failed; carries the HTTP status when there was one."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PullRequestRef(BaseModel):
    owner: str
    repo: str
    number: int

    @classmethod
    def parse(cls, spec: str) -> "PullRequestRef":
        """Parse 'owner/repo#N' or a GitHub PR URL into a ref."""
        s = spec.strip()
        m = _PR_SPEC.match(s) or _PR_URL.search(s)
        if not m:
            raise ValueError(
                f"not a PR reference: {spec!r} (expected 'owner/repo#N' or a PR URL)"
            )
        return cls(owner=m["owner"], repo=m["repo"], number=int(m["number"]))

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"


class CommitRef(BaseModel):
    owner: str
    repo: str
    sha: str

    @classmethod
    def parse(cls, spec: str) -> "CommitRef":
        """Parse 'owner/repo@<sha>' or a GitHub commit URL into a ref."""
        s = spec.strip()
        m = _COMMIT_SPEC.match(s) or _COMMIT_URL.search(s)
        if not m:
            raise ValueError(
                f"not a commit reference: {spec!r} (expected 'owner/repo@<sha>' or a commit URL)"
            )
        return cls(owner=m["owner"], repo=m["repo"], sha=m["sha"])

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}@{self.sha[:12]}"


def _error_for(resp: httpx.Response, subject: str) -> GitHubError:
    status = resp.status_code
    if status == 404:
        return GitHubError(
            f"{subject} not found — wrong reference, or a private repo and "
            f"GITHUB_TOKEN is unset or lacks access.",
            status=status,
        )
    if status == 401:
        return GitHubError("GitHub authentication failed — check GITHUB_TOKEN.", status=status)
    if status == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
        return GitHubError(
            "GitHub rate limit exceeded — set GITHUB_TOKEN for a higher limit.",
            status=status,
        )
    return GitHubError(f"GitHub API error {status}: {resp.text[:200]}", status=status)


class GitHubClient:
    """Thin wrapper over httpx for the GitHub calls the tool needs."""

    def __init__(
        self,
        token: str | None = None,
        *,
        client: httpx.Client | None = None,
        base_url: str = GITHUB_API,
        timeout: float = 30.0,
    ) -> None:
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self._owns_client = client is None
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {"Accept": accept, "X-GitHub-Api-Version": _API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get(
        self, path: str, accept: str, *, subject: str, params: dict[str, str] | None = None
    ) -> httpx.Response:
        resp = self._client.get(path, headers=self._headers(accept), params=params)
        if resp.status_code != 200:
            raise _error_for(resp, subject)
        return resp

    def fetch_pr_diff(self, ref: PullRequestRef) -> str:
        """Return the unified diff text for a PR, or raise `GitHubError`."""
        path = f"/repos/{ref.owner}/{ref.repo}/pulls/{ref.number}"
        return self._get(path, _DIFF_MEDIA_TYPE, subject=f"PR {ref.slug}").text

    def fetch_commit_diff(self, ref: CommitRef) -> str:
        """Return the unified diff text for a commit."""
        path = f"/repos/{ref.owner}/{ref.repo}/commits/{ref.sha}"
        return self._get(path, _DIFF_MEDIA_TYPE, subject=f"commit {ref.slug}").text

    def fetch_commit_parent_sha(self, ref: CommitRef) -> str:
        """Return the first-parent SHA of a commit (the pre-fix state)."""
        path = f"/repos/{ref.owner}/{ref.repo}/commits/{ref.sha}"
        data = self._get(path, _JSON_MEDIA_TYPE, subject=f"commit {ref.slug}").json()
        parents = data.get("parents") or []
        if not parents:
            raise GitHubError(f"commit {ref.slug} has no parent (root commit)")
        return parents[0]["sha"]

    def fetch_file(self, owner: str, repo: str, ref: str, path: str) -> str:
        """Return raw file content at a given ref (branch/tag/SHA)."""
        url = f"/repos/{owner}/{repo}/contents/{path}"
        subject = f"{owner}/{repo}:{path}@{ref[:12]}"
        return self._get(url, _RAW_MEDIA_TYPE, subject=subject, params={"ref": ref}).text

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def fetch_pr_diff(
    spec: str,
    *,
    token: str | None = None,
    client: httpx.Client | None = None,
) -> str:
    """Convenience: parse a PR spec and fetch its diff in one call."""
    ref = PullRequestRef.parse(spec)
    gh = GitHubClient(token=token, client=client)
    try:
        return gh.fetch_pr_diff(ref)
    finally:
        gh.close()
