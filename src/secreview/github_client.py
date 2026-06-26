"""Fetch a pull request's unified diff from the GitHub REST API.

We ask GitHub for the PR's `.diff` representation directly (the `diff` media
type on `GET /repos/{owner}/{repo}/pulls/{n}`) — that's exactly the unified-diff
text `diff.parse_diff` already consumes, so no reconstruction from per-file
JSON. Auth is via `GITHUB_TOKEN` (optional for public repos, but recommended
for the higher rate limit and private access).

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
_API_VERSION = "2022-11-28"

# "owner/repo#123"
_PR_SPEC = re.compile(r"^(?P<owner>[^/\s]+)/(?P<repo>[^/#\s]+)#(?P<number>\d+)$")
# "...github.com/owner/repo/pull/123..."
_PR_URL = re.compile(r"github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/pull/(?P<number>\d+)")


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


def _error_for(resp: httpx.Response, ref: PullRequestRef) -> GitHubError:
    status = resp.status_code
    if status == 404:
        return GitHubError(
            f"PR {ref.slug} not found — wrong owner/repo/number, or a private "
            f"repo and GITHUB_TOKEN is unset or lacks access.",
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
    """Thin wrapper over httpx for the one call we need: fetch a PR diff."""

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

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": _DIFF_MEDIA_TYPE, "X-GitHub-Api-Version": _API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def fetch_pr_diff(self, ref: PullRequestRef) -> str:
        """Return the unified diff text for a PR, or raise `GitHubError`."""
        url = f"/repos/{ref.owner}/{ref.repo}/pulls/{ref.number}"
        resp = self._client.get(url, headers=self._headers())
        if resp.status_code != 200:
            raise _error_for(resp, ref)
        return resp.text

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
