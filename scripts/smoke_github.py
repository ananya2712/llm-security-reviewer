import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import httpx

from secreview.github_client import (
    GITHUB_API,
    GitHubClient,
    GitHubError,
    PullRequestRef,
    fetch_pr_diff,
)

DIFF = """\
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,1 +1,1 @@
-safe()
+unsafe()
"""


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=GITHUB_API)


def main() -> None:
    # --- ref parsing: shorthand, URL, and rejection ---
    r = PullRequestRef.parse("octocat/Hello-World#42")
    assert (r.owner, r.repo, r.number) == ("octocat", "Hello-World", 42)
    assert r.slug == "octocat/Hello-World#42"
    r2 = PullRequestRef.parse("https://github.com/octocat/Hello-World/pull/7#discussion")
    assert (r2.owner, r2.repo, r2.number) == ("octocat", "Hello-World", 7)
    for bad in ["octocat/Hello-World", "not a ref", "octocat#42"]:
        try:
            PullRequestRef.parse(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {bad!r}")
    print("[ok] PullRequestRef.parse: shorthand + URL parsed, junk rejected")

    # --- happy path: correct endpoint, headers, and returned diff ---
    seen = {}

    def ok_handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["accept"] = request.headers.get("Accept")
        seen["auth"] = request.headers.get("Authorization")
        seen["apiver"] = request.headers.get("X-GitHub-Api-Version")
        return httpx.Response(200, text=DIFF)

    text = fetch_pr_diff("octocat/Hello-World#42", token="tok123", client=_client(ok_handler))
    assert text == DIFF
    assert seen["path"] == "/repos/octocat/Hello-World/pulls/42", seen["path"]
    assert seen["accept"] == "application/vnd.github.diff"
    assert seen["auth"] == "Bearer tok123"
    assert seen["apiver"] == "2022-11-28"
    print("[ok] fetch_pr_diff hits /repos/.../pulls/N with diff media type + auth")

    # --- no token: Authorization header omitted ---
    no_auth = {}

    def noauth_handler(request: httpx.Request) -> httpx.Response:
        no_auth["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, text=DIFF)

    GitHubClient(token="", client=_client(noauth_handler)).fetch_pr_diff(
        PullRequestRef.parse("o/r#1")
    )
    assert no_auth["auth"] is None
    print("[ok] empty/absent token -> no Authorization header")

    # --- 404 -> clear GitHubError ---
    def nf_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text='{"message":"Not Found"}')

    try:
        fetch_pr_diff("o/r#999", client=_client(nf_handler))
    except GitHubError as e:
        assert e.status == 404 and "not found" in str(e).lower()
        print("[ok] 404 -> GitHubError(status=404) with a helpful message")
    else:
        raise AssertionError("expected GitHubError on 404")

    # --- 403 + rate-limit header -> rate-limit message ---
    def rl_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}, text="rate limited")

    try:
        fetch_pr_diff("o/r#1", client=_client(rl_handler))
    except GitHubError as e:
        assert e.status == 403 and "rate limit" in str(e).lower()
        print("[ok] 403 with exhausted rate limit -> rate-limit GitHubError")
    else:
        raise AssertionError("expected GitHubError on 403 rate limit")


if __name__ == "__main__":
    main()
