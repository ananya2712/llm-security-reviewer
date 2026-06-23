import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secreview.diff import parse_diff
from secreview.prompts import LLMFinding, ReviewResult, build_messages
from secreview.providers import AnthropicProvider, ReviewProvider

SAMPLE = """\
diff --git a/app/db.py b/app/db.py
index 1111111..2222222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,4 +10,5 @@ def get_user(uid):
     conn = connect()
     cur = conn.cursor()
-    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
+    q = "SELECT * FROM users WHERE id = " + str(uid)
+    cur.execute(q)
     return cur.fetchone()
"""

EMPTY_FILE_DIFF = """\
diff --git a/app/empty.py b/app/empty.py
deleted file mode 100644
index 1111111..0000000
--- a/app/empty.py
+++ /dev/null
"""


class _StubMessages:
    """Stands in for client.messages — records kwargs, returns a canned parse."""

    def __init__(self, result, stop_reason="end_turn"):
        self._result = result
        self._stop_reason = stop_reason
        self.calls = 0
        self.last_kwargs = None

    def parse(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        return SimpleNamespace(parsed_output=self._result, stop_reason=self._stop_reason)


class _StubClient:
    def __init__(self, result, stop_reason="end_turn"):
        self.messages = _StubMessages(result, stop_reason)


def main() -> None:
    fd = parse_diff(SAMPLE)[0]

    canned = ReviewResult(
        findings=[
            LLMFinding(
                file="app/db.py",
                start_line=12,
                end_line=13,
                category="INJECTION",
                severity="HIGH",
                confidence=0.9,
                rationale="user input concatenated into SQL",
                code_snippet="cur.execute(q)",
            )
        ]
    )

    # --- happy path: parsed output maps to Finding(source="llm") ---
    client = _StubClient(canned)
    provider = AnthropicProvider(client=client)
    assert isinstance(provider, ReviewProvider)
    assert provider.name == "anthropic" and provider.model == "claude-sonnet-4-6"

    findings = provider.review_file(fd)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "llm", f.source
    assert f.category == "INJECTION" and f.start_line == 12 and f.end_line == 13
    print("[ok] parsed output -> Finding with source='llm' and fields preserved")

    # --- request shaping ---
    kw = client.messages.last_kwargs
    assert kw["model"] == "claude-sonnet-4-6"
    assert kw["output_format"] is ReviewResult
    assert kw["thinking"] == {"type": "adaptive"}
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "INJECTION" in kw["system"][0]["text"]
    assert kw["messages"] == build_messages(fd)
    assert kw["messages"][-1]["content"].startswith("File: app/db.py")
    print("[ok] request: sonnet-4-6, output_format, adaptive thinking, cached system, few-shot+diff")

    # --- refusal degrades to no findings ---
    refusing = _StubClient(None, stop_reason="refusal")
    assert AnthropicProvider(client=refusing).review_file(fd) == []
    assert refusing.messages.calls == 1
    print("[ok] refusal stop_reason -> [] (no crash)")

    # --- file with no reviewable hunks short-circuits without an API call ---
    no_hunk = parse_diff(EMPTY_FILE_DIFF)
    assert no_hunk and no_hunk[0].hunks == []
    skip_client = _StubClient(canned)
    assert AnthropicProvider(client=skip_client).review_file(no_hunk[0]) == []
    assert skip_client.messages.calls == 0, "should not call the API for an empty diff"
    print("[ok] empty-hunk file returns [] without calling the model")

    # --- review() loops review_file across files ---
    multi_client = _StubClient(canned)
    all_findings = AnthropicProvider(client=multi_client).review([fd, fd])
    assert len(all_findings) == 2 and multi_client.messages.calls == 2
    print("[ok] review() aggregates findings across files (2 calls -> 2 findings)")

    # --- thinking can be disabled ---
    nothink = _StubClient(canned)
    AnthropicProvider(client=nothink, thinking=False).review_file(fd)
    assert "thinking" not in nothink.messages.last_kwargs
    print("[ok] thinking=False omits the thinking param")


if __name__ == "__main__":
    main()
