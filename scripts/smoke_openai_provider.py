import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secreview.diff import parse_diff
from secreview.prompts import SYSTEM_PROMPT, LLMFinding, ReviewResult, build_messages
from secreview.providers import OpenAIProvider, ReviewProvider

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


class _StubCompletions:
    """Stands in for client.chat.completions — records kwargs, returns a canned parse."""

    def __init__(self, parsed, refusal=None):
        self._parsed = parsed
        self._refusal = refusal
        self.calls = 0
        self.last_kwargs = None

    def parse(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        message = SimpleNamespace(parsed=self._parsed, refusal=self._refusal)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class _StubOpenAI:
    def __init__(self, parsed, refusal=None):
        self.chat = SimpleNamespace(completions=_StubCompletions(parsed, refusal))


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

    # --- happy path ---
    client = _StubOpenAI(canned)
    provider = OpenAIProvider(client=client)
    assert isinstance(provider, ReviewProvider)
    assert provider.name == "openai" and provider.model == "gpt-4o"

    findings = provider.review_file(fd)
    assert len(findings) == 1 and findings[0].source == "llm"
    assert findings[0].category == "INJECTION" and findings[0].start_line == 12
    print("[ok] parsed output -> Finding with source='llm'")

    # --- request shaping: system message first, then few-shot + diff ---
    kw = client.chat.completions.last_kwargs
    assert kw["model"] == "gpt-4o"
    assert kw["response_format"] is ReviewResult
    assert "max_completion_tokens" not in kw  # omitted when unset
    msgs = kw["messages"]
    assert msgs[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert msgs[1:] == build_messages(fd)
    assert msgs[-1]["role"] == "user" and msgs[-1]["content"].startswith("File: app/db.py")
    print("[ok] request: gpt-4o, response_format=ReviewResult, system-first messages")

    # --- refusal degrades to [] ---
    refusing = _StubOpenAI(None, refusal="I can't help with that.")
    assert OpenAIProvider(client=refusing).review_file(fd) == []
    print("[ok] message.refusal -> [] (no crash)")

    # --- empty-hunk file short-circuits ---
    no_hunk = parse_diff(EMPTY_FILE_DIFF)[0]
    skip = _StubOpenAI(canned)
    assert OpenAIProvider(client=skip).review_file(no_hunk) == []
    assert skip.chat.completions.calls == 0
    print("[ok] empty-hunk file returns [] without calling the model")

    # --- max_completion_tokens passed through when set ---
    capped = _StubOpenAI(canned)
    OpenAIProvider(client=capped, max_completion_tokens=2048).review_file(fd)
    assert capped.chat.completions.last_kwargs["max_completion_tokens"] == 2048
    print("[ok] max_completion_tokens forwarded when set")


if __name__ == "__main__":
    main()
