import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secreview.diff import parse_diff
from secreview.models import Finding
from secreview.prompts import (
    FEW_SHOT_MESSAGES,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    LLMFinding,
    ReviewResult,
    build_messages,
    format_file_diff,
)

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


def main() -> None:
    # Drift guard: LLMFinding must stay Finding minus `source`.
    llm_fields = set(LLMFinding.model_fields)
    finding_fields = set(Finding.model_fields)
    assert llm_fields == finding_fields - {"source"}, (llm_fields, finding_fields)
    print("[ok] LLMFinding == Finding minus 'source'")

    assert PROMPT_VERSION == "v1"
    assert "INJECTION" in SYSTEM_PROMPT and "empty `findings`" in SYSTEM_PROMPT
    print("[ok] system prompt versioned + lists categories and the no-findings rule")

    fd = parse_diff(SAMPLE)[0]
    rendered = format_file_diff(fd)
    print("---- rendered diff ----")
    print(rendered)
    print("-----------------------")
    assert rendered.startswith("File: app/db.py\nLanguage: python\n")
    assert "@@ -10,4 +10,5 @@" in rendered
    # Added lines carry their NEW-file line number in the gutter.
    assert "  12| +    q = " in rendered, "added line 12 not annotated"
    assert "  13| +    cur.execute(q)" in rendered, "added line 13 not annotated"
    # Removed lines have a blank gutter (no NEW-file number).
    assert "    | -    cur.execute(" in rendered, "removed line should have blank gutter"
    print("[ok] hunk annotated with target line numbers; removed lines blank-guttered")

    # Few-shot block: alternating user/assistant, assistants are valid ReviewResult JSON.
    roles = [m["role"] for m in FEW_SHOT_MESSAGES]
    assert roles == ["user", "assistant", "user", "assistant"], roles
    pos = ReviewResult.model_validate_json(FEW_SHOT_MESSAGES[1]["content"])
    neg = ReviewResult.model_validate_json(FEW_SHOT_MESSAGES[3]["content"])
    assert len(pos.findings) == 1 and pos.findings[0].category == "INJECTION"
    assert pos.findings[0].start_line == 12 and pos.findings[0].end_line == 13
    assert neg.findings == []
    print("[ok] few-shot: 1 positive (INJECTION @12-13) + 1 negative (no findings)")

    msgs = build_messages(fd)
    assert len(msgs) == len(FEW_SHOT_MESSAGES) + 1
    assert msgs[-1]["role"] == "user" and "File: app/db.py" in msgs[-1]["content"]
    print("[ok] build_messages appends the real diff after the few-shot block")

    # end_line < start_line must be rejected at the boundary.
    try:
        LLMFinding(
            file="x",
            start_line=10,
            end_line=5,
            category="INJECTION",
            severity="LOW",
            confidence=0.5,
            rationale="r",
            code_snippet="s",
        )
    except ValueError:
        print("[ok] LLMFinding rejects end_line < start_line")
    else:
        raise AssertionError("expected ValueError for end_line < start_line")


if __name__ == "__main__":
    main()
