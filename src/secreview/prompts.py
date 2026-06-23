"""Prompt assembly for the LLM reviewer.

Owns everything the model sees: the versioned system prompt, the few-shot
block, and the function that renders a parsed ``FileDiff`` into the text the
model reviews. Also defines the *LLM-facing* output contract (``ReviewResult``)
— deliberately narrower than ``models.Finding`` (the model never sets
``source``; the provider stamps ``source="llm"`` when mapping back).

Decisions (see DESIGN.md):
- Diff lines are annotated with their NEW-file (target) line number so the
  model can produce accurate line refs — the eval matches with a ±3 window.
- Schema enforcement is via structured outputs (``output_config.format`` /
  ``messages.parse``), so this module exposes a Pydantic model rather than a
  hand-written tool schema. The provider wires ``ReviewResult`` in as the
  output format.
- The system prompt + few-shot block are byte-stable (no timestamps / ids) so
  the provider can prompt-cache them across an eval run.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from .diff import FileDiff, Hunk, parse_diff
from .models import Category, Severity

PROMPT_VERSION = "v1"


class LLMFinding(BaseModel):
    """A finding as the model emits it — ``models.Finding`` minus ``source``.

    Mirrors ``Finding`` field-for-field except ``source``, which the reviewer
    fills in. Kept structurally in lockstep with ``Finding`` by a drift guard
    in ``scripts/smoke_prompts.py``.
    """

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    category: Category
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    code_snippet: str

    @model_validator(mode="after")
    def _check_line_range(self) -> "LLMFinding":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class ReviewResult(BaseModel):
    """Top-level structured-output schema: the model returns a list of findings."""

    findings: list[LLMFinding]


SYSTEM_PROMPT = """\
You are a security code reviewer. You review unified diffs from pull requests \
in Python and JavaScript/TypeScript and report security vulnerabilities in the \
changed code.

Report findings in these categories:
- INJECTION: untrusted input reaches a SQL query, OS command, eval, or HTML/JS \
sink (SQL injection, command injection, XSS).
- AUTH: changes that weaken authentication or authorization — missing or \
removed access checks, broken session/token handling, privilege escalation.
- CRYPTO: weak or misused cryptography — broken algorithms (MD5/SHA1 for \
security, DES), ECB mode, hardcoded IV/salt, insecure randomness for secrets.
- SECRET: hardcoded credentials, API keys, tokens, or private keys in source.
- DESERIALIZATION: unsafe deserialization of untrusted data (pickle, \
yaml.load, native object deserialization).
- PATH_TRAVERSAL: user-controlled paths reaching filesystem operations without \
sanitization (../, absolute-path injection).
- SSRF: server-side requests to user-controlled URLs or hosts without \
validation.
- OTHER: a clear security issue that does not fit the categories above.

Severity is one of LOW, MEDIUM, HIGH, CRITICAL.

How to read the diff:
- Each line is prefixed with its line number in the NEW version of the file \
(the `NNN|` gutter), then a marker: `+` added, `-` removed, ` ` unchanged \
context. Removed lines have no line number.
- Context lines are shown only so you can understand the change. Report \
vulnerabilities that live in ADDED or modified (`+`) lines.

Rules:
- Use the NEW-file line numbers from the gutter for `start_line` and \
`end_line`, pointing at the lines that contain the vulnerability.
- `confidence` is your calibrated probability (0.0–1.0) that this is a real \
security issue.
- Keep `rationale` to one or two specific sentences. Put the offending lines \
in `code_snippet`.
- If the change introduces no security issues, return an empty `findings` \
list. Do not invent issues, and do not report style, performance, or \
non-security bugs.
"""


_MARKER = {"context": " ", "add": "+", "remove": "-"}
_GUTTER_WIDTH = 4


def _render_hunk(hunk: Hunk) -> str:
    """Render one hunk with a NEW-file line-number gutter and +/-/space markers."""
    header = (
        f"@@ -{hunk.source_start},{hunk.source_length} "
        f"+{hunk.target_start},{hunk.target_length} @@"
    )
    rows = [header]
    for ln in hunk.lines:
        gutter = (
            f"{ln.target_line_no:>{_GUTTER_WIDTH}}"
            if ln.target_line_no is not None
            else " " * _GUTTER_WIDTH
        )
        rows.append(f"{gutter}| {_MARKER[ln.type]}{ln.text}")
    return "\n".join(rows)


def format_file_diff(fd: FileDiff) -> str:
    """Render a parsed ``FileDiff`` into the annotated text the model reviews."""
    body = "\n\n".join(_render_hunk(h) for h in fd.hunks)
    return f"File: {fd.path}\nLanguage: {fd.language or 'unknown'}\n\n{body}"


# --- Few-shot block -----------------------------------------------------------
# Built by rendering real diffs through ``format_file_diff`` so the examples are
# byte-identical in shape to live input (train/serve parity). One positive
# (SQL injection introduced by a change) and one negative (a benign change that
# must produce no findings, to teach restraint).

_EXAMPLE_POSITIVE_DIFF = """\
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

_EXAMPLE_NEGATIVE_DIFF = """\
diff --git a/app/util.py b/app/util.py
index aaaaaaa..bbbbbbb 100644
--- a/app/util.py
+++ b/app/util.py
@@ -5,2 +5,3 @@ def greet(name):
     msg = "Hello, " + name
+    logger.info("greeting generated")
     return msg
"""

_EXAMPLE_POSITIVE_RESULT = ReviewResult(
    findings=[
        LLMFinding(
            file="app/db.py",
            start_line=12,
            end_line=13,
            category=Category.INJECTION,
            severity=Severity.HIGH,
            confidence=0.95,
            rationale=(
                "The user-controlled `uid` is concatenated into the SQL string "
                "instead of bound as a parameter, allowing SQL injection."
            ),
            code_snippet='q = "SELECT * FROM users WHERE id = " + str(uid)\ncur.execute(q)',
        )
    ]
)

_EXAMPLE_NEGATIVE_RESULT = ReviewResult(findings=[])


def _few_shot_messages() -> list[dict[str, str]]:
    pos = parse_diff(_EXAMPLE_POSITIVE_DIFF)[0]
    neg = parse_diff(_EXAMPLE_NEGATIVE_DIFF)[0]
    return [
        {"role": "user", "content": format_file_diff(pos)},
        {"role": "assistant", "content": _EXAMPLE_POSITIVE_RESULT.model_dump_json(indent=2)},
        {"role": "user", "content": format_file_diff(neg)},
        {"role": "assistant", "content": _EXAMPLE_NEGATIVE_RESULT.model_dump_json(indent=2)},
    ]


FEW_SHOT_MESSAGES: list[dict[str, str]] = _few_shot_messages()


def build_messages(fd: FileDiff) -> list[dict[str, str]]:
    """Assemble the message list for one file: few-shot block + the real diff.

    The provider passes ``SYSTEM_PROMPT`` as the system prompt and
    ``ReviewResult`` as the structured-output format.
    """
    return [*FEW_SHOT_MESSAGES, {"role": "user", "content": format_file_diff(fd)}]
