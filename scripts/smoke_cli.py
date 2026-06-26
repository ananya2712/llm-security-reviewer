import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rich.console import Console
from typer.testing import CliRunner

from secreview import cli
from secreview import report as report_mod
from secreview.diff import FileDiff
from secreview.models import Finding
from secreview.providers.base import ReviewProvider
from secreview.reviewer import ReviewReport

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


def _finding() -> Finding:
    return Finding(
        file="app/db.py",
        start_line=12,
        end_line=13,
        category="INJECTION",
        severity="HIGH",
        confidence=0.92,
        rationale="user input concatenated into SQL",
        code_snippet="cur.execute(q)",
        source="llm",
    )


class FakeProvider(ReviewProvider):
    name = "fake"
    model = "fake-1"

    def __init__(self, findings: list[Finding]):
        self._findings = findings

    def review_file(self, fd: FileDiff) -> list[Finding]:
        return list(self._findings)


def _report(findings: list[Finding]) -> ReviewReport:
    return ReviewReport(findings=findings, files_reviewed=["app/db.py"])


def main() -> None:
    runner = CliRunner()

    # --- report.py: table render captured to a string ---
    buf = Console(file=io.StringIO(), width=120)
    report_mod.render_terminal(_report([_finding()]), console=buf)
    out = buf.file.getvalue()
    assert "Security findings (1)" in out and "INJECTION" in out and "app/db.py:12-13" in out
    print("[ok] render_terminal: table with location, category, severity")

    # --- report.py: all-clear render ---
    buf2 = Console(file=io.StringIO(), width=120)
    report_mod.render_terminal(_report([]), console=buf2)
    assert "No security findings" in buf2.file.getvalue()
    print("[ok] render_terminal: all-clear line when no findings")

    # --- report.py: JSON ---
    payload = json.loads(report_mod.to_json(_report([_finding()])))
    assert payload["files_reviewed"] == ["app/db.py"]
    assert payload["findings"][0]["category"] == "INJECTION"
    assert payload["findings"][0]["source"] == "llm"
    print("[ok] to_json: machine-readable findings + files_reviewed")

    with tempfile.TemporaryDirectory() as d:
        diff_path = Path(d) / "sample.diff"
        diff_path.write_text(SAMPLE)

        # --- _load_diff: file + missing file + stdin ---
        assert cli._load_diff(str(diff_path)) == SAMPLE
        try:
            cli._load_diff(str(Path(d) / "nope.diff"))
        except Exception as e:
            assert "not found" in str(e)
        else:
            raise AssertionError("expected BadParameter for missing diff file")
        print("[ok] _load_diff reads files and rejects missing paths")

        # --- CLI end-to-end with a fake provider (no API key) ---
        orig = cli._make_provider
        orig_pr = cli._load_pr_diff
        cli._make_provider = lambda name, model, thinking: FakeProvider([_finding()])
        try:
            res = runner.invoke(cli.app, ["review", "--diff", str(diff_path), "--json"])
            assert res.exit_code == 0, res.output
            data = json.loads(res.stdout)
            assert data["findings"][0]["category"] == "INJECTION"
            print("[ok] `review --diff <file> --json` -> findings JSON")

            res2 = runner.invoke(cli.app, ["review", "--diff", str(diff_path)])
            assert res2.exit_code == 0, res2.output
            assert "INJECTION" in res2.stdout or "finding" in res2.stdout.lower()
            print("[ok] `review --diff <file>` -> table output")

            res3 = runner.invoke(cli.app, ["review", "--diff", "-"], input=SAMPLE)
            assert res3.exit_code == 0, res3.output
            print("[ok] `review --diff -` reads the diff from stdin")

            # PR mode: positional target, GitHub fetch stubbed
            cli._load_pr_diff = lambda target: SAMPLE
            res_pr = runner.invoke(cli.app, ["review", "octocat/Hello-World#1", "--json"])
            assert res_pr.exit_code == 0, res_pr.output
            assert json.loads(res_pr.stdout)["findings"][0]["category"] == "INJECTION"
            print("[ok] `review owner/repo#N` fetches the PR diff and reviews it")

            # exactly-one validation: neither, and both
            res_neither = runner.invoke(cli.app, ["review"])
            assert res_neither.exit_code != 0
            res_both = runner.invoke(
                cli.app, ["review", "octocat/Hello-World#1", "--diff", str(diff_path)]
            )
            assert res_both.exit_code != 0
            print("[ok] requires exactly one of PR target or --diff")

            # no findings path
            cli._make_provider = lambda name, model, thinking: FakeProvider([])
            res4 = runner.invoke(cli.app, ["review", "--diff", str(diff_path)])
            assert res4.exit_code == 0 and "No security findings" in res4.stdout
            print("[ok] clean diff -> all-clear message")
        finally:
            cli._make_provider = orig
            cli._load_pr_diff = orig_pr

        # --- unknown provider rejected before any API construction ---
        res5 = runner.invoke(cli.app, ["review", "--diff", str(diff_path), "-p", "bogus"])
        assert res5.exit_code != 0
        print("[ok] unknown --provider rejected")


if __name__ == "__main__":
    main()
