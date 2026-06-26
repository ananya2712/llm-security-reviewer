import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secreview.diff import FileDiff
from secreview.models import Finding
from secreview.providers.base import ReviewProvider
from secreview.reviewer import ReviewReport, review_diff

# Multi-file diff: one Python file with a vuln, plus a lockfile and a vendored
# file (both noise), plus a new TS file. Noise must be dropped before review.
SAMPLE = """\
diff --git a/src/db.py b/src/db.py
index 1111111..2222222 100644
--- a/src/db.py
+++ b/src/db.py
@@ -10,4 +10,5 @@ def get_user(uid):
     conn = connect()
     cur = conn.cursor()
-    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
+    q = "SELECT * FROM users WHERE id = " + str(uid)
+    cur.execute(q)
     return cur.fetchone()
diff --git a/package-lock.json b/package-lock.json
index 3333333..4444444 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,3 +1,3 @@
 {
-  "version": "1.0.0"
+  "version": "1.0.1"
 }
diff --git a/web/app.ts b/web/app.ts
new file mode 100644
index 0000000..7777777
--- /dev/null
+++ b/web/app.ts
@@ -0,0 +1,2 @@
+const token = "hardcoded";
+export {token};
"""


def _finding(file: str, start: int, end: int, category: str) -> Finding:
    return Finding(
        file=file,
        start_line=start,
        end_line=end,
        category=category,
        severity="HIGH",
        confidence=0.9,
        rationale="r",
        code_snippet="s",
        source="llm",
    )


class FakeProvider(ReviewProvider):
    """Returns canned findings per path; records which files it was asked to review."""

    name = "fake"
    model = "fake-1"

    def __init__(self, by_path: dict[str, list[Finding]]):
        self._by_path = by_path
        self.reviewed: list[str] = []

    def review_file(self, fd: FileDiff) -> list[Finding]:
        self.reviewed.append(fd.path)
        return list(self._by_path.get(fd.path, []))


def main() -> None:
    # web/app.ts returns two findings out of order to exercise the sort.
    provider = FakeProvider(
        {
            "src/db.py": [_finding("src/db.py", 12, 13, "INJECTION")],
            "web/app.ts": [
                _finding("web/app.ts", 2, 2, "OTHER"),
                _finding("web/app.ts", 1, 1, "SECRET"),
            ],
        }
    )

    report = review_diff(SAMPLE, provider)
    assert isinstance(report, ReviewReport)

    # Noise dropped: only the two real source files reach the provider.
    assert provider.reviewed == ["src/db.py", "web/app.ts"], provider.reviewed
    assert report.files_reviewed == ["src/db.py", "web/app.ts"]
    print("[ok] lockfile + vendored dropped; only src/db.py and web/app.ts reviewed")

    # Findings sorted by (file, start_line, end_line, category).
    keys = [(f.file, f.start_line, f.category.value) for f in report.findings]
    assert keys == [
        ("src/db.py", 12, "INJECTION"),
        ("web/app.ts", 1, "SECRET"),
        ("web/app.ts", 2, "OTHER"),
    ], keys
    assert report.finding_count == 3
    print("[ok] findings sorted deterministically; count =", report.finding_count)

    # Round-trips to JSON (report.py / eval will rely on this).
    rt = ReviewReport.model_validate_json(report.model_dump_json())
    assert rt == report
    print("[ok] ReviewReport JSON round-trips")

    # Empty / all-noise diff -> empty report, no provider calls.
    only_noise = FakeProvider({})
    empty = review_diff(
        "diff --git a/yarn.lock b/yarn.lock\n"
        "--- a/yarn.lock\n+++ b/yarn.lock\n"
        "@@ -1 +1 @@\n-a\n+b\n",
        only_noise,
    )
    assert empty.findings == [] and empty.files_reviewed == []
    assert only_noise.reviewed == []
    print("[ok] all-noise diff -> empty report, provider never called")


if __name__ == "__main__":
    main()
