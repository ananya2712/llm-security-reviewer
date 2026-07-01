import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from secreview.diff import parse_diff
from evals.synthesize import reverse_unified_diff

FIX = """\
diff --git a/app/db.py b/app/db.py
index 1111111..2222222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,5 +10,4 @@ def get_user(uid):
     conn = connect()
     cur = conn.cursor()
-    q = "SELECT * FROM users WHERE id = " + str(uid)
-    cur.execute(q)
+    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
     return cur.fetchone()
"""


def main() -> None:
    rev = reverse_unified_diff(FIX)

    # Hunk header sides swap: fix -10,5 +10,4  ->  reversed -10,4 +10,5
    assert "@@ -10,4 +10,5 @@" in rev, rev
    # The safe (parameterized) line is now removed; the vuln lines are now added.
    assert '-    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))' in rev
    assert '+    q = "SELECT * FROM users WHERE id = " + str(uid)' in rev
    assert "+    cur.execute(q)" in rev
    print("[ok] reverse swaps +/- and hunk sides")

    # Reversed diff parses, and the added (vuln) lines carry pre-fix line numbers.
    fd = parse_diff(rev)[0]
    assert fd.path == "app/db.py"
    added = [(ln.target_line_no, ln.text) for ln in fd.hunks[0].lines if ln.type == "add"]
    assert added == [
        (12, '    q = "SELECT * FROM users WHERE id = " + str(uid)'),
        (13, "    cur.execute(q)"),
    ], added
    print("[ok] reversed diff parses; vuln lines land at target 12,13 (== vulnerable_lines)")

    # Reversing twice returns the original (headers here already carry counts).
    assert reverse_unified_diff(rev) == FIX
    print("[ok] double reverse returns the original diff")

    # Single-line hunk header without explicit counts is handled.
    one = "@@ -5 +7 @@\n-a\n+b\n"
    assert reverse_unified_diff(one).startswith("@@ -7,1 +5,1 @@")
    print("[ok] single-line hunk header (no counts) reversed correctly")


if __name__ == "__main__":
    main()
