import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secreview.diff import parse_diff

SAMPLE = """\
diff --git a/src/db.py b/src/db.py
index 1111111..2222222 100644
--- a/src/db.py
+++ b/src/db.py
@@ -10,5 +10,6 @@ def get_user(uid):
     conn = connect()
     cur = conn.cursor()
-    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
+    q = f"SELECT * FROM users WHERE id = {uid}"
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
diff --git a/node_modules/foo/index.js b/node_modules/foo/index.js
index 5555555..6666666 100644
--- a/node_modules/foo/index.js
+++ b/node_modules/foo/index.js
@@ -1,1 +1,1 @@
-module.exports = 1
+module.exports = 2
diff --git a/web/app.ts b/web/app.ts
new file mode 100644
index 0000000..7777777
--- /dev/null
+++ b/web/app.ts
@@ -0,0 +1,2 @@
+const token = "hardcoded";
+export {token};
"""


def main() -> None:
    files = parse_diff(SAMPLE)

    paths = [f.path for f in files]
    print("[ok] kept files:", paths)
    assert paths == ["src/db.py", "web/app.ts"], "noise filter wrong"
    print("[ok] dropped lockfile + vendored dir")

    db = next(f for f in files if f.path == "src/db.py")
    assert db.language == "python", db.language
    assert not db.is_added
    assert len(db.hunks) == 1
    h = db.hunks[0]
    assert h.source_start == 10 and h.source_length == 5, (h.source_start, h.source_length)
    assert h.target_start == 10 and h.target_length == 6, (h.target_start, h.target_length)
    print("[ok] hunk ranges:", h.source_start, h.source_length, h.target_start, h.target_length)

    added = [ln for ln in h.lines if ln.type == "add"]
    removed = [ln for ln in h.lines if ln.type == "remove"]
    assert len(added) == 2 and len(removed) == 1
    assert added[0].target_line_no is not None and added[0].source_line_no is None
    assert removed[0].source_line_no is not None and removed[0].target_line_no is None
    print("[ok] line types + line numbers tracked")

    rendered = h.render_unified()
    assert rendered.startswith("@@ -10,5 +10,6 @@")
    assert "+    q = f\"SELECT" in rendered
    assert "-    cur.execute(" in rendered
    print("[ok] render_unified produces valid hunk")

    new_file = next(f for f in files if f.path == "web/app.ts")
    assert new_file.language == "typescript"
    assert new_file.is_added is True
    assert new_file.hunks[0].target_start == 1
    print("[ok] new file detected:", new_file.path, new_file.language)


if __name__ == "__main__":
    main()
