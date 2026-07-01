import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from evals.curate import (
    CurationError,
    add_to_manifest,
    make_candidate,
    suggest_category,
    suggest_vulnerable_lines,
)
from evals.manifest import load_manifest
from secreview.diff import parse_diff

# A fix commit diff: removes the vulnerable SQL lines (source 12,13), plus a
# lockfile change that must be filtered out as noise.
FIX_DIFF = """\
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
diff --git a/package-lock.json b/package-lock.json
index 3333333..4444444 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,1 +1,1 @@
-  "v": "1"
+  "v": "2"
"""

# An "add a missing check" fix — no removed lines.
ADD_ONLY_DIFF = """\
diff --git a/app/auth.py b/app/auth.py
index 5555555..6666666 100644
--- a/app/auth.py
+++ b/app/auth.py
@@ -5,2 +5,3 @@ def handler(req):
     user = req.user
+    if not user.is_admin: raise Forbidden()
     return do(user)
"""

LOCKFILE_ONLY = """\
diff --git a/package-lock.json b/package-lock.json
index 3333333..4444444 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,1 +1,1 @@
-  "v": "1"
+  "v": "2"
"""

SHA = "abcdef1234567890abcdef1234567890abcdef12"


class FakeGH:
    def __init__(self, diff, parent="parent00sha", file_content="PREFIX CONTENT\n"):
        self.diff = diff
        self.parent = parent
        self.file_content = file_content
        self.file_calls = []

    def fetch_commit_diff(self, ref):
        return self.diff

    def fetch_commit_parent_sha(self, ref):
        return self.parent

    def fetch_file(self, owner, repo, ref, path):
        self.file_calls.append((owner, repo, ref, path))
        return self.file_content


def main() -> None:
    # --- pure helpers ---
    assert suggest_category("CWE-89: SQL Injection") == "INJECTION"
    assert suggest_category("CWE-99999") is None and suggest_category(None) is None
    print("[ok] suggest_category maps known CWEs, None otherwise")

    db_fd = next(f for f in parse_diff(FIX_DIFF) if f.path == "app/db.py")
    assert suggest_vulnerable_lines(db_fd) == [12, 13]
    print("[ok] suggest_vulnerable_lines = pre-fix line numbers of removed lines")

    with tempfile.TemporaryDirectory() as d:
        dataset = Path(d)

        # --- full candidate build ---
        gh = FakeGH(FIX_DIFF)
        entry = make_candidate(f"octo/app@{SHA}", dataset, gh=gh, cwe="CWE-89")

        assert entry.id == "CWE-89-APP-ABCDEF1", entry.id
        assert entry.repo == "octo/app" and entry.fix_commit == SHA
        assert entry.category == "INJECTION" and entry.cwe == "CWE-89"
        assert entry.language == "python" and entry.vulnerable_file == "app/db.py"
        assert entry.vulnerable_lines == [12, 13]
        assert entry.fix_diff_path == "diffs/CWE-89-APP-ABCDEF1.diff"
        assert entry.prefix_file == "prefix/app/db.py"
        assert "NEEDS REVIEW" in entry.notes
        print("[ok] make_candidate: entry fields + auto vulnerable_lines + NEEDS REVIEW note")

        # noise filtered: only the .py reached the entry (lockfile dropped)
        assert (dataset / "diffs/CWE-89-APP-ABCDEF1.diff").read_text() == FIX_DIFF
        assert (dataset / "prefix/app/db.py").read_text() == "PREFIX CONTENT\n"
        assert gh.file_calls == [("octo", "app", "parent00sha", "app/db.py")]
        print("[ok] materialized fix diff + pre-fix file (fetched at the parent commit)")

        # --- no CWE -> OTHER + placeholder cwe ---
        e2 = make_candidate(f"octo/app@{SHA}", dataset, gh=FakeGH(FIX_DIFF), entry_id="E2")
        assert e2.category == "OTHER" and e2.cwe == "CWE-000"
        print("[ok] missing CWE -> category OTHER, placeholder cwe")

        # --- add-only fix -> placeholder vulnerable_lines + flagged note ---
        e3 = make_candidate(
            f"octo/app@{SHA}", dataset, gh=FakeGH(ADD_ONLY_DIFF), entry_id="E3", fetch_prefix=False
        )
        assert e3.vulnerable_lines == [1] and "placeholder" in e3.notes
        assert e3.prefix_file is None
        print("[ok] add-only fix -> placeholder lines, prefix skipped")

        # --- filtering: a lockfile-only commit is rejected ---
        try:
            make_candidate(f"octo/app@{SHA}", dataset, gh=FakeGH(LOCKFILE_ONLY), entry_id="E4")
        except CurationError as err:
            assert "no in-scope" in str(err)
            print("[ok] lockfile-only commit rejected (no in-scope files)")
        else:
            raise AssertionError("expected CurationError for a lockfile-only commit")

        # --- add_to_manifest: append + dedupe by id ---
        manifest = dataset / "staging_manifest.json"
        add_to_manifest(entry, manifest)
        add_to_manifest(e3, manifest)
        add_to_manifest(entry, manifest)  # same id again -> replace, not duplicate
        loaded = load_manifest(manifest)
        ids = [e.id for e in loaded]
        assert ids.count("CWE-89-APP-ABCDEF1") == 1 and "E3" in ids
        assert json.loads(manifest.read_text())  # valid JSON array
        print("[ok] add_to_manifest appends and dedupes by id")


if __name__ == "__main__":
    main()
