import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from secreview.models import Finding
from evals.manifest import DatasetEntry
from evals.matching import match_entry

ENTRY = DatasetEntry(
    id="E1",
    repo="x/y",
    fix_commit="a" * 40,
    cwe="CWE-89",
    category="INJECTION",
    language="python",
    vulnerable_file="app/db.py",
    vulnerable_lines=[12, 13],
    fix_diff_path="diffs/e1.diff",
)


def _f(file, start, end, category, source="llm") -> Finding:
    return Finding(
        file=file,
        start_line=start,
        end_line=end,
        category=category,
        severity="HIGH",
        confidence=0.9,
        rationale="r",
        code_snippet="s",
        source=source,
    )


def main() -> None:
    # True positive: same file, overlaps window, category matches.
    m = match_entry([_f("app/db.py", 12, 13, "INJECTION")], ENTRY)
    assert m.found and m.located
    assert m.strict_fp_categories == [] and m.generous_fp_categories == []
    print("[ok] TP: file+line+category match -> found, no FP")

    # Within the +/-3 window but not exactly on the lines -> still a TP.
    m = match_entry([_f("app/db.py", 15, 15, "INJECTION")], ENTRY)  # hi = 13+3 = 16
    assert m.found and m.located
    print("[ok] within +/-3 window counts as a hit")

    # Located but wrong category -> not a category TP (but localization counts).
    m = match_entry([_f("app/db.py", 12, 12, "SSRF")], ENTRY)
    assert m.located and not m.found
    assert m.strict_fp_categories == [] and m.generous_fp_categories == []
    print("[ok] right location, wrong category -> located but not found; in-window not FP")

    # On the vuln file but outside the window -> strict FP only (generous forgives it).
    m = match_entry([_f("app/db.py", 40, 40, "AUTH")], ENTRY)
    assert not m.found and not m.located
    assert m.strict_fp_categories == ["AUTH"] and m.generous_fp_categories == []
    print("[ok] on-file outside window -> strict FP, not generous FP")

    # On a different file -> FP under both strict and generous.
    m = match_entry([_f("app/other.py", 3, 3, "CRYPTO")], ENTRY)
    assert m.strict_fp_categories == ["CRYPTO"] and m.generous_fp_categories == ["CRYPTO"]
    print("[ok] off-file finding -> both strict and generous FP")

    # No findings -> a false negative (found False), no FPs.
    m = match_entry([], ENTRY)
    assert not m.found and not m.located
    print("[ok] no findings -> FN (found=False)")


if __name__ == "__main__":
    main()
