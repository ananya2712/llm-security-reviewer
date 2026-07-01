import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from evals.matching import EntryMatch
from evals.metrics import compute_metrics, write_csv


def _m(entry_id, category, found, located, strict=None, generous=None) -> EntryMatch:
    return EntryMatch(
        entry_id=entry_id,
        category=category,
        language="python",
        found=found,
        located=located,
        strict_fp_categories=strict or [],
        generous_fp_categories=generous or [],
    )


def main() -> None:
    # Two INJECTION entries (1 found, 1 missed) + one SECRET (found).
    # One entry also emits an off-file AUTH finding (FP under both views) and an
    # on-file-outside-window INJECTION finding (strict FP only).
    matches = [
        _m("i1", "INJECTION", found=True, located=True, strict=["INJECTION"], generous=[]),
        _m("i2", "INJECTION", found=False, located=False, strict=["AUTH"], generous=["AUTH"]),
        _m("s1", "SECRET", found=True, located=True),
    ]

    report = compute_metrics("llm", matches)
    by_cat = {r.category: r for r in report.rows}

    inj = by_cat["INJECTION"]
    assert inj.support == 2 and inj.tp == 1 and inj.fn == 1
    assert inj.recall == 0.5
    # INJECTION FP: 1 strict (the on-file-outside-window INJECTION), 0 generous.
    assert inj.strict_fp == 1 and inj.generous_fp == 0
    assert inj.strict_precision == 0.5 and inj.generous_precision == 1.0
    print("[ok] per-category INJECTION: recall .5, strict P .5, generous P 1.0")

    sec = by_cat["SECRET"]
    assert sec.support == 1 and sec.tp == 1 and sec.recall == 1.0
    print("[ok] per-category SECRET: recall 1.0")

    overall = by_cat["OVERALL"]
    assert overall.support == 3 and overall.tp == 2 and overall.fn == 1
    assert abs(overall.recall - 2 / 3) < 1e-9
    # Overall FP: strict = AUTH + INJECTION = 2 ; generous = AUTH = 1.
    assert overall.strict_fp == 2 and overall.generous_fp == 1
    assert overall.strict_precision == 0.5 and abs(overall.generous_precision - 2 / 3) < 1e-9
    print("[ok] OVERALL: recall 2/3, strict FP 2, generous FP 1")

    # located_recall = 2 of 3 entries localized.
    assert abs(report.located_recall - 2 / 3) < 1e-9
    print("[ok] located_recall = 2/3")

    # CSV writes a header + one row per category incl OVERALL.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "metrics.csv"
        write_csv(report, p)
        rows = list(csv.DictReader(p.open()))
        assert len(rows) == len(report.rows)
        assert rows[-1]["category"] == "OVERALL" and rows[-1]["tp"] == "2"
    print("[ok] write_csv emits header + all rows")


if __name__ == "__main__":
    main()
