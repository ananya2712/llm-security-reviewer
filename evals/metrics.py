"""Aggregate per-entry matches into precision/recall/F1, per category and overall.

Recall is category-aware (`found`). Precision is reported two ways per PLAN §5:
*strict* (findings on the vuln file outside the window count as FP) and
*generous* (only off-file findings count). Per-category precision buckets FP
findings by the finding's own category. `located_recall` is the localization
rate (vuln flagged at all, any category).
"""

from __future__ import annotations

import csv
from pathlib import Path

from pydantic import BaseModel

from evals.matching import EntryMatch


def _div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _f1(precision: float, recall: float) -> float:
    return _div(2 * precision * recall, precision + recall)


class Row(BaseModel):
    category: str
    support: int
    tp: int
    fn: int
    recall: float
    strict_fp: int
    strict_precision: float
    strict_f1: float
    generous_fp: int
    generous_precision: float
    generous_f1: float


class MetricsReport(BaseModel):
    tool: str
    rows: list[Row]  # one per category, then an "OVERALL" row
    located_recall: float


def _row(cat: str, support: int, tp: int, fn: int, strict_fp: int, generous_fp: int) -> Row:
    recall = _div(tp, tp + fn)
    strict_p = _div(tp, tp + strict_fp)
    generous_p = _div(tp, tp + generous_fp)
    return Row(
        category=cat,
        support=support,
        tp=tp,
        fn=fn,
        recall=recall,
        strict_fp=strict_fp,
        strict_precision=strict_p,
        strict_f1=_f1(strict_p, recall),
        generous_fp=generous_fp,
        generous_precision=generous_p,
        generous_f1=_f1(generous_p, recall),
    )


def compute_metrics(tool: str, matches: list[EntryMatch]) -> MetricsReport:
    categories = sorted({m.category for m in matches}, key=lambda c: c.value)
    rows: list[Row] = []

    for c in categories:
        subset = [m for m in matches if m.category == c]
        tp = sum(1 for m in subset if m.found)
        fn = len(subset) - tp
        strict_fp = sum(cat == c for m in matches for cat in m.strict_fp_categories)
        generous_fp = sum(cat == c for m in matches for cat in m.generous_fp_categories)
        rows.append(_row(c.value, len(subset), tp, fn, strict_fp, generous_fp))

    tp = sum(1 for m in matches if m.found)
    fn = len(matches) - tp
    strict_fp = sum(len(m.strict_fp_categories) for m in matches)
    generous_fp = sum(len(m.generous_fp_categories) for m in matches)
    rows.append(_row("OVERALL", len(matches), tp, fn, strict_fp, generous_fp))

    located = _div(sum(1 for m in matches if m.located), len(matches))
    return MetricsReport(tool=tool, rows=rows, located_recall=located)


def write_csv(report: MetricsReport, path: str | Path) -> None:
    fields = list(Row.model_fields)
    with Path(path).open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in report.rows:
            writer.writerow(row.model_dump())
