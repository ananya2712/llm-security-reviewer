"""Match a tool's findings against one dataset entry's ground truth.

A finding is a **true positive** when it lands on `vulnerable_file`, overlaps
`vulnerable_lines` within a ±window, and its category equals the labeled one.
We track two false-positive views (PLAN §5): *generous* counts only findings on
files with no known vuln; *strict* additionally counts findings on the
vulnerable file that fall outside the labeled window. FP categories are kept
(not just counts) so `metrics.py` can bucket precision per category.
"""

from __future__ import annotations

from pydantic import BaseModel

from secreview.models import Category, Finding

from evals.manifest import DatasetEntry

DEFAULT_WINDOW = 3


class EntryMatch(BaseModel):
    entry_id: str
    category: Category
    language: str
    found: bool  # located AND category matches → the TP
    located: bool  # vuln location flagged, any category (for localization recall)
    strict_fp_categories: list[Category]
    generous_fp_categories: list[Category]


def match_entry(
    findings: list[Finding], entry: DatasetEntry, window: int = DEFAULT_WINDOW
) -> EntryMatch:
    lo = min(entry.vulnerable_lines) - window
    hi = max(entry.vulnerable_lines) + window

    found = located = False
    strict: list[Category] = []
    generous: list[Category] = []

    for f in findings:
        if f.file == entry.vulnerable_file:
            overlaps = not (f.end_line < lo or f.start_line > hi)
            if overlaps:
                located = True
                if f.category == entry.category:
                    found = True
                # in-window findings are never counted as FP (could be the vuln)
            else:
                strict.append(f.category)  # on the vuln file but outside the window
        else:
            strict.append(f.category)  # file with no known vuln
            generous.append(f.category)

    return EntryMatch(
        entry_id=entry.id,
        category=entry.category,
        language=entry.language,
        found=found,
        located=located,
        strict_fp_categories=strict,
        generous_fp_categories=generous,
    )
