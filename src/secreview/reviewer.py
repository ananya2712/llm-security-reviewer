"""Orchestration: raw diff text -> parsed/filtered files -> provider -> report.

The thin seam between `diff.parse_diff` and a `ReviewProvider`. It decides
*what* gets reviewed (files with reviewable hunks, after noise filtering),
hands them to the provider, and returns a deterministic, report-ready
`ReviewReport`. Token budgeting / chunking will land here later (DESIGN §5);
for v1 it's a straight pass-through.
"""

from __future__ import annotations

from pydantic import BaseModel

from .diff import parse_diff
from .models import Finding
from .providers.base import ReviewProvider


class ReviewReport(BaseModel):
    """Everything a caller (CLI, report.py, eval) needs from one review.

    `findings` is sorted deterministically so report output and eval runs are
    reproducible. `files_reviewed` are the paths actually sent to the model
    (noise files and hunk-less files are excluded).
    """

    findings: list[Finding]
    files_reviewed: list[str]

    @property
    def finding_count(self) -> int:
        return len(self.findings)


def _sort_key(f: Finding) -> tuple[str, int, int, str]:
    return (f.file, f.start_line, f.end_line, f.category.value)


def review_diff(diff_text: str, provider: ReviewProvider) -> ReviewReport:
    """Review a unified diff and return a sorted, deterministic report.

    Noise files (binaries, lockfiles, vendored, minified) are dropped by
    `parse_diff`; we then drop files with no hunks (pure renames/deletions)
    since there's nothing for the model to read.
    """
    files = [fd for fd in parse_diff(diff_text) if fd.hunks]
    findings = provider.review(files)
    findings.sort(key=_sort_key)
    return ReviewReport(findings=findings, files_reviewed=[fd.path for fd in files])
