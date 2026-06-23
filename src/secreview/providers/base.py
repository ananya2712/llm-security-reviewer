"""Provider abstraction: turn a parsed diff into `Finding`s via some LLM.

A provider owns one model + SDK. `review_file` is the unit of work (one API
call per file, never splitting a hunk — see PLAN §4); `review` loops it across
a whole diff. Mapping the model's `LLMFinding` output to the canonical
`Finding` (stamping `source="llm"`) is shared here so every provider does it
identically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..diff import FileDiff
from ..models import Finding
from ..prompts import ReviewResult


def to_findings(result: ReviewResult) -> list[Finding]:
    """Map the LLM-facing `ReviewResult` to canonical `Finding`s (source=llm)."""
    return [Finding(**f.model_dump(), source="llm") for f in result.findings]


class ReviewProvider(ABC):
    """One model behind a uniform `review_file` / `review` interface.

    Subclasses set `name` (short id for eval reporting) and `model`.
    """

    name: str
    model: str

    @abstractmethod
    def review_file(self, fd: FileDiff) -> list[Finding]:
        """Review a single file's diff and return its findings."""

    def review(self, files: list[FileDiff]) -> list[Finding]:
        """Review every file in a parsed diff, concatenating findings."""
        out: list[Finding] = []
        for fd in files:
            out.extend(self.review_file(fd))
        return out
