"""The eval dataset contract: one `DatasetEntry` per curated CVE-fix.

Loaded from `dataset/manifest.json`. The harness reverses each entry's fix diff
into a synthetic "PR that introduces the vuln", runs both tools, and matches
their findings against `vulnerable_file` + `vulnerable_lines`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from secreview.models import Category


class DatasetEntry(BaseModel):
    id: str
    repo: str
    fix_commit: str
    cwe: str
    category: Category
    language: str
    vulnerable_file: str
    vulnerable_lines: list[int] = Field(min_length=1)
    fix_diff_path: str
    prefix_file: str | None = None  # pre-fix file on disk, for Semgrep (file-level)
    notes: str = ""

    @model_validator(mode="after")
    def _check_lines(self) -> "DatasetEntry":
        if any(n < 1 for n in self.vulnerable_lines):
            raise ValueError("vulnerable_lines must be 1-indexed (>= 1)")
        return self


def load_manifest(path: str | Path) -> list[DatasetEntry]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list):
        raise ValueError("manifest must be a JSON array of entries")
    return [DatasetEntry.model_validate(e) for e in data]
