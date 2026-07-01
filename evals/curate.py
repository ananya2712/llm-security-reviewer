"""Turn a CVE fix commit into a (mostly-filled) dataset entry.

This does the mechanical part of curation; a human still verifies the result.
Given `owner/repo@<sha>` it:

  1. fetches the fix commit's diff and drops out-of-scope / noise files,
  2. rejects fixes that aren't small (single / few source files),
  3. materializes the fix diff and the pre-fix file (for Semgrep) on disk,
  4. auto-suggests `vulnerable_lines` from the lines the fix *removed*, and
  5. emits a `DatasetEntry` flagged NEEDS REVIEW for the human to confirm.

The CWE (and thus category) is the human's call — pass `--cwe` to seed it. The
GitHub client is injectable so the whole flow is testable without the network.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from secreview.diff import FileDiff, parse_diff
from secreview.github_client import CommitRef, GitHubClient
from secreview.models import Category
from secreview.semgrep_runner import CWE_CATEGORY

from evals.manifest import DatasetEntry, load_manifest

IN_SCOPE_LANGUAGES = {"python", "javascript", "typescript"}
MAX_SOURCE_FILES = 3  # "small-multi-file fixes only" (PLAN §5)


class CurationError(RuntimeError):
    """A commit can't be turned into a usable entry (filtered out)."""


def suggest_category(cwe: str | None) -> Category | None:
    """Map a CWE id (e.g. 'CWE-89' or 'CWE-89: ...') to our category, if known."""
    if not cwe:
        return None
    key = cwe.split(":", 1)[0].strip().upper()
    return CWE_CATEGORY.get(key)


def in_scope_files(files: list[FileDiff]) -> list[FileDiff]:
    """Keep only Python/JS/TS files (noise is already dropped by parse_diff)."""
    return [f for f in files if f.language in IN_SCOPE_LANGUAGES]


def _change_count(fd: FileDiff) -> int:
    return sum(1 for h in fd.hunks for ln in h.lines if ln.type in ("add", "remove"))


def primary_file(files: list[FileDiff]) -> FileDiff:
    """The file with the most changed lines — the likely locus of the fix."""
    return max(files, key=_change_count)


def suggest_vulnerable_lines(fd: FileDiff) -> list[int]:
    """Pre-fix line numbers the fix removed — the strongest guess at the vuln.

    Empty when the fix only *adds* lines (e.g. inserting a missing check); the
    human then marks the lines by hand.
    """
    return sorted(
        {
            ln.source_line_no
            for h in fd.hunks
            for ln in h.lines
            if ln.type == "remove" and ln.source_line_no is not None
        }
    )


def _default_id(ref: CommitRef, cwe: str | None) -> str:
    parts = [cwe.replace(":", "").split()[0] if cwe else None, ref.repo, ref.sha[:7]]
    slug = "-".join(p for p in parts if p)
    return re.sub(r"[^A-Za-z0-9._-]+", "-", slug).strip("-").upper()


def make_candidate(
    commit_spec: str,
    dataset_dir: str | Path,
    *,
    gh: GitHubClient | None = None,
    cwe: str | None = None,
    entry_id: str | None = None,
    fetch_prefix: bool = True,
) -> DatasetEntry:
    """Fetch, filter, materialize, and build a NEEDS-REVIEW `DatasetEntry`."""
    ref = CommitRef.parse(commit_spec)
    gh = gh or GitHubClient()
    dataset_dir = Path(dataset_dir)

    files = in_scope_files(parse_diff(gh.fetch_commit_diff(ref)))
    if not files:
        raise CurationError(f"{ref.slug}: no in-scope Python/JS/TS files changed")
    if len(files) > MAX_SOURCE_FILES:
        raise CurationError(
            f"{ref.slug}: touches {len(files)} source files (> {MAX_SOURCE_FILES}); not a small fix"
        )

    primary = primary_file(files)
    eid = entry_id or _default_id(ref, cwe)

    diff_rel = f"diffs/{eid}.diff"
    _write(dataset_dir / diff_rel, gh.fetch_commit_diff(ref))

    prefix_rel: str | None = None
    if fetch_prefix:
        parent = gh.fetch_commit_parent_sha(ref)
        prefix_rel = f"prefix/{primary.path}"
        _write(dataset_dir / prefix_rel, gh.fetch_file(ref.owner, ref.repo, parent, primary.path))

    vuln = suggest_vulnerable_lines(primary)
    note = "NEEDS REVIEW: confirm cwe/category; verify vulnerable_lines (auto-suggested from removed lines)"
    if not vuln:
        note += "; no removed lines — vulnerable_lines is a placeholder"

    return DatasetEntry(
        id=eid,
        repo=f"{ref.owner}/{ref.repo}",
        fix_commit=ref.sha,
        cwe=cwe or "CWE-000",
        category=suggest_category(cwe) or Category.OTHER,
        language=primary.language or "unknown",
        vulnerable_file=primary.path,
        vulnerable_lines=vuln or [1],
        fix_diff_path=diff_rel,
        prefix_file=prefix_rel,
        notes=note,
    )


def add_to_manifest(entry: DatasetEntry, manifest_path: str | Path) -> None:
    """Append (or replace by id) an entry in the manifest JSON array."""
    manifest_path = Path(manifest_path)
    entries = load_manifest(manifest_path) if manifest_path.exists() else []
    entries = [e for e in entries if e.id != entry.id] + [entry]
    manifest_path.write_text(
        json.dumps([e.model_dump() for e in entries], indent=2) + "\n"
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a dataset entry from a CVE fix commit.")
    parser.add_argument("commit", help="'owner/repo@<sha>' or a GitHub commit URL")
    parser.add_argument("--cwe", default=None, help="CWE id, e.g. CWE-89 (seeds the category)")
    parser.add_argument("--id", dest="entry_id", default=None, help="Override the entry id")
    parser.add_argument("--dataset-dir", default="evals/dataset", help="Dataset root")
    parser.add_argument("--no-prefix", action="store_true", help="Skip fetching the pre-fix file")
    parser.add_argument(
        "--commit-to-manifest",
        action="store_true",
        help="Append to manifest.json (default: just print the entry for review)",
    )
    args = parser.parse_args()

    entry = make_candidate(
        args.commit,
        args.dataset_dir,
        cwe=args.cwe,
        entry_id=args.entry_id,
        fetch_prefix=not args.no_prefix,
    )

    print(json.dumps(entry.model_dump(), indent=2))
    print(f"\n# {entry.notes}", flush=True)

    if args.commit_to_manifest:
        add_to_manifest(entry, Path(args.dataset_dir) / "manifest.json")
        print(f"# appended {entry.id} to manifest.json")
    else:
        print("# review the entry above, then re-run with --commit-to-manifest to add it")


if __name__ == "__main__":
    main()
