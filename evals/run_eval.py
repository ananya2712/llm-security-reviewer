"""Orchestrate a full eval run: reverse each fix, run both tools, score them.

For every entry: read its fix diff, reverse it into a synthetic vuln-introducing
PR, run the LLM reviewer on the reversed diff and Semgrep on the pre-fix file,
then match both against ground truth and compute metrics.

The two tools are injected as callables so the pure orchestration is testable
with fakes; `default_reviewer` / `default_semgrep` wire in the real components.
Results (per-entry matches + metrics + CSVs) are written under `results/`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

from secreview.models import Finding

from evals.manifest import DatasetEntry, load_manifest
from evals.matching import EntryMatch, match_entry
from evals.metrics import MetricsReport, compute_metrics, write_csv
from evals.synthesize import reverse_unified_diff

# (entry, reversed_diff) -> findings ; (entry) -> findings
ReviewerFn = Callable[[DatasetEntry, str], list[Finding]]
SemgrepFn = Callable[[DatasetEntry], list[Finding]]


class ToolRun(BaseModel):
    matches: list[EntryMatch]
    metrics: MetricsReport


class EvalRun(BaseModel):
    llm: ToolRun
    semgrep: ToolRun


def run_eval(
    entries: list[DatasetEntry],
    *,
    reviewer: ReviewerFn,
    semgrep: SemgrepFn,
    dataset_dir: str | Path,
    window: int = 3,
) -> EvalRun:
    dataset_dir = Path(dataset_dir)
    llm_matches: list[EntryMatch] = []
    semgrep_matches: list[EntryMatch] = []

    for entry in entries:
        fix_diff = (dataset_dir / entry.fix_diff_path).read_text()
        reversed_diff = reverse_unified_diff(fix_diff)
        llm_matches.append(match_entry(reviewer(entry, reversed_diff), entry, window))
        semgrep_matches.append(match_entry(semgrep(entry), entry, window))

    return EvalRun(
        llm=ToolRun(matches=llm_matches, metrics=compute_metrics("llm", llm_matches)),
        semgrep=ToolRun(matches=semgrep_matches, metrics=compute_metrics("semgrep", semgrep_matches)),
    )


def default_reviewer(provider) -> ReviewerFn:
    """Wrap a `ReviewProvider` as a reviewer callable over the reversed diff."""
    from secreview.reviewer import review_diff

    return lambda entry, reversed_diff: review_diff(reversed_diff, provider).findings


def default_semgrep(runner, dataset_dir: str | Path) -> SemgrepFn:
    """Wrap a `SemgrepRunner` to scan each entry's pre-fix file."""
    dataset_dir = Path(dataset_dir)

    def scan(entry: DatasetEntry) -> list[Finding]:
        if not entry.prefix_file:
            return []
        return runner.scan(dataset_dir / entry.prefix_file)

    return scan


def write_results(run: EvalRun, out_dir: str | Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(run.model_dump_json(indent=2))
    write_csv(run.llm.metrics, out_dir / "metrics_llm.csv")
    write_csv(run.semgrep.metrics, out_dir / "metrics_semgrep.csv")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the secreview vs Semgrep eval.")
    parser.add_argument("manifest", help="Path to dataset/manifest.json")
    parser.add_argument("--out", default="evals/results", help="Output directory")
    parser.add_argument("--model", default=None, help="Override the reviewer model")
    args = parser.parse_args()

    from secreview.providers import AnthropicProvider
    from secreview.semgrep_runner import SemgrepRunner

    manifest_path = Path(args.manifest)
    entries = load_manifest(manifest_path)
    provider = AnthropicProvider(model=args.model) if args.model else AnthropicProvider()

    run = run_eval(
        entries,
        reviewer=default_reviewer(provider),
        semgrep=default_semgrep(SemgrepRunner(), manifest_path.parent),
        dataset_dir=manifest_path.parent,
    )
    write_results(run, args.out)

    for tool in (run.llm.metrics, run.semgrep.metrics):
        overall = tool.rows[-1]
        print(
            f"[{tool.tool:8}] recall={overall.recall:.2f} "
            f"precision(strict)={overall.strict_precision:.2f} "
            f"precision(generous)={overall.generous_precision:.2f} "
            f"located={tool.located_recall:.2f}"
        )


if __name__ == "__main__":
    main()
