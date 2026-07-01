import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from secreview.models import Finding
from evals.manifest import load_manifest
from evals.run_eval import EvalRun, run_eval, write_results

DATASET = ROOT / "evals" / "dataset"


def _f(file, start, end, category) -> Finding:
    return Finding(
        file=file,
        start_line=start,
        end_line=end,
        category=category,
        severity="HIGH",
        confidence=0.9,
        rationale="r",
        code_snippet="s",
        source="llm",
    )


def main() -> None:
    entries = load_manifest(DATASET / "manifest.json")
    assert [e.id for e in entries] == ["SAMPLE-SQLI-PY", "SAMPLE-SECRET-JS"]
    print("[ok] sample manifest loads (2 entries)")

    seen_diffs = {}

    def fake_reviewer(entry, reversed_diff):
        # Capture the reversed diff the runner produced, and "find" each vuln.
        seen_diffs[entry.id] = reversed_diff
        if entry.id == "SAMPLE-SQLI-PY":
            return [_f("app/db.py", 12, 13, "INJECTION")]  # TP
        return [_f("web/config.js", 1, 1, "SECRET")]  # TP

    def fake_semgrep(entry):
        # Semgrep finds the SQLi, misses the secret (typical), plus one off-file FP.
        if entry.id == "SAMPLE-SQLI-PY":
            return [_f("app/db.py", 12, 12, "INJECTION"), _f("app/other.py", 9, 9, "OTHER")]
        return []

    run = run_eval(
        entries, reviewer=fake_reviewer, semgrep=fake_semgrep, dataset_dir=DATASET
    )
    assert isinstance(run, EvalRun)

    # The reviewer must have received the *reversed* fix (vuln lines added).
    assert '+    q = "SELECT * FROM users WHERE id = " + str(uid)' in seen_diffs["SAMPLE-SQLI-PY"]
    print("[ok] runner reversed each fix diff before handing it to the reviewer")

    llm = {r.category: r for r in run.llm.metrics.rows}["OVERALL"]
    assert llm.tp == 2 and llm.fn == 0 and llm.recall == 1.0
    assert llm.strict_fp == 0 and llm.strict_precision == 1.0
    print("[ok] LLM: recall 1.0, precision 1.0 on the sample")

    sg = {r.category: r for r in run.semgrep.metrics.rows}["OVERALL"]
    assert sg.tp == 1 and sg.fn == 1 and sg.recall == 0.5
    assert sg.strict_fp == 1 and sg.generous_fp == 1  # the off-file OTHER finding
    print("[ok] Semgrep: recall 0.5, 1 FP on the sample")

    # Results serialize to disk (JSON + per-tool CSVs).
    with tempfile.TemporaryDirectory() as d:
        write_results(run, d)
        assert (Path(d) / "results.json").is_file()
        assert (Path(d) / "metrics_llm.csv").is_file()
        assert (Path(d) / "metrics_semgrep.csv").is_file()
    print("[ok] write_results emits results.json + metrics_{llm,semgrep}.csv")


if __name__ == "__main__":
    main()
