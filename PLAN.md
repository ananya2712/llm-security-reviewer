# LLM Security Code Reviewer — Plan & Design

## 1. Goal

A CLI tool that takes a GitHub PR diff, asks an LLM to flag security-relevant
changes, and is benchmarked against Semgrep on ~50 curated CVE-fix diffs with
precision/recall reported per category.

**Resume line target:** "Built LLM security code reviewer; benchmarked vs
Semgrep on 50 CVE-fix diffs (precision 0.81, recall 0.74)."

## 2. Scope

**In scope**
- CLI: `secreview review <owner/repo#PR>` and `secreview review --diff <file>`
- Detection categories (v1): injection (SQLi/cmd/XSS), auth changes, crypto
  misuse, hardcoded secrets, unsafe deserialization, path traversal, SSRF
- Languages (v1): Python + JavaScript/TypeScript (broadest CVE coverage, best
  Semgrep rules)
- Eval harness comparing Claude + one comparison model + Semgrep
- 50 curated CVE-fix diffs with line-level ground truth

**Out of scope (v1)**
- GitHub App / bot mode (CLI first; Action wrapper if time)
- IDE integration
- Languages beyond Python/JS
- Fix suggestions (just detection + explanation)

## 3. Architecture

```
                ┌──────────────────────────────────────────┐
                │              secreview CLI               │
                └──────────────────────────────────────────┘
                          │                       │
                ┌─────────▼─────────┐   ┌─────────▼────────┐
                │  github_client    │   │   diff loader    │
                │  (fetch PR diff)  │   │  (--diff file)   │
                └─────────┬─────────┘   └─────────┬────────┘
                          └───────────┬───────────┘
                                      ▼
                          ┌──────────────────────┐
                          │   diff.py            │
                          │   parse → hunks      │
                          │   filter noise files │
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │   reviewer.py        │
                          │   prompts + provider │
                          │   → Finding[]        │
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │   report.py          │
                          │   human + JSON out   │
                          └──────────────────────┘

Parallel eval pipeline:
  dataset → [reviewer, semgrep_runner] → matcher → metrics → results/*.csv
```

### Key modules

| Module | Responsibility |
|---|---|
| `github_client.py` | Fetch PR via GitHub REST (`/pulls/{n}`, `/pulls/{n}/files`). Return unified diff + per-file metadata + base/head SHAs. Auth via `GITHUB_TOKEN`. |
| `diff.py` | Parse unified diff with `unidiff`. Group by file, drop binary + vendored + lockfile noise. Provide line-anchored hunks to the reviewer. |
| `providers/` | Thin abstraction: `review(diff, context) -> list[Finding]`. Implementations: `anthropic_provider.py` (Claude Sonnet 4.6), `openai_provider.py` (GPT-4-class). |
| `prompts.py` | System prompt + few-shot examples + structured output schema. Versioned (`v1`, `v2`…) so eval results stay reproducible. |
| `models.py` | Pydantic `Finding { file, start_line, end_line, category, severity, confidence, rationale, code_snippet }`. |
| `semgrep_runner.py` | Subprocess `semgrep --config p/security-audit --config p/secrets --json`. Normalize output into the same `Finding` shape. |
| `report.py` | Render findings to terminal (rich) + machine-readable JSON. |

### Data contract: `Finding`

```python
class Finding(BaseModel):
    file: str
    start_line: int            # 1-indexed, in post-diff file
    end_line: int
    category: Category         # enum: INJECTION, AUTH, CRYPTO, SECRET, ...
    severity: Severity         # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float          # 0..1 (LLM-self-reported; Semgrep = 1.0)
    rationale: str             # short explanation
    code_snippet: str          # the offending lines
    source: Literal["llm", "semgrep"]
```

## 4. LLM design

- **Model:** Claude Sonnet 4.6 (`claude-sonnet-4-6`) as primary; one comparison
  model (likely GPT-4-class) for the eval delta.
- **Structured output:** request JSON matching `Finding[]` schema. Use
  Anthropic's tool-use for schema enforcement.
- **Chunking:** if a diff has > N hunks or > M tokens, batch by file. Never
  split a hunk across calls.
- **Prompt structure:**
  1. System: role + categories + JSON schema + "report nothing if nothing"
  2. User: file path, language, hunk(s) with ±20 lines of surrounding context
  3. Few-shot: 2–3 worked examples (one positive, one negative)
- **No chain-of-thought in output** — keep responses cheap and parseable. If
  we want reasoning, use Claude's extended thinking, not free-text in JSON.
- **Caching:** prompt cache the system prompt + few-shot block. Big cost win
  across an eval run of 50 diffs × 2 models.

## 5. Eval methodology

### Dataset curation
Source candidates (in priority order):
1. **CVEfixes dataset** (Bhandari et al.) — has commit-level fix data with CWE labels
2. **GitHub Advisory DB** — fixes link to commits via `references`
3. **NVD** — link out to GitHub fix commits

Curation pipeline (`evals/curate.py`):
- Filter to Python + JS/TS repos
- Filter to in-scope CWEs (mapped to our categories)
- Single-file or small-multi-file fixes only (keeps ground truth tractable)
- Hand-verify each one: confirm the CWE, mark vulnerable lines in pre-fix file
- Target: 50 entries, ~25 Python + ~25 JS/TS, balanced across categories

Manifest entry:
```json
{
  "id": "CVE-2023-XXXXX",
  "repo": "owner/repo",
  "fix_commit": "abc123",
  "cwe": "CWE-89",
  "category": "INJECTION",
  "language": "python",
  "vulnerable_file": "src/db.py",
  "vulnerable_lines": [42, 43, 44],
  "fix_diff_path": "diffs/CVE-2023-XXXXX.diff",
  "notes": "..."
}
```

### Eval mechanics
For each entry, we want to test "would the reviewer catch this if it were
introduced in a PR?" So:

1. **Reverse the fix diff** → synthetic "PR that introduces the vuln"
2. Run LLM reviewer on the reversed diff
3. Run Semgrep on the **pre-fix** file (Semgrep is file-level, not diff-level)
4. Collect findings from both

### Matching findings → ground truth
A finding is a **true positive** if:
- File matches `vulnerable_file`, AND
- `[start_line, end_line]` overlaps with `vulnerable_lines` (±3 line window), AND
- `category` matches the labeled category (loose match — exact CWE not required)

- **FN:** the CVE has no qualifying finding from that tool
- **FP:** a finding on a file/range that doesn't match any known CVE location

### Honest reporting caveat
Files in the dataset may have *other* real vulnerabilities not in our labels.
A "false positive" on the same file is therefore noisy. We report two numbers:
- **Strict FP:** any finding outside the labeled lines on the vulnerable file
- **Generous FP:** only count findings on files with no known vuln

### Metrics reported
- Per-category precision / recall / F1
- Overall precision / recall / F1
- LLM-vs-Semgrep agreement (Cohen's κ)
- Cost per diff (LLM) and runtime per diff (both)
- Confusion matrix CSV in `evals/results/`

## 6. Milestones (3–4 weeks)

| Week | Deliverable | Definition of done |
|---|---|---|
| 1 | Core reviewer working end-to-end | `secreview review owner/repo#42` returns Findings JSON on real PRs; 10 hand-tested diffs |
| 2 | Eval harness + dataset v1 | 50-entry manifest committed; Semgrep runner working; eval CLI runs end-to-end on the 50 |
| 3 | Metrics + prompt iteration | precision/recall reported; ≥2 prompt iterations based on FP/FN analysis; comparison model integrated |
| 4 | Polish + writeup | README with results table + methodology + reproducibility steps; optional GitHub Action wrapper |

## 7. Project structure

```
llm-security-reviewer/
├── pyproject.toml
├── README.md
├── PLAN.md                       # this file
├── .env.example
├── .gitignore
├── src/secreview/
│   ├── __init__.py
│   ├── cli.py
│   ├── github_client.py
│   ├── diff.py
│   ├── models.py
│   ├── reviewer.py
│   ├── prompts.py
│   ├── semgrep_runner.py
│   ├── report.py
│   └── providers/
│       ├── __init__.py
│       ├── base.py
│       ├── anthropic_provider.py
│       └── openai_provider.py
├── evals/
│   ├── curate.py
│   ├── run_eval.py
│   ├── matching.py
│   ├── metrics.py
│   ├── dataset/
│   │   ├── manifest.json
│   │   └── diffs/
│   └── results/
├── tests/
│   ├── test_diff.py
│   ├── test_matching.py
│   ├── test_providers.py
│   └── fixtures/
└── scripts/
    └── smoke.sh
```

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Dataset curation eats more than a week | Start with 20 high-quality entries; expand to 50 if time. Lean on CVEfixes' existing structure rather than rolling our own. |
| LLM API cost during iteration | Prompt cache aggressively; develop against a 5-diff smoke set, only run full 50 on milestone evals. Budget: ~$100. |
| Semgrep baseline isn't apples-to-apples | Document exact rulesets used per language; rerun whenever changed. Report both p/security-audit alone and full ensemble. |
| Ground-truth FP noise | Report strict + generous FP separately; hand-spot-check 10 "false positives" to estimate real FP rate. |
| Scope creep on supported languages | Lock to Python + JS/TS for v1; explicit "out of scope" list in README. |

## 9. Open questions

- Should we let the LLM see the *original* (pre-edit) file content too, or only
  the diff? Diff-only is closer to a real review tool; full-file is more
  accurate. **Default:** diff + ±20 lines context. Revisit if recall is poor.
- Do we want to evaluate on the same file with both tools, or compare on each
  tool's preferred input? **Decision:** both tools see the same pre-fix file
  state. Diff is reconstructed; Semgrep just scans the file.
- Comparison model: GPT-4o-class vs an open-weights model (Llama-3-70B)? Latter
  is more interesting as a "narrative" but more setup. **Default:** GPT-4-class
  via OpenAI for v1.