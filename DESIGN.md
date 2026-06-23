# secreview — Technical Design Decisions

Companion to `PLAN.md`. `PLAN.md` is the upfront goal/scope/architecture;
this doc captures implementation-level decisions made as the code is built,
with the rationale for each.

Updated through: **step 4 (providers)**.

---

## 1. Project setup

### 1.1 `src/` layout
Package lives at `src/secreview/`, not at the project root.

**Why:** prevents implicit imports from the project root from masking real
packaging bugs. With a flat layout, `import secreview` can resolve via cwd
even if the package isn't installed — so packaging breakage stays hidden
until release. With `src/`, you must install (or set `PYTHONPATH`) to import,
which means tests and scripts exercise the same import path users will hit.

### 1.2 Build backend: hatchling
Chosen via `[build-system] requires = ["hatchling"]`.

**Why:** PEP 517-compliant, no `setup.py`, and is the default the modern
Python ecosystem has converged on (used by pydantic, FastAPI, etc.). No
external config files needed beyond `pyproject.toml`.

### 1.3 Python 3.11+
**Why:** we use PEP 604 union syntax (`int | None`), `Literal`, modern
Pydantic v2, and `from __future__ import annotations` semantics. 3.11 is
also old enough now (2026) that no environment we care about lacks it.

### 1.4 Dependency choices

| Package | Role | Why this one |
|---|---|---|
| `anthropic` | Primary LLM SDK | Per PLAN: Claude Sonnet 4.6 is the primary reviewer. Official SDK supports tool-use (for structured output) and prompt caching. |
| `openai` | Comparison LLM SDK | Per PLAN: GPT-4-class as the eval comparison model. |
| `pydantic` v2 | Data models | Validation at the boundary (LLM output, diff parsing). Gives us free JSON (de)serialization with type-safe schemas — important since the LLM emits JSON we need to validate. |
| `unidiff` | Parse unified diffs | Mature, single-purpose, no transitive deps. Rolling our own diff parser is a tar pit (binary detection, rename tracking, hunk math). |
| `httpx` | HTTP client (for GitHub API) | Sync + async support, modern API, better timeouts/retries than `requests`. |
| `typer` | CLI framework | Click under the hood, but with type-hint-driven arg parsing. Less boilerplate than argparse, plays nice with `pyproject.toml` entry points. |
| `rich` | Terminal output | For `report.py`'s human-readable findings table. Standard choice for colored/structured CLI output. |
| `python-dotenv` | Load `.env` | Lets contributors set `ANTHROPIC_API_KEY` etc. in a local file without leaking to shell history. |

Dev/eval extras are split (`[project.optional-dependencies]`) so the base
install stays slim — `semgrep` and `pandas` are heavy and only needed for
running evals.

### 1.5 Editable install + macOS Sequoia workaround
`pip install -e .` works, but on macOS Sequoia + Python 3.13 the
`.pth` file hatchling creates (`_editable_impl_secreview.pth`) gets the
macOS `hidden` filesystem flag attached (via the `com.apple.provenance`
extended attribute). Python 3.13's `site.py` was updated to skip hidden
`.pth` files for safety, so the package becomes unimportable.

**Decision:** smoke scripts in `scripts/` self-bootstrap with
`sys.path.insert(0, "src")` so they don't depend on the `.pth` being
processed. The real package code is unaffected; only ad-hoc script
invocation needs the workaround. Pytest is already configured with
`pythonpath = ["src"]` in `pyproject.toml`, so tests are fine too.

**Why not "just fix the flag once":** `pip` operations re-apply the
provenance xattr and the hidden coupling sometimes returns. The bootstrap
makes the scripts robust to this regardless of install state.

---

## 2. `models.py` — the `Finding` contract

The data contract every other module reads or writes. See PLAN.md §3 for
the original schema.

### 2.1 String-valued enums (`Category`, `Severity`)
Both inherit `(str, Enum)`.

**Why:** Pydantic's JSON output serializes them as readable strings
(`"INJECTION"`, `"HIGH"`) rather than ints. Critical because:
- The LLM emits JSON using these names — round-trip stays human-readable.
- CSV exports of eval results stay readable without an extra mapping step.
- We get free `category == "INJECTION"` string comparisons in eval glue
  code if needed.

### 2.2 `OTHER` category
Not in the original PLAN list, added during implementation.

**Why:** the LLM will occasionally find something genuinely security-relevant
that doesn't fit our 7 named categories. Forcing it into the nearest fit
distorts per-category metrics. `OTHER` lets us surface those findings while
keeping the labeled categories clean. Eval matching can choose to ignore
`OTHER` for category-level recall.

### 2.3 Line numbers are **target-file** (post-diff) indexed
PLAN.md said this; reinforcing here because it's load-bearing.

**Why:** when a reviewer reports "line 42 of foo.py is unsafe," users open
the new version of the file, not the pre-diff version. Target-line indexing
matches how humans read diffs.

### 2.4 `confidence` as float in [0, 1], LLM self-reported
**Why:** lets us filter "low-confidence" findings or weight precision/recall
by confidence. Semgrep findings get confidence = 1.0 since the rule either
matched or it didn't — there's no useful probabilistic signal there.
LLM self-confidence is noisy but better than nothing, and useful for
calibration analysis in the eval.

### 2.5 Cross-field validation: `end_line >= start_line`
Done in a `@model_validator(mode="after")` since field-level validators
can't see other fields.

**Why:** catches bad LLM output at the boundary. A model emitting
`start_line=10, end_line=5` would silently break downstream line-overlap
matching in the eval.

### 2.6 `source` as `Literal["llm", "semgrep"]`
Not an Enum.

**Why:** there are exactly two and ever-likely-to-be-two values, and it's
a discriminator the eval code reads constantly. `Literal` keeps it
lightweight; no need for an enum's machinery.

---

## 3. `diff.py` — unified diff parsing

Module-level docstring: parse a unified diff into per-file structured hunks,
dropping noise files. Wraps `unidiff` so we never expose its types upstream.

### 3.1 Pydantic models, not dataclasses
`DiffLine`, `Hunk`, `FileDiff` are all `BaseModel`.

**Why:** consistency with `Finding`. Also: easier serialization for caching
parsed diffs to disk during eval, and field validation for free. The
overhead is irrelevant at our scale (≤ a few thousand lines per diff).

### 3.2 Both `source_line_no` and `target_line_no` on every line
`source_line_no` is `None` for added lines; `target_line_no` is `None` for
removed lines.

**Why:** removed lines have no post-image line number — there's nothing to
point at. Added/context lines have both numbers for the same reason. This
also matches `unidiff`'s native representation, so no information is lost.
The LLM input format can choose which to surface (we'll surface target
line numbers for added/context lines, since findings reference target
lines per §2.3).

### 3.3 `render_unified()` on `Hunk`
Reconstructs the standard unified-diff hunk text from the structured form.

**Why:** the LLM will see hunks formatted like real `git diff` output —
which it has seen millions of times in training. Reconstructing from
structured form (rather than carrying the raw text through) means the
prompt sees exactly what we parsed, with no encoding/whitespace
surprises.

**Open question:** whether to annotate each line with its target line
number in the prompt (helps the LLM produce accurate line refs at the
cost of slightly weirder formatting). Deferred to `prompts.py` since that's
where prompt-input formatting belongs — `diff.py` just exposes the data.

### 3.4 Noise filtering
Drops three classes of file:

| Class | Examples | Reason to drop |
|---|---|---|
| Binary | images, archives | No source to review; `unidiff` flags these via `is_binary_file`. |
| Lockfiles | `package-lock.json`, `poetry.lock`, `Cargo.lock`, 6 more | Auto-generated. Reviewing a lockfile finding is always noise. |
| Vendored | `node_modules/`, `vendor/`, `third_party/`, `dist/`, `build/`, `.next/`, `.venv/`, `site-packages/` | Code we didn't write; findings here aren't actionable in a PR review. |
| Minified | `*.min.js`, `*.min.css`, `*.map` | Compiled output, not source. |

**Why a hardcoded list (not config):** v1 scope is small enough that
the list fits in one screen. If users want more granular control later,
this becomes a config-driven predicate.

### 3.5 Language detection via suffix only
No shebang inspection, no MIME sniffing.

**Why:** v1 supports Python + JS/TS only, all of which have unambiguous
suffixes. Adding shell-script detection or ambiguous-extension handling
is scope creep. Returns `None` for unknown suffixes; the reviewer will
still run on them but won't be able to specialize prompts by language.

### 3.6 Returns flat `list[FileDiff]`
Not a `ParsedDiff` wrapper object.

**Why:** the only consumer (`reviewer.py`) iterates per-file. A wrapper
would add no useful methods today; if we need diff-level metadata
later (stats, base SHA, etc.) we'll add it then.

### 3.7 Strips `a/` and `b/` path prefixes
`git diff` writes paths as `a/src/foo.py` and `b/src/foo.py`; we strip
those.

**Why:** the rest of the pipeline (and the user's mental model of the
file) uses `src/foo.py`. Carrying the `a/`/`b/` prefix would mean every
downstream consumer has to remember to strip it.

---

## 4. Smoke test conventions

Quick sanity scripts live in `scripts/smoke_<module>.py`, not `tests/`.

**Why split smoke from tests:**
- Smoke scripts are end-to-end, hand-runnable sanity checks during build.
- Pytest under `tests/` will be the formal regression suite.
- Smoke scripts can do things like hit a real API later (e.g.,
  `smoke_anthropic.py` once we have the provider); tests will stay hermetic.

Each smoke script:
- Self-bootstraps with `sys.path.insert(0, "src")` so it works regardless
  of editable install state (see §1.5).
- Prints `[ok] <claim>` per check — grep-friendly, single line per assertion.
- Exits non-zero on failure (default Python behavior for uncaught
  `AssertionError`).

---

## 5. Things deliberately deferred

So future steps don't accidentally re-litigate these:

- **Chunking / token budgeting** in `reviewer.py` — wait until we have one
  real diff to size against. Premature limits will be wrong.
- **Prompt versioning** — `prompts.py` will tag prompts `v1`, `v2`, … so
  eval results stay reproducible. Not implemented yet.
- **Caching strategy** for Anthropic prompt caching — will live in
  `providers/anthropic_provider.py`. Big eval cost win, but not yet wired.
- **GitHub PR-fetch retries / rate-limit handling** — `github_client.py`
  concern. Default to single attempt + clear error first; add retries only
  if needed in practice.
- **Context expansion** (the "±20 lines" from PLAN §4) — needs the full
  file, which we only get once `github_client.py` can fetch post-image
  file contents. Diff-only review is the v0; expand later if recall is poor.

---

## 6. Open questions tracked so far

- **Annotate diff lines with target line numbers in the LLM prompt?**
  **Resolved (step 3): yes, annotate.** See §7.1.
- **`OTHER` category in eval matching:** count toward category-level recall
  or ignore? Lean toward "ignore for per-category, count for overall."
  Decide when wiring up `evals/matching.py`.
- **Editable install fragility on macOS:** keep the script bootstrap as the
  durable fix, or switch to a different build backend (`setuptools`,
  `flit`) that doesn't trigger the provenance/hidden coupling? Bootstrap is
  cheaper for now; revisit if we hit it elsewhere.

---

## 7. `prompts.py` — the LLM interface

Owns everything the model sees: the versioned system prompt, the few-shot
block, and the renderer that turns a parsed `FileDiff` into review text. Also
defines the LLM-facing output contract.

### 7.1 Diff lines are annotated with NEW-file line numbers
Each line is rendered `NNN| <marker><text>`, where `NNN` is the
**target** (post-diff) line number and `<marker>` is `+`/`-`/space. Removed
lines get a blank gutter (they have no target number).

**Why (resolves §6 OQ1):** the eval matches a finding to ground truth with a
±3-line window, so line-reference accuracy is load-bearing. Putting the number
the model should cite directly in front of each line removes the need for it to
do `@@`-header arithmetic, which is where line drift comes from. We accept the
slightly non-standard format (vs. raw `git diff`) for the accuracy gain. The
same renderer (`format_file_diff`) produces both the few-shot examples and live
input, so the model never sees a format in training it won't see at serve time.

### 7.2 Structured output via `output_config.format`, not tool-use
PLAN §4 originally said "use tool-use for schema enforcement." We're using the
modern structured-outputs path (`messages.parse` + `output_config.format`)
instead.

**Why:** it reuses our Pydantic models directly (no hand-written tool schema to
keep in sync), validates client-side, composes with extended thinking, and is
the SDK's current recommendation. `prompts.py` therefore exposes a Pydantic
model (`ReviewResult`); the provider wires it in as the output format. Numeric
constraints (`confidence` 0–1, `start_line ≥ 1`) aren't expressible in the JSON
Schema subset structured outputs accepts — the SDK strips them from the wire
schema and re-validates them client-side, which is exactly what we want.

### 7.3 `LLMFinding` is `Finding` minus `source`
The model emits `LLMFinding` (8 fields); the reviewer stamps `source="llm"`
when mapping to the canonical `Finding`.

**Why:** the model has no meaningful notion of `source` — forcing it to always
emit `"llm"` wastes tokens and adds a way for it to be wrong (e.g. emitting
`"semgrep"`). Keeping the field off the LLM schema is cleaner. Cost: two
near-identical models that can drift. Mitigated by a drift guard in
`scripts/smoke_prompts.py` asserting `LLMFinding` fields == `Finding` fields −
`{source}`. If the duplication becomes annoying we can make `Finding` extend
`LLMFinding`, but that means editing the already-documented `models.py`
contract, so not yet.

### 7.4 Few-shot: one positive, one negative
One example introduces a SQL injection (added lines), one is a benign change
that must yield `findings: []`.

**Why:** the negative example is the important one — it teaches restraint so the
model doesn't pattern-match every string operation into an INJECTION finding,
which would tank precision. Examples are built by running real diffs through
`format_file_diff` (not hand-written text) so their formatting is guaranteed
identical to live input.

### 7.5 System prompt + few-shot are byte-stable
No timestamps, ids, or per-request content in either.

**Why:** lets the provider prompt-cache the whole prefix across an eval run
(50 diffs × 2 models). Per the caching prefix-match rule, any volatile byte in
the prefix would void the cache; keeping these frozen here means the provider
just adds a `cache_control` breakpoint and gets the cost win for free.

**Deferred to `providers/`:** whether to surface target line numbers for
*removed* lines (currently blank — they have no post-image number, and the eval
references target lines only), and prompt-cache breakpoint placement.

---

## 8. `providers/` — the LLM backends

`base.ReviewProvider` is the uniform interface; `anthropic_provider` is the
first (and primary) implementation.

### 8.1 `review_file` is the unit; `review` loops it
The abstract method is per-file (`review_file(fd) -> list[Finding]`); the base
class provides a concrete `review(files)` that concatenates across the diff.

**Why:** one API call per file keeps a whole file's hunks in a single request
(PLAN §4: "never split a hunk across calls") while staying the natural batching
boundary for token budgeting later. Orchestration lives in the thin `review`
loop now; it moves to `reviewer.py` once we add chunking/cost tracking.

### 8.2 Structured outputs via `messages.parse`, refusals degrade to `[]`
We call `client.messages.parse(..., output_format=ReviewResult)` and read
`resp.parsed_output` (SDK 0.104.1). On a safety `refusal` stop reason — or any
`None` parsed output — `review_file` returns `[]` rather than raising.

**Why:** a single refused file shouldn't sink a 50-diff eval run. "No findings"
is the safe degradation, and the eval scores it as a miss (an honest FN) rather
than crashing the batch. Real retry/error policy is still deferred (PLAN risk
table) — the SDK already auto-retries 429/5xx.

### 8.3 Primary model is Sonnet 4.6, constructor-overridable
`DEFAULT_MODEL = "claude-sonnet-4-6"`, per PLAN §4's deliberate cost choice for
the 50-diff × 2-model eval.

**Why not Opus:** the current Anthropic guidance defaults to Opus 4.8, but the
project explicitly picked Sonnet 4.6 up front to keep the eval within the ~$100
budget. `model` is a constructor arg so the comparison run or a one-off
higher-effort pass can override without code changes.

### 8.4 Adaptive thinking on by default
`thinking={"type": "adaptive"}` unless `thinking=False`.

**Why:** security review is reasoning-heavy (tracing taint from source to sink),
exactly what adaptive thinking is for, and it composes with structured outputs.
Toggleable so the eval can measure the thinking-vs-cost delta. We don't surface
thinking text (default `display` is omitted) — we only consume the parsed JSON.

### 8.5 `cache_control` on the system block (a no-op at v1 sizes)
The system prompt is sent as a cached text block.

**Why keep it despite being below the min-cacheable prefix:** at v1 the
system + few-shot prefix (~800 tokens) is under Sonnet's 2048-token minimum, so
nothing actually caches yet — the marker is silently ignored, no harm. It's
there so the cost win lands automatically once the prompt grows (±20-line
context expansion, more few-shot). Few-shot-block caching (a second breakpoint
on the last example turn) is deferred until the prefix clears the threshold.

### 8.6 Lazy client creation → hermetic smoke tests
The `anthropic.Anthropic()` client is only constructed when none is injected;
`scripts/smoke_providers.py` passes a stub client.

**Why:** lets the smoke test verify request shaping (model, `output_format`,
adaptive thinking, cached system, few-shot+diff messages), the
`LLMFinding → Finding(source="llm")` mapping, refusal handling, and the
empty-hunk short-circuit — all without an API key or spend. A real-API
`smoke_anthropic.py` (anticipated in §4) is deferred; it needs a key and costs
money, so it'll be opt-in.

**Still deferred:** `openai_provider.py` (the eval comparison model — only
needed for week-3 metrics, not Milestone-1 end-to-end), token budgeting /
chunking, and the real-API smoke.
