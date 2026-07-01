# secreview — Technical Design Decisions

Companion to `PLAN.md`. `PLAN.md` is the upfront goal/scope/architecture;
this doc captures implementation-level decisions made as the code is built,
with the rationale for each.

Updated through: **step 9 (curate.py — dataset workflow)**.

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

**Still deferred:** token budgeting / chunking, and the real-API smoke.

### 8.7 `openai_provider.py` — the eval comparison backend
Mirrors `AnthropicProvider` for the OpenAI Chat Completions API so eval results
differ only by model, not by harness: same `SYSTEM_PROMPT` + few-shot, same
`ReviewResult` schema, same `Finding(source="llm")` mapping, same
refusal-degrades-to-`[]` policy and empty-hunk short-circuit.

Backend-specific deltas:
- **System prompt rides in `messages`.** OpenAI has no separate `system` param,
  so the call prepends `{"role": "system", ...}` then `build_messages(fd)`.
- **`chat.completions.parse(response_format=ReviewResult)`**, parsed model on
  `choices[0].message.parsed`; a refusal sets `message.refusal` (parsed None).
- **No thinking/effort param** — gpt-4o-class isn't a reasoning model.
- **Default model `gpt-4o`** (PLAN §4's "GPT-4o-class"), constructor-overridable.

**Why `ReviewResult` is reused unchanged:** OpenAI strict structured outputs is
narrower than Anthropic's, but current OpenAI accepts the numeric range
constraints our schema carries (`confidence` 0–1, `start_line ≥ 1`). Verified
empirically: the SDK's `openai.lib._pydantic.to_strict_json_schema(ReviewResult)`
**keeps** `minimum`/`maximum` rather than stripping them — the SDK (kept in sync
with the API) would drop unsupported keywords, so retaining them means the API
takes them. No constraint-free parallel model needed.

---

## 9. `reviewer.py` — orchestration

The seam between `diff.parse_diff` and a `ReviewProvider`. `review_diff(text,
provider) -> ReviewReport` is the one entry point the CLI / eval call.

### 9.1 The reviewer owns "what gets reviewed"
It parses, then drops files with no hunks (`[fd for fd in parse_diff(text) if
fd.hunks]`) before handing them to the provider.

**Why here, not in the provider:** scope selection is an orchestration concern,
not a per-backend one — every provider should review the same set. The
provider's own empty-hunk guard (§8 / `review_file`) stays as belt-and-suspenders,
but the reviewer is the single source of truth for which files count. This is
also where token budgeting / chunking will slot in later without touching any
provider.

### 9.2 `ReviewReport`, not a bare `list[Finding]`
Returns a Pydantic `ReviewReport { findings, files_reviewed }` with a
`finding_count` convenience property.

**Why:** the CLI wants to say "reviewed N files, found M issues" — including the
zero-findings case, which a bare list can't distinguish from "nothing
reviewed." `files_reviewed` records exactly what the model saw (post-noise,
post-empty-hunk). Pydantic gives report.py / the eval free, stable JSON
serialization (round-trip verified in the smoke test).

### 9.3 Findings sorted by `(file, start_line, end_line, category)`
Sorted before returning.

**Why:** deterministic output makes report rendering stable and eval runs
reproducible (diffable results across prompt iterations). The model can emit
findings in any order; sorting normalizes it. Category sorts by its string
value — fine since `Category` is a `str` enum.

**Deferred:** cross-finding **dedup**. A single call per file rarely repeats a
finding, so v1 skips it; revisit if overlap shows up once context expansion or
multi-call chunking lands.

---

## 10. `report.py` + `cli.py` — the user-facing edge (Milestone 1)

### 10.1 `report.py` is rendering-only, no I/O policy
Exposes `render_terminal(report, console=None)` (rich table or an all-clear
line) and `to_json(report)`.

**Why split from the CLI:** rendering is the part worth unit-testing, and the
eval harness wants `to_json` without going through argv. Passing an optional
`console` lets tests capture output to a `StringIO` buffer instead of a TTY. The
table shows `file:start-end`, category, severity (color-coded by urgency),
confidence, and rationale; `to_json` is just `ReviewReport.model_dump_json` so
the wire format is the same object the eval consumes.

### 10.2 `cli.py` is thin wiring over testable helpers
`review` does four things: `_load_diff` → `_make_provider` → `review_diff` →
render. The two helpers are module-level so a smoke test can monkeypatch
`_make_provider` to a fake and exercise the whole command via Typer's
`CliRunner` — no API key, no spend.

**Why `--diff` only (no PR target yet):** PR-fetch needs `github_client.py`;
diff-file/stdin review is the v0 (PLAN §9, "diff-only is the v0"). `--diff -`
reads stdin so `git diff | secreview review --diff -` works today.

### 10.3 An `@app.callback()` keeps the `review` subcommand name
Typer collapses a single-command app and drops the command name; an (empty)
callback forces it to keep `secreview review …` as PLAN specifies. The
`secreview` console script points at the `Typer` app object, which is callable.

### 10.4 Provider selection is a name→class map; thinking is anthropic-only
`--provider anthropic|openai`, optional `--model` override, `--no-thinking`
(ignored for OpenAI, which has no thinking param). Unknown providers raise a
`BadParameter` before any client is constructed (so it fails fast without a
key).

**Milestone 1 status:** `secreview review --diff <file>` returns findings
end-to-end on a real diff; `github_client.py` (§11) adds PR-fetch mode. A
real-API smoke to watch Claude flag the sample live is still nice-to-have.

---

## 11. `github_client.py` — PR-fetch mode

### 11.1 Ask GitHub for the `.diff` representation directly
`GET /repos/{owner}/{repo}/pulls/{n}` with `Accept: application/vnd.github.diff`
returns the unified-diff text as the response body.

**Why not `/pulls/{n}/files` (JSON):** that endpoint returns per-file patch
fragments we'd have to stitch back into a unified diff (and it paginates at 30
files). The `.diff` media type hands us exactly what `diff.parse_diff` already
eats — zero reconstruction, no pagination. Base/head SHAs and richer per-file
metadata (PLAN §3) aren't needed for diff review; they'll be added via the JSON
endpoint when the eval/context-expansion work needs them.

### 11.2 `PullRequestRef.parse` accepts shorthand and URLs
`owner/repo#N` (the PLAN spelling) and `…github.com/owner/repo/pull/N` both
parse; anything else raises `ValueError`.

**Why both:** `owner/repo#N` is the documented CLI form, but people paste PR
URLs constantly — accepting them costs one regex and removes a papercut.

### 11.3 Single attempt, typed errors, status-specific messages
No retries; failures raise `GitHubError` carrying the HTTP status, with messages
tuned per case (404 → wrong ref / private repo without token; 401 → bad token;
403 + `X-RateLimit-Remaining: 0` → set a token for a higher limit).

**Why (PLAN risk table):** "single attempt + clear error first; add retries only
if needed." The actionable message matters more than resilience at this stage —
the most common failure (private repo, no token) is a config issue the user
fixes once, not a transient the client should paper over. The SDK-less httpx
client is injectable (`client=`), so the smoke test drives every status path via
`httpx.MockTransport` without network.

### 11.4 Token from `GITHUB_TOKEN`, optional
Read from the env unless passed explicitly; omitted → no `Authorization` header
(public PRs still work at the unauthenticated 60-req/hr limit).

**Why optional:** public CVE-fix PRs (the eval's bread and butter) are readable
unauthenticated, so the tool works out of the box; a token only buys rate limit
and private access. The CLI surfaces this via `GITHUB_TOKEN` (documented in
`.env.example`), not a flag, to keep the secret out of shell history.

---

## 12. `evals/` + `semgrep_runner.py` — the eval harness (Milestone 2 core)

The harness lives at the repo root (`evals/`, dev-only, not shipped in the
wheel); only `semgrep_runner.py` sits in the package (it produces `Finding`s the
CLI could surface too). Pipeline: `manifest → reverse fix → run both tools →
match → metrics → results/`.

### 12.1 "Reverse the fix" to synthesize a vuln-introducing PR
`synthesize.reverse_unified_diff` flips a fix diff (vuln→safe) into a diff that
*adds* the vulnerable lines. It reverses only hunk headers and `+`/`-` markers;
`diff --git` / `--- ` / `+++ ` header lines are left untouched.

**Why leave the headers:** both name the same path (only the `a/`/`b/` prefix
differs, which `parse_diff` strips), so leaving them keeps the output a
well-formed *single-file* diff — swapping `--- `/`+++ ` order tripped unidiff's
"target without source" and split it into two files. Bonus: the result reads as
a normal forward PR turning safe code into vulnerable code, which is exactly the
scenario under test. Load-bearing consequence: the added (vuln) lines carry the
**pre-fix** file's line numbers, matching the manifest's `vulnerable_lines`.
Reversal is its own inverse (`reverse(reverse(x)) == x`), which the smoke checks.

### 12.2 `semgrep_runner.py` — file-level, normalized to `Finding`
Semgrep scans the **pre-fix file** (it's file-level, not diff-level, per PLAN
§5) via `--config p/security-audit --config p/secrets --json`, mapped to
`Finding(source="semgrep", confidence=1.0)`. CWE→`Category` via a lookup table;
`ERROR/WARNING/INFO`→`HIGH/MEDIUM/LOW`. The subprocess is injectable so tests
feed canned JSON with no Semgrep installed.

**Why `confidence=1.0`:** a rule matched or it didn't — there's no probabilistic
signal (DESIGN §2.4). Unmapped CWEs fall to `OTHER` rather than forcing a fit.

### 12.3 Matching: category-aware TP, two FP views
`match_entry` returns `found` (file + ±3-line window + category match),
`located` (location hit, any category — for localization recall), and the FP
findings' **categories** under two policies: *generous* (off-file only) and
*strict* (off-file **plus** on-vuln-file-outside-window). In-window findings are
never FP (they could be the real vuln).

**Why keep FP categories, not counts:** lets `metrics.py` bucket precision per
category. **Why two FP views (PLAN §5):** dataset labels are incomplete — a
finding elsewhere on the vuln file may be a *real* other bug, so counting it as
FP is noisy; reporting strict and generous brackets the true rate. `±3` absorbs
off-by-a-few line drift between the reported and labeled lines.

### 12.4 Metrics: per-category + overall, precision reported both ways
`compute_metrics` emits a `Row` per category plus `OVERALL`, each with recall,
and strict/generous precision + F1; plus `located_recall`. Zero denominators →
`0.0`. `write_csv` dumps it for `results/`.

**Why category-aware recall (`found`) as the headline** but `located_recall`
alongside: the primary number is "did the tool find *this* vuln class here";
localization recall shows how often it flagged the right spot but mislabeled it
(e.g. as `OTHER`) — the DESIGN §2.2 `OTHER` question, surfaced as a metric
rather than baked into matching.

### 12.5 `run_eval` takes injected tool callables
The orchestrator reads each fix diff, reverses it, and calls a `reviewer(entry,
reversed_diff)` and `semgrep(entry)` callable; `default_reviewer` /
`default_semgrep` wire in the real `AnthropicProvider` + `SemgrepRunner`.

**Why callables:** keeps the pure orchestration (read → reverse → match →
aggregate) hermetically testable with fakes — the `run_eval` smoke drives the
whole pipeline over the sample dataset with no API key or Semgrep, and even
asserts the reviewer received the *reversed* diff.

### 12.6 Synthetic sample dataset; real curation deferred
`dataset/` ships **2 clearly-labeled synthetic fixtures** (an SQLi and a
hardcoded-secret) — fix diffs + pre-fix files + manifest — so the harness runs
end-to-end today.

**Why defer `curate.py`:** the real 50-entry CVE-fix dataset is manual data work
(PLAN §5 curation "hand-verify each one"); a CVEfixes/Advisory-DB scraper's
output still needs human CWE verification and line labeling. Building the harness
to *consume* a manifest lets the dataset grow independently. The fixtures are
named `SAMPLE-*` / `SYNTHETIC` so they're never mistaken for real benchmark data.

**Still deferred:** Cohen's κ (LLM–Semgrep agreement) and per-diff cost/runtime
tracking — PLAN §5 "nice to haves" that don't block a first metrics run.

---

## 13. `curate.py` — turning a fix commit into a dataset entry

### 13.1 Curation is human-in-the-loop by design
`make_candidate("owner/repo@<sha>", …)` does the mechanical work — fetch the fix
diff, filter to in-scope files, materialize the diff + pre-fix file, and build a
`DatasetEntry` — but stamps every entry `NEEDS REVIEW` and the CLI prints it for
inspection rather than committing to `manifest.json` (opt in with
`--commit-to-manifest`).

**Why not fully automated:** the label that matters most — *which lines are the
vulnerability* and *what CWE/category* — is a judgment call. A scraper that
auto-appended entries would silently seed the benchmark with wrong ground truth,
and every downstream metric would inherit the error. Doing the fetch/filter/
materialize mechanically (~90% of the effort) while gating the labels behind a
human keeps the dataset trustworthy. This is the honest read of PLAN §5's
"hand-verify each one."

### 13.2 `vulnerable_lines` auto-suggested from the *removed* lines
The strongest cheap signal for "where was the vuln" is the set of lines the fix
**deleted** — their pre-fix (`source_line_no`) numbers. `suggest_vulnerable_lines`
returns exactly those.

**Why removed-lines:** a fix diff's removed lines *are* the vulnerable code being
excised, and their pre-fix line numbers are precisely what the manifest wants.
It's a suggestion the human confirms — and it degrades honestly: an
*add-only* fix (inserting a missing check, removing nothing) yields an empty set,
so we write a placeholder `[1]` and flag it in the note rather than guessing.

### 13.3 Filters: in-scope languages + small fixes only
Keep only Python/JS/TS files (noise already dropped by `parse_diff`); reject
commits touching more than `MAX_SOURCE_FILES` (3). The **primary** file (most
changed lines) anchors `vulnerable_file` / the pre-fix fetch.

**Why:** matches the v1 language scope, and small fixes keep ground truth
tractable (PLAN §5) — a 20-file refactor-plus-fix is impossible to label
cleanly. A `CurationError` (not a crash) tells the curator *why* a commit was
skipped so they move on.

### 13.4 Pre-fix file via the parent commit
Semgrep needs the vulnerable file *before* the fix, so the curator fetches it at
the fix commit's **first parent** (`fetch_commit_parent_sha` → `fetch_file` with
`?ref=<parent>`), extending `github_client` with commit/file endpoints
(`CommitRef`, `.diff` for commits, raw contents at a ref).

**Why the parent, not `<sha>~1`:** the GitHub contents API resolves a SHA/branch,
not `~1` syntax, so we read the commit JSON for `parents[0].sha` first. The
whole flow takes an injectable `GitHubClient`, so `smoke_curate` drives
fetch→filter→materialize→entry over fakes with no network.

**Shared CWE map:** `semgrep_runner.CWE_CATEGORY` (made public) is reused by
`suggest_category` so the Semgrep normalizer and the curator agree on
CWE→category — one table, no drift.
