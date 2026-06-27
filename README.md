# secreview

**An LLM-assisted security code reviewer for pull-request diffs.** Point it at a
GitHub PR (or a local diff) and it asks an LLM to flag security-relevant
changes — SQL/command injection, auth weakening, crypto misuse, hardcoded
secrets, unsafe deserialization, path traversal, and SSRF — with a line-anchored
rationale, severity, and confidence for each finding.

The longer-term goal is a rigorous benchmark: **secreview vs. Semgrep on ~50
curated CVE-fix diffs**, with precision/recall reported per category. See
[`PLAN.md`](PLAN.md) for the full plan and [`DESIGN.md`](DESIGN.md) for the
implementation-decision log.

> **Status:** Milestone 1 complete — the reviewer runs end-to-end as a CLI on
> real PRs and diffs. The eval harness + dataset (the benchmark numbers) are the
> next milestone and are **not built yet**; this README does not quote
> precision/recall figures because there aren't any real ones to quote.

---

## How it works

```
 PR (owner/repo#N)  ──┐
                      ├─►  unified diff  ──►  parse + filter noise  ──►  per-file
 local diff / stdin ──┘     (github_client / --diff)   (diff.py)          hunks
                                                                            │
                                                                            ▼
                                            LLM reviewer  ◄── prompt + few-shot
                                            (providers/)      (prompts.py)
                                                 │  structured output (Finding[])
                                                 ▼
                                   sorted report  ──►  rich table  /  JSON
                                   (reviewer.py)        (report.py)
```

- **Diff-native.** It reviews the *changed* lines, with each line annotated by
  its post-diff line number so findings point at precise locations.
- **Noise-filtered.** Binaries, lockfiles, vendored/minified code, and hunk-less
  files are dropped before they ever reach the model.
- **Structured output.** Findings come back as a validated schema (no
  free-text parsing), via the modern structured-outputs path.
- **Two backends.** Claude (primary) and an OpenAI model (the eval comparison),
  behind one provider interface.

### Detection categories

`INJECTION` · `AUTH` · `CRYPTO` · `SECRET` · `DESERIALIZATION` ·
`PATH_TRAVERSAL` · `SSRF` · `OTHER` — each finding also carries a severity
(`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) and a self-reported confidence in `[0, 1]`.

**Languages (v1):** Python and JavaScript/TypeScript.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/ananya2712/llm-security-reviewer.git
cd llm-security-reviewer

python3 -m venv .venv && source .venv/bin/activate
pip install -e .          # installs the `secreview` command
```

> On macOS + Python 3.13, an editable install's `.pth` file can be skipped by
> `site.py` (a known provenance/hidden-flag quirk). If `secreview` isn't found,
> run it module-style instead — it's equivalent:
>
> ```bash
> PYTHONPATH=src python -m secreview.cli review ...
> ```

---

## Configuration

Copy `.env.example` to `.env` (or export the variables):

| Variable            | Required?            | Purpose                                            |
| ------------------- | -------------------- | -------------------------------------------------- |
| `ANTHROPIC_API_KEY` | yes (default backend)| Claude — the primary reviewer.                     |
| `OPENAI_API_KEY`    | only for `-p openai` | The comparison model.                              |
| `GITHUB_TOKEN`      | optional             | Higher rate limit + private PRs. Public PRs work without it (at the 60 req/hr unauthenticated limit). |

---

## Usage

```text
secreview review [TARGET] [OPTIONS]

  TARGET            A PR reference: 'owner/repo#N' or a GitHub PR URL.
  -d, --diff PATH   Review a local unified diff file, or '-' for stdin.
  -p, --provider    Backend: anthropic (default) | openai.
  -m, --model       Override the backend's default model.
  --no-thinking     Disable adaptive thinking (anthropic only).
  --json            Emit machine-readable JSON instead of a table.
```

Provide **exactly one** of a PR target or `--diff`.

### Review a GitHub PR

```bash
export ANTHROPIC_API_KEY=sk-ant-...
secreview review octocat/Hello-World#42
# or a URL:
secreview review https://github.com/octocat/Hello-World/pull/42
```

### Review a local diff

```bash
# from a file
git diff main...feature > change.diff
secreview review --diff change.diff

# straight from a pipe
git diff main...feature | secreview review --diff -
```

### Example output

```text
                          Security findings (1)
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Location       ┃ Category  ┃ Severity ┃ Conf ┃ Rationale                      ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ src/db.py:12-13│ INJECTION │ HIGH     │ 0.95 │ User-controlled `uid` is con-  │
│                │           │          │      │ catenated into the SQL string  │
│                │           │          │      │ instead of bound, allowing     │
│                │           │          │      │ SQL injection.                 │
└────────────────┴───────────┴──────────┴──────┴────────────────────────────────┘

1 finding(s) across 1 reviewed file(s).
```

A clean diff prints `✓ No security findings across N reviewed file(s).`

### Machine-readable output

```bash
secreview review --diff change.diff --json
```

```json
{
  "findings": [
    {
      "file": "src/db.py",
      "start_line": 12,
      "end_line": 13,
      "category": "INJECTION",
      "severity": "HIGH",
      "confidence": 0.95,
      "rationale": "User-controlled `uid` is concatenated into the SQL string instead of bound, allowing SQL injection.",
      "code_snippet": "q = \"SELECT * FROM users WHERE id = \" + str(uid)\ncur.execute(q)",
      "source": "llm"
    }
  ],
  "files_reviewed": ["src/db.py"]
}
```

### Use the comparison model

```bash
export OPENAI_API_KEY=sk-...
secreview review --diff change.diff --provider openai
secreview review --diff change.diff -p anthropic -m claude-opus-4-8   # override model
```

---

## Development

The package lives under `src/secreview/` (a `src/` layout, so tests and scripts
exercise the same import path users hit). Each module ships a hermetic smoke
script under `scripts/` — no API keys or network needed (LLM/GitHub clients are
stubbed):

```bash
for s in models diff prompts providers openai_provider reviewer github cli; do
  python scripts/smoke_$s.py
done
```

| Module                          | Responsibility                                            |
| ------------------------------- | --------------------------------------------------------- |
| `models.py`                     | The `Finding` data contract (Pydantic).                   |
| `diff.py`                       | Parse unified diffs; drop binary/lockfile/vendored noise. |
| `prompts.py`                    | Versioned system prompt, few-shot, annotated-diff render. |
| `providers/`                    | `ReviewProvider` + Anthropic (primary) & OpenAI backends. |
| `reviewer.py`                   | Orchestration → deterministic `ReviewReport`.             |
| `report.py`                     | Rich terminal table + JSON.                               |
| `github_client.py`              | Fetch a PR's unified diff from the GitHub API.            |
| `cli.py`                        | The `secreview` command.                                  |

Dev tooling (`pytest`, `ruff`, `mypy`) installs via the `dev` extra:
`pip install -e ".[dev]"`.

---

## Roadmap

- [x] **Milestone 1** — core reviewer end-to-end (`secreview review` on real PRs/diffs).
- [ ] **Milestone 2** — eval harness + Semgrep baseline + a 50-entry CVE-fix dataset.
- [ ] **Milestone 3** — precision/recall per category; prompt iteration; comparison-model delta.
- [ ] **Milestone 4** — results writeup + reproducibility; optional GitHub Action wrapper.

## Scope & limitations

- v1 targets **Python and JS/TS**; other languages are reviewed but not specialized.
- It reports security issues only — not style, performance, or general bugs.
- Findings are **LLM-generated**: treat them as prompts for human review, not
  ground truth. Confidence is self-reported and noisy.
- Diff-only review (no surrounding-file context yet); context expansion is planned.

## License

MIT — see [`pyproject.toml`](pyproject.toml).
