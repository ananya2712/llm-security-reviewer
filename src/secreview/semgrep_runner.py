"""Run Semgrep on a file/dir and normalize its output into `Finding`s.

Semgrep is file-level (not diff-level), so the eval scans the *pre-fix* file.
Output is mapped into the same `Finding` shape as the LLM path (with
`source="semgrep"`, `confidence=1.0` — the rule matched or it didn't), so the
matcher treats both tools identically.

The subprocess call is injectable (`runner=`) so tests feed canned JSON without
Semgrep installed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

from .models import Category, Finding, Severity

# Ruleset used for the baseline. Documented per PLAN's risk table; rerun if changed.
DEFAULT_CONFIGS: tuple[str, ...] = ("p/security-audit", "p/secrets")

# Semgrep ERROR/WARNING/INFO → our severity (Semgrep has no CRITICAL tier).
_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# CWE id → our Category. Covers the v1 in-scope classes; everything else → OTHER.
CWE_CATEGORY: dict[str, Category] = {
    "CWE-89": Category.INJECTION,  # SQLi
    "CWE-78": Category.INJECTION,  # OS command
    "CWE-79": Category.INJECTION,  # XSS
    "CWE-94": Category.INJECTION,  # code injection
    "CWE-287": Category.AUTH,  # improper authentication
    "CWE-306": Category.AUTH,  # missing auth
    "CWE-862": Category.AUTH,  # missing authorization
    "CWE-863": Category.AUTH,  # incorrect authorization
    "CWE-327": Category.CRYPTO,  # broken/risky crypto
    "CWE-326": Category.CRYPTO,  # inadequate encryption strength
    "CWE-916": Category.CRYPTO,  # weak password hash
    "CWE-798": Category.SECRET,  # hardcoded credentials
    "CWE-259": Category.SECRET,  # hardcoded password
    "CWE-502": Category.DESERIALIZATION,  # unsafe deserialization
    "CWE-22": Category.PATH_TRAVERSAL,  # path traversal
    "CWE-918": Category.SSRF,  # SSRF
}

RunnerFn = Callable[[Path, tuple[str, ...]], str]


class SemgrepRunner:
    def __init__(
        self,
        configs: tuple[str, ...] = DEFAULT_CONFIGS,
        *,
        runner: RunnerFn | None = None,
    ) -> None:
        self._configs = configs
        self._runner = runner or self._run_semgrep

    def scan(self, path: str | Path) -> list[Finding]:
        raw = self._runner(Path(path), self._configs)
        return self._parse(raw)

    @staticmethod
    def _run_semgrep(path: Path, configs: tuple[str, ...]) -> str:
        cmd = ["semgrep", "--json", "--quiet", "--disable-version-check"]
        for c in configs:
            cmd += ["--config", c]
        cmd.append(str(path))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # Semgrep exits 0 with findings; nonzero only on internal error.
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"semgrep failed (exit {proc.returncode}): {proc.stderr[:300]}")
        return proc.stdout

    @staticmethod
    def _category(metadata: dict) -> Category:
        for cwe in metadata.get("cwe", []) or []:
            # entries look like "CWE-89: Improper Neutralization ..."
            key = str(cwe).split(":", 1)[0].strip().upper()
            if key in CWE_CATEGORY:
                return CWE_CATEGORY[key]
        return Category.OTHER

    def _parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        data = json.loads(raw)
        findings: list[Finding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            start = int(r["start"]["line"])
            end = max(int(r["end"]["line"]), start)
            findings.append(
                Finding(
                    file=r["path"],
                    start_line=start,
                    end_line=end,
                    category=self._category(metadata),
                    severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                    confidence=1.0,
                    rationale=extra.get("message", r.get("check_id", "")).strip() or "semgrep match",
                    code_snippet=(extra.get("lines", "") or "").strip(),
                    source="semgrep",
                )
            )
        return findings
