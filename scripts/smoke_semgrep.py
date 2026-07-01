import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from secreview.semgrep_runner import SemgrepRunner

# A canned Semgrep --json payload (two results: a mapped CWE and an unmapped one).
CANNED = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.sqli",
                "path": "app/db.py",
                "start": {"line": 12},
                "end": {"line": 13},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected string concatenation in a SQL statement.",
                    "lines": "q = ... + str(uid)",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                },
            },
            {
                "check_id": "generic.misc.thing",
                "path": "app/util.py",
                "start": {"line": 4},
                "end": {"line": 4},
                "extra": {
                    "severity": "WARNING",
                    "message": "some other issue",
                    "metadata": {"cwe": ["CWE-1004: something unmapped"]},
                },
            },
        ]
    }
)


def main() -> None:
    calls = {}

    def fake_runner(path, configs):
        calls["path"] = str(path)
        calls["configs"] = configs
        return CANNED

    runner = SemgrepRunner(runner=fake_runner)
    findings = runner.scan("app/db.py")

    assert calls["configs"] == ("p/security-audit", "p/secrets")
    assert len(findings) == 2
    print("[ok] runner invoked with default configs; 2 results parsed")

    sqli = findings[0]
    assert sqli.source == "semgrep" and sqli.confidence == 1.0
    assert sqli.category == "INJECTION" and sqli.severity == "HIGH"
    assert sqli.file == "app/db.py" and sqli.start_line == 12 and sqli.end_line == 13
    print("[ok] CWE-89/ERROR -> INJECTION/HIGH, source=semgrep, confidence=1.0")

    other = findings[1]
    assert other.category == "OTHER" and other.severity == "MEDIUM"
    print("[ok] unmapped CWE + WARNING -> OTHER/MEDIUM")

    # Empty / no-results output yields no findings.
    assert SemgrepRunner(runner=lambda p, c: "").scan("x") == []
    assert SemgrepRunner(runner=lambda p, c: '{"results": []}').scan("x") == []
    print("[ok] empty output -> no findings")


if __name__ == "__main__":
    main()
