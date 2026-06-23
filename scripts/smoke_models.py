import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydantic import ValidationError

from secreview.models import Category, Finding, Severity


def main() -> None:
    f = Finding(
        file="src/db.py",
        start_line=42,
        end_line=44,
        category=Category.INJECTION,
        severity=Severity.HIGH,
        confidence=0.85,
        rationale="String-formatted SQL with user-controlled input.",
        code_snippet='cursor.execute(f"SELECT * FROM u WHERE id={uid}")',
        source="llm",
    )

    j = f.model_dump_json()
    print("[ok] dump_json:", j)

    f2 = Finding.model_validate_json(j)
    assert f2 == f, "round-trip mismatch"
    print("[ok] round-trip equal")

    print("[ok] enum serialized as string:", '"INJECTION"' in j)

    checks = [
        ("end_line < start_line", dict(start_line=10, end_line=5)),
        ("start_line = 0",        dict(start_line=0,  end_line=1)),
        ("confidence > 1",        dict(confidence=1.5)),
        ("confidence < 0",        dict(confidence=-0.1)),
        ("bad category",          dict(category="NOT_A_CATEGORY")),
        ("bad source",            dict(source="human")),
    ]
    base = dict(
        file="x.py", start_line=1, end_line=1,
        category=Category.AUTH, severity=Severity.LOW,
        confidence=0.5, rationale="x", code_snippet="x", source="llm",
    )
    for label, override in checks:
        kwargs = base | override
        try:
            Finding(**kwargs)
        except ValidationError:
            print(f"[ok] rejected: {label}")
        else:
            print(f"[FAIL] accepted invalid: {label}")
            raise SystemExit(1)


if __name__ == "__main__":
    main()
