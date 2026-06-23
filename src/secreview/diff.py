from __future__ import annotations

from typing import Literal

from pydantic import BaseModel
from unidiff import PatchSet

LineType = Literal["context", "add", "remove"]

_LANG_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

_LOCKFILE_NAMES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "Cargo.lock",
    "uv.lock",
}

_VENDORED_DIRS: tuple[str, ...] = (
    "node_modules/",
    "vendor/",
    "third_party/",
    "dist/",
    "build/",
    ".next/",
    ".venv/",
    "site-packages/",
)


class DiffLine(BaseModel):
    type: LineType
    text: str
    source_line_no: int | None
    target_line_no: int | None


class Hunk(BaseModel):
    source_start: int
    source_length: int
    target_start: int
    target_length: int
    lines: list[DiffLine]

    @property
    def target_end(self) -> int:
        return self.target_start + max(self.target_length, 1) - 1

    def render_unified(self) -> str:
        header = (
            f"@@ -{self.source_start},{self.source_length} "
            f"+{self.target_start},{self.target_length} @@"
        )
        body = []
        for ln in self.lines:
            marker = {"context": " ", "add": "+", "remove": "-"}[ln.type]
            body.append(f"{marker}{ln.text}")
        return "\n".join([header, *body])


class FileDiff(BaseModel):
    path: str
    language: str | None
    is_added: bool
    is_removed: bool
    hunks: list[Hunk]


def _suffix(path: str) -> str:
    i = path.rfind(".")
    return path[i:].lower() if i >= 0 else ""


def _basename(path: str) -> str:
    i = path.rfind("/")
    return path[i + 1 :] if i >= 0 else path


def _detect_language(path: str) -> str | None:
    return _LANG_BY_SUFFIX.get(_suffix(path))


def _is_noise(path: str) -> bool:
    if _basename(path) in _LOCKFILE_NAMES:
        return True
    if any(seg in path for seg in _VENDORED_DIRS):
        return True
    base = _basename(path)
    if base.endswith((".min.js", ".min.css", ".map")):
        return True
    return False


def _line_type(c: str) -> LineType:
    if c == "+":
        return "add"
    if c == "-":
        return "remove"
    return "context"


def parse_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff string into per-file hunks, dropping noise files."""
    patch = PatchSet.from_string(text)
    out: list[FileDiff] = []

    for pf in patch:
        path = pf.target_file if pf.target_file != "/dev/null" else pf.source_file
        if path.startswith(("a/", "b/")):
            path = path[2:]

        if pf.is_binary_file or _is_noise(path):
            continue

        hunks: list[Hunk] = []
        for h in pf:
            lines = [
                DiffLine(
                    type=_line_type(line.line_type),
                    text=line.value.rstrip("\n"),
                    source_line_no=line.source_line_no,
                    target_line_no=line.target_line_no,
                )
                for line in h
            ]
            hunks.append(
                Hunk(
                    source_start=h.source_start,
                    source_length=h.source_length,
                    target_start=h.target_start,
                    target_length=h.target_length,
                    lines=lines,
                )
            )

        out.append(
            FileDiff(
                path=path,
                language=_detect_language(path),
                is_added=pf.is_added_file,
                is_removed=pf.is_removed_file,
                hunks=hunks,
            )
        )

    return out
