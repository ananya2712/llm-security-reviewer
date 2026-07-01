"""Reverse a fix diff into a synthetic "PR that introduces the vulnerability".

A CVE fix diff goes vulnerable → safe (removes the bad lines, adds the good
ones). Reversing it (like `git diff -R`) yields a diff that *adds* the
vulnerable lines — which is what we feed the reviewer, simulating the vuln
being introduced in a PR. After reversal the added lines carry the pre-fix
file's line numbers, so they line up with the manifest's `vulnerable_lines`.
"""

from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def _reverse_header(line: str) -> str:
    m = _HUNK.match(line)
    if not m:
        return line
    src, src_len, tgt, tgt_len, tail = m.groups()
    src_len = "1" if src_len is None else src_len
    tgt_len = "1" if tgt_len is None else tgt_len
    # swap the two sides
    return f"@@ -{tgt},{tgt_len} +{src},{src_len} @@{tail}"


def reverse_unified_diff(text: str) -> str:
    """Return the reverse of a unified diff (swap +/- lines and hunk sides).

    The `diff --git` / `index` / `--- ` / `+++ ` header lines are left as-is:
    both name the same path (differing only by the `a/` vs `b/` prefix, which
    `diff.parse_diff` strips), so leaving them keeps the result a well-formed,
    single-file diff. The result reads as a forward PR that *introduces* the
    vulnerability — the added lines are the pre-fix (vulnerable) code, carrying
    the pre-fix file's line numbers.
    """
    out: list[str] = []
    in_hunk = False
    for line in text.splitlines():
        if line.startswith("@@"):
            out.append(_reverse_header(line))
            in_hunk = True
        elif line.startswith("diff --git"):
            out.append(line)
            in_hunk = False
        elif in_hunk and line[:1] == "+":
            out.append("-" + line[1:])
        elif in_hunk and line[:1] == "-":
            out.append("+" + line[1:])
        else:
            out.append(line)  # header lines, context lines, "\ No newline", etc.
    result = "\n".join(out)
    return result + "\n" if text.endswith("\n") else result
