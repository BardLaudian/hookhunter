"""Helpers for the human review of a drafted label (docs/DATASET.md, labelling protocol).

Nothing here talks to the network. The checks only look at things a person would otherwise check by hand:
does the labelled file exist, is the line range inside it, is the function where the label says it is, does the
fix touch the labelled lines. They never sign anything: signing is a separate, explicit step.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from wpbench.cases import Case
from wpbench.diff import FileDiff

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
_VERSION_LINE = re.compile(r"^[-+].*(version|VERSION|Version)")
_TABLE = re.compile(r"^\s*\[")
_CASE_ID = re.compile(r'^\s*id\s*=\s*"([^"]+)"')
RANGE_SLACK = 10  # same slack the scorer uses around the truth lines (docs/SPEC.md section 5)
LARGE_RANGE = 100  # the function cap of the scorer


class ReviewError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    level: str  # "ok" | "warn" | "error"
    name: str
    detail: str


def hunk_ranges(diff_text: str) -> list[tuple[int, int]]:
    """Line ranges of the OLD file touched by a unified diff (inclusive). Pure insertions count as one line."""
    out: list[tuple[int, int]] = []
    for line in diff_text.splitlines():
        m = _HUNK.match(line)
        if m:
            start = int(m.group(1))
            length = int(m.group(2)) if m.group(2) is not None else 1
            out.append((start, start + max(length, 1) - 1))
    return out


def drop_version_noise(diff_text: str) -> str:
    """Remove +/- lines that only bump a version string, so the security change is easier to see."""
    return "".join(line for line in diff_text.splitlines(keepends=True) if not _VERSION_LINE.match(line))


def excerpt(path: Path, start: int, end: int, context: int = 2, max_lines: int = 40) -> str:
    """Numbered lines start-context .. end+context of a file, shortened to max_lines."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, start - context), min(len(lines), end + context)
    shown = list(range(lo, hi + 1))
    cut = len(shown) > max_lines
    if cut:
        shown = shown[:max_lines]
    body = "\n".join(f"{n:6d}  {lines[n - 1][:200]}{'   <-- label' if start <= n <= end else ''}" for n in shown)
    return body + (f"\n       ... {hi - shown[-1]} more line(s)" if cut else "")


def check_truth(case: Case, vuln_dir: Path, diffs: list[FileDiff]) -> list[Finding]:
    """Automatic sanity checks of the drafted label against the vulnerable tree and the fix diff."""
    t = case.truth
    if not t:
        return [Finding("error", "label", "the case has no [case.truth]")]
    out: list[Finding] = []
    path = vuln_dir / str(t["file"])
    if not path.is_file():
        return [Finding("error", "file", f"{t['file']} does not exist in the vulnerable release")]
    text = path.read_text(encoding="utf-8", errors="replace")
    n_lines = len(text.splitlines())
    start, end = int(t["line_start"]), int(t["line_end"])
    out.append(Finding("ok", "file", f"{t['file']} ({n_lines} lines)"))
    if start > n_lines:
        out.append(Finding("error", "lines", f"line_start {start} is beyond the end of the file ({n_lines})"))
    elif end > n_lines:
        out.append(Finding("warn", "lines", f"line_end {end} is beyond the end of the file ({n_lines})"))
    else:
        out.append(Finding("ok", "lines", f"{start}-{end} inside the file"))
    if end - start + 1 > LARGE_RANGE:
        out.append(Finding("warn", "lines", f"the range is {end - start + 1} lines long; a precise sink is easier to match"))
    func = str(t.get("function") or "")
    if func:
        found = [i for i, line in enumerate(text.splitlines(), 1) if re.search(rf"function\s+&?\s*{re.escape(func)}\s*\(", line)]
        if not found:
            out.append(Finding("warn", "function", f"no 'function {func}(' in {t['file']} (method of a bundled class, closure or a different name?)"))
        else:
            near = [i for i in found if i <= end and start - i <= LARGE_RANGE]
            if near:
                out.append(Finding("ok", "function", f"{func} defined at line {near[0]}"))
            else:
                out.append(Finding("warn", "function", f"{func} is defined at line {found[0]}, away from the labelled lines {start}-{end}"))
    touched = [d for d in diffs if d.path == t["file"]]
    if not touched:
        out.append(Finding("warn", "fix", "the fix does not change the labelled file; the notes should say where the fix is"))
    else:
        ranges = [r for d in touched for r in hunk_ranges(d.text)]
        hit = any(lo <= end + RANGE_SLACK and hi >= start - RANGE_SLACK for lo, hi in ranges)
        out.append(Finding("ok" if hit else "warn", "fix", "the fix changes the labelled lines" if hit else "the fix changes the file but not these lines; confirm the label points at the sink"))
    notes = str(t.get("notes") or "")
    drafts = [ln.strip() for ln in notes.splitlines() if ln.strip().startswith("Draft") and ln.strip().rstrip(".") != "Draft"]
    if drafts:
        out.append(Finding("warn", "notes", "open doubt: " + " | ".join(drafts)))
    return out


def sign_text(text: str, case_id: str, by: str, on: str) -> str:
    """Set reviewed_by and reviewed_on in the [case.truth] table of one case, leaving the rest of the file untouched."""
    if not by.strip() or '"' in by or "\n" in by:
        raise ReviewError("the reviewer name must be non-empty text without quotes")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", on):
        raise ReviewError("the review date must be YYYY-MM-DD")
    lines = text.splitlines(keepends=True)
    heads = [i for i, line in enumerate(lines) if line.strip() == "[[case]]"]
    spans = list(zip(heads, [*heads[1:], len(lines)], strict=True))
    chosen = [(a, b) for a, b in spans if any((m := _CASE_ID.match(line)) and m.group(1) == case_id for line in lines[a:b])]
    if len(chosen) != 1:
        raise ReviewError(f"case {case_id} not found in cases.toml" if not chosen else f"case {case_id} appears more than once")
    a, b = chosen[0]
    block = lines[a:b]
    truth_at = next((i for i, line in enumerate(block) if line.strip() == "[case.truth]"), None)
    if truth_at is None:
        raise ReviewError(f"case {case_id} has no [case.truth] table to sign")
    new = [ln for ln in block if not re.match(r"^\s*reviewed_(by|on)\s*=", ln)]
    while new and not new[-1].strip():
        new.pop()
    if not new[-1].endswith("\n"):
        new[-1] += "\n"
    new += [f'reviewed_by = "{by}"\n', f'reviewed_on = "{on}"\n', "\n"]
    out = "".join(lines[:a] + new + lines[b:])
    try:
        data = tomllib.loads(out)
    except tomllib.TOMLDecodeError as exc:  # never write a broken file
        raise ReviewError(f"signing would break cases.toml: {exc}") from exc
    signed = next((c for c in data["case"] if c.get("id") == case_id), None)
    if not signed or signed.get("truth", {}).get("reviewed_by") != by:
        raise ReviewError("the signature did not land in the [case.truth] table")
    return out
