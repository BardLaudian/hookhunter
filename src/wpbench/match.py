"""Matching a finding against the ground truth (docs/SPEC.md section 5)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from wpbench.cwe_families import compatible

TOLERANCE = 10
FUNCTION_CAP = 100  # docs/SPEC.md section 5: the same-function clause only counts within this many lines of the truth
CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def norm_path(path: str) -> str:
    p = str(path).strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    for prefix in ("/work/plugin/", "plugin/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.lstrip("/").casefold()


def norm_function(name: str) -> str:
    n = re.split(r"::|->", str(name).strip())[-1]
    return n.replace("()", "").strip().casefold()


@dataclass(frozen=True)
class Truth:
    file: str
    function: str
    line_start: int
    line_end: int
    cwe: str
    cls: str


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    same_file: bool
    location: bool
    family: bool


def truth_from_case(case: Any) -> Truth:
    t = case.truth
    return Truth(t["file"], t["function"], int(t["line_start"]), int(t["line_end"]), case.cwe, case.cls)


def match(finding: dict[str, Any], truth: Truth, tolerance: int = TOLERANCE, function_cap: int | None = FUNCTION_CAP) -> MatchResult:
    """Same file AND (line ranges overlap within the tolerance OR same function name) AND compatible family.

    ``function_cap`` limits the function clause to findings within that many lines of the truth, so a giant dispatcher function does
    not match every finding inside it (docs/SPEC.md section 5, docs/DECISIONS.md section 16); None disables it (sensitivity analysis).
    """
    same_file = norm_path(finding.get("file", "")) == norm_path(truth.file)
    lo, hi = sorted((int(finding.get("line_start", 0)), int(finding.get("line_end", 0))))
    overlap = lo - tolerance <= truth.line_end and hi + tolerance >= truth.line_start
    fn_f, fn_t = norm_function(finding.get("function", "")), norm_function(truth.function)
    gap = max(truth.line_start - hi, lo - truth.line_end, 0)
    location = overlap or (bool(fn_f) and fn_f == fn_t and (function_cap is None or gap <= function_cap))
    fam = compatible(str(finding.get("cwe", "")), finding.get("class"), truth.cwe, truth.cls)
    return MatchResult(same_file and location and fam, same_file, location, fam)


def ranked(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Highest confidence first; the agent's own order breaks ties (it was asked to list the most severe first)."""
    return [f for _, f in sorted(enumerate(findings), key=lambda p: (CONF_RANK.get(str(p[1].get("confidence")), 3), p[0]))]


@dataclass(frozen=True)
class RunScore:
    hit: bool  # at least one finding matches
    hit_at_3: bool  # a match among the three highest-confidence findings
    matched: tuple[int, ...]  # indexes into the findings list
    unmatched: tuple[int, ...]


def score_findings(findings: Sequence[dict[str, Any]], truth: Truth, function_cap: int | None = FUNCTION_CAP) -> RunScore:
    flags = [match(f, truth, function_cap=function_cap).matched for f in findings]
    top3 = ranked(findings)[:3]
    ids = {id(f) for f in top3}
    at3 = any(flags[i] for i, f in enumerate(findings) if id(f) in ids)
    return RunScore(any(flags), at3, tuple(i for i, m in enumerate(flags) if m), tuple(i for i, m in enumerate(flags) if not m))
