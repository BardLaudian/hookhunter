"""Seeded, stratified assignment of cases to the dev and test splits (docs/DATASET.md)."""

from __future__ import annotations

import random
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from wpbench.cases import Case, Issue


class SplitError(Exception):
    pass


@dataclass(frozen=True)
class SplitResult:
    assignment: dict[str, str]  # case id -> "dev" | "test"
    seed: str
    dev: int
    test: int


def assign(cases: list[Case], seed: str, dev: int = 15, test: int = 25, force: bool = False) -> SplitResult:
    """Assign every case to dev or test. Deterministic for a given seed and set of cases, stratified by class.

    Refuses to touch a dataset that already has assignments unless force is set: the test split is frozen once it exists.
    """
    if not cases:
        raise SplitError("the dataset has no cases")
    if any(c.split for c in cases) and not force:
        raise SplitError("cases already have a split; the test split is frozen once committed. Use --force only to build a new dataset")
    if dev < 1 or test < 1:
        raise SplitError("--dev and --test must be positive")
    n = len(cases)
    dev_total = max(1, min(n - 1, round(n * dev / (dev + test)))) if n > 1 else 1
    by_class: dict[str, list[Case]] = defaultdict(list)
    for c in cases:
        by_class[c.cls].append(c)
    quota = {cls: len(group) * dev_total / n for cls, group in by_class.items()}
    take = {cls: int(q) for cls, q in quota.items()}
    remainder = dev_total - sum(take.values())
    for cls in sorted(quota, key=lambda k: (-(quota[k] - take[k]), k))[:remainder]:
        take[cls] += 1
    assignment: dict[str, str] = {}
    for cls in sorted(by_class):
        ids = sorted(c.id for c in by_class[cls])
        random.Random(f"{seed}:{cls}").shuffle(ids)
        for i, cid in enumerate(ids):
            assignment[cid] = "dev" if i < take[cls] else "test"
    return SplitResult(assignment, seed, sum(v == "dev" for v in assignment.values()), sum(v == "test" for v in assignment.values()))


_TABLE = re.compile(r"^\s*\[")
_KEY = re.compile(r"^\s*(\w+)\s*=")


def apply_to_text(text: str, assignment: dict[str, str]) -> str:
    """Set `split = "..."` in each [[case]] block of cases.toml, leaving everything else (comments, order, truth tables) untouched."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    block: list[str] = []  # lines of the current [[case]] header section (up to the next table)
    in_case = False

    def flush() -> None:
        nonlocal block
        cid = next((m.group(1) for line in block if (m := re.match(r'^\s*id\s*=\s*"([^"]+)"', line))), None)
        if cid in assignment:
            new = f'split = "{assignment[cid]}"\n'
            idx = next((i for i, line in enumerate(block) if (m := _KEY.match(line)) and m.group(1) == "split"), None)
            if idx is not None:
                block[idx] = new
            else:
                last_key = max((i for i, line in enumerate(block) if _KEY.match(line)), default=0)
                if not block[last_key].endswith("\n"):
                    block[last_key] += "\n"
                block.insert(last_key + 1, new)
        out.extend(block)
        block = []

    for line in lines:
        if _TABLE.match(line):
            if in_case:
                flush()
            in_case = line.strip() == "[[case]]"
            (block if in_case else out).append(line)
        else:
            (block if in_case else out).append(line)
    if in_case:
        flush()
    return "".join(out)


def write_splits_file(path: Path, result: SplitResult) -> None:
    ids = {role: sorted(cid for cid, r in result.assignment.items() if r == role) for role in ("dev", "test")}
    body = [
        "# Written by `wpbench split`. Commit it with cases.toml: the seed makes the assignment reproducible and auditable.",
        f'seed = "{result.seed}"',
        f'assigned_on = "{date.today().isoformat()}"',
        'method = "stratified by class; per-class shuffle seeded with seed:class; remainders to the largest fractional share"',
        f"dev_count = {result.dev}",
        f"test_count = {result.test}",
        "",
    ]
    for role in ("dev", "test"):
        body.append(f"{role} = [" + ", ".join(f'"{i}"' for i in ids[role]) + "]")
    path.write_text("\n".join(body) + "\n")


def check_splits_file(path: Path, cases: list[Case]) -> list[Issue]:
    """Cross-check dataset/splits.toml against the split fields of cases.toml."""
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        return [Issue("error", "-", str(path), f"not valid TOML: {exc}")]
    listed = {role: set(data.get(role, [])) for role in ("dev", "test")}
    issues = [Issue("error", i, "split", "listed in both dev and test of splits.toml") for i in sorted(listed["dev"] & listed["test"])]
    by_id = {c.id: c for c in cases}
    for role, ids in listed.items():
        for cid in sorted(ids):
            case = by_id.get(cid)
            if case is None:
                issues.append(Issue("error", cid, "split", f"listed in splits.toml ({role}) but missing from cases.toml"))
            elif case.split != role:
                issues.append(Issue("error", cid, "split", f"splits.toml says {role}, cases.toml says {case.split!r}"))
    return issues
