"""PHP-only diff between the vulnerable and the fixed release of a case (the first step of the labelling protocol)."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from wpbench.vocab import PHP_SUFFIXES

CHANGED_LINES_LIMIT = 300  # docs/DATASET.md: the relevant diff should stay around this size


@dataclass(frozen=True)
class FileDiff:
    path: str
    status: str  # "added" | "removed" | "modified"
    added: int
    removed: int
    text: str


def _php_files(root: Path) -> dict[str, Path]:
    return {str(p.relative_to(root)).replace("\\", "/"): p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in PHP_SUFFIXES}


def _lines(path: Path | None) -> list[str]:
    if path is None:
        return []
    return path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)


def diff_trees(old: Path, new: Path) -> list[FileDiff]:
    old_files, new_files = _php_files(old), _php_files(new)
    out: list[FileDiff] = []
    for rel in sorted(set(old_files) | set(new_files)):
        a, b = _lines(old_files.get(rel)), _lines(new_files.get(rel))
        if a == b:
            continue
        status = "added" if rel not in old_files else "removed" if rel not in new_files else "modified"
        body = list(difflib.unified_diff(a, b, f"vuln/{rel}", f"fixed/{rel}", n=3))
        added = sum(1 for line in body if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in body if line.startswith("-") and not line.startswith("---"))
        text = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in body)
        out.append(FileDiff(rel, status, added, removed, text))
    return out


def changed_lines(diffs: list[FileDiff]) -> int:
    return sum(d.added + d.removed for d in diffs)
