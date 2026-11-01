"""Dataset records (dataset/cases.toml, docs/DATASET.md) and their validation."""

from __future__ import annotations

import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

from wpbench.vocab import AUTH_LEVELS, CLASSES, SOURCES, SPLITS

DEFAULT_DATASET = Path("dataset/cases.toml")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")

CASE_KEYS = {
    "id", "cve", "source", "source_url", "retrieved", "slug", "vuln_version", "fixed_version", "vuln_sha256", "fixed_sha256", "cwe",
    "class", "auth", "published", "after_cutoff", "split", "truth",
}
TRUTH_KEYS = {
    "file", "function", "line_start", "line_end", "entry_point", "data_flow", "notes", "drafted_by", "reviewed_by", "reviewed_on",
}


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning"
    case_id: str
    field: str
    message: str

    def __str__(self) -> str:
        return f"{self.level}: {self.case_id}: {self.field}: {self.message}"


@dataclass
class Case:
    id: str
    cve: str
    source: str
    source_url: str
    retrieved: str
    slug: str
    vuln_version: str
    fixed_version: str
    vuln_sha256: str
    fixed_sha256: str
    cwe: str
    cls: str
    auth: str
    published: str
    after_cutoff: bool
    split: str | None = None
    truth: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def signed(self) -> bool:
        """A label counts for metrics only if a human reviewed it (CLAUDE.md, docs/DATASET.md)."""
        return bool(self.truth and self.truth.get("reviewed_by") and self.truth.get("reviewed_on"))

    def zip_url(self, version: str) -> str:
        return f"https://downloads.wordpress.org/plugin/{self.slug}.{version}.zip"


def _iso(value: Any) -> str | None:
    """Accept TOML dates and ISO strings; return an ISO date string or None."""
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError:
            return None
    return None


def _check_str(raw: dict[str, Any], key: str, cid: str, issues: list[Issue], pattern: re.Pattern[str] | None = None, hint: str = "") -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        issues.append(Issue("error", cid, key, "required text value is missing"))
        return ""
    if pattern and not pattern.match(value):
        issues.append(Issue("error", cid, key, f"{value!r} is not valid{(': ' + hint) if hint else ''}"))
    return value


def _check_hash(raw: dict[str, Any], key: str, cid: str, issues: list[Issue]) -> str:
    value = raw.get(key, "")
    if not isinstance(value, str):
        issues.append(Issue("error", cid, key, "must be a text value"))
        return ""
    if value in ("", "…", "..."):
        issues.append(Issue("warning", cid, key, "SHA-256 not recorded yet; fetch refuses it unless --allow-unhashed"))
        return ""
    if not SHA256_RE.match(value):
        issues.append(Issue("error", cid, key, "must be 64 lower-case hexadecimal characters"))
    return value


def _parse_truth(raw: Any, cid: str, issues: list[Issue]) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        issues.append(Issue("error", cid, "truth", "must be a table"))
        return None
    for key in sorted(set(raw) - TRUTH_KEYS):
        issues.append(Issue("warning", cid, f"truth.{key}", "unexpected field"))
    file = raw.get("file")
    if not isinstance(file, str) or not file or PurePosixPath(file).is_absolute() or ".." in PurePosixPath(file).parts or "\\" in file:
        issues.append(Issue("error", cid, "truth.file", "must be a relative path with forward slashes and no '..'"))
    ls, le = raw.get("line_start"), raw.get("line_end")
    if not (isinstance(ls, int) and isinstance(le, int) and not isinstance(ls, bool) and not isinstance(le, bool) and 1 <= ls <= le):
        issues.append(Issue("error", cid, "truth.line_start/line_end", "must be integers with 1 <= line_start <= line_end"))
    for key in ("function", "entry_point", "data_flow", "notes"):
        if key in raw and not isinstance(raw[key], str):
            issues.append(Issue("error", cid, f"truth.{key}", "must be text"))
    if not raw.get("data_flow"):
        issues.append(Issue("warning", cid, "truth.data_flow", "empty"))
    if isinstance(raw.get("notes"), str) and len(raw["notes"].splitlines()) > 5:
        issues.append(Issue("warning", cid, "truth.notes", "more than 5 lines; keep excerpts short (plugin source is not redistributed)"))
    reviewed_by, reviewed_on = raw.get("reviewed_by"), raw.get("reviewed_on")
    if reviewed_by and not _iso(reviewed_on):
        issues.append(Issue("error", cid, "truth.reviewed_on", "required (ISO date) when reviewed_by is set"))
    if reviewed_on and not reviewed_by:
        issues.append(Issue("error", cid, "truth.reviewed_by", "required when reviewed_on is set"))
    if not reviewed_by:
        issues.append(Issue("warning", cid, "truth.reviewed_by", "label not signed by a human: excluded from every reported metric"))
    return dict(raw)


def parse_case(raw: dict[str, Any], issues: list[Issue]) -> Case:
    raw_id = raw.get("id")
    cid: str = raw_id if isinstance(raw_id, str) else "?"
    cid = _check_str(raw, "id", cid, issues, re.compile(r"^wp-\d{4}$"), "expected wp-0001") or cid
    for key in sorted(set(raw) - CASE_KEYS - {"truth"}):
        issues.append(Issue("warning", cid, key, "unexpected field"))
    after_cutoff, split_value = raw.get("after_cutoff"), raw.get("split")
    case = Case(
        id=cid,
        cve=_check_str(raw, "cve", cid, issues, re.compile(r"^CVE-\d{4}-\d{4,}$"), "expected CVE-YYYY-NNNN"),
        source=_check_str(raw, "source", cid, issues),
        source_url=_check_str(raw, "source_url", cid, issues, re.compile(r"^https://\S+$"), "expected an https URL"),
        retrieved=_iso(raw.get("retrieved")) or "",
        slug=_check_str(raw, "slug", cid, issues, re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$"), "lower-case wordpress.org slug"),
        vuln_version=_check_str(raw, "vuln_version", cid, issues, VERSION_RE),
        fixed_version=_check_str(raw, "fixed_version", cid, issues, VERSION_RE),
        vuln_sha256=_check_hash(raw, "vuln_sha256", cid, issues),
        fixed_sha256=_check_hash(raw, "fixed_sha256", cid, issues),
        cwe=_check_str(raw, "cwe", cid, issues, re.compile(r"^CWE-\d+$"), "expected CWE-NN"),
        cls=_check_str(raw, "class", cid, issues),
        auth=_check_str(raw, "auth", cid, issues),
        published=_iso(raw.get("published")) or "",
        after_cutoff=after_cutoff if isinstance(after_cutoff, bool) else False,
        split=split_value if isinstance(split_value, str) else None,
        truth=_parse_truth(raw.get("truth"), cid, issues),
        extra={k: raw[k] for k in sorted(set(raw) - CASE_KEYS)},
    )
    if not _iso(raw.get("retrieved")):
        issues.append(Issue("error", cid, "retrieved", "required ISO date (YYYY-MM-DD)"))
    if not case.published:
        issues.append(Issue("error", cid, "published", "required ISO date (YYYY-MM-DD)"))
    elif case.retrieved and case.published > case.retrieved:
        issues.append(Issue("warning", cid, "published", "is later than the retrieval date"))
    if not isinstance(raw.get("after_cutoff"), bool):
        issues.append(Issue("error", cid, "after_cutoff", "required boolean"))
    if case.source and case.source not in SOURCES:
        issues.append(Issue("error", cid, "source", f"{case.source!r} is not one of {', '.join(SOURCES)}"))
    if case.cls and case.cls not in CLASSES:
        issues.append(Issue("error", cid, "class", f"{case.cls!r} is not a known class slug"))
    if case.auth and case.auth not in AUTH_LEVELS:
        issues.append(Issue("error", cid, "auth", f"{case.auth!r} is not one of {', '.join(AUTH_LEVELS)}"))
    if case.split is not None and case.split not in SPLITS:
        issues.append(Issue("error", cid, "split", f"{case.split!r} is not one of {', '.join(SPLITS)}"))
    if "split" in raw and case.split is None:
        issues.append(Issue("error", cid, "split", "must be text"))
    if case.vuln_version and case.vuln_version == case.fixed_version:
        issues.append(Issue("error", cid, "fixed_version", "must differ from vuln_version"))
    return case


def load_cases(path: Path = DEFAULT_DATASET) -> tuple[list[Case], list[Issue]]:
    """Parse and validate a dataset file. Returns every case that could be read, plus all issues found."""
    issues: list[Issue] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], [Issue("error", "-", str(path), "dataset file not found")]
    except tomllib.TOMLDecodeError as exc:
        return [], [Issue("error", "-", str(path), f"not valid TOML: {exc}")]
    for key in sorted(set(data) - {"case"}):
        issues.append(Issue("warning", "-", key, "unexpected top-level key"))
    raw_cases = data.get("case", [])
    if not isinstance(raw_cases, list):
        return [], [*issues, Issue("error", "-", "case", "must be an array of tables ([[case]])")]
    cases = [parse_case(dict(raw), issues) for raw in raw_cases]
    ids = Counter(c.id for c in cases)
    issues += [Issue("error", i, "id", "duplicated") for i, n in sorted(ids.items()) if n > 1]
    pairs = Counter((c.cve, c.slug) for c in cases)
    issues += [Issue("error", c.id, "cve", f"{c.cve} in {c.slug} appears in more than one case") for c in cases if pairs[(c.cve, c.slug)] > 1]
    return cases, issues


def summarise(cases: list[Case]) -> dict[str, Any]:
    return {
        "cases": len(cases),
        "by_split": dict(sorted(Counter(c.split or "unassigned" for c in cases).items())),
        "by_class": dict(sorted(Counter(c.cls for c in cases).items())),
        "labelled": sum(1 for c in cases if c.truth),
        "signed_labels": sum(1 for c in cases if c.signed),
        "after_cutoff": sum(1 for c in cases if c.after_cutoff),
    }
