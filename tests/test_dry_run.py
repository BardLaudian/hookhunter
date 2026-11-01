"""The dry run of the workflow on the synthetic fixtures: artifacts are valid, match the labelled ground truth, and are up to date.

The matching rule is the one in docs/SPEC.md section 5 (same file and line overlap within 10 lines or same function, compatible family).
It is provisional: Phase 4 builds the real scorer.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import jsonschema
import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS / "dry_run"))
import build_dry_run as dry  # noqa: E402
from conftest import FIXTURES, marker_lines  # noqa: E402

BENCH = TESTS / "dry_run" / "bench"
SCHEMA = json.loads((TESTS.parents[2] / "schemas" / "findings.schema.json").read_text())
FAMILY = {
    "stored-xss": "xss", "reflected-xss": "xss", "dom-xss": "xss", "sqli": "sqli", "missing-authz": "authz", "csrf": "csrf",
    "path-traversal": "file", "file-delete": "file", "file-upload": "file", "file-inclusion": "file", "object-injection": "object-injection",
    "ssrf": "ssrf", "open-redirect": "open-redirect", "privesc": "privesc", "rce": "rce", "info-disclosure": "info-disclosure", "xxe": "xxe",
}
FIXTURE_FAMILY = {"xss": "xss", "sqli": "sqli", "authz": "authz", "csrf": "csrf", "file-ops": "file", "object-injection": "object-injection",
                  "ssrf": "ssrf", "open-redirect": "open-redirect", "privesc": "privesc", "rce": "rce", "info-disclosure": "info-disclosure", "xxe": "xxe"}
NAMES = sorted(p.name for p in FIXTURES.iterdir())
VULN = [n for n in NAMES if n.endswith("-vuln")]
SAFE = [n for n in NAMES if n.endswith("-safe")]


def load(name: str) -> list[dict]:
    return json.loads((BENCH / f"{name}.json").read_text())["findings"]


def matches(finding: dict, line: int, family: str, fn_lines: dict[str, list[int]]) -> bool:
    near = finding["line_start"] - 10 <= line <= finding["line_end"] + 10
    same_fn = bool(finding["function"]) and line in fn_lines.get(finding["function"], [])
    return (near or same_fn) and FAMILY[finding["class"]] == family


@pytest.mark.parametrize("name", NAMES)
def test_bench_file_is_valid_and_points_at_real_lines(name):
    findings = load(name)
    jsonschema.validate({"findings": findings}, SCHEMA)
    src = (FIXTURES / name / f"{name}.php").read_text()
    n_lines = len(src.splitlines())
    for f in findings:
        assert f["file"] == f"{name}.php"
        assert 1 <= f["line_start"] <= f["line_end"] <= n_lines
        assert f["function"] == "" or re.search(rf"function\s+&?{re.escape(f['function'])}\b", src) or f["function"] == "{closure}"


@pytest.mark.parametrize("name", SAFE)
def test_safe_twins_have_no_findings(name):
    assert load(name) == []


@pytest.mark.parametrize("name", VULN)
def test_every_labelled_vulnerable_line_is_found_and_nothing_else_is_reported(name):
    family = FIXTURE_FAMILY[name[: -len("-vuln")]]
    findings = load(name)
    labelled = marker_lines(name, "VULN")
    src = (FIXTURES / name / f"{name}.php").read_text().splitlines()
    fn_lines: dict[str, list[int]] = {}
    for start, line in enumerate(src, 1):
        fm = re.search(r"function\s+(\w+)", line)
        if fm:
            end = next((i for i in range(start, len(src) + 1) if src[i - 1].startswith("}")), len(src))
            fn_lines[fm.group(1)] = list(range(start, end + 1))
    missed = [ln for ln in labelled if not any(matches(f, ln, family, fn_lines) for f in findings)]
    assert missed == [], f"labelled lines with no matching finding: {missed}"
    extra = [f for f in findings if not any(f["line_start"] == ln for ln in labelled)] if labelled else findings
    if name != "csrf-vuln":  # csrf-vuln has no sink label: its finding is the missing nonce, located at the update_option line
        assert extra == [], f"findings at unlabelled lines: {extra}"


def test_csrf_fixture_finding_is_the_unprotected_write():
    [f] = load("csrf-vuln")
    assert f["class"] == "csrf" and f["entry_point"] == "admin_init" and f["auth_required"] == "unauthenticated"


def test_needs_dynamic_check_findings_are_not_high_confidence():
    for name in NAMES:
        for f in load(name):
            if f["class"] == "object-injection":
                assert f["confidence"] == "medium"
    assert [f["confidence"] for f in load("surface")][-1] == "low"


def test_finding_counts_add_up():
    """23 labelled lines in 11 vulnerable fixtures + the csrf finding + 3 unlabelled issues in `surface` = every reported finding."""
    labelled = sum(len(marker_lines(n, "VULN")) for n in VULN)
    by_fixture = {n: len(load(n)) for n in NAMES}
    assert labelled == 23
    assert by_fixture["csrf-vuln"] == 1 and by_fixture["surface"] == 3 and by_fixture["edge"] == 0
    assert sum(by_fixture.values()) == labelled + 1 + 3


def test_artifacts_are_up_to_date_with_the_generator_and_fixtures():
    found = dry.build()
    for name, items in found.items():
        assert json.loads((BENCH / f"{name}.json").read_text()) == dry.bench_json(items), f"{name}.json is stale; run dry_run/build_dry_run.py"
    assert (TESTS / "dry_run" / "REPORT.md").read_text() == dry.report(found)
