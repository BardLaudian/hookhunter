from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import TRUTH, case_block, make_dataset

from wpbench.cases import load_cases, summarise
from wpbench.vocab import AUTH_LEVELS, CLASSES, CONFIDENCE

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "findings.schema.json").read_text())


@pytest.fixture
def dataset(tmp_path):
    return make_dataset(tmp_path)


def messages(issues, level="error"):
    return [str(i) for i in issues if i.level == level]


def test_vocabularies_match_the_findings_schema():
    props = SCHEMA["properties"]["findings"]["items"]["properties"]
    assert set(CLASSES) == set(props["class"]["enum"])
    assert set(AUTH_LEVELS) == set(props["auth_required"]["enum"])
    assert set(CONFIDENCE) == set(props["confidence"]["enum"])


def test_valid_case_loads_without_issues(dataset):
    cases, issues = load_cases(dataset(case_block(1)))
    assert issues == []
    assert cases[0].id == "wp-0001" and cases[0].cls == "stored-xss" and cases[0].after_cutoff is True
    assert cases[0].zip_url("1.0.1") == "https://downloads.wordpress.org/plugin/fake-plugin-1.1.0.1.zip"


def test_toml_dates_are_accepted(dataset):
    path = dataset(case_block(1).replace("retrieved = '2026-11-02'", "retrieved = 2026-11-02").replace('retrieved = "2026-11-02"', "retrieved = 2026-11-02"))
    cases, issues = load_cases(path)
    assert issues == [] and cases[0].retrieved == "2026-11-02"


def test_empty_dataset_is_valid(dataset):
    cases, issues = load_cases(dataset("# nothing yet\n"))
    assert cases == [] and issues == []


def test_missing_and_malformed_files_are_reported(tmp_path):
    assert "not found" in messages(load_cases(tmp_path / "none.toml")[1])[0]
    bad = tmp_path / "bad.toml"
    bad.write_text("[[case]\nid = ")
    assert "not valid TOML" in messages(load_cases(bad)[1])[0]


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"id": "case-1"}, "id: 'case-1' is not valid"),
        ({"cve": "CVE-26-1"}, "cve:"),
        ({"cwe": "79"}, "cwe:"),
        ({"slug": "Bad_Slug"}, "slug:"),
        ({"source": "twitter"}, "source:"),
        ({"source_url": "http://example.invalid/x"}, "source_url:"),
        ({"class": "xss"}, "class: 'xss' is not a known class slug"),
        ({"auth": "author"}, "auth:"),
        ({"split": "train"}, "split:"),
        ({"vuln_sha256": "XYZ"}, "vuln_sha256: must be 64"),
        ({"fixed_version": "1.0.0"}, "fixed_version: must differ"),
        ({"published": "15/07/2026"}, "published: required ISO date"),
        ({"after_cutoff": None}, "after_cutoff"),
        ({"vuln_version": None}, "vuln_version: required"),
    ],
)
def test_each_field_rule_reports_an_error(dataset, override, needle):
    _, issues = load_cases(dataset(case_block(1, **override)))
    assert any(needle in m for m in messages(issues)), messages(issues)


def test_missing_hash_is_a_warning_not_an_error(dataset):
    _, issues = load_cases(dataset(case_block(1, vuln_sha256="", fixed_sha256=None)))
    assert messages(issues) == [] and len(messages(issues, "warning")) == 2


def test_duplicate_ids_and_cve_in_the_same_plugin(dataset):
    _, issues = load_cases(dataset(case_block(1), case_block(1, slug="fake-plugin-2")))
    assert any("duplicated" in m for m in messages(issues))
    _, issues = load_cases(dataset(case_block(1), case_block(2, cve="CVE-2026-1001", slug="fake-plugin-1")))
    assert any("more than one case" in m for m in messages(issues))


def test_unexpected_fields_are_warnings(dataset):
    _, issues = load_cases(dataset(case_block(1, colour="red")))
    assert messages(issues) == [] and any("unexpected field" in m for m in messages(issues, "warning"))


def test_published_after_retrieved_is_a_warning(dataset):
    _, issues = load_cases(dataset(case_block(1, published="2026-12-01")))
    assert messages(issues) == [] and any("later than" in m for m in messages(issues, "warning"))


def test_unsigned_label_is_a_warning_and_is_not_counted(dataset):
    cases, issues = load_cases(dataset(case_block(1) + TRUTH))
    assert messages(issues) == []
    assert any("not signed" in m for m in messages(issues, "warning"))
    assert not cases[0].signed and summarise(cases)["signed_labels"] == 0 and summarise(cases)["labelled"] == 1


def test_signed_label_counts(dataset):
    cases, issues = load_cases(dataset(case_block(1) + TRUTH + 'reviewed_by = "A. Reviewer"\nreviewed_on = "2026-11-03"\n'))
    assert issues == [] and cases[0].signed and summarise(cases)["signed_labels"] == 1


@pytest.mark.parametrize(
    ("patch", "needle"),
    [
        ('line_start = 120\nline_end = 134', 'line_start = 140\nline_end = 134'),
        ('file = "includes/class-admin.php"', 'file = "../etc/passwd"'),
        ('file = "includes/class-admin.php"', 'file = "/abs/path.php"'),
        ('line_start = 120', 'line_start = 0'),
    ],
)
def test_truth_rules(dataset, patch, needle):
    text = case_block(1) + TRUTH.replace(patch, needle) + 'reviewed_by = "A"\nreviewed_on = "2026-11-03"\n'
    assert messages(load_cases(dataset(text))[1])


def test_reviewed_by_requires_a_date_and_vice_versa(dataset):
    _, issues = load_cases(dataset(case_block(1) + TRUTH + 'reviewed_by = "A"\n'))
    assert any("reviewed_on" in m for m in messages(issues))
    _, issues = load_cases(dataset(case_block(1) + TRUTH + 'reviewed_on = "2026-11-03"\n'))
    assert any("reviewed_by" in m for m in messages(issues))


def test_summary_counts(dataset):
    cases, _ = load_cases(dataset(case_block(1, split="dev"), case_block(2, split="test", **{"class": "sqli"}), case_block(3, **{"class": "sqli"})))
    s = summarise(cases)
    assert s["cases"] == 3 and s["by_split"] == {"dev": 1, "test": 1, "unassigned": 1} and s["by_class"] == {"sqli": 2, "stored-xss": 1}
