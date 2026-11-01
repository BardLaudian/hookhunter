"""Checks on SKILL.md, the findings schema and the activation eval prompts (S3)."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import jsonschema
import pytest
import yaml

SKILL = Path(__file__).resolve().parents[1]
REPO = SKILL.parents[1]
TEXT = (SKILL / "SKILL.md").read_text()
SCHEMA = json.loads((REPO / "schemas" / "findings.schema.json").read_text())
EVALS = json.loads((SKILL / "tests" / "evals" / "triggers.json").read_text())["prompts"]


def frontmatter() -> dict:
    m = re.match(r"---\n(.*?)\n---\n", TEXT, re.S)
    assert m, "frontmatter must start on the first line"
    return yaml.safe_load(m.group(1))


def test_skill_md_is_at_most_250_lines():
    assert len(TEXT.splitlines()) <= 250


def test_frontmatter_fields():
    fm = frontmatter()
    assert fm["name"] == "wp-plugin-audit" == SKILL.name
    assert set(fm) == {"name", "description", "allowed-tools"}, "only fields that other agents also understand, plus allowed-tools"
    assert fm["allowed-tools"] == "Read Grep Glob Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/*)"


def test_description_is_bounded_and_leads_with_the_use_case():
    desc = " ".join(frontmatter()["description"].split())
    assert len(desc) <= 1536  # Claude Code truncates description + when_to_use at 1,536 characters
    assert desc.startswith("Audit the PHP source of a WordPress plugin or theme")
    assert "<" not in desc and ">" not in desc
    for phrase in ("WordPress", "vulnerabilit", "En español", "auditar", "buscar vulnerabilidades", "Not for"):
        assert phrase in desc


def test_modes_hard_rules_and_workflow_steps_are_present():
    for mode in ("**bench**", "**diff**", "**audit**"):
        assert mode in TEXT
    rules = re.search(r"## Hard rules\n(.*?)\n## ", TEXT, re.S).group(1)
    assert len(re.findall(r"^\d+\. ", rules, re.M)) == 7
    for step in ("### 0. Gate", "### 1. Map", "### 2. Hunt by class", "### 3. Refute", "### 4. Variants", "### 5. Coverage", "### 6. Report"):
        assert step in TEXT
    for status in ("`confirmed`", "`needs-dynamic-check`", "`refuted`"):
        assert status in TEXT


def test_every_referenced_file_and_script_exists():
    for ref in set(re.findall(r"`(reference/[\w./-]+\.md)`", TEXT)):
        assert (SKILL / ref).is_file(), ref
    for script in set(re.findall(r"scripts/([\w]+\.py)", TEXT)):
        assert (SKILL / "scripts" / script).is_file(), script
    for cmd in re.findall(r"python3 (\S+)", TEXT):
        assert cmd.startswith("${CLAUDE_SKILL_DIR}/scripts/"), cmd


def test_all_twelve_classes_are_in_the_hunt_table_including_xxe():
    classes = {p.stem for p in (SKILL / "reference" / "classes").glob("*.md")}
    mentioned = set(re.findall(r"`reference/classes/([\w-]+)\.md`", TEXT))
    assert mentioned == classes and len(classes) == 12


def test_bench_example_validates_against_the_schema():
    block = re.search(r"```json\n(.*?)\n```", TEXT, re.S).group(1)
    jsonschema.validate(json.loads(block), SCHEMA)


def test_schema_is_valid_and_its_enumerations_are_documented_in_skill_md():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    props = SCHEMA["properties"]["findings"]["items"]["properties"]
    for key in ("class", "auth_required", "confidence"):
        for value in props[key]["enum"]:
            assert f"`{value}`" in TEXT, f"{key}={value} is not documented in SKILL.md"


def test_class_to_cwe_table_agrees_with_the_default_mapping():
    table = dict(re.findall(r"\| ((?:`[\w-]+`(?:, )?)+) \| (CWE-\d+)", TEXT))
    pairs = {slug: cwe for slugs, cwe in table.items() for slug in re.findall(r"`([\w-]+)`", slugs)}
    assert set(pairs) <= set(SCHEMA["properties"]["findings"]["items"]["properties"]["class"]["enum"])
    assert pairs["sqli"] == "CWE-89" and pairs["stored-xss"] == "CWE-79" and pairs["xxe"] == "CWE-611"


def test_schema_rejects_malformed_findings():
    good = {"file": "a.php", "line_start": 1, "line_end": 2, "function": "", "entry_point": "", "cwe": "CWE-79", "class": "stored-xss",
            "auth_required": "subscriber", "data_flow": "x -> y", "confidence": "high"}
    jsonschema.validate({"findings": [good]}, SCHEMA)
    for patch in ({"file": "/abs/a.php"}, {"cwe": "79"}, {"class": "xss"}, {"auth_required": "author"}, {"confidence": "certain"}, {"line_start": 0}):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"findings": [{**good, **patch}]}, SCHEMA)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"findings": [{**good, "poc": "x"}]}, SCHEMA)  # no PoC field (project rule)


def test_eval_prompts_cover_both_languages_and_both_outcomes():
    ids = [e["id"] for e in EVALS]
    assert len(ids) == len(set(ids))
    counts = Counter((e["lang"], e["expect_trigger"], e["split"]) for e in EVALS)
    for lang in ("en", "es"):
        for expect in (True, False):
            for split in ("dev", "heldout"):
                assert counts[(lang, expect, split)] >= 3, (lang, expect, split)
    assert sum(e["expect_trigger"] for e in EVALS) >= 16
    assert sum(not e["expect_trigger"] for e in EVALS) >= 16
