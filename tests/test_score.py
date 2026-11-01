from __future__ import annotations

import json
import math
from pathlib import Path

from wpbench.cases import Case
from wpbench.score import (
    load_records,
    per_case,
    precision_breakdown,
    read_sheet,
    sample_unmatched,
    score_records,
    summarise,
    write_sheet,
)
from wpbench.stats import bootstrap_diff, bootstrap_mean

TRUTH = {"file": "a.php", "function": "go", "line_start": 10, "line_end": 12, "entry_point": "x", "data_flow": "y", "notes": "n", "reviewed_by": "me", "reviewed_on": "2026-11-01"}


def case(cid: str, signed: bool = True) -> Case:
    t = dict(TRUTH) if signed else {k: v for k, v in TRUTH.items() if not k.startswith("reviewed")}
    return Case(cid, "CVE-1", "nvd", "u", "2026-11-01", "s", "1", "2", "a" * 64, "b" * 64, "CWE-79", "reflected-xss", "unauthenticated", "2026-07-01", True, None, t)


def finding(**over: object) -> dict[str, object]:
    return {"file": "a.php", "line_start": 11, "line_end": 11, "function": "go", "entry_point": "x", "cwe": "CWE-79", "class": "reflected-xss", "auth_required": "unauthenticated", "data_flow": "d", "confidence": "high"} | over


def write_run(root: Path, name: str, cid: str, version: str, cond: str, findings: list[dict[str, object]] | None, status: str = "ok", cost: float = 0.1, skill: bool = False) -> None:
    d = root / name / f"{cid}.{version}.{cond}.r1"
    d.mkdir(parents=True)
    (d / "record.json").write_text(json.dumps({"run_id": d.name, "case_id": cid, "version": version, "condition": cond, "repeat": 1, "status": status, "findings": findings, "cost_usd": cost, "turns": 5, "wall_s": 9, "skill_invoked": skill, "tool_calls": 3}))


def test_unsigned_cases_are_excluded(tmp_path: Path) -> None:
    write_run(tmp_path, "e", "wp-0001", "vuln", "A", [finding()])
    write_run(tmp_path, "e", "wp-0002", "vuln", "A", [finding()])
    rows, unsigned = score_records(load_records([tmp_path / "e"]).records, [case("wp-0001"), case("wp-0002", signed=False)])
    assert [r["case_id"] for r in rows] == ["wp-0001"] and unsigned == ["wp-0002"]


def test_infrastructure_errors_are_excluded_but_invalid_output_is_a_miss(tmp_path: Path) -> None:
    write_run(tmp_path, "e", "wp-0001", "vuln", "A", None, status="error")
    write_run(tmp_path, "e", "wp-0002", "vuln", "A", None, status="invalid_output")
    loaded = load_records([tmp_path / "e"])
    assert [e["run_id"] for e in loaded.excluded] == ["wp-0001.vuln.A.r1"]
    rows, _ = score_records(loaded.records, [case("wp-0001"), case("wp-0002")])
    assert len(rows) == 1 and rows[0]["hit"] is False and rows[0]["status"] == "invalid_output"


def test_invalid_experiment_only_counts_for_condition_a(tmp_path: Path) -> None:
    write_run(tmp_path, "e", "wp-0001", "vuln", "A", [finding()])
    write_run(tmp_path, "e", "wp-0001", "vuln", "B", [finding()])
    (tmp_path / "e" / "INVALID.txt").write_text("x")
    loaded = load_records([tmp_path / "e"])
    assert [r["condition"] for r in loaded.records] == ["A"] and len(loaded.excluded) == 1


def test_later_experiment_replaces_the_same_run(tmp_path: Path) -> None:
    write_run(tmp_path, "one", "wp-0001", "vuln", "B", [], skill=False)
    write_run(tmp_path, "two", "wp-0001", "vuln", "B", [finding()], skill=True)
    recs = load_records([tmp_path / "one", tmp_path / "two"]).records
    assert len(recs) == 1 and recs[0]["experiment"] == "two"


def test_summary_recall_false_alarms_and_cost(tmp_path: Path) -> None:
    for cid, hit_a, hit_c in (("wp-0001", True, True), ("wp-0002", False, True)):
        write_run(tmp_path, "e", cid, "vuln", "A", [finding()] if hit_a else [finding(file="z.php")], cost=0.2)
        write_run(tmp_path, "e", cid, "vuln", "C-full", [finding()] if hit_c else [], cost=0.1, skill=True)
        write_run(tmp_path, "e", cid, "fixed", "A", [finding()] if cid == "wp-0001" else [], cost=0.2)
    rows, _ = score_records(load_records([tmp_path / "e"]).records, [case("wp-0001"), case("wp-0002")])
    s = summarise(rows, boot=200)
    a = next(c for c in s["conditions"] if c["condition"] == "A")
    c = next(c for c in s["conditions"] if c["condition"] == "C-full")
    assert a["recall"] == 0.5 and c["recall"] == 1.0
    assert a["false_alarm_rate"] == 0.5 and a["false_alarm_cases"] == 2  # the fixed version of wp-0001 still reports the bug
    assert c["false_alarm_rate"] is None and c["skill_invoked_rate"] == 1.0
    assert math.isclose(a["cost_usd"], 0.8) and math.isclose(a["cost_per_hit"], 0.8)
    assert s["differences"][0]["recall_diff"] == 0.5 and s["differences"][0]["paired_cases"] == 2
    assert per_case(rows, "A", "vuln", "hit") == {"wp-0001": 1.0, "wp-0002": 0.0}


def test_bootstrap_is_deterministic_and_brackets_the_mean() -> None:
    data = {str(i): float(i % 2) for i in range(20)}
    lo, hi = bootstrap_mean(data, 2000, 1)
    assert (lo, hi) == bootstrap_mean(data, 2000, 1) and lo < 0.5 < hi
    assert bootstrap_mean({"a": 1.0, "b": 1.0}, 500, 1) == (1.0, 1.0)
    assert math.isnan(bootstrap_mean({}, 10, 1)[0])
    d, ci, n = bootstrap_diff({"a": 1.0, "b": 1.0, "c": 1.0}, {"a": 0.0, "b": 0.0, "d": 0.0}, 500, 1)
    assert d == 1.0 and n == 2 and ci == (1.0, 1.0)  # only the shared cases are compared


def test_sheet_keeps_human_labels_and_samples_when_large(tmp_path: Path) -> None:
    write_run(tmp_path, "e", "wp-0001", "vuln", "A", [finding(), finding(file="z.php"), finding(file="y.php")])
    rows, _ = score_records(load_records([tmp_path / "e"]).records, [case("wp-0001")])
    items, sampled = sample_unmatched(rows)
    assert len(items) == 2 and not sampled
    sheet = tmp_path / "sheet.csv"
    write_sheet(sheet, items, {})
    text = sheet.read_text().replace(",,,\n", ",fp,looks safe,me\n", 1)  # a human fills the first row
    sheet.write_text(text)
    write_sheet(sheet, items, read_sheet(sheet))  # re-scoring must not wipe it
    labels = [r["label"] for r in read_sheet(sheet).values()]
    assert labels.count("fp") == 1
    b = precision_breakdown(rows, read_sheet(sheet))["A"]
    assert b["matched"] == 1 and b["fp"] == 1 and b["unlabelled"] == 1
    many = [{"run_id": f"r{i}", "case_id": "c", "condition": "A", "version": "vuln", "unmatched": [0], "findings": [finding()]} for i in range(80)]
    items2, sampled2 = sample_unmatched(many)
    assert len(items2) == 50 and sampled2 and items2 == sample_unmatched(many)[0]
