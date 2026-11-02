"""Score runs against the signed ground truth: recall, recall@3, fixed-version false alarms, cost, paired bootstrap CIs.

Rules (docs/SPEC.md section 5, docs/DECISIONS.md section 16):
- only cases with a signed label count; the others are reported as excluded;
- ``invalid_output`` counts as a miss (the agent failed to deliver); ``error``/``timeout``/``budget`` are infrastructure and are
  excluded and listed, never silently counted as misses;
- records of an experiment that has an ``INVALID.txt`` count only for condition A (the defect did not touch it);
- the vulnerable and the fixed version of a case are scored with the same ground truth: a hit on the fixed version is a false alarm.
"""

from __future__ import annotations

import csv
import json
import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wpbench.cases import Case
from wpbench.match import FUNCTION_CAP, score_findings, truth_from_case
from wpbench.stats import bootstrap_diff, bootstrap_mean, mean

INFRA = {"error", "timeout", "budget"}
SHEET_FIELDS = ["id", "run_id", "case_id", "condition", "file", "line_start", "line_end", "function", "cwe", "class", "auth_required", "confidence", "data_flow", "label", "note", "labelled_by"]
LABELS = ("fp", "plausible", "real-but-other")
SHEET_LIMIT = 50


@dataclass
class Loaded:
    records: list[dict[str, Any]] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(default_factory=list)


def load_records(run_dirs: Sequence[Path], conditions: Sequence[str] | None = None) -> Loaded:
    out = Loaded()
    seen: dict[str, str] = {}
    for d in run_dirs:
        invalid = (d / "INVALID.txt").exists()
        for path in sorted(d.glob("*/record.json")):
            rec = json.loads(path.read_text(encoding="utf-8"))
            rec["experiment"] = d.name
            cond = rec.get("condition")
            if conditions and cond not in conditions:
                continue
            if invalid and cond != "A":
                out.excluded.append({"run_id": rec["run_id"], "experiment": d.name, "reason": "experiment marked INVALID for this condition"})
                continue
            if rec.get("status") in INFRA:
                out.excluded.append({"run_id": rec["run_id"], "experiment": d.name, "reason": f"{rec['status']}: {str(rec.get('detail'))[:60]}"})
                continue
            key = rec["run_id"]
            if key in seen:  # a later experiment replaces an earlier run of the same cell
                out.records = [r for r in out.records if r["run_id"] != key]
            seen[key] = d.name
            out.records.append(rec)
    return out


def score_records(records: Sequence[dict[str, Any]], cases: Sequence[Case], function_cap: int | None = FUNCTION_CAP) -> tuple[list[dict[str, Any]], list[str]]:
    """One row per run with its hit flags. Returns (rows, ids of cases skipped for lack of a signed label)."""
    by_id = {c.id: c for c in cases}
    rows: list[dict[str, Any]] = []
    unsigned: set[str] = set()
    for rec in records:
        case = by_id.get(rec["case_id"])
        if case is None or not case.signed:
            unsigned.add(rec["case_id"])
            continue
        findings = rec.get("findings") or []
        s = score_findings(findings, truth_from_case(case), function_cap)
        rows.append({
            "run_id": rec["run_id"], "experiment": rec["experiment"], "case_id": rec["case_id"], "version": rec["version"], "condition": rec["condition"],
            "repeat": rec["repeat"], "status": rec["status"], "n_findings": len(findings), "hit": s.hit, "hit_at_3": s.hit_at_3,
            "matched": list(s.matched), "unmatched": list(s.unmatched), "cost_usd": rec.get("cost_usd") or 0.0, "turns": rec.get("turns"),
            "wall_s": rec.get("wall_s"), "skill_invoked": bool(rec.get("skill_invoked")), "tool_calls": rec.get("tool_calls"), "findings": findings,
        })
    return rows, sorted(unsigned)


def per_case(rows: Sequence[dict[str, Any]], condition: str, version: str, key: str) -> dict[str, float]:
    """Mean over repeats of a boolean per case, for one condition and version."""
    acc: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        if r["condition"] == condition and r["version"] == version:
            acc[r["case_id"]].append(float(r[key]))
    return {c: mean(v) for c, v in acc.items()}


def summarise(rows: Sequence[dict[str, Any]], seed: int = 20261101, boot: int = 10_000) -> dict[str, Any]:
    conditions = sorted({r["condition"] for r in rows}, key=lambda c: (c != "A", c))
    summary: list[dict[str, Any]] = []
    recall_cases: dict[str, dict[str, float]] = {}
    for cond in conditions:
        vuln = [r for r in rows if r["condition"] == cond and r["version"] == "vuln"]
        fixed = [r for r in rows if r["condition"] == cond and r["version"] == "fixed"]
        rec, rec3, fa = per_case(rows, cond, "vuln", "hit"), per_case(rows, cond, "vuln", "hit_at_3"), per_case(rows, cond, "fixed", "hit")
        recall_cases[cond] = rec
        cost = sum(r["cost_usd"] for r in vuln + fixed)
        hits = sum(1 for r in vuln if r["hit"])
        summary.append({
            "condition": cond, "vuln_runs": len(vuln), "fixed_runs": len(fixed), "cases": len(rec),
            "recall": mean(list(rec.values())), "recall_ci": bootstrap_mean(rec, boot, seed),
            "recall_at_3": mean(list(rec3.values())), "false_alarm_rate": mean(list(fa.values())) if fa else None,
            "false_alarm_cases": len(fa), "findings_per_vuln_run": mean([r["n_findings"] for r in vuln]) if vuln else None,
            "unmatched_per_vuln_run": mean([len(r["unmatched"]) for r in vuln]) if vuln else None,
            "cost_usd": cost, "cost_per_hit": (cost / hits) if hits else None,
            "mean_cost_per_run": mean([r["cost_usd"] for r in vuln + fixed]), "skill_invoked_rate": mean([float(r["skill_invoked"]) for r in vuln + fixed]),
            "mean_turns": mean([float(r["turns"]) for r in vuln + fixed if r["turns"] is not None]),
        })
    diffs = []
    for cond in conditions:
        if cond != "A" and "A" in recall_cases:
            d, ci, n = bootstrap_diff(recall_cases[cond], recall_cases["A"], boot, seed)
            diffs.append({"condition": cond, "versus": "A", "recall_diff": d, "ci": ci, "paired_cases": n})
    return {"conditions": summary, "differences": diffs}


def sample_unmatched(rows: Sequence[dict[str, Any]], seed: int = 20261101, limit: int = SHEET_LIMIT) -> tuple[list[dict[str, Any]], bool]:
    """Unmatched findings of the vulnerable runs, all if there are at most ``limit``, else a seeded sample. Returns (items, sampled)."""
    items = [
        {"id": f"{r['run_id']}#{i}", "run_id": r["run_id"], "case_id": r["case_id"], "condition": r["condition"], **{k: r["findings"][i].get(k, "") for k in SHEET_FIELDS[4:13]}}
        for r in rows if r["version"] == "vuln" for i in r["unmatched"]
    ]
    if len(items) <= limit:
        return items, False
    return sorted(random.Random(seed).sample(items, limit), key=lambda x: x["id"]), True


def read_sheet(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8", newline="") as fh:
        return {r["id"]: r for r in csv.DictReader(fh)}


def write_sheet(path: Path, items: Sequence[dict[str, Any]], previous: dict[str, dict[str, str]]) -> None:
    """Write the labelling sheet, keeping labels a human already entered for the same finding id."""
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SHEET_FIELDS)
        w.writeheader()
        for it in items:
            old = previous.get(it["id"], {})
            w.writerow({**it, "label": old.get("label", ""), "note": old.get("note", ""), "labelled_by": old.get("labelled_by", "")})


def precision_breakdown(rows: Sequence[dict[str, Any]], sheet: dict[str, dict[str, str]]) -> dict[str, dict[str, int]]:
    """Per condition: matched findings and, for the unmatched ones, the human labels (never a single unexplained precision number)."""
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        if r["version"] != "vuln":
            continue
        b = out.setdefault(r["condition"], {"matched": 0, "fp": 0, "plausible": 0, "real-but-other": 0, "unlabelled": 0, "not_in_sample": 0})
        b["matched"] += len(r["matched"])
        for i in r["unmatched"]:
            row = sheet.get(f"{r['run_id']}#{i}")
            if row is None:
                b["not_in_sample"] += 1
            elif row.get("label") in LABELS:
                b[row["label"]] += 1
            else:
                b["unlabelled"] += 1
    return out


def write_outputs(out_dir: Path, rows: Sequence[dict[str, Any]], summary: dict[str, Any], extra: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "per_run.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps({k: v for k, v in r.items() if k != "findings"}) + "\n")
    cols = ["condition", "cases", "vuln_runs", "fixed_runs", "recall", "recall_ci_low", "recall_ci_high", "recall_at_3", "false_alarm_rate", "findings_per_vuln_run",
            "unmatched_per_vuln_run", "cost_usd", "cost_per_hit", "mean_cost_per_run", "skill_invoked_rate", "mean_turns"]
    with (out_dir / "summary.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for s in summary["conditions"]:
            w.writerow({**{k: s.get(k) for k in cols}, "recall_ci_low": s["recall_ci"][0], "recall_ci_high": s["recall_ci"][1]})
    (out_dir / "summary.json").write_text(json.dumps({**summary, **extra}, indent=1, default=list), encoding="utf-8")
