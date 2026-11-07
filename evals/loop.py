#!/usr/bin/env python3
"""Paired evaluation of hookhunter against the same agent without the skill, and the usefulness verdict.

  loop.py run   --cases DIR --truth cases.toml [--ids a,b] [--conditions A,C] [--repeats 2] [--model claude-haiku-5-5] [--jobs 4] --out DIR
  loop.py score --out DIR [--truth cases.toml]          summary, paired difference, verdict against evals/criterion.json

Conditions (identical prompt, model, budget and tools except the skill):
  A  no skill: tools Read, Grep, Glob
  C  hookhunter copied to .claude/skills/hookhunter: tools Read, Grep, Glob, Skill(hookhunter) and Bash limited by evals/bash_guard.py
     to the skill's own scripts. The skill's hooks (Stop gate, Read tracker) run as they would for a user.

Each run is a headless `claude -p` in a fresh work dir holding ./plugin (a copy of the case) and, for C, the skill. Findings are taken
from the final message, validated, and matched with wp-audit-bench's rule (src/wpbench/match.py: same file AND lines within 10 or
same function within 100 lines AND compatible CWE family). Invalid output is a miss. Static analysis only: the plugin code is never run.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent
sys.path.insert(0, str(SKILL / "scripts"))
from hh_validate import extract, validate  # noqa: E402

PROMPT_DEFAULT = Path("/root/bench/prompts/task.md")


def load_truth(path: Path) -> dict[str, dict[str, Any]]:
    d = tomllib.loads(path.read_text())
    return {c["id"]: c for c in d["case"]}


def case_dir(cases: Path, cid: str) -> Path:
    base = cases / cid
    return base / "vuln" if (base / "vuln").is_dir() else base


def stage(work: Path, plugin: Path, cond: str) -> list[str]:
    shutil.copytree(plugin, work / "plugin", symlinks=False, ignore=shutil.ignore_patterns(".git"))
    tools = "Read,Grep,Glob"
    allowed = "Read,Grep,Glob"
    if cond == "C":
        dst = work / ".claude" / "skills" / "hookhunter"
        shutil.copytree(SKILL, dst, ignore=shutil.ignore_patterns(".git", "evals", "__pycache__", "tests"))
        (work / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": f"python3 {HERE / 'bash_guard.py'}"}]}]}}))
        tools = "Read,Grep,Glob,Bash,Skill"
        allowed = "Read,Grep,Glob,Skill(hookhunter),Bash(python3 .claude/skills/hookhunter/scripts/*)," \
                  f"Bash(python3 {dst}/scripts/*)"
    return ["--tools", tools, "--allowedTools", allowed]


def run_one(args: argparse.Namespace, cid: str, cond: str, rep: int, truth: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {"case": cid, "condition": cond, "repeat": rep, "model": args.model}
    with tempfile.TemporaryDirectory(prefix=f"hh-{cid}-{cond}-") as td:
        work = Path(td)
        extra = stage(work, case_dir(Path(args.cases), cid), cond)
        prompt = Path(args.prompt).read_text()
        cmd = ["claude", "-p", prompt, "--output-format", "json", "--model", args.model, "--no-session-persistence",
               "--setting-sources", "project", "--strict-mcp-config", "--max-budget-usd", str(args.budget), *extra]
        env = dict(os.environ, HH_STATE_DIR=str(work / ".hhstate"))
        t0 = time.time()
        try:
            p = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=args.timeout, env=env)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired:
            rec.update(status="timeout", wall_s=round(time.time() - t0, 1))
            return rec
        rec["wall_s"] = round(time.time() - t0, 1)
        try:
            j = json.loads(out)
        except ValueError:
            rec.update(status="error", detail=(out or p.stderr)[-300:])
            return rec
        rec.update(cost_usd=j.get("total_cost_usd"), turns=j.get("num_turns"), terminal=j.get("terminal_reason"), rc=rc)
        led = work / ".hhstate" / "hookhunter"
        ledgers = list(led.glob("*/ledger.json")) if led.is_dir() else []
        if ledgers:
            L = json.loads(ledgers[0].read_text())
            req = [r for r in L["rows"] if r["required"]]
            rec["ledger"] = {"rows": len(L["rows"]), "required": len(req), "required_done": sum(1 for r in req if r.get("verdict")),
                             "stop_blocks": L.get("stop_blocks", 0), "verdicts": sum(1 for r in L["rows"] if r.get("verdict"))}
        rec["skill_used"] = bool(ledgers)
        obj, warn = extract(str(j.get("result") or ""))
        errs = [warn] if obj is None else validate(obj)
        if errs:
            rec.update(status="invalid_output", errors=errs[:5])
            return rec
        findings = obj["findings"]
        rec.update(status="ok", n_findings=len(findings), findings=findings)
        rec.update(score(findings, truth, args.bench))
    return rec


def score(findings: list[dict[str, Any]], case: dict[str, Any], bench: str) -> dict[str, Any]:
    sys.path.insert(0, bench)
    from wpbench.match import Truth, score_findings  # type: ignore

    t = case["truth"]
    tr = Truth(t["file"], t["function"], int(t["line_start"]), int(t["line_end"]), case["cwe"], case["class"])
    s = score_findings(findings, tr)
    return {"hit": s.hit, "hit_at_3": s.hit_at_3, "matched": list(s.matched)}


def cmd_run(args: argparse.Namespace) -> int:
    truth = load_truth(Path(args.truth))
    ids = args.ids.split(",") if args.ids else sorted(p.name for p in Path(args.cases).iterdir() if p.is_dir() and p.name in truth)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    done = set()
    res_file = out / "runs.jsonl"
    if res_file.exists():
        for line in res_file.read_text().splitlines():
            r = json.loads(line)
            if r.get("status") in ("ok", "invalid_output"):
                done.add((r["case"], r["condition"], r["repeat"]))
    plan = [(c, k, r) for r in range(1, args.repeats + 1) for c in ids for k in args.conditions.split(",") if (c, k, r) not in done]
    random.Random(7).shuffle(plan)  # interleave conditions so drift (load, model updates) hits both alike
    print(f"{len(plan)} runs to do ({len(done)} already done)", file=sys.stderr)
    with cf.ThreadPoolExecutor(args.jobs) as ex, res_file.open("a") as fh:
        futs = {ex.submit(run_one, args, c, k, r, truth[c]): (c, k, r) for c, k, r in plan}
        for f in cf.as_completed(futs):
            rec = f.result()
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            print(f"{rec['case']} {rec['condition']} r{rec['repeat']}: {rec.get('status')} hit={rec.get('hit')} "
                  f"${(rec.get('cost_usd') or 0):.3f} {rec.get('ledger', '')}", file=sys.stderr)
    return 0


def _bootstrap(diffs: list[float], n: int = 10000, seed: int = 20261107) -> tuple[float, float]:
    rng = random.Random(seed)
    if not diffs:
        return (0.0, 0.0)
    ms = sorted(sum(rng.choice(diffs) for _ in diffs) / len(diffs) for _ in range(n))
    return ms[int(0.025 * n)], ms[int(0.975 * n) - 1]


def summarize(runs: list[dict[str, Any]], crit: dict[str, Any]) -> dict[str, Any]:
    by: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in runs:
        if r.get("status") in ("ok", "invalid_output"):
            by.setdefault((r["case"], r["condition"]), []).append(r)
    conds = sorted({k for _, k in by})
    cases = sorted({c for c, _ in by})
    per: dict[str, Any] = {}
    for k in conds:
        rs = [r for (c, kk), v in by.items() if kk == k for r in v]
        rec = [sum(bool(r.get("hit")) for r in by[(c, k)]) / len(by[(c, k)]) for c in cases if (c, k) in by]
        cost = [r.get("cost_usd") or 0 for r in rs]
        per[k] = {"runs": len(rs), "cases": len(rec), "recall": round(sum(rec) / len(rec), 3) if rec else None,
                  "recall_at_3": round(sum(bool(r.get("hit_at_3")) for r in rs) / len(rs), 3) if rs else None,
                  "invalid_rate": round(sum(r["status"] == "invalid_output" for r in rs) / len(rs), 3) if rs else None,
                  "findings_per_run": round(sum(r.get("n_findings", 0) for r in rs) / len(rs), 2) if rs else None,
                  "cost_per_run": round(sum(cost) / len(cost), 4) if cost else None}
    out: dict[str, Any] = {"conditions": per}
    if {"A", "C"} <= set(conds):
        paired = [c for c in cases if (c, "A") in by and (c, "C") in by]
        ha = {c: sum(bool(r.get("hit")) for r in by[(c, "A")]) / len(by[(c, "A")]) for c in paired}
        hc = {c: sum(bool(r.get("hit")) for r in by[(c, "C")]) / len(by[(c, "C")]) for c in paired}
        diffs = [hc[c] - ha[c] for c in paired]
        lo, hi = _bootstrap(diffs)
        d = sum(diffs) / len(diffs) if diffs else 0.0
        win = sum(1 for x in diffs if x > 0)
        loss = sum(1 for x in diffs if x < 0)
        ca, cc = per["A"]["cost_per_run"] or 1e-9, per["C"]["cost_per_run"] or 0
        out["paired"] = {"cases": len(paired), "recall_diff": round(d, 3), "ci95": [round(lo, 3), round(hi, 3)],
                         "cases_C_better": win, "cases_A_better": loss, "cost_ratio_C_over_A": round(cc / ca, 2)}
        out["verdict"] = verdict(out, crit)
    return out


def verdict(s: dict[str, Any], crit: dict[str, Any]) -> dict[str, Any]:
    p, a, c = s["paired"], s["conditions"]["A"], s["conditions"]["C"]
    checks = {
        "enough_cases": p["cases"] >= crit["min_cases"],
        "recall_gain": p["recall_diff"] >= crit["min_recall_gain"],
        "gain_not_noise": p["ci95"][0] > 0,
        "absolute_recall": (c["recall"] or 0) >= crit["min_recall_C"],
        "precision_proxy": (c["findings_per_run"] or 0) <= crit["max_findings_per_run"],
        "cost": p["cost_ratio_C_over_A"] <= crit["max_cost_ratio"],
        "valid_output": (c["invalid_rate"] or 0) <= crit["max_invalid_rate"],
    }
    if not checks["enough_cases"]:
        label = "INCONCLUSIVE (too few cases)"
    elif all(checks.values()):
        label = "USEFUL"
    elif p["ci95"][1] < 0:
        label = "HARMFUL (worse than no skill)"
    elif checks["recall_gain"] and not checks["gain_not_noise"]:
        label = "PROMISING (gain not yet distinguishable from noise)"
    else:
        label = "NOT YET USEFUL"
    return {"label": label, "checks": checks}


def cmd_score(args: argparse.Namespace) -> int:
    runs = [json.loads(x) for x in (Path(args.out) / "runs.jsonl").read_text().splitlines() if x.strip()]
    crit = json.loads((HERE / "criterion.json").read_text())
    s = summarize(runs, crit)
    (Path(args.out) / "summary.json").write_text(json.dumps(s, indent=1))
    print(json.dumps(s, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--cases", required=True)
    r.add_argument("--truth", required=True)
    r.add_argument("--ids", default="")
    r.add_argument("--conditions", default="A,C")
    r.add_argument("--repeats", type=int, default=2)
    r.add_argument("--model", default="claude-haiku-5-5")
    r.add_argument("--jobs", type=int, default=4)
    r.add_argument("--budget", type=float, default=3.0)
    r.add_argument("--timeout", type=int, default=1800)
    r.add_argument("--prompt", default=str(PROMPT_DEFAULT))
    r.add_argument("--bench", default="/root/bench/src")
    r.add_argument("--out", required=True)
    s = sub.add_parser("score")
    s.add_argument("--out", required=True)
    a = ap.parse_args()
    return cmd_run(a) if a.cmd == "run" else cmd_score(a)


if __name__ == "__main__":
    raise SystemExit(main())
