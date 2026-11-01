#!/usr/bin/env python3
"""Run the activation evals: does Claude Code load the skill for audit requests and leave it alone otherwise?

Usage: run_trigger_evals.py [--split dev|heldout|all] [--model sonnet] [--out results.json]

For each prompt in evals/triggers.json it starts `claude -p` in a scratch workspace whose `.claude/skills/` holds a copy of this skill, with user-level
settings and plugins excluded (--setting-sources project) so that other skills do not compete. One assistant turn is enough: the question is whether the
first move is a call to the Skill tool for `wp-plugin-audit`. It costs real API money (about 0.02 USD per prompt at the time of writing) and needs the
`claude` CLI to be logged in, so it is not part of the pytest suite.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
SKILL_NAME = "wp-plugin-audit"
EVALS = Path(__file__).resolve().parent / "evals" / "triggers.json"


def make_workspace(root: Path) -> Path:
    dest = root / ".claude" / "skills" / SKILL_NAME
    shutil.copytree(SKILL_DIR, dest, ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc"))
    return root


def run_one(item: dict, workspace: Path, model: str, budget: float) -> dict:
    cmd = [
        "claude", "-p", item["prompt"], "--output-format", "stream-json", "--verbose", "--max-turns", "1",
        "--model", model, "--no-session-persistence", "--setting-sources", "project", "--strict-mcp-config",
        "--tools", "Skill,Read,Grep,Glob", "--max-budget-usd", str(budget),
    ]
    proc = subprocess.run(cmd, cwd=workspace, capture_output=True, text=True, timeout=300)
    tools: list[dict] = []
    cost = 0.0
    skills_listed: list[str] = []
    for line in proc.stdout.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            skills_listed = ev.get("skills", [])
        if ev.get("type") == "assistant":
            for block in ev.get("message", {}).get("content", []):
                if block.get("type") == "tool_use":
                    tools.append({"name": block.get("name"), "skill": (block.get("input") or {}).get("skill")})
        if ev.get("type") == "result":
            cost = float(ev.get("total_cost_usd") or 0)
    invoked = [t["skill"] for t in tools if t["name"] == "Skill"]
    triggered = any(s and s.split(":")[-1] == SKILL_NAME for s in invoked)
    return {
        "id": item["id"], "group": item["group"], "lang": item["lang"], "split": item["split"], "expect_trigger": item["expect_trigger"],
        "triggered": triggered, "skills_invoked": invoked, "first_tools": [t["name"] for t in tools],
        "skill_was_listed": SKILL_NAME in skills_listed, "cost_usd": round(cost, 4),
        "returncode": proc.returncode,
    }


def summarise(rows: list[dict]) -> dict:
    tp = sum(r["expect_trigger"] and r["triggered"] for r in rows)
    fn = sum(r["expect_trigger"] and not r["triggered"] for r in rows)
    fp = sum(not r["expect_trigger"] and r["triggered"] for r in rows)
    tn = sum(not r["expect_trigger"] and not r["triggered"] for r in rows)
    out = {"n": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn, "cost_usd": round(sum(r["cost_usd"] for r in rows), 3)}
    out["recall"] = round(tp / (tp + fn), 3) if tp + fn else None
    out["false_trigger_rate"] = round(fp / (fp + tn), 3) if fp + tn else None
    for lang in ("en", "es"):
        sub = [r for r in rows if r["lang"] == lang and r["expect_trigger"]]
        out[f"recall_{lang}"] = round(sum(r["triggered"] for r in sub) / len(sub), 3) if sub else None
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="dev")
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--budget", type=float, default=0.5, help="max USD per prompt")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--out", type=Path)
    ns = ap.parse_args()
    if shutil.which("claude") is None:
        print("error: the claude CLI is not on PATH", file=sys.stderr)
        return 2
    items = json.loads(EVALS.read_text())["prompts"]
    items = [i for i in items if ns.split == "all" or i["split"] == ns.split]
    with tempfile.TemporaryDirectory() as tmp:
        workspace = make_workspace(Path(tmp))
        with ThreadPoolExecutor(max_workers=ns.workers) as pool:
            rows = list(pool.map(lambda it: run_one(it, workspace, ns.model, ns.budget), items))
    result = {"split": ns.split, "model": ns.model, "summary": summarise(rows), "rows": rows}
    text = json.dumps(result, indent=1, ensure_ascii=False)
    if ns.out:
        ns.out.write_text(text + "\n")
    print(json.dumps(result["summary"], indent=1))
    for r in rows:
        ok = r["triggered"] == r["expect_trigger"]
        print(f"{'ok  ' if ok else 'FAIL'} {r['id']:7s} expect={r['expect_trigger']!s:5s} triggered={r['triggered']!s:5s} skills={r['skills_invoked']} tools={r['first_tools']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
