#!/usr/bin/env python3
"""Offline inner-loop metric (no model calls): does the worklist put the ground-truth function in front of the agent?

  script_recall.py --cases DIR --truth cases.toml [--required 25]

For each case: the rank of the first ledger row that overlaps the truth location (same file, lines within 10), and whether that row is
required. `in_required` is an upper bound on what the ledger can add: a bug outside the required rows depends on the agent's own reading.
Cheap enough to run after every script change; it is NOT the usefulness measure (that is loop.py, with the model in the loop).
"""
import argparse, json, sys, tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from hh_ledger import build_rows, pick_required  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--cases", required=True); ap.add_argument("--truth", required=True); ap.add_argument("--required", type=int, default=25)
a = ap.parse_args()
truth = {c["id"]: c for c in tomllib.loads(Path(a.truth).read_text())["case"]}
res = []
for d in sorted(Path(a.cases).iterdir()):
    if d.name not in truth:
        continue
    t = truth[d.name]["truth"]
    root = d / "vuln" if (d / "vuln").is_dir() else d
    rows, meta = build_rows(root)
    for n, r in enumerate(rows, 1):
        r["id"] = f"U{n}"
    pick_required(rows, a.required)
    hit = None
    for n, r in enumerate(rows, 1):
        lo, _, hi = r["lines"].partition("-")
        if r["file"] == t["file"] and int(lo) - 10 <= t["line_end"] and int(hi or lo) + 10 >= t["line_start"]:
            hit = {"rank": n, "required": r["required"], "sources": r["sources"]}
            break
    res.append({"case": d.name, "class": truth[d.name].get("class"), "rows": len(rows), "truth_row": hit})
    print(json.dumps(res[-1]))
n = len(res)
print(json.dumps({"cases": n, "in_rows": sum(1 for r in res if r["truth_row"]), "in_required": sum(1 for r in res if r["truth_row"] and r["truth_row"]["required"])}))
