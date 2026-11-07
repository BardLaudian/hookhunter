#!/usr/bin/env python3
"""Walk list: every admin page, AJAX / REST / admin-post controller and shortcode, with the places where a request value reaches a sink.

Usage: wp_walk.py <plugin-dir> [--depth N] [--classes xss,sqli,...] [--backend auto|treesitter|regex]

Why: hits found only by following an advisory's hint are the easy ones. This script makes the walk systematic. For each function it reports the
sinks whose arguments are, or are built from, a request-derived value (`request_tainted` in wp_sinks.py: superglobals, `$this->get('x')`
style getters, `$_SERVER['REQUEST_URI'|'PHP_SELF'|'HTTP_HOST']`, a two-argument `add_query_arg`, REST accessors) and that nothing neutralises
(`risk: unguarded`). Functions are listed even when no mapped entry reaches them (`reached_by: []`): admin pages registered through a
variable (`$menu_slug`), controllers behind a router, and template helpers are exactly the ones that hide here.

Output:
  functions   ranked list, one row per function with tainted unguarded sinks: reached_by (entry points, best tier first), sinks (line, sink, classes)
  checklist   every walkable entry (menu page, ajax, admin_post, rest, shortcode, block, xmlrpc, request-hook) with its handler, tier and the
              number of tainted sinks it reaches: open each one, tick it off in the coverage note, and say which were not read
  unresolved  entry points the map could not resolve (read them by hand)
A row is a place to read, not a finding: refute it with evidence (reference/verification.md section 3b). Static analysis only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import build_index  # noqa: E402
from wp_join import TIER_RANK, _confirmed, _func_at, _handler_func, _priority, _reach  # noqa: E402
from wp_map import build_map  # noqa: E402
from wp_sinks import scan_sinks  # noqa: E402

WALK_TYPES = {"menu", "ajax", "admin-post", "rest", "shortcode", "block", "xmlrpc", "request-hook", "widget"}
DEFAULT_CLASSES = {"xss", "sqli", "file-ops", "file-inclusion", "ssrf", "open-redirect", "object-injection", "rce", "xxe", "path-traversal"}
IMPACT = {"rce": 0, "object-injection": 0, "sqli": 0, "file-inclusion": 0, "file-ops": 0, "xxe": 0, "ssrf": 1, "open-redirect": 2, "xss": 1}


def build_walk(idx: Any, classes: set[str], depth: int) -> dict[str, Any]:
    entries = build_map(idx)
    sinks = [s for s in scan_sinks(idx) if s["risk"] == "unguarded" and s.get("request_tainted") and classes & set(s["classes"])]
    by_func: dict[int, list[dict[str, Any]]] = {}
    top_level: list[dict[str, Any]] = []
    for s in sinks:
        f = _func_at(idx, s["file"], s["line"])
        (by_func.setdefault(f.index, []).append(s) if f is not None else top_level.append(s))

    func_entries: dict[int, list[tuple[int, str]]] = {}
    checklist: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for e in entries:
        h = _handler_func(idx, e)
        reach_idx: set[int] = set()
        if h is not None:
            for fi in _reach(idx, h, depth):
                reach_idx.add(fi)
                if fi in by_func:
                    func_entries.setdefault(fi, []).append((_priority(e), f"{e['type']}:{e['name'][:60]} [{e['file']}:{e['line']}] tier {e['tier']}{'' if _confirmed(e) else ' (unconfirmed)'}"))
        elif "handler-unresolved" in e.get("flags", []):
            unresolved.append({"id": e["id"], "type": e["type"], "name": e["name"], "registered_at": f"{e['file']}:{e['line']}"})
        if e["type"] in WALK_TYPES:
            n = sum(len(by_func[fi]) for fi in reach_idx if fi in by_func)
            checklist.append({"entry": f"{e['type']}:{e['name'][:60]}", "tier": e["tier"], "tier_confirmed": _confirmed(e), "registered_at": f"{e['file']}:{e['line']}",
                              "handler": e.get("handler"), "handler_resolved": h is not None, "tainted_unguarded_sinks_reached": n})

    rows: list[dict[str, Any]] = []
    for fi, ss in by_func.items():
        f = idx.funcs[fi]
        ents = sorted(func_entries.get(fi, []))
        best = ents[0][0] if ents else 1  # not reached by any mapped entry: reachability unknown, never ranked below confirmed non-anonymous
        impact = min(min((IMPACT.get(c, 3) for c in s["classes"]), default=3) for s in ss)
        rows.append({"priority": best, "file": f.file, "function": f.qualname, "lines": f"{f.line}-{f.end_line}", "reached_by": [t for _, t in ents[:4]],
                     "reached_by_total": len(ents),
                     "sinks": [{"line": s["line"], "sink": s["sink"], "classes": s["classes"], "origin": s.get("origin"), "args": s["args"][:110]} for s in sorted(ss, key=lambda x: x["line"])][:12],
                     "sink_count": len(ss), "_impact": impact})
    rows.sort(key=lambda r: (r["priority"], r["_impact"], -r["sink_count"]))
    for n, r in enumerate(rows, 1):
        r["rank"] = n
        del r["_impact"]
    checklist.sort(key=lambda c: (0 if c["handler_resolved"] else -1, TIER_RANK.get(c["tier"], 0), -c["tainted_unguarded_sinks_reached"]))
    return {"entries": len(entries), "tainted_unguarded_sinks": len(sinks), "functions": rows,
            "top_level_tainted_sinks": [{"at": f"{s['file']}:{s['line']}", "sink": s["sink"], "classes": s["classes"], "args": s["args"][:110]} for s in top_level],
            "checklist": checklist, "unresolved": unresolved}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--classes", default=",".join(sorted(DEFAULT_CLASSES)))
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ap.add_argument("--top", type=int, default=0, help="keep only the N best function rows (the checklist and unresolved are always complete)")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    res = build_walk(idx, set(ns.classes.split(",")), ns.depth)
    total = len(res["functions"])
    if ns.top and total > ns.top:
        res["functions"] = res["functions"][: ns.top]
    res.update({"root": idx.root, "backend": idx.backend, "functions_total": total, "functions_shown": len(res["functions"])})
    json.dump(res, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
