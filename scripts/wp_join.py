#!/usr/bin/env python3
"""Join the entry-point map with the sink inventory: which entry points reach which dangerous calls.

Usage: wp_join.py <plugin-dir> [--risk unguarded[,guarded]] [--depth N] [--top N] [--backend auto|treesitter|regex]

For every entry point of wp_map.py it follows calls by name (same rules as the map's `superglobals_via_callees`,
default depth 3) and lists the wp_sinks.py sinks found in the handler or in a function it reaches. The output is a
ranked candidate list, one row per (entry point, sink), highest priority first.

Ranking: `priority` (below), then registered endpoints (ajax, rest, admin-post...) before hooks that merely run, then
entry points that read request input, then sink impact (rce / object-injection / file / sqli first), then distance.
Priority (lowest first):
  0  tier `unauth` (wp_ajax_nopriv_*, REST with a permissive permission_callback, boot code, file-level code, auth hooks)
  1  tier NOT CONFIRMED: handler-unresolved, or the tier rests on a static capability hint
     (`capability-check (static hint)`), `cap-check-in-callee-only`, `is_admin-is-not-authz`
  2  tier `subscriber`          3  tier `author+`          4  tier `admin` backed by a menu capability
Nothing is dropped because of its tier. An unconfirmed tier moves a candidate UP, never down: the hint may sit in
another branch of the handler, in a callee, or behind a hook that anonymous users can reach. Every row carries
`verify`: the registration line to open before believing any tier lower than 0.

Also reported, never omitted:
  unresolved_entries   entry points whose handler the map could not resolve (dynamic wp_ajax_* loops, callables in arrays...)
  unreached_sinks      unguarded sinks that no mapped entry reaches within the depth (indirect registrations, include
                       chains, callables stored in properties): each needs a manual look at who calls the function
Static analysis only. A candidate is a place to read, not a finding; refute it with evidence (see reference/verification.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import Func, Index, build_index  # noqa: E402
from _wp import _callees  # noqa: E402
from wp_map import build_map  # noqa: E402
from wp_sinks import scan_sinks  # noqa: E402

TIER_RANK = {"unauth": 0, "subscriber": 2, "author+": 3, "admin": 4, "system": 5}
ENDPOINT_TYPES = {"ajax", "rest", "admin-post", "xmlrpc", "shortcode", "block", "cron"}  # registered for a request; others are hooks that run on their own
IMPACT = {"rce": 0, "object-injection": 0, "file-ops": 0, "sqli": 0, "xxe": 0, "ssrf": 1, "privesc": 1, "authz": 2, "xss": 2, "open-redirect": 2, "info-disclosure": 3}
UNCONFIRMED_FLAGS = {"handler-unresolved", "cap-check-in-callee-only", "is_admin-is-not-authz"}


def _confirmed(e: dict[str, Any]) -> bool:
    if UNCONFIRMED_FLAGS & set(e.get("flags", [])):
        return False
    return "static hint" not in (e.get("tier_basis") or "")


def _priority(e: dict[str, Any]) -> int:
    tier = e.get("tier", "unauth")
    base = TIER_RANK.get(tier, 0)
    if tier != "unauth" and not _confirmed(e):
        return 1
    return base


def _func_at(idx: Index, file: str, line: int) -> Func | None:
    best = None
    for f in idx.funcs:
        if f.file == file and f.line <= line <= f.end_line:
            if best is None or (f.end_line - f.line) < (best.end_line - best.line):
                best = f
    return best


def _handler_func(idx: Index, e: dict[str, Any]) -> Func | None:
    hf, hl = e.get("handler_file"), e.get("handler_line")
    if not hf or not hl:
        return None
    for f in idx.funcs:
        if f.file == hf and f.line == hl:
            return f
    return _func_at(idx, hf, hl)


def _reach(idx: Index, root: Func, depth: int) -> dict[int, tuple[int, list[str]]]:
    """Function index -> (distance, call path) for ``root`` and every function it reaches within ``depth`` calls."""
    out: dict[int, tuple[int, list[str]]] = {root.index: (0, [root.qualname])}
    frontier = [root]
    for d in range(1, depth + 1):
        nxt: list[Func] = []
        for fn in frontier:
            for g in _callees(idx, fn):
                if g.index not in out:
                    out[g.index] = (d, out[fn.index][1] + [g.qualname])
                    nxt.append(g)
        frontier = nxt
    return out


def build_join(idx: Index, risks: set[str], depth: int) -> dict[str, Any]:
    entries = build_map(idx)
    sinks = [s for s in scan_sinks(idx) if s["risk"] in risks]
    sink_func: list[Func | None] = [_func_at(idx, s["file"], s["line"]) for s in sinks]
    by_func: dict[int, list[int]] = {}
    top_level: dict[str, list[int]] = {}
    for i, f in enumerate(sink_func):
        if f is None:
            top_level.setdefault(sinks[i]["file"], []).append(i)
        else:
            by_func.setdefault(f.index, []).append(i)

    cands: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    reached: set[int] = set()
    without_sink = 0
    for e in entries:
        h = _handler_func(idx, e)
        hits: list[tuple[int, int, list[str]]] = []  # sink index, distance, path
        if h is not None:
            for fi, (dist, path) in _reach(idx, h, depth).items():
                for si in by_func.get(fi, []):
                    hits.append((si, dist, path))
        if e.get("type") in ("file-level",) or h is None and e.get("handler_file"):
            for si in top_level.get(e.get("handler_file") or e["file"], []):
                hits.append((si, 0, ["<file level>"]))
        if h is None and "handler-unresolved" in e.get("flags", []):
            unresolved.append({
                "id": e["id"], "type": e["type"], "name": e["name"], "handler": e["handler"], "registered_at": f"{e['file']}:{e['line']}",
                "tier_if_hook_is_as_named": e["tier"],
                "action": "handler not resolved by the map: grep -r the handler name, resolve the dynamic registration by hand, then re-run the sinks on it",
            })
        if not hits:
            without_sink += 1
            continue
        pri = _priority(e)
        for si, dist, path in hits:
            s = sinks[si]
            reached.add(si)
            cands.append({
                "priority": pri,
                "tier": e["tier"],
                "tier_confirmed": _confirmed(e),
                "entry": {"id": e["id"], "type": e["type"], "name": e["name"], "registered_at": f"{e['file']}:{e['line']}",
                          "flags": e.get("flags", []), "nonce_check": e.get("nonce_check"), "cap_check": e.get("cap_check"),
                          "tier_basis": e.get("tier_basis")},
                "sink": {"file": s["file"], "line": s["line"], "function": s["function"], "sink": s["sink"], "call": s["call"],
                         "classes": s["classes"], "risk": s["risk"], "origin": s.get("origin"), "args": s.get("args"),
                         "request_tainted": bool(s.get("request_tainted"))},
                "distance": dist,
                "path": path,
                "request_input": bool(e.get("superglobals") or e.get("superglobals_via_callees")),
                "verify": (f"open {e['file']}:{e['line']} (the registration) and the capability/permission code it names; "
                           "do not accept a tier higher than 0 from this table alone") if pri > 0 else
                          f"open {e['file']}:{e['line']}; check whether anonymous requests really reach it",
            })
    cands.sort(key=lambda c: (c["priority"], c["entry"]["type"] not in ENDPOINT_TYPES, not c["request_input"],
                              min((IMPACT.get(k, 3) for k in c["sink"]["classes"]), default=3), c["sink"]["origin"] != "request", c["distance"]))
    for n, c in enumerate(cands, 1):
        c["rank"] = n
    unreached = [{"at": f"{s['file']}:{s['line']}", "function": s["function"], "sink": s["sink"], "classes": s["classes"], "origin": s.get("origin"),
                  "request_tainted": bool(s.get("request_tainted"))}
                 for i, s in enumerate(sinks) if i not in reached and s["risk"] == "unguarded"]
    return {"entries": len(entries), "sinks_considered": len(sinks), "entries_with_no_reachable_sink": without_sink,
            "candidates": cands, "unresolved_entries": unresolved, "unreached_sinks": unreached}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--risk", default="unguarded", help="comma list of sink risks to join (default unguarded)")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--top", type=int, default=0, help="keep only the N best candidates (unresolved entries and unreached sinks are always kept)")
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    res = build_join(idx, set(ns.risk.split(",")), ns.depth)
    total = len(res["candidates"])
    if ns.top and total > ns.top:
        res["candidates"] = res["candidates"][: ns.top]
    res.update({"root": idx.root, "backend": idx.backend, "candidates_total": total, "candidates_shown": len(res["candidates"])})
    json.dump(res, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
