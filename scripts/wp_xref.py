#!/usr/bin/env python3
"""Cross-references for a function, method or hook name, as JSON.

Usage: wp_xref.py <plugin-dir> <name> [--backend auto|treesitter|regex]

<name> may be a function (``save_settings``), a method (``Admin::save`` or ``save``) or a hook
(``wp_ajax_save_settings``). Reports definitions, callers, the registrations that make it
reachable from WordPress, the handlers attached to it when it is a hook, and what it calls.
Static analysis only; nothing is executed or fetched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import Index, build_index  # noqa: E402
from _wp import literal, parse_callback, resolve  # noqa: E402

REGISTRARS = {
    "add_action": (0, 1), "add_filter": (0, 1), "add_shortcode": (0, 1), "register_activation_hook": (0, 1),
    "register_deactivation_hook": (0, 1), "register_uninstall_hook": (0, 1),
}


def xref(idx: Index, name: str) -> dict[str, Any]:
    cls_want, _, fn = name.rpartition("::")
    fn_low = fn.lower()
    defs = [f for f in idx.by_name(fn) if not cls_want or f.cls.lower() == cls_want.lower()]
    def_idx = {f.index for f in defs}

    callers = []
    for c in idx.calls:
        if c.name != fn_low or c.kind == "construct":
            continue
        if cls_want and c.kind in ("method", "static") and c.recv.lower() not in ("$this", "self", "static", cls_want.lower()):
            continue
        owner = idx.func_of(c)
        callers.append({"file": c.file, "line": c.line, "function": owner.qualname if owner else None,
                        "kind": c.kind, "receiver": c.recv or None})

    registered_as, hook_handlers = [], []
    for c in idx.calls:
        if c.name == "register_rest_route":
            # callbacks live inside the options array; match by text
            if any(parse_callback(v).name.lower() == fn_low for v in _array_callbacks(c.args[2] if len(c.args) > 2 else "")):
                registered_as.append({"hook": "rest:" + (literal(c.args[0]) or "?") + (literal(c.args[1]) or "?"),
                                      "registrar": c.name, "file": c.file, "line": c.line})
            continue
        spec = REGISTRARS.get(c.name)
        if not spec or len(c.args) <= max(spec):
            continue
        hook = literal(c.args[spec[0]]) or c.args[spec[0]]
        cb = parse_callback(c.args[spec[1]])
        target = resolve(idx, cb, c)
        hits_def = target is not None and target.index in def_idx
        if hits_def or (cb.kind in ("function", "method") and cb.name.lower() == fn_low and not defs):
            registered_as.append({"hook": hook, "registrar": c.name, "file": c.file, "line": c.line})
        if hook == name:
            hook_handlers.append({"registrar": c.name, "file": c.file, "line": c.line,
                                  "handler": target.qualname if target else cb.name or c.args[spec[1]][:60],
                                  "handler_file": target.file if target else None,
                                  "handler_line": target.line if target else None})

    callees = []
    for f in defs:
        seen = set()
        for c in idx.calls_in(f):
            if (c.name, c.line) not in seen:
                seen.add((c.name, c.line))
                callees.append({"name": c.name, "kind": c.kind, "line": c.line, "file": c.file})

    return {
        "name": name,
        "definitions": [{"function": f.qualname, "file": f.file, "line": f.line, "end_line": f.end_line} for f in defs],
        "callers": callers, "registered_as": registered_as, "hook_handlers": hook_handlers, "callees": callees,
    }


def _array_callbacks(text: str) -> list[str]:
    from _wp import array_pairs
    return [v for k, v in array_pairs(text) if k in ("callback", "permission_callback")]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("name")
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    res = xref(idx, ns.name)
    res.update({"root": idx.root, "backend": idx.backend, "files_parsed": len(idx.files), "skipped": idx.skipped})
    json.dump(res, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
