#!/usr/bin/env python3
"""Attack-surface map of a WordPress plugin or theme, as JSON.

Usage: wp_map.py <plugin-dir> [--top N] [--backend auto|treesitter|regex]

Lists entry points (AJAX, admin-post, REST, shortcodes, blocks, admin pages, hooks that read
superglobals, cron, widgets, XML-RPC) with the handler, a reachability tier and *static hints*
about nonce / capability checks. Hints are not proof: confirm in the code.
Static analysis only; nothing is executed or fetched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import Call, Index, build_index  # noqa: E402
from _wp import (  # noqa: E402
    TIER_ORDER,
    array_pairs,
    guards_of,
    literal,
    parse_callback,
    resolve,
    superglobals_of,
    tier_for_capability,
)

# Hooks that run on (nearly) every request; entry points only when the handler reads input.
REQUEST_HOOKS = {
    "init", "admin_init", "wp_loaded", "template_redirect", "parse_request", "plugins_loaded",
    "wp", "send_headers", "login_init", "after_setup_theme", "pre_get_posts",
}
_HOOK_ADDERS = {"add_action", "add_filter"}
_PREFIX_RE = re.compile(r"""^['"]([\w\-]*)['"]\s*\.""")


def _hook_name(arg: str) -> tuple[str, bool] | None:
    lit = literal(arg)
    if lit is not None:
        return lit, False
    m = _PREFIX_RE.match(arg.strip())
    return (m.group(1) + "*", True) if m else None


def _entry(idx: Index, site: Call, etype: str, name: str, cb_text: str, tier: str, basis: str,
           **extra: Any) -> dict[str, Any]:
    cb = parse_callback(cb_text)
    f = resolve(idx, cb, site)
    e: dict[str, Any] = {
        "type": etype, "name": name, "file": site.file, "line": site.line,
        "handler": f.qualname if f else (cb.name or cb_text[:60]),
        "handler_file": f.file if f else None, "handler_line": f.line if f else None,
        "tier": tier, "tier_basis": basis, "nonce_check": None, "cap_check": None,
        "capability": None, "superglobals": [], "flags": [],
    }
    e.update(extra)
    if f is None:
        e["flags"].append("handler-unresolved")
        return e
    g = guards_of(idx, f)
    e["nonce_check"], e["cap_check"], e["capability"] = g["nonce"], g["cap"], g["capability"]
    e["superglobals"] = superglobals_of(f)
    if e["cap_check"] and e["capability"] and etype not in ("menu", "rest"):
        e["tier"], e["tier_basis"] = tier_for_capability(e["capability"]), "capability-check (static hint)"
    if e["cap_check"] is None:
        e["flags"].append("no-cap-check")
    if e["nonce_check"] is None:
        e["flags"].append("no-nonce")
    if e["superglobals"]:
        e["flags"].append("reads-superglobals")
    return e


def _rest(idx: Index, c: Call, out: list[dict[str, Any]]) -> None:
    if len(c.args) < 3:
        return
    route = (literal(c.args[0]) or "?") + "/" + (literal(c.args[1]) or "?").lstrip("/")
    specs = [dict(array_pairs(c.args[2]))]
    for spec in specs:
        cb_text = spec.get("callback", "")
        perm = spec.get("permission_callback")
        if perm is None:
            tier, basis, flags = "unauth", "permission_callback missing", ["missing-permission-callback"]
        elif re.fullmatch(r"""['"]?__return_true['"]?""", perm.strip()):
            tier, basis, flags = "unauth", "permission_callback is __return_true", ["permission-callback-true"]
        else:
            pf = resolve(idx, parse_callback(perm), c)
            body = pf.body if pf else perm
            cm = re.search(r"current_user_can\s*\(\s*['\"]([\w\-]+)['\"]", body)
            if cm:
                tier, basis, flags = tier_for_capability(cm.group(1)), f"permission_callback checks '{cm.group(1)}'", []
            elif "is_user_logged_in" in body:
                tier, basis, flags = "subscriber", "permission_callback requires login", []
            else:
                tier, basis, flags = "unauth", "permission_callback not understood (verify)", ["permission-callback-unclear"]
        e = _entry(idx, c, "rest", route, cb_text, tier, basis)
        e["flags"] = flags + e["flags"]
        if e["handler_file"] is None and not cb_text:
            e["flags"].append("callback-missing")
        out.append(e)


def build_map(idx: Index) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    cron_hooks: set[str] = set()
    for c in idx.calls:
        if c.name == "wp_schedule_event" and len(c.args) > 2 and literal(c.args[2]):
            cron_hooks.add(literal(c.args[2]) or "")
        elif c.name == "wp_schedule_single_event" and len(c.args) > 1 and literal(c.args[1]):
            cron_hooks.add(literal(c.args[1]) or "")

    for c in idx.calls:
        if c.kind not in ("func",):
            continue
        n = c.name
        if n in _HOOK_ADDERS and len(c.args) >= 2:
            hn = _hook_name(c.args[0])
            if hn is None:
                continue
            hook, dyn = hn
            cbt = c.args[1]
            extra = {"dynamic": True} if dyn else {}
            if hook.startswith("wp_ajax_nopriv_"):
                entries.append(_entry(idx, c, "ajax", hook, cbt, "unauth", "wp_ajax_nopriv_ hook", **extra))
            elif hook.startswith("wp_ajax_"):
                entries.append(_entry(idx, c, "ajax", hook, cbt, "subscriber", "wp_ajax_ hook (any logged-in user)", **extra))
            elif hook.startswith("admin_post_nopriv_"):
                entries.append(_entry(idx, c, "admin_post", hook, cbt, "unauth", "admin_post_nopriv_ hook", **extra))
            elif hook.startswith("admin_post_"):
                entries.append(_entry(idx, c, "admin_post", hook, cbt, "subscriber", "admin_post_ hook (any logged-in user)", **extra))
            elif hook == "xmlrpc_methods":
                entries.append(_entry(idx, c, "xmlrpc", hook, cbt, "subscriber", "XML-RPC (credentials required)"))
            elif hook in cron_hooks:
                entries.append(_entry(idx, c, "cron", hook, cbt, "system", "scheduled event"))
            elif hook in REQUEST_HOOKS:
                e = _entry(idx, c, "request-hook", hook, cbt, "unauth",
                           "runs on every request (admin_init also on admin-ajax.php / admin-post.php for visitors)")
                if e["superglobals"]:
                    entries.append(e)
        elif n == "add_shortcode" and len(c.args) >= 2:
            e = _entry(idx, c, "shortcode", literal(c.args[0]) or c.args[0], c.args[1], "author+",
                       "attributes written by contributor+; rendered for visitors")
            if e["superglobals"]:
                e["tier"], e["tier_basis"] = "unauth", "shortcode reads request input"
            entries.append(e)
        elif n == "register_rest_route":
            _rest(idx, c, entries)
        elif n == "register_block_type" and len(c.args) >= 2:
            cb = dict(array_pairs(c.args[1])).get("render_callback")
            if cb:
                entries.append(_entry(idx, c, "block", literal(c.args[0]) or c.args[0], cb, "author+", "block attributes written by contributor+"))
        elif n in ("add_menu_page", "add_options_page", "add_management_page", "add_theme_page", "add_submenu_page"):
            off = 1 if n == "add_submenu_page" else 0
            if len(c.args) >= off + 5:
                cap = literal(c.args[off + 2]) or ""
                tier = tier_for_capability(cap) if cap else "admin"
                e = _entry(idx, c, "menu", literal(c.args[off + 3]) or c.args[off + 3], c.args[off + 4], tier,
                           f"menu capability '{cap or '?'}'")
                e["capability"] = cap or None
                entries.append(e)
        elif n == "register_widget" and c.args:
            wc = (literal(c.args[0]) or c.args[0]).strip("\\")
            e = _entry(idx, c, "widget", wc, f"'{wc}::widget'", "unauth", "widget output rendered for visitors")
            entries.append(e)
    entries.sort(key=lambda e: (
        TIER_ORDER[e["tier"]], "no-cap-check" not in e["flags"] and "no-nonce" not in e["flags"],
        not e["superglobals"], e["file"], e["line"]))
    for i, e in enumerate(entries):
        e["id"] = i + 1
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--top", type=int, default=0, help="keep only the N highest-ranked entry points")
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    entries = build_map(idx)
    total = len(entries)
    if ns.top and total > ns.top:
        entries = entries[: ns.top]
    json.dump({
        "root": idx.root, "backend": idx.backend, "files_parsed": len(idx.files),
        "skipped": idx.skipped, "entry_points_total": total, "entry_points_shown": len(entries),
        "truncated": len(entries) < total, "entry_points": entries,
    }, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
