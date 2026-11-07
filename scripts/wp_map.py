#!/usr/bin/env python3
"""Attack-surface map of a WordPress plugin or theme, as JSON.

Usage: wp_map.py <plugin-dir> [--top N] [--backend auto|treesitter|regex]

Lists entry points (AJAX, admin-post, REST, shortcodes, blocks, admin pages, hooks that read
superglobals, cron, widgets, XML-RPC) with the handler, a reachability tier and *static hints*
about nonce / capability checks. Hints are not proof: confirm in the code.
Also lists authentication/password hooks (type auth-hook) that read input, boot-time code (constructors, run()/init() methods) and file-level statements that read request input,
and reports request input read up to three calls below a handler (`superglobals_via_callees`).
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
    reach_account_calls,
    request_reach,
    resolve,
    superglobals_of,
    tier_for_capability,
)

# Hooks that run on (nearly) every request; entry points only when the handler reads input.
REQUEST_HOOKS = {
    "init", "admin_init", "wp_loaded", "template_redirect", "parse_request", "plugins_loaded",
    "wp", "send_headers", "login_init", "after_setup_theme", "pre_get_posts",
}
# Authentication, password and registration hooks (mostly filters). A handler here that reads request input is reachable by
# visitors on wp-login.php / admin-post.php and can swap a generated secret for a request value or skip a check.
AUTH_HOOKS = {
    "random_password", "authenticate", "wp_authenticate_user", "password_reset", "after_password_reset", "retrieve_password",
    "retrieve_password_key", "retrieve_password_message", "allow_password_reset", "registration_errors", "user_register",
    "pre_user_login", "pre_user_pass", "wp_pre_insert_user_data", "insert_user_meta", "login_redirect", "registration_redirect",
    "determine_current_user", "check_password", "auth_cookie_valid", "set_auth_cookie", "wp_login", "lostpassword_post",
    "lostpassword_errors", "validate_password_reset", "wp_insert_user", "profile_update",
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
    reach = request_reach(idx, f)
    e["superglobals"] = reach["direct"]
    e["superglobals_via_callees"] = reach["via_callees"]
    if re.search(r"\bis_admin\s*\(", f.body) and e["cap_check"] is None:
        e["flags"].append("is_admin-is-not-authz")
    e["account_control"] = reach_account_calls(idx, f)
    if e["account_control"]:
        e["flags"].append("account-control-reachable")
    if e["cap_check"] and e["capability"] and etype not in ("menu", "rest"):
        if etype == "request-hook" and e["cap_check"] != "handler":
            # runs for every visitor; a capability check somewhere below it may guard only one branch
            e["flags"].append("cap-check-in-callee-only")
        else:
            e["tier"], e["tier_basis"] = tier_for_capability(e["capability"]), "capability-check (static hint)"
    if e["cap_check"] is None:
        e["flags"].append("no-cap-check")
    if e["nonce_check"] is None:
        e["flags"].append("no-nonce")
    if e["superglobals"]:
        e["flags"].append("reads-superglobals")
    elif e["superglobals_via_callees"]:
        e["flags"].append("reads-superglobals-via-callee")
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


BOOT_NAMES = {"__construct", "run", "init", "boot", "bootstrap", "load", "setup", "start", "execute", "register", "initialize", "initialise"}


def _boot_entries(idx: Index, known: set[tuple[str | None, int | None]]) -> list[dict[str, Any]]:
    """Code that is not a registered handler but runs at load and reads request input.

    Constructors and run()/init()-style methods that read a superglobal other than $_SERVER directly or
    within three calls, and file-level statements (outside any function) that read one. These are
    reachable by every visitor whenever the plugin is loaded, whatever hook the class is created on.
    """
    out: list[dict[str, Any]] = []
    for f in idx.funcs:
        if f.name.lower() not in BOOT_NAMES or (f.file, f.line) in known:
            continue
        reach = request_reach(idx, f)
        direct = [g for g in reach["direct"] if g != "$_SERVER"]
        via = [g for g in reach["via_callees"] if not g.startswith("$_SERVER")]
        if not direct and not via:
            continue
        gd = guards_of(idx, f)
        flags = ["boot-code", "reads-superglobals" if direct else "reads-superglobals-via-callee"]
        if gd["cap"] is None:
            flags.append("no-cap-check")
        if gd["nonce"] is None:
            flags.append("no-nonce")
        if re.search(r"\bis_admin\s*\(", f.body) and gd["cap"] is None:
            flags.append("is_admin-is-not-authz")
        out.append({
            "type": "boot-code", "name": f.qualname, "file": f.file, "line": f.line, "handler": f.qualname,
            "handler_file": f.file, "handler_line": f.line, "tier": "unauth",
            "tier_basis": "constructor/run-style method that reads request input; runs whenever the class is created at load (find where)",
            "nonce_check": gd["nonce"], "cap_check": gd["cap"], "capability": gd["capability"],
            "superglobals": direct, "superglobals_via_callees": via, "flags": flags,
        })
    by_file: dict[str, dict[str, Any]] = {}
    for c in idx.calls:
        if c.func >= 0:
            continue
        txt = " ".join(c.args) + " " + c.recv
        sg = {g for g in re.findall(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b", txt)}
        if not sg:
            continue
        rec = by_file.setdefault(c.file, {"line": c.line, "sg": set(), "n": 0})
        rec["sg"] |= sg
        rec["n"] += 1
        rec["line"] = min(rec["line"], c.line)
    for fname, rec in by_file.items():
        try:
            src = (Path(idx.root) / fname).read_text(errors="replace")
        except OSError:
            src = ""
        guarded = bool(re.search(r"defined\s*\(\s*['\"]ABSPATH['\"]|ABSPATH\s*\)\s*(?:\|\||or)?\s*(?:exit|die)|!\s*defined\s*\(\s*['\"]ABSPATH", src))
        out.append({
            "type": "file-level", "name": f"{fname} ({rec['n']} statements)", "file": fname, "line": rec["line"], "handler": None,
            "handler_file": None, "handler_line": None,
            "tier": "admin" if guarded else "unauth",
            "tier_basis": ("ABSPATH guard present: runs only when another file includes it (find the hook that does)" if guarded
                           else "no ABSPATH guard: the file can be requested directly by URL"),
            "nonce_check": None, "cap_check": None, "capability": None, "superglobals": sorted(rec["sg"]),
            "superglobals_via_callees": [],
            "flags": ["file-level", "reads-superglobals"] + ([] if guarded else ["no-abspath-guard"]),
        })
    return out


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
            elif hook in AUTH_HOOKS:
                e = _entry(idx, c, "auth-hook", hook, cbt, "unauth",
                           "authentication/password/registration hook: runs for visitors on wp-login.php and similar endpoints")
                if e["superglobals"] or e.get("superglobals_via_callees"):
                    entries.append(e)
            elif hook in REQUEST_HOOKS:
                e = _entry(idx, c, "request-hook", hook, cbt, "unauth",
                           "runs on every request (admin_init also on admin-ajax.php / admin-post.php for visitors)")
                if e["superglobals"] or e.get("superglobals_via_callees"):
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
    entries.extend(_boot_entries(idx, {(e["handler_file"], e["handler_line"]) for e in entries if e.get("handler_file")}))
    entries.sort(key=lambda e: (
        TIER_ORDER[e["tier"]],
        # logs in / re-passwords / creates an account with no capability check: look at these first
        not (e.get("account_control") and e["cap_check"] is None),
        e["type"] != "auth-hook" or bool(e["cap_check"]),
        "no-cap-check" not in e["flags"] and "no-nonce" not in e["flags"],
        # request input found only below the handler ranks after registered endpoints and direct readers
        e["type"] in ("request-hook", "boot-code", "file-level") and not e["superglobals"],
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
    notes = []
    if len(idx.files) >= 300 and total <= max(12, len(idx.files) // 40):
        notes.append(f"framework-style plugin? {len(idx.files)} files parsed but only {total} entry points: the plugin probably routes requests "
                     "through its own dispatcher (an action router, a front controller, a service container). Find the central dispatch "
                     "(Grep -r for `$_REQUEST[`, `action_router`, `->dispatch(`, `register_rest_route` in loops) and read it fully; do not rely on this map.")
    json.dump({
        "root": idx.root, "backend": idx.backend, "files_parsed": len(idx.files),
        "skipped": idx.skipped, "entry_points_total": total, "entry_points_shown": len(entries),
        "truncated": len(entries) < total, "notes": notes, "entry_points": entries,
    }, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
