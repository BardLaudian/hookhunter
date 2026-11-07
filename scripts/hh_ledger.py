#!/usr/bin/env python3
"""The audit worklist: one row per function to review, a verdict per row, and coverage you can prove.

Usage (all arguments are plain tokens, no quotes needed):
  hh_ledger.py init <plugin-dir> [--required N] [--session S]   build the worklist from map + join + walk (one parse)
  hh_ledger.py next [--n N] [--session S]                         the next rows without a verdict, required first
  hh_ledger.py show <id> [--session S]                            one row in full (entries, all sinks)
  hh_ledger.py mark <id[,id...]> <verdict> [options] [--session S]
        finding     --class=<slug> [--lines=A-B]                  a confirmed vulnerability (goes into the JSON)
        needs-check --class=<slug> --gap=<slug>                   complete except one runtime fact (JSON, confidence medium/low)
        clean       --reason=<slug> --evidence=<file:line>[,...]  refuted, with the line that proves it
        skip        --reason=<slug>                               not reviewed (counts against coverage)
  hh_ledger.py status [--session S]                               coverage, findings, what blocks the final answer
  hh_ledger.py abandon --reason=<slug> [--session S]              stop the Stop-hook gate (say why in your answer)

Why it exists. Measured runs failed in the same three ways: the agent stopped after a few rows although budget was
left; it dropped candidates as "admin only" or "sanitised" without opening the line that would prove it; and it saw
the right row among many and moved on. The ledger turns those rules into checks:
  * every row gets a verdict, and the Stop hook will not let the run end while a *required* row has none;
  * `clean` needs evidence: a file:line that exists and holds a guard of the kind the reason claims
    (current_user_can for cap-check, check_ajax_referer for nonce, add_action for not-reachable, prepare for prepared...);
    `is_admin()` is never accepted as authorization;
  * when the Read tracker hook is active, `clean` is refused for a function you never opened.

Rows. A row is a function: the handler of an entry point (authorization and CSRF are judged there) or the function
that holds a dangerous call (wp_join candidates, wp_walk rows, unreached unguarded sinks). Unresolved registrations
become rows too. Rows are ranked: unauthenticated or unconfirmed tier first, request-tainted unguarded sinks first,
high-impact classes first. The first N (default 15) are required; after them the agent follows its own judgment.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import build_index  # noqa: E402
from _state import find_ledger, load, save, state_dir  # noqa: E402
from wp_join import IMPACT, _func_at, build_join  # noqa: E402
from wp_walk import WALK_TYPES, build_walk  # noqa: E402

BENCH_CLASSES = ["stored-xss", "reflected-xss", "dom-xss", "sqli", "missing-authz", "csrf", "path-traversal", "file-delete", "file-upload",
                 "file-inclusion", "object-injection", "ssrf", "open-redirect", "privesc", "rce", "info-disclosure", "xxe"]
CLASS_FILE = {"rce": "rce", "object-injection": "object-injection", "file-ops": "file-ops", "file-inclusion": "file-ops", "path-traversal": "file-ops",
              "sqli": "sqli", "xxe": "xxe", "ssrf": "ssrf", "privesc": "privesc", "authz": "authz", "xss": "xss", "open-redirect": "open-redirect",
              "info-disclosure": "info-disclosure", "csrf": "csrf"}
TIER_SCORE = {"unauth": 0, "subscriber": 1, "author+": 2, "admin": 3, "system": 4}
# Evidence accepted for each `clean` reason: the cited line must match one of these patterns.
EVIDENCE = {
    "cap-check": r"current_user_can|user_can\s*\(|permission_callback|is_super_admin|map_meta_cap|->has_cap\s*\(",
    "nonce": r"check_ajax_referer|wp_verify_nonce|check_admin_referer",
    "nonce-and-cap": r"current_user_can|user_can\s*\(|check_ajax_referer|wp_verify_nonce|check_admin_referer|permission_callback",
    "not-reachable": r"add_action|add_filter|register_rest_route|add_shortcode|add_menu_page|add_submenu_page|add_options_page|wp_ajax_|->add_action\s*\(|function_exists|defined\s*\(|return\b|exit|die\b",
    "sanitized": r"sanitize_|absint|intval|\(int\)|\(bool\)|\(float\)|floatval|preg_match|preg_replace|in_array|array_key_exists|ctype_|is_numeric|filter_var|basename|realpath|validate_file|wp_check_filetype|wp_kses|sanitize_key|=== ?['\"]|switch\s*\(",
    "escaped": r"esc_|wp_kses|htmlspecialchars|htmlentities|wp_json_encode|json_encode|absint|intval|\(int\)",
    "prepared": r"->prepare\s*\(|absint|intval|\(int\)|esc_sql|%d|in_array|array_map\s*\(\s*['\"](?:absint|intval)",
    "constant-input": r".",
    "dead-code": r".",
    "intended-feature": r".",
    "same-privilege": r"current_user_can|user_can\s*\(|unfiltered_html|manage_options|permission_callback",
    "safe-destination": r"wp_safe_redirect|wp_validate_redirect|wp_safe_remote_|wp_http_validate_url|reject_unsafe_urls|home_url|admin_url|site_url",
}
NOT_AUTHZ = re.compile(r"\bis_admin\s*\(|\bis_user_logged_in\s*\(")
SKIP_REASONS = {"budget", "vendor-library", "out-of-scope", "duplicate", "unparseable", "other"}
GAP_REASONS = {"filter", "constant", "server-config", "library-version", "php-version", "other-plugin", "option-value", "role-setup", "other"}


def _sid(ns: argparse.Namespace) -> str | None:
    return getattr(ns, "session", None)


def _ledger_path(ns: argparse.Namespace, must: bool = True) -> Path:
    p = find_ledger(_sid(ns))
    if p is None and must:
        sys.exit("no ledger for this session: run `hh_ledger.py init <plugin-dir> --session <id>` first")
    return p  # type: ignore[return-value]


# --------------------------------------------------------------------------- init


def _tier_of(tier: str, confirmed: bool) -> int:
    t = TIER_SCORE.get(tier, 1)
    return min(t, 1) if not confirmed else t


def build_rows(root: Path, backend: str = "auto") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    idx = build_index(root, backend)
    join = build_join(idx, {"unguarded"}, 3)
    walk = build_walk(idx, {"xss", "sqli", "file-ops", "file-inclusion", "ssrf", "open-redirect", "object-injection", "rce", "xxe", "path-traversal"}, 3)
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def row(file: str, func: str, lines: str) -> dict[str, Any]:
        key = (file, func)
        if key not in rows:
            rows[key] = {"file": file, "function": func, "lines": lines, "tier": "system", "tier_confirmed": True, "best": 9,
                         "entries": [], "_ekeys": set(), "sinks": [], "sources": set(), "tainted": False, "impact": 3}
        return rows[key]

    def lines_of(file: str, line: int) -> tuple[str, str]:
        f = _func_at(idx, file, line)
        return (f.qualname, f"{f.line}-{f.end_line}") if f else ("<file level>", f"{max(1, line - 5)}-{line + 5}")

    def add_entry(r: dict[str, Any], tier: str, confirmed: bool, text: str) -> None:
        s = _tier_of(tier, confirmed)
        if s < r["best"]:
            r["best"], r["tier"], r["tier_confirmed"] = s, tier, confirmed
        m = re.search(r"([\w./-]+\.(?:php|inc|phtml):\d+)", text)
        key = (text.split(":", 1)[0], m.group(1)) if m else (text, "")
        if key not in r["_ekeys"]:
            r["_ekeys"].add(key)
            r["entries"].append(text)

    def add_sink(r: dict[str, Any], s: dict[str, Any], tainted: bool) -> None:
        key = (s["line"], s["sink"])
        if all((x["line"], x["sink"]) != key for x in r["sinks"]):
            r["sinks"].append({"line": s["line"], "sink": s["sink"], "classes": s.get("classes", []), "origin": s.get("origin"),
                               "args": (s.get("args") or "")[:100]})
        r["tainted"] = r["tainted"] or tainted or s.get("origin") in ("request", "stored")
        r["impact"] = min(r["impact"], min((IMPACT.get(c, 3) for c in s.get("classes", [])), default=3))

    for c in join["candidates"]:
        s = c["sink"]
        name, lines = lines_of(s["file"], s["line"])
        r = row(s["file"], name, lines)
        e = c["entry"]
        add_entry(r, c["tier"], c["tier_confirmed"], f"{e['type']}:{e['name'][:60]} @ {e['registered_at']} ({c['tier']}{'' if c['tier_confirmed'] else ', unconfirmed'})")
        add_sink(r, s, bool(s.get("request_tainted")))
        r["sources"].add("join")
    for w in walk["functions"]:
        r = row(w["file"], w["function"], w["lines"])
        if not w["reached_by"]:
            add_entry(r, "subscriber", False, "not reached by any mapped entry: find who calls it (router, template, variable hook)")
        for t in w["reached_by"]:
            m = re.search(r"tier (\S+)", t)
            add_entry(r, m.group(1) if m else "subscriber", "unconfirmed" not in t, t)
        for s in w["sinks"]:
            add_sink(r, s, True)
        r["sources"].add("walk")
    # Handlers of request entry points: authorization / CSRF are judged in the handler even without a sink.
    for ck in walk["checklist"]:
        if not ck["handler_resolved"]:
            continue
        typ = ck["entry"].split(":", 1)[0]
        if typ not in WALK_TYPES:
            continue
        reg_file, reg_line = ck["registered_at"].rsplit(":", 1)
        handler = str(ck.get("handler") or "")
        cand = [f for f in idx.by_name(handler.split("::")[-1].split("->")[-1].strip("'\" ")) if handler] if handler else []
        if not cand:
            continue
        f = sorted(cand, key=lambda x: (x.file != reg_file, abs(x.line - int(reg_line))))[0]
        r = row(f.file, f.qualname, f"{f.line}-{f.end_line}")
        add_entry(r, ck["tier"], ck["tier_confirmed"], f"{ck['entry']} @ {ck['registered_at']} ({ck['tier']}{'' if ck['tier_confirmed'] else ', unconfirmed'})")
        r["sources"].add("handler")
    for u in join["unresolved_entries"]:
        file, line = u["registered_at"].rsplit(":", 1)
        r = row(file, f"<unresolved {u['type']} registration>", f"{max(1, int(line) - 8)}-{int(line) + 8}")
        add_entry(r, u.get("tier_if_hook_is_as_named", "subscriber"), False, f"{u['type']}:{u['name'][:60]} handler {u['handler'][:60]} - resolve it by hand")
        r["sources"].add("unresolved")
    for s in join["unreached_sinks"]:
        file, line = s["at"].rsplit(":", 1)
        name, lines = lines_of(file, int(line))
        r = row(file, name, lines)
        if not r["entries"]:
            add_entry(r, "subscriber", False, "no mapped entry reaches it: find the caller (Grep the function name)")
        add_sink(r, {"line": int(line), "sink": s["sink"], "classes": s["classes"], "origin": s.get("origin")}, bool(s.get("request_tainted")))
        r["sources"].add("unreached")

    # Helpers that receive outside data through a parameter (templates, query builders, routers) were where measured misses sat:
    # a sink whose line uses a parameter, or a variable assigned from one, counts as fed from outside.
    def param_fed(r: dict[str, Any]) -> bool:
        if not r["sinks"] or r["function"].startswith("<"):
            return False
        a, _, b = r["lines"].partition("-")
        f = _func_at(idx, r["file"], int(a))
        if f is None:
            return False
        sig = f.body.split("{", 1)[0]
        params = set(re.findall(r"\$\w+", sig))
        if not params:
            return False
        body_lines = f.body.splitlines()
        for _ in range(2):  # two hops of $x = ...$param...
            for ln in body_lines:
                m = re.match(r"\s*(\$\w+)\s*=[^=>]", ln)
                if m and any(p in ln[m.end():] for p in params):
                    params.add(m.group(1))
        for sk in r["sinks"]:
            if IMPACT.get(next(iter(sk["classes"]), ""), 3) > 1 and sk["sink"] not in ("sql-build", "include", "html-build"):
                continue
            i = sk["line"] - f.line
            if 0 <= i < len(body_lines) and any(re.search(re.escape(p) + r"\b", body_lines[i]) for p in params):
                return True
        return False

    out = []
    for r in rows.values():
        r["param_fed"] = param_fed(r)
        has_sink = bool(r["sinks"])
        # handler-only rows matter when they are reachable by low tiers; unreached sinks without taint are last
        r["score"] = [r["best"], 0 if r["tainted"] or r["param_fed"] else 1, 0 if has_sink else 1, r["impact"], -len(r["sinks"])]
        r["sources"] = sorted(r["sources"])
        r["sinks"].sort(key=lambda x: x["line"])
        r["entries"] = r["entries"][:4]
        del r["best"], r["_ekeys"]
        out.append(r)
    out.sort(key=lambda r: (r["score"], r["file"], r["function"]))
    meta = {"files_parsed": len(idx.files), "skipped": idx.skipped[:30], "backend": idx.backend, "entries": join["entries"],
            "join_candidates": len(join["candidates"]), "walk_functions": len(walk["functions"]), "unresolved": len(join["unresolved_entries"])}
    return out, meta


def pick_required(rows: list[dict[str, Any]], n: int) -> None:
    """Required rows come from three quotas so that one noisy source cannot fill the list:
    half from the global ranking, a third from functions no mapped entry reaches (helpers, templates, routers: where
    measured misses sat), the rest from request handlers without a sink (authorization / CSRF)."""
    chosen: list[str] = []

    def take(cands: list[dict[str, Any]], k: int) -> None:
        for r in cands:
            if k <= 0 or len(chosen) >= n:
                return
            if r["id"] not in chosen:
                chosen.append(r["id"])
                k -= 1

    take(rows, n // 2)
    unreached = [r for r in rows if "unreached" in r["sources"] and "join" not in r["sources"]]
    unreached.sort(key=lambda r: (not (r["tainted"] or r.get("param_fed")), r["impact"], r["score"]))
    take(unreached, n // 3)
    take([r for r in rows if r["sources"] == ["handler"]], n - len(chosen))
    take(rows, n - len(chosen))
    req = set(chosen)
    for r in rows:
        r["required"] = r["id"] in req


def cmd_init(ns: argparse.Namespace) -> int:
    root = Path(ns.root).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    rows, meta = build_rows(root, ns.backend)
    for n, r in enumerate(rows, 1):
        r["id"] = f"U{n}"
        r["verdict"] = None
    pick_required(rows, ns.required)
    d = state_dir(_sid(ns))
    if d is None:
        print("error: no writable state directory (set HH_STATE_DIR)", file=sys.stderr)
        return 2
    led = {"root": str(root), "session": _sid(ns), "required": ns.required, "meta": meta, "rows": rows, "abandoned": None, "stop_blocks": 0}
    save(d / "ledger.json", led)
    print(json.dumps({"ledger": str(d / "ledger.json"), "rows": len(rows), "required": min(ns.required, len(rows)), **meta}, indent=1))
    print("\nNext rows (open each, then mark it):")
    _print_next(led, 8)
    return 0


# --------------------------------------------------------------------------- next / show


def _class_files(r: dict[str, Any]) -> list[str]:
    cls = sorted({CLASS_FILE.get(c, c) for s in r["sinks"] for c in s["classes"] if CLASS_FILE.get(c, c) in CLASS_FILE.values()})
    if not r["sinks"] or any("handler" == s for s in r["sources"]):
        cls = sorted(set(cls) | {"authz", "csrf"})
    return [f"reference/classes/{c}.md" for c in cls]


def _brief(r: dict[str, Any], full: bool = False) -> dict[str, Any]:
    a, _, b = r["lines"].partition("-")
    a_i, b_i = int(a), int(b or a)
    out = {"id": r["id"], "required": r["required"], "tier": r["tier"] + ("" if r["tier_confirmed"] else " (unconfirmed: treat as lower)"),
           "function": r["function"], "at": f"{r['file']}:{r['lines']}",
           "open": f"Read {r['file']} offset={a_i} limit={min(b_i - a_i + 1, 400)}",
           "entries": r["entries"] if full else r["entries"][:2],
           "sinks": r["sinks"] if full else [f"{s['line']} {s['sink']} {','.join(s['classes'])}{' origin=' + s['origin'] if s.get('origin') else ''}" for s in r["sinks"][:5]],
           "why": "+".join(r["sources"]), "consult": _class_files(r)}
    if len(r["sinks"]) > 5 and not full:
        out["sinks"].append(f"... {len(r['sinks']) - 5} more (show {r['id']})")
    if r.get("verdict"):
        out["verdict"] = r["verdict"]
    return out


def _pending(led: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [r for r in led["rows"] if not r.get("verdict")]
    return sorted(rows, key=lambda r: (not r["required"], r["score"]))


def _print_next(led: dict[str, Any], n: int) -> None:
    rows = _pending(led)
    for r in rows[:n]:
        print(json.dumps(_brief(r), ensure_ascii=False))
    req_left = sum(1 for r in rows if r["required"])
    print(f"\n{req_left} required rows without verdict, {len(rows) - req_left} optional. "
          f"After reading a row: hh_ledger.py mark <id> finding|needs-check|clean|skip ... (see --help).")


def cmd_next(ns: argparse.Namespace) -> int:
    led = load(_ledger_path(ns))
    _print_next(led, ns.n)
    return 0


def cmd_show(ns: argparse.Namespace) -> int:
    led = load(_ledger_path(ns))
    for r in led["rows"]:
        if r["id"] == ns.id:
            print(json.dumps(_brief(r, full=True), indent=1, ensure_ascii=False))
            return 0
    print(f"no row {ns.id}", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- mark


def _reads(ledger: Path) -> list[dict[str, Any]] | None:
    p = ledger.parent / "reads.jsonl"
    if not p.is_file():
        return None
    out = []
    for line in p.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def _was_read(reads: list[dict[str, Any]], root: str, r: dict[str, Any]) -> bool:
    a, _, b = r["lines"].partition("-")
    a_i, b_i = int(a), int(b or a)
    target = str(Path(root) / r["file"])
    for x in reads:
        fp = str(x.get("file_path") or "")
        if not (fp == target or fp.replace("\\", "/").endswith("/" + r["file"])):
            continue
        off = int(x.get("offset") or 1)
        lim = int(x.get("limit") or 2000)
        if off <= b_i and off + lim - 1 >= a_i:
            return True
    return False


def _check_evidence(root: str, reason: str, evidence: list[str]) -> list[str]:
    errs = []
    pat = re.compile(EVIDENCE[reason])
    ok_any = False
    for ev in evidence:
        m = re.fullmatch(r"(.+):(\d+)", ev)
        if not m:
            errs.append(f"evidence {ev!r} is not file:line")
            continue
        path = Path(root) / m.group(1)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            errs.append(f"evidence {ev!r}: file not found under the plugin root")
            continue
        ln = int(m.group(2))
        if not 1 <= ln <= len(lines):
            errs.append(f"evidence {ev!r}: line out of range (file has {len(lines)} lines)")
            continue
        text = lines[ln - 1]
        if reason in ("cap-check", "nonce-and-cap", "same-privilege") and NOT_AUTHZ.search(text) and not pat.search(text):
            errs.append(f"evidence {ev!r} is is_admin()/is_user_logged_in(): that is not authorization (admin-ajax.php sets is_admin() for visitors)")
            continue
        if pat.search(text):
            ok_any = True
        else:
            errs.append(f"evidence {ev!r} holds `{text.strip()[:90]}`, which is not a guard of kind '{reason}'")
    if ok_any:
        return []  # one line that proves the reason is enough; the others may be context
    return errs or ["no evidence line proves the reason"]


def cmd_mark(ns: argparse.Namespace) -> int:
    path = _ledger_path(ns)
    led = load(path)
    ids = [i.strip() for i in ns.ids.split(",") if i.strip()]
    by_id = {r["id"]: r for r in led["rows"]}
    errs: list[str] = []
    v = ns.verdict
    if v in ("finding", "needs-check") and ns.cls not in BENCH_CLASSES:
        errs.append(f"--class must be one of {BENCH_CLASSES}")
    if v == "needs-check" and ns.gap not in GAP_REASONS:
        errs.append(f"--gap must be one of {sorted(GAP_REASONS)}")
    if v == "clean" and ns.reason not in EVIDENCE:
        errs.append(f"--reason must be one of {sorted(EVIDENCE)} (use skip for 'not reviewed')")
    if v == "skip" and ns.reason not in SKIP_REASONS:
        errs.append(f"--reason must be one of {sorted(SKIP_REASONS)}")
    evidence = [e for e in (ns.evidence or "").split(",") if e]
    if v == "clean" and not evidence:
        errs.append("clean needs --evidence=file:line[,file:line]: the registration line and the guard, or the sanitiser line (reference/verification.md 3b)")
    if v == "clean" and evidence and not errs:
        errs += _check_evidence(led["root"], ns.reason, evidence)
    reads = _reads(path)
    for i in ids:
        r = by_id.get(i)
        if r is None:
            errs.append(f"no row {i}")
            continue
        if v == "clean" and reads is not None and not _was_read(reads, led["root"], r):
            errs.append(f"{i}: you never opened {r['file']}:{r['lines']} with Read; open the function before calling it clean")
    if errs:
        print(json.dumps({"accepted": False, "errors": errs}, indent=1))
        return 1
    for i in ids:
        r = by_id[i]
        verdict: dict[str, Any] = {"status": v}
        if v in ("finding", "needs-check"):
            verdict["class"] = ns.cls
            if ns.lines:
                verdict["lines"] = ns.lines
        if v == "needs-check":
            verdict["gap"] = ns.gap
        if v in ("clean", "skip"):
            verdict["reason"] = ns.reason
        if evidence:
            verdict["evidence"] = evidence
        r["verdict"] = verdict
    save(path, led)
    left = sum(1 for r in led["rows"] if r["required"] and not r.get("verdict"))
    print(json.dumps({"accepted": True, "ids": ids, "required_left": left}))
    if v == "finding":
        print("Variants: Grep the same sink, helper and parameter across the plugin (SKILL.md step 4) before moving on.")
    return 0


# --------------------------------------------------------------------------- status / abandon


def summary(led: dict[str, Any]) -> dict[str, Any]:
    rows = led["rows"]
    req = [r for r in rows if r["required"]]
    by = lambda rs, s: sum(1 for r in rs if (r.get("verdict") or {}).get("status") == s)  # noqa: E731
    return {
        "rows": len(rows), "required": len(req),
        "required_done": sum(1 for r in req if r.get("verdict")),
        "findings": [{"id": r["id"], "at": f"{r['file']}:{r['verdict'].get('lines', r['lines'])}", "function": r["function"],
                      "class": r["verdict"]["class"], "status": r["verdict"]["status"], "tier": r["tier"]}
                     for r in rows if (r.get("verdict") or {}).get("status") in ("finding", "needs-check")],
        "clean": by(rows, "clean"), "skipped": by(rows, "skip"), "optional_unreviewed": sum(1 for r in rows if not r["required"] and not r.get("verdict")),
        "abandoned": led.get("abandoned"),
        "coverage_note": (f"reviewed {sum(1 for r in rows if r.get('verdict') and r['verdict']['status'] != 'skip')} of {len(rows)} rows "
                          f"({sum(1 for r in req if r.get('verdict'))}/{len(req)} required); skipped {by(rows, 'skip')}; "
                          f"files parsed {led['meta']['files_parsed']}, skipped dirs {len(led['meta']['skipped'])}"),
    }


def cmd_status(ns: argparse.Namespace) -> int:
    led = load(_ledger_path(ns))
    s = summary(led)
    print(json.dumps(s, indent=1, ensure_ascii=False))
    left = s["required"] - s["required_done"]
    if left and not s["abandoned"]:
        print(f"\n{left} required rows still need a verdict; the Stop hook will block the final answer until they have one.")
    return 0


def cmd_abandon(ns: argparse.Namespace) -> int:
    path = _ledger_path(ns)
    led = load(path)
    led["abandoned"] = ns.reason
    save(path, led)
    print(json.dumps({"abandoned": ns.reason, "note": "say in your answer that coverage is partial and why"}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("root")
    p.add_argument("--required", type=int, default=15)
    p.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    p.add_argument("--session", default=argparse.SUPPRESS)
    p = sub.add_parser("next")
    p.add_argument("--n", type=int, default=8)
    p.add_argument("--session", default=argparse.SUPPRESS)
    p = sub.add_parser("show")
    p.add_argument("id")
    p.add_argument("--session", default=argparse.SUPPRESS)
    p = sub.add_parser("mark")
    p.add_argument("ids")
    p.add_argument("verdict", choices=["finding", "needs-check", "clean", "skip"])
    p.add_argument("--class", dest="cls")
    p.add_argument("--lines")
    p.add_argument("--gap")
    p.add_argument("--reason")
    p.add_argument("--evidence")
    p.add_argument("--session", default=argparse.SUPPRESS)
    p = sub.add_parser("status")
    p.add_argument("--session", default=argparse.SUPPRESS)
    p = sub.add_parser("abandon")
    p.add_argument("--reason", required=True)
    p.add_argument("--session", default=argparse.SUPPRESS)
    ns = ap.parse_args(argv)
    return {"init": cmd_init, "next": cmd_next, "show": cmd_show, "mark": cmd_mark, "status": cmd_status, "abandon": cmd_abandon}[ns.cmd](ns)


if __name__ == "__main__":
    raise SystemExit(main())
