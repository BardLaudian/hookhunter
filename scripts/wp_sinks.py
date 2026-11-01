#!/usr/bin/env python3
"""Sink inventory for a WordPress plugin or theme, as JSON.

Usage: wp_sinks.py <plugin-dir> [--class xss,sqli] [--risk unguarded,guarded,constant]
                   [--backend auto|treesitter|regex]

Every dangerous call is listed with its enclosing function, the guards found *inside its
arguments*, and sanitisers / checks found elsewhere in the same function.

risk:
  unguarded - a variable or user-influenced value reaches the sink and nothing in the
              arguments (or, for rules that depend on a prior check, the function) neutralises it
  guarded   - an escaper / prepare() / validator / capability check accounts for it
  constant  - no variable reaches the sink (hidden unless --risk constant). For the dispatch rules
              (callee, class or callable chosen by a variable) it means no request-derived value
              was found in the function: see "request taint" below.

Request taint (dispatch rules only): a value counts as request-derived if it contains a
superglobal, a REST request accessor, php://input or a stored-option read, or a variable assigned
from such an expression earlier in the same function. A value read out of a server-side array
(`$handlers[ $_POST['op'] ]`) is not tainted: the key is chosen, the value is not. This is a
heuristic over one function; it does not follow parameters, properties or other functions.
A "guarded" sink is a hint, not proof: check the guard fits the sink's context.
Static analysis only; nothing is executed or fetched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _php import DYNAMIC, NEW_DYNAMIC, SUPERGLOBALS_RE, Call, Func, Index, build_index  # noqa: E402

VAR_RE = re.compile(r"(?<![\\\w])\$[A-Za-z_]\w*")
GETTER_RE = re.compile(r"\b(?:get_option|get_post_meta|get_user_meta|get_term_meta|get_transient|get_site_option|get_query_var|get_the_title|get_comment_text)\s*\(")
# Vocabulary reported as "sanitizers_in_function" so the model sees nearby checks.
NEARBY_RE = re.compile(
    r"\b(?:esc_\w+|sanitize_\w+|wp_kses\w*|absint|intval|floatval|escapeshellarg|escapeshellcmd|basename|"
    r"wp_basename|realpath|validate_file|wp_validate_redirect|wp_http_validate_url|check_ajax_referer|"
    r"check_admin_referer|wp_verify_nonce|current_user_can|user_can|is_super_admin|in_array|"
    r"array_key_exists|wp_check_filetype\w*|htmlspecialchars|htmlentities|prepare|wp_unslash)\b(?=\s*\()")

XSS_GUARDS = (r"esc_\w+|wp_kses\w*|absint|intval|floatval|htmlspecialchars|htmlentities|json_encode|"
              r"wp_json_encode|sanitize_html_class|sanitize_key|number_format")
FILE_GUARDS = r"basename|wp_basename|realpath|sanitize_file_name|validate_file|absint|intval"
FILE_FUNC_GUARD = (r"\b(?:wp_check_filetype\w*|validate_file|realpath|sanitize_file_name|basename|wp_basename|"
                   r"in_array|array_key_exists)\s*\(")
CAP_FUNC_GUARD = r"\b(?:current_user_can|user_can|is_super_admin)\s*\("
SHELL_GUARDS = r"escapeshellarg|escapeshellcmd"
SQL_GUARDS = r"esc_sql|absint|intval|floatval|prepare|esc_like"


@dataclass(frozen=True)
class Rule:
    sink: str
    classes: tuple[str, ...]
    names: tuple[str, ...]
    kinds: tuple[str, ...] = ("func",)
    recv: str = ""  # regex on the receiver (method/static rules)
    arg_idx: int | None = None  # inspect only this argument (None = all)
    arg_match: tuple[int, str] | None = None  # rule applies only if this argument matches
    max_args: int | None = None
    arg_guards: str = ""  # call names that neutralise a value wrapped in them
    func_guard: str = ""  # regex over the enclosing function that neutralises the sink
    args_safe: str = ""  # regex over the whole argument text that makes the call safe
    risky_if: str = ""  # regex over the arguments: without it the call is safe by default
    needs_var: bool = True
    taint_only: bool = False  # flag only when the inspected value is request-derived (see "request taint")
    always_guarded: bool = False
    getters: bool = False  # treat get_option()-style reads as user-influenced values
    custom: str = ""
    hint: str = ""


def _r(sink: str, classes: str, names: str, **kw: Any) -> Rule:
    return Rule(sink, tuple(classes.split(",")), tuple(names.split(",")), **kw)


RULES: tuple[Rule, ...] = (
    _r("echo", "xss", "echo,print,printf,vprintf,_e,wp_die,die,exit", kinds=("construct", "func"),
       arg_guards=XSS_GUARDS, getters=True, hint="output; escape late with the function that fits the context"),
    _r("wpdb-query", "sqli", "query,get_results,get_row,get_var,get_col", kinds=("method",), recv=r"wpdb|\bdb\b",
       arg_idx=0, arg_guards=SQL_GUARDS, custom="query", hint="build the query with $wpdb->prepare()"),
    _r("wpdb-prepare", "sqli", "prepare", kinds=("method",), recv=r"wpdb|\bdb\b", custom="prepare",
       hint="a variable inside the query string defeats prepare(); values belong in placeholders"),
    _r("raw-sql", "sqli", "mysqli_query,mysql_query,pg_query", arg_guards="esc_sql|mysqli_real_escape_string|absint|intval"),
    _r("include", "file-inclusion", "include,include_once,require,require_once", kinds=("construct",),
       arg_guards=FILE_GUARDS, func_guard=FILE_FUNC_GUARD, hint="LFI/RFI: user-influenced path"),
    _r("file-op", "file-ops",
       "move_uploaded_file,copy,rename,file_put_contents,fopen,unlink,rmdir,mkdir,touch,readfile,file,fpassthru,"
       "wp_delete_file,wp_handle_upload,unzip_file",
       arg_guards=FILE_GUARDS, func_guard=FILE_FUNC_GUARD, hint="path traversal / arbitrary file write, read or delete / upload"),
    _r("file-read", "file-ops,ssrf", "file_get_contents", arg_guards=FILE_GUARDS,
       func_guard=FILE_FUNC_GUARD + "|" + r"\bwp_http_validate_url\s*\(", hint="local file read or SSRF with a URL"),
    _r("unserialize", "object-injection", "unserialize,maybe_unserialize", args_safe=r"allowed_classes['\"]?\s*=>\s*(?:false|\[|array)",
       hint="PHP object injection; prefer json_decode"),
    _r("http-request", "ssrf", "wp_remote_get,wp_remote_post,wp_remote_request,wp_remote_head,get_headers,fsockopen",
       arg_guards="wp_http_validate_url", func_guard=r"\b(?:wp_http_validate_url|in_array)\s*\(",
       hint="SSRF; wp_safe_remote_* or wp_http_validate_url() reject internal hosts"),
    _r("safe-http-request", "ssrf", "wp_safe_remote_get,wp_safe_remote_post,wp_safe_remote_request,wp_safe_remote_head",
       always_guarded=True, hint="wp_safe_remote_* validates the host (still check redirects/ports)"),
    _r("curl-url", "ssrf", "curl_setopt", arg_match=(1, r"CURLOPT_URL"), arg_idx=2, arg_guards="wp_http_validate_url",
       func_guard=r"\b(?:wp_http_validate_url|in_array)\s*\(", hint="SSRF via cURL"),
    _r("redirect", "open-redirect", "wp_redirect", arg_guards=r"wp_validate_redirect|home_url|admin_url|site_url|get_permalink|wp_get_referer",
       func_guard=r"\b(?:wp_validate_redirect|in_array)\s*\(", hint="open redirect; use wp_safe_redirect()"),
    _r("header-location", "open-redirect", "header", arg_match=(0, r"""(?i)^['"]?\s*location"""),
       arg_guards=r"wp_validate_redirect|home_url|admin_url|site_url", func_guard=r"\b(?:wp_validate_redirect|in_array)\s*\(",
       hint="open redirect via Location header"),
    _r("safe-redirect", "open-redirect", "wp_safe_redirect", always_guarded=True, hint="wp_safe_redirect() restricts the host"),
    _r("user-write", "privesc", "wp_update_user,wp_insert_user,update_user_meta,add_user_meta",
       arg_guards="absint|intval", func_guard=CAP_FUNC_GUARD, hint="needs a capability check and a role allow-list"),
    _r("account-control", "privesc",
       "wp_set_current_user,wp_set_auth_cookie,wp_set_password,reset_password,wp_signon,wp_create_user,add_user_to_blog,"
       "add_existing_user_to_blog,remove_user_from_blog,grant_super_admin,revoke_super_admin",
       func_guard=CAP_FUNC_GUARD, hint="logs in, creates, re-passwords or promotes an account; casting the id does not authorise the caller"),
    _r("privileged-option", "privesc,authz", "update_option,add_option,update_site_option", needs_var=False, func_guard=CAP_FUNC_GUARD,
       arg_match=(0, r"""(?i)^['"](?:default_role|users_can_register|admin_email|siteurl|home|active_plugins|template|stylesheet)['"]$|user_roles['"]?\s*$"""),
       hint="option that controls who can register, what roles can do, or which code loads"),
    _r("option-name", "privesc,authz", "update_option,add_option,update_site_option", arg_idx=0, func_guard=CAP_FUNC_GUARD,
       hint="the request chooses which option is written (default_role, user_roles and similar are options)"),
    _r("role-change", "privesc", "set_role,add_role,add_cap,remove_cap", kinds=("method", "func"), func_guard=CAP_FUNC_GUARD,
       hint="role/capability change"),
    _r("option-write", "authz,privesc", "update_option,add_option,delete_option,update_site_option", arg_guards="absint|intval",
       func_guard=CAP_FUNC_GUARD, hint="state change; who may call this? (sanitising the value does not fix authorisation)"),
    _r("content-write", "authz", "wp_insert_post,wp_update_post,wp_delete_post,wp_delete_user,wp_delete_attachment",
       arg_guards="absint|intval", func_guard=CAP_FUNC_GUARD, hint="state change; who may call this?"),
    _r("exec", "rce", "eval,system,exec,passthru,shell_exec,proc_open,popen,pcntl_exec,assert,create_function",
       arg_guards=SHELL_GUARDS, hint="command / code execution"),
    _r("dynamic-call", "rce", "call_user_func,call_user_func_array,extract", func_guard=r"\b(?:in_array|array_key_exists)\s*\(",
       hint="user-chosen callable / variable overwrite"),
    _r("debug-output", "info-disclosure", "phpinfo,var_dump,debug_print_backtrace,debug_zval_dump", needs_var=False,
       func_guard=CAP_FUNC_GUARD, hint="debug information"),
    _r("print_r", "info-disclosure", "print_r,var_export", max_args=1, needs_var=False, func_guard=CAP_FUNC_GUARD,
       hint="debug information"),
    _r("user-data", "info-disclosure", "get_users,get_userdata,get_user_by,get_user_meta", needs_var=False,
       func_guard=CAP_FUNC_GUARD, hint="who may read this user data? (exposure depends on where the result goes)"),
    _r("url-fetch", "ssrf", "curl_init,download_url,media_sideload_image,fetch_feed,wp_oembed_get,wp_remote_fopen", arg_idx=0,
       arg_guards="wp_http_validate_url", func_guard=r"\b(?:wp_http_validate_url|in_array)\s*\(", hint="fetches the URL given as first argument; see the http-request rules"),
    _r("soap-client", "ssrf", "soapclient", kinds=("new",), arg_idx=0, arg_guards="wp_http_validate_url",
       func_guard=r"\b(?:wp_http_validate_url|in_array)\s*\(", hint="fetches the WSDL URL"),
    _r("dynamic-callee", "rce", DYNAMIC, kinds=("dynamic",), taint_only=True, needs_var=False, func_guard=r"\b(?:in_array|array_key_exists)\s*\(",
       hint="function or method chosen by the request: call from a fixed map keyed by a validated string"),
    _r("dynamic-class", "rce", NEW_DYNAMIC, kinds=("new",), taint_only=True, needs_var=False, func_guard=r"\b(?:in_array|array_key_exists)\s*\(",
       hint="class chosen by the request"),
    _r("callable-param", "rce", "array_map,register_shutdown_function,spl_autoload_register", arg_idx=0, taint_only=True, needs_var=False,
       func_guard=r"\b(?:in_array|array_key_exists)\s*\(", hint="callable chosen by the request runs on the data"),
    _r("callable-param", "rce", "array_filter,array_walk,array_walk_recursive,array_reduce,usort,uasort,uksort,preg_replace_callback,add_action,add_filter",
       arg_idx=1, taint_only=True, needs_var=False, func_guard=r"\b(?:in_array|array_key_exists)\s*\(", hint="callable chosen by the request runs on the data"),
    _r("hook-dispatch", "rce", "do_action,apply_filters,do_action_ref_array,apply_filters_ref_array,do_shortcode", arg_idx=0, taint_only=True,
       needs_var=False, func_guard=r"\b(?:in_array|array_key_exists)\s*\(",
       hint="runs every callback registered on a request-chosen hook name, or every shortcode found in request content"),
    _r("parse-str", "rce", "parse_str", max_args=1, hint="without a result array it creates variables named by the request (removed in PHP 8)"),
    _r("mail-params", "rce", "mail", arg_idx=4, arg_guards=SHELL_GUARDS, hint="fifth argument goes to the mail program; escapeshellcmd inside mail() still allows extra options"),
    _r("xml-load", "xxe", "simplexml_load_string,simplexml_load_file,loadxml", kinds=("func", "method"),
       risky_if=r"LIBXML_(?:NOENT|DTDLOAD|DTDATTR)", hint="XXE only when LIBXML_NOENT/DTDLOAD are set (or PHP < 8 without libxml_disable_entity_loader)"),
)

_BY_NAME: dict[str, list[Rule]] = {}
for _rule in RULES:
    for _n in _rule.names:
        _BY_NAME.setdefault(_n, []).append(_rule)


REQUEST_SOURCE_RE = re.compile(
    SUPERGLOBALS_RE.pattern
    + r"|->get_(?:param|params|json_params|body|body_params|query_params|url_params|file_params|header|headers)\s*\(|php://input")
_ASSIGN_RE = re.compile(r"(\$[A-Za-z_]\w*)\s*(?:\.|\?\?|\+|-|\*)?=(?![=>])\s*(.+?)\s*;", re.S)
_FOREACH_RE = re.compile(r"foreach\s*\(\s*(.+?)\s+as\s+(?:(\$[A-Za-z_]\w*)\s*=>\s*)?(\$[A-Za-z_]\w*)", re.S)
_LOOKUP_BASE_RE = re.compile(r"\s*(\$[A-Za-z_]\w*(?:->\w+)*)\s*\[")


def _lookup_parts(expr: str) -> tuple[str, str] | None:
    """For `$base[ ... ] ?? rest` return (base, rest); None if the expression is not an array lookup."""
    m = _LOOKUP_BASE_RE.match(expr)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(expr) and depth:
        depth += {"[": 1, "]": -1}.get(expr[i], 0)
        i += 1
    if depth:
        return None
    rest = expr[i:].strip()
    if rest and not rest.startswith("??"):
        return None
    return m.group(1), rest[2:].strip()


def _is_tainted(expr: str, tainted: frozenset[str]) -> bool:
    lookup = _lookup_parts(expr)
    if lookup and not REQUEST_SOURCE_RE.match(lookup[0]):
        base, rest = lookup
        return base in tainted or (bool(rest) and _is_tainted(rest, tainted))
    return bool(REQUEST_SOURCE_RE.search(expr) or GETTER_RE.search(expr) or any(v in tainted for v in VAR_RE.findall(expr)))


@lru_cache(maxsize=1024)
def tainted_vars(body: str) -> frozenset[str]:
    """Variables assigned, directly or through other variables, from request-derived expressions in this function."""
    assigns = [(m.group(1), m.group(2)) for m in _ASSIGN_RE.finditer(body)]
    for m in _FOREACH_RE.finditer(body):
        assigns += [(v, m.group(1)) for v in (m.group(2), m.group(3)) if v]
    tainted: frozenset[str] = frozenset()
    while True:
        grown = tainted | {var for var, rhs in assigns if var not in tainted and _is_tainted(rhs, tainted)}
        if grown == tainted:
            return tainted
        tainted = grown


def _blank_single_quoted(text: str) -> str:
    # Keep double-quoted strings whole (their `'$x'` still interpolates); blank single-quoted ones.
    return re.sub(r'("(?:\\.|[^"\\])*")|\'(?:\\.|[^\'\\])*\'', lambda m: m.group(1) or "''", text)


def _strip_calls(text: str, names: str) -> str:
    """Remove ``name( ... )`` calls (balanced parentheses) for the given alternation of names."""
    pat = re.compile(rf"(?:\$\w+(?:->\w+)*(?:->|::))?(?<![\w$])(?:{names})\s*\(")
    while True:
        m = pat.search(text)
        if not m:
            return text
        i = m.end()
        depth = 1
        quote = ""
        while i < len(text) and depth:
            ch = text[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        text = text[: m.start()] + " " + text[i:]


def remaining_vars(arg: str, guards: str, getters: bool = False) -> list[str]:
    t = _blank_single_quoted(arg)
    if guards:
        t = _strip_calls(t, guards)
    t = re.sub(r"\((?:int|integer|float|double|bool|boolean)\)\s*\$\w+(?:\[[^\]]*\])*", " ", t)
    t = re.sub(r"\$wpdb->\w+", " ", t)
    t = t.replace("\\$", " ")
    found = VAR_RE.findall(t)
    if getters:
        found += [m.group().rstrip("( ") + "()" for m in GETTER_RE.finditer(t)]
    return found


def _has_var(arg: str) -> bool:
    return bool(VAR_RE.search(_blank_single_quoted(arg).replace("\\$", " ")))


def _assess(rule: Rule, call: Call, func: Func | None) -> tuple[str, list[str]]:
    """Return (risk, guard names seen in the arguments)."""
    args = list(call.args)
    target = args if rule.arg_idx is None else args[rule.arg_idx : rule.arg_idx + 1]
    joined = " , ".join(args)
    in_args = sorted({m.group(0).rstrip("( \t") for m in re.finditer(rf"(?:->)?\b(?:{rule.arg_guards})\s*\(", joined)}) if rule.arg_guards else []
    in_args = [g.lstrip("->") for g in in_args]
    if rule.always_guarded:
        return "guarded", in_args
    if rule.taint_only:
        values = [call.recv] if call.kind in ("dynamic",) or call.name == NEW_DYNAMIC else target
        tv = tainted_vars(func.body) if func else frozenset()
        if not any(_is_tainted(v, tv) for v in values):
            return "constant", in_args
        if rule.func_guard and func and re.search(rule.func_guard, func.body):
            return "guarded", in_args
        return "unguarded", in_args
    if rule.custom == "prepare":
        first = args[0] if args else ""
        if re.fullmatch(r"\s*\$\w+\s*", first):
            return "guarded", in_args
        left = remaining_vars(first, "esc_sql|absint|intval|floatval|esc_like")
        return ("unguarded" if left else ("guarded" if _has_var(first) else "constant")), in_args
    if rule.needs_var and not any(_has_var(a) or (rule.getters and GETTER_RE.search(a)) for a in target):
        return "constant", in_args
    if rule.needs_var:
        left = [v for a in target for v in remaining_vars(a, rule.arg_guards, rule.getters)]
        if not left:
            return "guarded", in_args
    if rule.args_safe and re.search(rule.args_safe, joined):
        return "guarded", in_args
    if rule.func_guard and func and re.search(rule.func_guard, func.body):
        return "guarded", in_args
    if rule.risky_if and not re.search(rule.risky_if, joined):
        return "guarded", in_args
    return "unguarded", in_args


def _applies(rule: Rule, call: Call) -> bool:
    if call.kind not in rule.kinds:
        return False
    if rule.recv and not re.search(rule.recv, call.recv):
        return False
    if rule.max_args is not None and len(call.args) > rule.max_args:
        return False
    if rule.arg_match:
        i, rx = rule.arg_match
        if len(call.args) <= i or not re.search(rx, call.args[i]):
            return False
    return True


def scan_sinks(idx: Index) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for call in idx.calls:
        for rule in _BY_NAME.get(call.name, []):
            if not _applies(rule, call):
                continue
            func = idx.func_of(call)
            risk, in_args = _assess(rule, call, func)
            snippet = ", ".join(call.args)
            out.append({
                "file": call.file, "line": call.line, "end_line": call.end_line,
                "function": func.qualname if func else None,
                "sink": rule.sink, "call": call.name, "classes": list(rule.classes), "risk": risk,
                "args": snippet if len(snippet) <= 160 else snippet[:157] + "...",
                "guards_in_args": in_args,
                "sanitizers_in_function": sorted({m.group() for m in NEARBY_RE.finditer(func.body)}) if func else [],
                "hint": rule.hint,
            })
    out.sort(key=lambda s: (s["file"], s["line"], s["sink"]))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--class", dest="classes", default="", help="comma list, e.g. xss,sqli")
    ap.add_argument("--risk", default="unguarded,guarded", help="comma list of unguarded,guarded,constant")
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    sinks = scan_sinks(idx)
    want_c = {c for c in ns.classes.split(",") if c}
    want_r = {r for r in ns.risk.split(",") if r}
    shown = [s for s in sinks if s["risk"] in want_r and (not want_c or want_c & set(s["classes"]))]
    counts: dict[str, int] = {}
    for s in sinks:
        counts[s["risk"]] = counts.get(s["risk"], 0) + 1
    json.dump({"root": idx.root, "backend": idx.backend, "files_parsed": len(idx.files), "skipped": idx.skipped,
               "totals_by_risk": counts, "sinks_shown": len(shown), "sinks": shown}, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
