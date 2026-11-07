#!/usr/bin/env python3
"""Sink inventory for a WordPress plugin or theme, as JSON.

Usage: wp_sinks.py <plugin-dir> [--class xss,sqli] [--risk unguarded,guarded,constant]
                   [--backend auto|treesitter|regex]

Every dangerous call is listed with its enclosing function, the guards found *inside its
arguments*, and sanitisers / checks found elsewhere in the same function.

risk:
  unguarded - a variable or user-influenced value reaches the sink and nothing in the
              arguments (or, for rules that depend on a prior check, the function) neutralises it
  guarded   - an escaper / prepare() / validator / capability check accounts for it (a prepare() whose format string
              interpolates a variable outside placeholders does not: it stays unguarded; table names and %s lists are ignored)
  constant  - no variable reaches the sink (hidden unless --risk constant). For the dispatch rules
              (callee, class or callable chosen by a variable) it means no request-derived value
              was found in the function: see "request taint" below.

Request taint (dispatch rules only): a value counts as request-derived if it contains a
superglobal, a REST request accessor, php://input or a stored-option read, or a variable assigned
from such an expression earlier in the same function. A value read out of a server-side array
(`$handlers[ $_POST['op'] ]`) is not tainted: the key is chosen, the value is not. This is a
heuristic over one function; it does not follow parameters, properties or other functions.
Function-level data guards (basename, in_array, validate_file, wp_validate_redirect, ...) count only if they act on
the value reaching the sink: assigned back to it, or in an if/while condition whose block holds the sink or ends the
request. The accepted guard is reported as `function_guard_accepted`. Capability checks count anywhere in the function.
`weak_gates_in_function` lists is_admin / wp_doing_ajax / is_user_logged_in, which never count as a guard.
Beyond single calls it reports `html-build` (an HTML string assembled from a query result, option, meta or request value with no
escaper; `origin` says which), `unchecked-guard-result` (the result of a check_/verify_ helper that can return an error object is assigned
and never tested) `meta-key` (user meta key is a variable), `sql-build` (quoted variable in SQL assembled as text), `safety-flag-disabled`
(a $safe/$verify parameter that defaults to true is passed false) and `filetype-override` (filters on the file type check).
`origin` (stored|request) says where a file/include/url/unserialize/redirect value comes from. Filter with --sink.
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

from _php import DYNAMIC, NEW_DYNAMIC, SUPERGLOBALS_RE, Call, Func, Index, build_index, split_args, strip_comments  # noqa: E402
from _wp import literal, parse_callback, resolve  # noqa: E402

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
       arg_guards=FILE_GUARDS, func_guard=FILE_FUNC_GUARD, getters=True,
       hint="LFI/RFI: user-influenced path (an option or meta value counts: who can write it?)"),
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
    _r("meta-key", "privesc", "update_user_meta,add_user_meta", arg_idx=1, arg_match=(1, r"^\s*\$[\w>\[\]'\"$\- ]+\s*$"), func_guard=r"\b(?:in_array|array_key_exists|\w*banned\w*|\w*allow\w*|\w*whitelist\w*)\s*\(",
       hint="the meta KEY is a variable: if it comes from the request, {prefix}capabilities and {prefix}user_level can be named. A denylist is not enough "
            "(case, accents/collation, whitespace, multisite prefix); use an allowlist of keys"),
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
       func_guard=r"\blibxml_disable_entity_loader\s*\(\s*true\s*\)",
       hint="XXE: a request-influenced document is parsed. Entity expansion needs LIBXML_NOENT/DTDLOAD, or an old libxml/PHP < 8 "
            "without libxml_disable_entity_loader(true): treat as needs-dynamic-check unless the runtime is known"),
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


# Wider source vocabulary used only for the `request_tainted` flag (and wp_walk.py): framework getters, 2-argument add_query_arg
# (it reflects the current URL), and the server variables that carry the URL.
_WALK_SRC_RE = re.compile(
    REQUEST_SOURCE_RE.pattern
    + r"|\$_SERVER\s*\[\s*['\"](?:REQUEST_URI|PHP_SELF|QUERY_STRING|HTTP_HOST|HTTP_REFERER|PATH_INFO)['\"]\s*\]"
    + r"|\$(?:this|request|req|params|post|input|wp_query|query|wp)\s*->\s*(?:get|input|param|query|post|get_param|query_vars)\b\s*[\(\[]\s*['\"]\w+['\"]\s*[\)\]]"
    + r"|\$request\s*\[\s*['\"]\w+['\"]\s*\]|\$wp_query\s*->\s*query_vars\s*\["
    + r"|\bget_query_var\s*\(|\bfilter_input\s*\(|\bget_search_query\s*\("
    + r"|\badd_query_arg\s*\(\s*(?:'[^']*'|\"[^\"]*\")\s*,\s*[^,()]+\)(?!\s*,)")


@lru_cache(maxsize=1024)
def _walk_tainted_vars(body: str) -> frozenset[str]:
    assigns = [(m.group(1), m.group(2)) for m in _ASSIGN_RE.finditer(body)]
    for m in _FOREACH_RE.finditer(body):
        assigns += [(v, m.group(1)) for v in (m.group(2), m.group(3)) if v]
    tainted: frozenset[str] = frozenset()
    while True:
        grown = tainted | {var for var, rhs in assigns if var not in tainted and (_WALK_SRC_RE.search(rhs) or any(v in tainted for v in VAR_RE.findall(rhs)))}
        if grown == tainted:
            return tainted
        tainted = grown


def _request_tainted(call: Call, func: Func | None) -> bool:
    """True when an argument of the call is, or is built from, a request-derived value (wider vocabulary than the dispatch rules)."""
    tv = _walk_tainted_vars(func.body) if func else frozenset()
    return any(_WALK_SRC_RE.search(a) or any(v in tv for v in VAR_RE.findall(a)) for a in call.args)


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


_WEAK_GATES_RE = re.compile(r"\b(?:is_admin|wp_doing_ajax|is_user_logged_in)\s*\(")
_EXIT_RE = re.compile(r"\b(?:return|exit|die|wp_die|continue|throw|wp_send_json_error|wp_send_json)\b")
_COND_RE = re.compile(r"\b(?:if|elseif|while)\s*\(")
_ASSIGN_TAIL_RE = re.compile(r"(\$[A-Za-z_]\w*)(?:\[[^\]]*\]|->\w+)*\s*(?:\?\?)?=(?!=)\s*(?:\(\w+\)\s*)?(?:[\w\\\\]+\s*\(\s*)*$")


def _close(text: str, open_idx: int, op: str = "(", cl: str = ")") -> int:
    """Index just after the bracket that closes the one at open_idx (len(text) if unbalanced)."""
    depth, i, quote = 0, open_idx, ""
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == op:
            depth += 1
        elif ch == cl:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _sink_vars(values: list[str]) -> set[str]:
    return set(VAR_RE.findall(_blank_single_quoted(" , ".join(values)).replace("\\$", " ")))


_SAFE_SQL_NAME_RE = re.compile(r"^\$(?:\w*table\w*|tbl\w*|\w*_tbl|placeholders?\w*|in_clause|wpdb)$", re.I)
_SAFE_SQL_RHS_RE = re.compile(r"\$wpdb->|->table_name|\b\w*_(?:TBL|TABLE)\w*\b|array_fill\s*\(|esc_sql|absint|intval|\(int\)")


def _safe_sql_vars(func: Func | None) -> frozenset[str]:
    """Variables that are table names, ``%s`` placeholder lists or already neutralised: interpolating them into a prepare() format is not the bug."""
    if func is None:
        return frozenset()
    safe = set()
    for var, rhs, _off in _assignments(func.body):
        if _SAFE_SQL_NAME_RE.match(var) or _SAFE_SQL_RHS_RE.search(rhs):
            safe.add(var)
    return frozenset(safe)


def _prepare_format_left(fmt: str, func: Func | None) -> list[str]:
    """Variables interpolated into a prepare() format string outside placeholders (a column name, a LIMIT, an ORDER BY...)."""
    t = re.sub(r"\$this->(?:w?pdb|db)->\w+|\$this->\w*(?:table|tbl)\w*", " ", fmt, flags=re.I)
    safe = _safe_sql_vars(func)
    return [v for v in remaining_vars(t, "esc_sql|absint|intval|floatval|esc_like|array_fill|count|sizeof") if v not in safe and not _SAFE_SQL_NAME_RE.match(v)]


def _nested_prepare_left(expr: str, func: Func | None) -> list[str] | None:
    """For an argument like ``$wpdb->prepare( "...", ... )`` return the unsafe interpolated variables of its format; None if there is no prepare call."""
    m = re.search(r"->prepare\s*\(", expr)
    if not m:
        return None
    end = _close(expr, m.end() - 1)
    args = split_args(strip_comments(expr[m.end(): max(m.end(), end - 1)]))
    if not args or re.fullmatch(r"\s*\$\w+\s*", args[0]):  # a bare $query: built elsewhere, same convention as the wpdb-prepare rule
        return []
    return _prepare_format_left(args[0], func)


def _func_guard_hit(rule: Rule, call: Call, func: Func, values: list[str]) -> str | None:
    """Return a description of the function-level guard that really covers this sink, else None.

    A capability guard (current_user_can ...) counts anywhere in the function. A *data* guard
    (basename, in_array, validate_file, wp_validate_redirect ...) counts only if it acts on the
    value that reaches the sink: it is assigned back to a sink variable, or it sits in an
    if/while condition whose block contains the sink or ends the request (return/exit/die/...).
    A guard used inside an echo, header(), log line or an unrelated variable does not count.
    """
    if not rule.func_guard:
        return None
    body = func.body
    if rule.func_guard == CAP_FUNC_GUARD or rule.sink == "xml-load":
        m = re.search(rule.func_guard, body)
        return f"{m.group().rstrip('( ')}() somewhere in the function" if m else None
    svars = _sink_vars(values)
    sink_off = max(call.line - func.line, 0)
    for m in re.finditer(rule.func_guard, body):
        start = m.start()
        stmt = max(body.rfind(c, 0, start) for c in ";{}") + 1
        prefix = body[stmt:start]
        gline = func.line + body.count("\n", 0, start)
        name = m.group().rstrip("( \t")
        am = _ASSIGN_TAIL_RE.search(prefix)
        if am and am.group(1) in svars:
            return f"{name}() assigned back to {am.group(1)} (line {gline})"
        conds = list(_COND_RE.finditer(prefix))
        if conds:
            open_idx = stmt + conds[-1].end() - 1
            cond_end = _close(body, open_idx)
            if cond_end > start:
                args_end = _close(body, m.end() - 1)
                if not (svars & set(VAR_RE.findall(body[m.end():args_end]))):
                    continue
                j = cond_end
                while j < len(body) and body[j].isspace():
                    j += 1
                if j < len(body) and body[j] == "{":
                    blk_end = _close(body, j, "{", "}")
                else:
                    blk_end = body.find(";", j) + 1 or len(body)
                blk = body[j:blk_end]
                b0 = body.count("\n", 0, j)
                b1 = body.count("\n", 0, blk_end)
                if b0 <= sink_off <= b1 or _EXIT_RE.search(blk):
                    return f"{name}() in a condition at line {gline} that wraps the sink or ends the request"
            continue
        if re.search(r"&&|\|\||\?|\band\b|\bor\b", prefix) and not re.match(r"\s*(?:echo|print|header|return)\b", prefix):
            args_end = _close(body, m.end() - 1)
            if svars & set(VAR_RE.findall(body[m.end():args_end])):
                return f"{name}() in a boolean/ternary expression at line {gline}"
    return None


def _assess(rule: Rule, call: Call, func: Func | None) -> tuple[str, list[str], str | None]:
    """Return (risk, guard names seen in the arguments, function-level guard that was accepted)."""
    args = list(call.args)
    target = args if rule.arg_idx is None else args[rule.arg_idx : rule.arg_idx + 1]
    joined = " , ".join(args)
    in_args = sorted({m.group(0).rstrip("( \t") for m in re.finditer(rf"(?:->)?\b(?:{rule.arg_guards})\s*\(", joined)}) if rule.arg_guards else []
    in_args = [g.lstrip("->") for g in in_args]
    if rule.always_guarded:
        return "guarded", in_args, None
    if rule.taint_only:
        values = [call.recv] if call.kind in ("dynamic",) or call.name == NEW_DYNAMIC else target
        tv = tainted_vars(func.body) if func else frozenset()
        if not any(_is_tainted(v, tv) for v in values):
            return "constant", in_args, None
        hit = _func_guard_hit(rule, call, func, values) if func else None
        if hit:
            return "guarded", in_args, hit
        return "unguarded", in_args, None
    if rule.custom == "prepare":
        first = args[0] if args else ""
        if re.fullmatch(r"\s*\$\w+\s*", first):
            return "guarded", in_args, None
        left = _prepare_format_left(first, func)
        return ("unguarded" if left else ("guarded" if _has_var(first) else "constant")), in_args, None
    if rule.needs_var and not any(_has_var(a) or (rule.getters and GETTER_RE.search(a)) for a in target):
        return "constant", in_args, None
    if rule.needs_var:
        left = [v for a in target for v in remaining_vars(a, rule.arg_guards, rule.getters)]
        if rule.sink == "wpdb-query" and not left:
            # prepare() is only a guard when the format string holds no variable outside placeholders
            bad = [v for a in target for v in (_nested_prepare_left(a, func) or [])]
            if bad:
                return "unguarded", in_args + ["prepare(format interpolates %s)" % ", ".join(sorted(set(bad)))], None
        if not left:
            return "guarded", in_args, None
    if rule.args_safe and re.search(rule.args_safe, joined):
        return "guarded", in_args, None
    hit = _func_guard_hit(rule, call, func, target or args) if func else None
    if hit:
        return "guarded", in_args, hit
    if rule.risky_if and not re.search(rule.risky_if, joined):
        return "guarded", in_args, None
    return "unguarded", in_args, None


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


DB_READ_RE = re.compile(r"\b\w*(?:get_results|get_row|get_col|get_var|fetch_assoc|fetch_object|fetch_all|get_posts|get_comments|get_users|get_terms|get_option|get_post_meta|get_user_meta|get_transient)\s*\(|\bdb_get_\w+\s*\(|\$(?:query|sql)\b|\bSELECT\s|->cart_contents|\bWC\(\)->(?:cart|session)|->session->get\(|\$_SESSION|\bwc_get_order_item_meta\s*\(")
_CHECK_NAME_RE = re.compile(r"(?:check|verify|validate|authori[sz]e|permission|can_|require|ensure|assert)", re.I)
_ERR_RETURN_RE = re.compile(r"return\s+(?:new\s+\\?WP_(?:REST_Response|Error)\b|false\b|null\b|array\s*\(\s*['\"]error)", re.I)


def _closure(body: str, seed: "re.Pattern[str]") -> frozenset[str]:
    assigns = [(m.group(1), m.group(2)) for m in _ASSIGN_RE.finditer(body)]
    for m in _FOREACH_RE.finditer(body):
        assigns += [(v, m.group(1)) for v in (m.group(2), m.group(3)) if v]
    out: frozenset[str] = frozenset()
    while True:
        grown = out | {v for v, rhs in assigns if v not in out and (seed.search(rhs) or any(x in out for x in VAR_RE.findall(rhs)))}
        if grown == out:
            return out
        out = grown


_ASSIGN_START_RE = re.compile(r"(\$[A-Za-z_]\w*)\s*(?:\.|\?\?)?=(?![=>])\s*")


def _assignments(body: str):
    """(var, rhs, rhs_offset) for each assignment; the right-hand side ends at the first ';' outside quotes and brackets."""
    for m in _ASSIGN_START_RE.finditer(body):
        i, depth, quote = m.end(), 0, ""
        while i < len(body):
            ch = body[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif ch == ";" and depth == 0:
                break
            i += 1
        yield m.group(1), body[m.end():i], m.end()


def _extra_sinks(idx: Index) -> list[dict[str, Any]]:
    """Patterns that are not a single dangerous call: HTML built from stored data, and a guard's result that nobody tests."""
    out: list[dict[str, Any]] = []

    def rec(f: Func, off: int, sink: str, classes: list[str], call: str, args: str, hint: str, extra: dict[str, Any]) -> None:
        line = f.line + f.body.count("\n", 0, off)
        out.append({
            "file": f.file, "line": line, "end_line": line, "function": f.qualname, "sink": sink, "call": call,
            "classes": classes, "risk": "unguarded", "args": args[:157] + "..." if len(args) > 160 else args,
            "guards_in_args": [], "sanitizers_in_function": sorted({m.group() for m in NEARBY_RE.finditer(f.body)}),
            "function_guard_accepted": None,
            "weak_gates_in_function": sorted({m.group().rstrip("( \t") for m in _WEAK_GATES_RE.finditer(f.body)}),
            "hint": hint, **extra})

    for f in idx.funcs:
        body = f.body
        # 1. HTML string assembled from a stored or request-derived value, escaper missing (printed elsewhere, so no echo sink)
        stored = _closure(body, DB_READ_RE)
        reqt = tainted_vars(body)
        if stored or reqt:
            for var, rhs, off in _assignments(body):
                if not re.search(r"<\s*[A-Za-z/]", rhs):
                    continue
                left = [v for v in remaining_vars(rhs, XSS_GUARDS) if v in stored or v in reqt]
                if left:
                    kind = "stored" if any(v in stored for v in left) else "request"
                    rec(f, off, "html-build", ["xss"], "(assignment)", f"{var} = {rhs.strip()}",
                        f"HTML built from a {kind}-derived value ({', '.join(sorted(set(left)))}) with no escaper; find where {var} is printed "
                        "(echo, return, JSON) and who can write the value", {"origin": kind})
        # 2. result of a check/verify function that returns an error object instead of stopping, assigned and never tested
        for c in idx.calls_in(f):
            if not _CHECK_NAME_RE.search(c.name):
                continue
            callees = [g for g in idx.by_name(c.name) if g is not f]
            if not callees or not any(_ERR_RETURN_RE.search(g.body) for g in callees):
                continue
            rx = re.compile(rf"(\$[A-Za-z_]\w*)\s*=\s*(?:\$this->|self::|static::)?{re.escape(c.name)}\s*\(", re.I)
            for m in rx.finditer(body):
                if f.line + body.count("\n", 0, m.start()) != c.line:
                    continue
                v = re.escape(m.group(1))
                tail = body[m.end():]
                tested = re.search(rf"is_wp_error\s*\(\s*{v}|instanceof\s+\\?\w+|\bif\s*\(\s*!?\s*{v}\b|!\s*{v}\b|{v}\s*(?:===|!==|==|!=)|\bisset\s*\(\s*{v}|\bempty\s*\(\s*{v}", tail)
                if not tested:
                    rec(f, m.start(), "unchecked-guard-result", ["authz", "privesc"], c.name, f"{m.group(1)} = {c.name}(...)",
                        f"{c.name}() can return an error object/false instead of stopping, and {m.group(1)} is never tested before use: "
                        "the check does not enforce (wp-traps.md trap 21)", {})
    return out


_SQL_LIT_RE = re.compile(r'"(?:\\.|[^"\\])*"', re.S)
_SQL_WORD_RE = re.compile(r"\b(?:LIKE|WHERE|SELECT|INSERT|UPDATE|DELETE|ORDER\s+BY|IN\s*\()\b|\b(?:AND|OR)\s+[\w.`$>{}-]+\s*(?:=|LIKE)", re.I)
_SQL_INTERP_RE = re.compile(r"'\s*\{?(\$[A-Za-z_]\w*)(?:\}|\b)")
# Unquoted interpolation in a numeric SQL position (= < > BETWEEN ... AND, IN (, LIMIT, OFFSET): quotes are not needed to inject there.
_SQL_NUM_INTERP_RE = re.compile(r"(?:[=<>]|\bBETWEEN|\bAND|\bIN\s*\(|\bLIMIT|\bOFFSET|,)\s*\{?(\$[A-Za-z_]\w*)((?:\[[^\]]{1,30}\])*)\}?(?!\s*\w*')", re.I)
_SQL_NUM_WORD_RE = re.compile(r"\b(?:WHERE|BETWEEN|LIMIT|OFFSET|IN\s*\(|ORDER\s+BY|SELECT|UPDATE|DELETE)\b|\bAND\s*\(?\s*[\w.`]+\s*(?:BETWEEN|[=<>])", re.I)
_SQL_TABLEISH_RE = re.compile(r"^\$(?:wpdb|table|tbl|prefix|this)", re.I)
_SQL_SAFE_ASSIGN_RE = re.compile(r"esc_sql|absint|intval|floatval|\(int\)|\(float\)|->prepare\s*\(|sanitize_key")
_FLAG_PARAM_RE = re.compile(r"^\$(?:safe|verify|validate|sanitize|sanitise|check|secure|strict|escape|escaped|sslverify|ssl_verify|enforce|restrict)\w*$", re.I)
_FLAG_DEF_RE = re.compile(r"function\s+&?\s*\w*\s*\(", re.S)
_FILETYPE_HOOKS = {"wp_check_filetype_and_ext", "upload_mimes", "mime_types", "wp_handle_upload_prefilter"}
_DANGEROUS_EXT_RE = re.compile(r"""\[\s*['"](?:php\d?|phtml|phar|pht|phps|inc|js|html?|svgz?|xml|swf|exe|sh)(?:\|[a-z0-9|]+)?['"]\s*\]""", re.I)


def _flag_params(f: Func) -> dict[int, str]:
    """{position: name} of parameters that look like a safety switch and default to true."""
    m = _FLAG_DEF_RE.search(f.body)
    if not m:
        return {}
    depth, i = 0, m.end() - 1
    j = _close(f.body, i)
    out: dict[int, str] = {}
    for pos, prm in enumerate(split_args(f.body[m.end():j - 1])):
        pm = re.match(r"\s*(?:[\w\\?|]+\s+)?&?\s*(\$[A-Za-z_]\w*)\s*=\s*true\b", prm, re.I)
        if pm and _FLAG_PARAM_RE.match(pm.group(1)):
            out[pos] = pm.group(1)
    return out


def _more_sinks(idx: Index) -> list[dict[str, Any]]:
    """SQL assembled as text, safety flags switched off, and filters that override the file type check."""
    out: list[dict[str, Any]] = []

    def rec(f: Func, line: int, sink: str, classes: list[str], call: str, args: str, hint: str, extra: dict[str, Any] | None = None, risk: str = "unguarded") -> None:
        out.append({
            "file": f.file, "line": line, "end_line": line, "function": f.qualname, "sink": sink, "call": call,
            "classes": classes, "risk": risk, "args": args[:157] + "..." if len(args) > 160 else args,
            "guards_in_args": [], "sanitizers_in_function": sorted({m.group() for m in NEARBY_RE.finditer(f.body)}),
            "function_guard_accepted": None,
            "weak_gates_in_function": sorted({m.group().rstrip("( \t") for m in _WEAK_GATES_RE.finditer(f.body)}),
            "hint": hint, **(extra or {})})

    # 1. sql-build: a SQL fragment with a quoted variable, built as text (filters such as posts_search, helpers returning clauses)
    for f in idx.funcs:
        body = f.body
        if "'" not in body or not re.search(r"LIKE|WHERE|SELECT|AND|OR", body):
            continue
        stored = _closure(body, DB_READ_RE)
        reqt = tainted_vars(body)
        assigns = {v: rhs for v, rhs, _ in _assignments(body)}
        for lm in _SQL_LIT_RE.finditer(body):
            lit = lm.group()
            if not (_SQL_WORD_RE.search(lit) or _SQL_NUM_WORD_RE.search(lit)):
                continue
            pre = body[max(0, lm.start() - 60):lm.start()]
            if re.search(r"prepare\s*\(\s*$", pre) or "->prepare" in pre[-30:]:
                continue
            for vm in _SQL_INTERP_RE.finditer(lit):
                var = vm.group(1)
                if var in ("$wpdb", "$this"):
                    continue
                rhs = assigns.get(var, "")
                if rhs and _SQL_SAFE_ASSIGN_RE.search(rhs):
                    continue
                origin = "request" if var in reqt else ("stored" if var in stored else "")
                line = f.line + body.count("\n", 0, lm.start())
                rec(f, line, "sql-build", ["sqli"], "(string)", lit.strip()[:150],
                    f"quoted variable {var} inside a SQL string built as text (esc_like escapes % _ \\ but NOT quotes; "
                    "add_slashes from magic quotes can turn \\' into \\\\'); where does this fragment end up (posts_search / where filters, $wpdb->query)?",
                    {"origin": origin} if origin else None)
                break
            else:
                if not _SQL_NUM_WORD_RE.search(lit):
                    continue
                for vm in _SQL_NUM_INTERP_RE.finditer(lit):
                    var = vm.group(1)
                    if _SQL_TABLEISH_RE.match(var):
                        continue
                    rhs = assigns.get(var, "")
                    if rhs and _SQL_SAFE_ASSIGN_RE.search(rhs):
                        continue
                    if re.search(r"(?:absint|intval|floatval|\(int\)|\(float\))\s*\(?\s*" + re.escape(var) + r"\b", body):
                        continue
                    origin = "request" if var in reqt else ("stored" if var in stored else "")
                    line = f.line + body.count("\n", 0, lm.start())
                    rec(f, line, "sql-build", ["sqli"], "(string)", lit.strip()[:150],
                        f"unquoted variable {var}{vm.group(2)} in a numeric SQL position (comparison, BETWEEN, IN, LIMIT): no quote is needed to inject; "
                        "is it cast to int/float on every path before it reaches the query?",
                        {"origin": origin} if origin else None)
                    break

    # 2. safety flag switched off: callee has a $safe/$verify/... = true parameter and the call passes false
    flagged: dict[str, list[tuple[Func, dict[int, str]]]] = {}
    for f in idx.funcs:
        fp = _flag_params(f)
        if fp:
            flagged.setdefault(f.name.lower(), []).append((f, fp))
    for c in idx.calls:
        if c.kind not in ("func", "method", "static") or c.name not in flagged:
            continue
        defs = flagged[c.name]
        if c.kind == "static" and c.recv.lower() not in ("self", "static", "parent"):
            want = c.recv.strip("\\").rsplit("\\", 1)[-1].lower()
            defs = [d for d in defs if d[0].cls.lower() == want] or []
        elif c.kind == "method" and c.recv.lower() in ("$this",):
            owner = idx.func_of(c)
            defs = [d for d in defs if owner and d[0].cls == owner.cls]
        if not defs:
            continue
        for fn, fp in defs:
            for pos, pname in fp.items():
                if len(c.args) > pos and re.fullmatch(r"\s*(?:false|0|null)\s*", c.args[pos], re.I):
                    caller = idx.func_of(c)
                    if caller is None:
                        continue
                    cls = ["ssrf"] if re.search(r"wp_safe_remote|wp_remote_|curl", fn.body) else (
                        ["xss"] if re.search(r"esc_|kses", fn.body) else (["sqli"] if "prepare" in fn.body else ["authz"]))
                    rec(caller, c.line, "safety-flag-disabled", cls, c.name, ", ".join(c.args),
                        f"{fn.qualname}() has {pname} = true by default and this call passes {c.args[pos].strip()}: the protected path "
                        f"(for example wp_safe_remote_* instead of wp_remote_*) is switched off here. Who controls the value that reaches it?")
                    break

    # 3. filetype-override: a filter on wp_check_filetype_and_ext / upload_mimes that rewrites ext/type or allows executable types
    for c in idx.calls:
        if c.kind != "func" or c.name not in ("add_filter",) or len(c.args) < 2:
            continue
        hook = literal(c.args[0])
        if hook not in _FILETYPE_HOOKS:
            continue
        h = resolve(idx, parse_callback(c.args[1]), c)
        if h is None:
            continue
        b = h.body
        overrides = bool(re.search(r"\[\s*['\"](?:ext|type)['\"]\s*\]\s*=(?!=)", b)) and hook == "wp_check_filetype_and_ext"
        dangerous = hook in ("upload_mimes", "mime_types") and bool(_DANGEROUS_EXT_RE.search(b))
        if not (overrides or dangerous):
            continue
        verifies = bool(re.search(r"mime_content_type|finfo_|getimagesize|wp_get_image_mime|wp_check_filetype\s*\(", b)) and bool(re.search(r"in_array|===", b))
        weak = bool(re.search(r"strpos\s*\(|stripos\s*\(|strstr\s*\(|preg_match\s*\(", b)) and not re.search(r"pathinfo\s*\(", b)
        what = "overrides the extension/type that WordPress computed" if overrides else "allows an executable or active-content type"
        rec(h, h.line, "filetype-override", ["file-ops"], f"add_filter({hook})", c.args[1],
            f"filter on {hook} {what}" + ("; the match is a substring/regex test on the file name (shell.woff.php passes) " if weak else "")
            + ("; no content or exact-extension check found" if not verifies else ""),
            risk="guarded" if verifies and not weak else "unguarded")
    return out


_ORIGIN_CLASSES = {"file-ops", "file-inclusion", "ssrf", "object-injection", "open-redirect", "xxe"}


def _origin(rule: Rule, call: Call, func: Func | None) -> str:
    """'stored' / 'request' when a value inspected by the sink comes from storage or from the request inside this function."""
    if func is None or not (_ORIGIN_CLASSES & set(rule.classes)):
        return ""
    target = list(call.args) if rule.arg_idx is None else list(call.args[rule.arg_idx:rule.arg_idx + 1])
    names = _sink_vars(target)
    text = " ".join(target)
    if REQUEST_SOURCE_RE.search(text):
        return "request"
    if DB_READ_RE.search(text) or names & _closure(func.body, DB_READ_RE):
        return "stored"  # also when the key that selects the stored item comes from the request
    if names & tainted_vars(func.body):
        return "request"
    return ""


def scan_sinks(idx: Index) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for call in idx.calls:
        for rule in _BY_NAME.get(call.name, []):
            if not _applies(rule, call):
                continue
            func = idx.func_of(call)
            risk, in_args, accepted = _assess(rule, call, func)
            snippet = ", ".join(call.args)
            origin = _origin(rule, call, func)
            out.append({
                "file": call.file, "line": call.line, "end_line": call.end_line,
                "function": func.qualname if func else None,
                "sink": rule.sink, "call": call.name, "classes": list(rule.classes), "risk": risk,
                "args": snippet if len(snippet) <= 160 else snippet[:157] + "...",
                "guards_in_args": in_args,
                "sanitizers_in_function": sorted({m.group() for m in NEARBY_RE.finditer(func.body)}) if func else [],
                "request_tainted": _request_tainted(call, func),
                "function_guard_accepted": accepted,
                "weak_gates_in_function": sorted({m.group().rstrip("( \t") for m in _WEAK_GATES_RE.finditer(func.body)}) if func else [],
                "hint": rule.hint + (" The value is read from storage (option/meta/cart/session/query): find who writes it and whether a lower privilege can." if origin == "stored" else ""),
                **({"origin": origin} if origin else {}),
            })
    out += _extra_sinks(idx)
    out += _more_sinks(idx)
    out.sort(key=lambda s: (s["file"], s["line"], s["sink"]))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--class", dest="classes", default="", help="comma list, e.g. xss,sqli")
    ap.add_argument("--risk", default="unguarded,guarded", help="comma list of unguarded,guarded,constant")
    ap.add_argument("--sink", default="", help="comma list of sink names, e.g. html-build,unchecked-guard-result,meta-key,account-control")
    ap.add_argument("--backend", choices=["auto", "treesitter", "regex"], default="auto")
    ns = ap.parse_args(argv)
    if not ns.root.is_dir():
        print(f"error: {ns.root} is not a directory", file=sys.stderr)
        return 2
    idx = build_index(ns.root, ns.backend)
    sinks = scan_sinks(idx)
    want_c = {c for c in ns.classes.split(",") if c}
    want_r = {r for r in ns.risk.split(",") if r}
    want_s = {x for x in ns.sink.split(",") if x}
    shown = [s for s in sinks if s["risk"] in want_r and (not want_c or want_c & set(s["classes"])) and (not want_s or s["sink"] in want_s)]
    counts: dict[str, int] = {}
    for s in sinks:
        counts[s["risk"]] = counts.get(s["risk"], 0) + 1
    json.dump({"root": idx.root, "backend": idx.backend, "files_parsed": len(idx.files), "skipped": idx.skipped,
               "totals_by_risk": counts, "sinks_shown": len(shown), "sinks": shown}, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
