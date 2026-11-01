#!/usr/bin/env python3
"""Regenerate the dry-run artifacts from the analysis below.

The analysis (findings, refuted candidates, reasons) is what the workflow of SKILL.md produced when it was followed by hand on the synthetic
fixtures: wp_map.py and wp_sinks.py for candidates, wp_xref.py and reading each handler for the refutation pass. This script only turns that
analysis into files: one bench-mode JSON per fixture (bench/<fixture>.json) and an audit-mode report (REPORT.md). Line numbers are looked
up in the fixture source from a text selector, so they follow the fixtures if these change.

Usage: build_dry_run.py        (run from anywhere)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent
FIXTURES = TESTS / "fixtures"
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS.parent / "scripts"))
from test_reference import cvss31  # noqa: E402  (the formula checked against FIRST's examples)

CWE = {"stored-xss": "CWE-79", "reflected-xss": "CWE-79", "dom-xss": "CWE-79", "sqli": "CWE-89", "missing-authz": "CWE-862", "csrf": "CWE-352",
       "path-traversal": "CWE-22", "file-delete": "CWE-22", "file-upload": "CWE-434", "file-inclusion": "CWE-98", "object-injection": "CWE-502",
       "ssrf": "CWE-918", "open-redirect": "CWE-601", "privesc": "CWE-269", "rce": "CWE-94", "info-disclosure": "CWE-200", "xxe": "CWE-611"}
BASE = {"AC": "L", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
ORDER_CONF = {"high": 0, "medium": 1, "low": 2}


def F(sel, fn, ep, cls, auth, conf, flow, metrics, impact, fail, repro, fix, cwe=None, note=""):
    return dict(sel=sel, function=fn, entry_point=ep, cls=cls, auth=auth, confidence=conf, data_flow=flow, metrics=metrics, impact=impact,
                fail=fail, repro=repro, fix=fix, cwe=cwe or CWE[cls], note=note,
                status="confirmed" if conf == "high" else "needs-dynamic-check")


def R(where, reason, text):
    return dict(where=where, reason=reason, text=text)


ANALYSIS: dict[str, dict] = {
    "authz-vuln": {"findings": [F(
        "update_option( 'fx_title'", "fx_save", "wp_ajax_fx_save", "missing-authz", "subscriber", "high",
        "$_POST['t'] -> sanitize_text_field -> update_option('fx_title'); check_ajax_referer only, no current_user_can",
        dict(PR="L", I="L"), "Any logged-in user holding the action nonce changes the plugin option `fx_title`; severity depends on what the option controls.",
        "`check_ajax_referer` proves the request came from a page the user loaded, not that the user may change options (wp-traps 2).",
        "On a local test site, log in as a subscriber, take the nonce the plugin prints for `fx_save`, send the AJAX action with a changed `t`, and read the option back.",
        "Call `current_user_can( 'manage_options' )` and stop with `wp_send_json_error( null, 403 )` before `update_option`.")]},
    "csrf-vuln": {"findings": [F(
        "update_option( 'fx_opt'", "fx_handle_form", "admin_init", "csrf", "unauthenticated", "high",
        "$_POST['fx_opt'] -> sanitize_text_field -> update_option('fx_opt'); current_user_can present, no nonce",
        dict(PR="N", UI="R", I="L"), "A page controlled by the attacker can make a logged-in administrator's browser post the form and change `fx_opt`. `admin_init` also runs for admin-post.php and admin-ajax.php.",
        "The handler checks the capability (authority) but never a nonce (intent); `isset( $_POST )` is the only gate.",
        "On a local test site, as a logged-in administrator, load a page that auto-submits a form to an admin URL with `fx_opt` set; the option changes without any nonce.",
        "Print `wp_nonce_field( 'fx_form' )` in the form and call `check_admin_referer( 'fx_form' )` before `update_option`.")]},
    "file-ops-vuln": {"findings": [
        F("move_uploaded_file(", "fx_files", "wp_ajax_nopriv_fx_files", "file-upload", "unauthenticated", "high",
          "$_FILES['f']['name'] -> $dest in wp-content/uploads -> move_uploaded_file; no extension or type check, no capability",
          dict(PR="N", I="H"), "An unauthenticated visitor stores a file with an attacker-chosen name and extension in the uploads directory. Whether it can be executed depends on the web server (not verified); with PHP execution allowed the score becomes 9.8.",
          "Name and type come from the client; nothing validates the extension and the handler is registered for visitors.",
          "On a local test site, post a harmless text file named `probe.txt` to the action and confirm it appears under uploads with the same name.",
          "Require `upload_files`, pass the file through `wp_handle_upload()` with an allow-list of types, and use `wp_unique_filename()`."),
        F("include $_GET['tpl']", "fx_files", "wp_ajax_nopriv_fx_files", "file-inclusion", "unauthenticated", "high",
          "$_GET['tpl'] -> include, no allow-list, no containment",
          dict(PR="N", C="H"), "A visitor chooses the file that PHP includes; PHP files execute, other readable files are printed. Combined with the upload finding this reaches code execution.",
          "The request value is the whole path; there is no allow-list, `basename` or `realpath` containment.",
          "On a local test site, request the action with `tpl` set to a harmless readable text file and observe its content in the response.",
          "Select the template from a fixed array (`in_array( $tpl, $allowed, true )`) and build the path from constants."),
        F("unlink(", "fx_files", "wp_ajax_nopriv_fx_files", "file-delete", "unauthenticated", "high",
          "$_POST['file'] -> WP_CONTENT_DIR . '/' . value -> unlink; no basename or realpath",
          dict(PR="N", I="H", A="H"), "A visitor deletes any file the web user can delete inside or outside wp-content through `../`; deleting configuration files can lead to site takeover.",
          "The value is concatenated into the path unvalidated.",
          "On a local test site, create a scratch file inside wp-content, post its relative name to the action and confirm it is removed.",
          "Use `wp_delete_file_from_directory( $path, $base )` with a file name from `basename()` and require a capability.")]},
    "info-disclosure-vuln": {"findings": [
        F("phpinfo()", "fx_dump", "wp_ajax_nopriv_fx_dump", "info-disclosure", "unauthenticated", "high",
          "nopriv handler -> phpinfo(), no capability check", dict(PR="N", C="L"),
          "Any visitor reads PHP configuration, loaded extensions, paths and environment variables.",
          "A debug function is reachable without authentication.",
          "On a local test site, request the action unauthenticated and observe the PHP information page.",
          "Remove the call, or require an administrator capability."),
        F("get_users()", "fx_dump", "wp_ajax_nopriv_fx_dump", "info-disclosure", "unauthenticated", "high",
          "get_users() (WP_User objects with user_pass) -> wp_send_json_success; no capability",
          dict(PR="N", C="H"), "Any visitor receives every user row, including email addresses and password hashes.",
          "`get_users()` returns full `WP_User` objects (the whole users row, `SELECT *`) and the response is sent unfiltered.",
          "On a local test site, request the action unauthenticated and compare the JSON fields with the users table columns.",
          "Check `current_user_can( 'list_users' )` and request only the needed fields: `get_users( array( 'fields' => array( 'ID', 'display_name' ) ) )`.")]},
    "object-injection-vuln": {"findings": [
        F("unserialize( base64_decode", "fx_prefs", "init", "object-injection", "unauthenticated", "medium",
          "$_COOKIE['fx_prefs'] -> base64_decode (restores quotes) -> unserialize, no allowed_classes",
          None, "Attacker-controlled data reaches `unserialize` on every request. Impact depends on a gadget class in the plugin, core, or another active plugin; the plugin defines none.",
          "No `allowed_classes`, no signature. `base64_decode` restores the quotes that `wp_magic_quotes` escaped, so the string is intact.",
          "Not reproduced: needs a gadget available on the site.",
          "Use `json_decode()`; if serialization is unavoidable, sign it with an HMAC checked with `hash_equals()` before decoding."),
        F("maybe_unserialize( wp_unslash", "fx_prefs", "init", "object-injection", "unauthenticated", "medium",
          "$_POST['data'] -> wp_unslash (restores quotes) -> maybe_unserialize, no allowed_classes",
          None, "Same weakness as above through a POST field; `wp_unslash` removes the slashes that would otherwise break the string.",
          "`maybe_unserialize` adds no options; the unslashed string is deserialized.",
          "Not reproduced: needs a gadget available on the site.",
          "Replace with `json_decode( wp_unslash( ... ), true )`.")]},
    "open-redirect-vuln": {"findings": [
        F("wp_redirect( $_GET['next'] )", "fx_go", "template_redirect", "open-redirect", "unauthenticated", "high",
          "$_GET['next'] -> wp_redirect; no wp_validate_redirect", dict(PR="N", UI="R", S="C", C="L", I="L"),
          "A link on the site's own domain sends the visitor to any external address.",
          "`wp_redirect` does not validate the host.", "On a local test site, open a front-end URL with `next` set to an external address and observe the Location header.",
          "Use `wp_safe_redirect()` (or `wp_validate_redirect()`) and keep the `exit`."),
        F("header( 'Location: '", "fx_go", "template_redirect", "open-redirect", "unauthenticated", "high",
          "$_GET['to'] -> header('Location: ' . value); no validation", dict(PR="N", UI="R", S="C", C="L", I="L"),
          "Same effect through a second parameter.", "The raw header is built from the request value.",
          "On a local test site, open a front-end URL with `to` set to an external address and observe the Location header.",
          "Replace with `wp_safe_redirect( $_GET['to'] )` followed by `exit`.")]},
    "privesc-vuln": {"findings": [
        F("wp_update_user(", "fx_role", "wp_ajax_fx_role", "privesc", "subscriber", "high",
          "$_POST['role'] -> wp_update_user(array('role'=>...)); nonce only, no promote_users, no role allow-list",
          dict(PR="L", C="H", I="H", A="H"), "A subscriber sets any user's role, including their own, to administrator.",
          "`wp_insert_user` and `wp_update_user` do not check the caller; the handler checks a nonce but no capability and accepts any role.",
          "On a local test site, as a subscriber, post the action with the nonce, your own user id and `role=administrator`; reload your profile.",
          "Require `promote_users` and `promote_user` for the id, and accept only roles from `get_editable_roles()`."),
        F("update_user_meta(", "fx_role", "wp_ajax_fx_role", "privesc", "subscriber", "high",
          "$_POST['caps'] -> update_user_meta(id, 'wp_capabilities', value); same missing checks",
          dict(PR="L", C="H", I="H", A="H"), "Direct write of the capabilities meta key, an alternative route to the same escalation.",
          "The meta key that stores roles is written from request data without a capability check.",
          "On a local test site, as a subscriber, post the action with a `caps` value naming the administrator role and reload your profile.",
          "Remove the write; change roles only through `WP_User::set_role()` after the checks above.")]},
    "rce-vuln": {"findings": [
        F("eval(", "fx_run", "wp_ajax_nopriv_fx_run", "rce", "unauthenticated", "high",
          "$_POST['code'] -> eval; nopriv, no nonce, no capability", dict(PR="N", C="H", I="H", A="H"),
          "A visitor runs PHP code on the server.", "Request text is evaluated; nothing restricts it.",
          "On a local test site, post a harmless expression such as the arithmetic `1+1` to the action and observe that it is evaluated.",
          "Delete the handler; never evaluate request text."),
        F("shell_exec( 'ping -c1 '", "fx_run", "wp_ajax_nopriv_fx_run", "rce", "unauthenticated", "high",
          "$_GET['host'] -> concatenated into the command line of shell_exec", dict(PR="N", C="H", I="H", A="H"), cwe="CWE-78",
          impact="A visitor runs operating-system commands as the web user.", fail="No `escapeshellarg()` and the shell parses the whole line.",
          repro="On a local test site, request the action with a `host` value containing a harmless extra command that writes a marker file inside wp-content.",
          fix="Build the command with `proc_open( array( 'ping', '-c1', '--', $host ) )` or at least `escapeshellarg( $host )`, and require a capability."),
        F("call_user_func(", "fx_run", "wp_ajax_nopriv_fx_run", "rce", "unauthenticated", "high",
          "$_POST['fn'] -> call_user_func; no allow-list", dict(PR="N", C="L", I="L", A="L"),
          "A visitor calls any PHP function that takes no arguments (information disclosure, state changes). Limited next to the findings above.",
          "The callable is chosen by the request.", "On a local test site, post the name of a harmless zero-argument function and observe its effect.",
          "Select from a fixed map of handlers keyed by a validated string.")]},
    "sqli-vuln": {"findings": [
        F("get_results( \"SELECT", "fx_find", "wp_ajax_nopriv_fx_find", "sqli", "unauthenticated", "high",
          "$_GET['id'] -> wp_unslash -> concatenated in a numeric position of $wpdb->get_results; no prepare, no cast",
          dict(PR="N", C="H"), "A visitor reads any table (users, options) through UNION or boolean/time-based techniques.",
          "The value sits unquoted in the query, so quote escaping is irrelevant; there is no placeholder and no integer cast.",
          "On a local test site, request the action with `id` set to a value whose truth changes the number of rows returned and compare the responses.",
          "Use `$wpdb->prepare( '... WHERE id = %d', $id )` with `absint()`."),
        F("$wpdb->query( $wpdb->prepare", "fx_find", "wp_ajax_nopriv_fx_find", "sqli", "unauthenticated", "high",
          "$_GET['id'] -> wp_unslash -> interpolated inside the quoted template passed to prepare() (no placeholder)",
          dict(PR="N", C="H", I="H", A="H"), "The same value ends inside a quoted string of a DELETE; `wp_unslash` removed the slashes that would have protected it.",
          "`prepare()` only protects values passed as arguments; a variable inside the template is concatenated as is.",
          "On a local test site, send an `id` containing a single quote and observe the database error or changed behaviour.",
          "Pass the value as a placeholder argument: `$wpdb->prepare( '... WHERE name = %s', $id )`.")]},
    "ssrf-vuln": {"findings": [
        F("wp_remote_get(", "fx_fetch", "wp_ajax_nopriv_fx_fetch", "ssrf", "unauthenticated", "high",
          "$_POST['url'] -> wp_remote_get (no wp_http_validate_url) -> response body returned via wp_send_json",
          dict(PR="N", S="C", C="H"), "A visitor makes the server request any URL, including loopback and internal addresses, and reads the response.",
          "`wp_remote_get` does not validate the host, and the body is returned.",
          "On a local test site, post the URL of a second local service you own and observe its response in the JSON.",
          "Use `wp_safe_remote_get()` with `wp_http_validate_url()`, require a capability, and do not return the body."),
        F("curl_setopt(", "fx_fetch", "wp_ajax_nopriv_fx_fetch", "ssrf", "unauthenticated", "high",
          "$_GET['u'] -> CURLOPT_URL -> curl_exec; response not returned (blind)", dict(PR="N", S="C", C="L"),
          "A visitor makes the server send a request to any URL (all cURL protocols); the response is discarded.",
          "The URL is not validated and cURL is not restricted to http(s).", "On a local test site, post a URL of a listener you own and watch for the request.",
          "Use the WordPress HTTP API with validation; set `CURLOPT_PROTOCOLS` and block private ranges if cURL must be used.")]},
    "xss-vuln": {"findings": [
        F("echo '<p>Results for '", "fx_xss_render", "fx_search", "reflected-xss", "unauthenticated", "high",
          "$_GET['q'] -> echo in a text node of the [fx_search] shortcode, no esc_html", dict(PR="N", UI="R", S="C", C="L", I="L"),
          "On any page that contains the shortcode, a crafted link runs script in the visitor's browser.",
          "The request value is printed without output escaping.",
          "On a local test site, publish a page with `[fx_search]`, open it with `q` containing a harmless unique marker string and confirm it appears unescaped in the page source.",
          "Escape at output: `esc_html( wp_unslash( $_GET['q'] ) )`."),
        F("printf( '<input value=", "fx_xss_render", "fx_search", "reflected-xss", "unauthenticated", "high",
          "$_GET['v'] -> printf into a double-quoted attribute, no esc_attr", dict(PR="N", UI="R", S="C", C="L", I="L"),
          "The same page lets a crafted link break out of the `value` attribute.", "No `esc_attr` for the attribute context.",
          "On a local test site, open the page with `v` containing a double quote and observe the attribute closing in the page source.",
          "Escape with `esc_attr( wp_unslash( $_GET['v'] ) )`.")]},
    "xxe-vuln": {"findings": [
        F("simplexml_load_string(", "fx_xml", "wp_ajax_nopriv_fx_xml", "xxe", "unauthenticated", "high",
          "$_POST['x'] -> wp_unslash -> simplexml_load_string(LIBXML_NOENT) -> value returned via wp_send_json",
          dict(PR="N", C="H"), "A visitor submits XML whose entities are resolved, reading local files; the parsed value is returned.",
          "`LIBXML_NOENT` enables entity substitution; no resolver guard.", "On a local test site, post a document defining an internal entity and observe the substituted value in the response.",
          "Parse with default flags; if flags are needed, install `libxml_set_external_entity_loader( fn() => null )` for the parse."),
        F("$dom->loadXML(", "fx_xml", "wp_ajax_nopriv_fx_xml", "xxe", "unauthenticated", "high",
          "$_POST['y'] -> wp_unslash -> DOMDocument::loadXML(LIBXML_NOENT | LIBXML_DTDLOAD); result not returned (blind)",
          dict(PR="N", S="C", C="L"), "A visitor makes the parser fetch external entities and DTDs (requests to chosen URLs); content is not returned.",
          "`LIBXML_NOENT` and `LIBXML_DTDLOAD` both enabled.", "On a local test site, post a document referencing an external DTD on a listener you own and watch for the request.",
          "Remove the flags.")]},
    "surface": {"findings": [
        F("update_option( 'fx_b'", "FX_Admin::ajax_b", "wp_ajax_nopriv_fx_b", "missing-authz", "unauthenticated", "high",
          "$_POST['b'] -> update_option('fx_b'); nopriv, no nonce, no capability", dict(PR="N", I="L"),
          "A visitor changes the plugin option `fx_b`.", "No authentication, nonce or capability.", "On a local test site, post the action unauthenticated and read the option.",
          "Register only `wp_ajax_` and add `current_user_can()`; never expose option writes to visitors."),
        F("update_option( 'fx_c'", "fx_post_c", "admin_post_nopriv_fx_c", "missing-authz", "unauthenticated", "high",
          "$_POST['c'] -> update_option('fx_c'); admin_post_nopriv, no nonce, no capability", dict(PR="N", I="L"),
          "A visitor changes the plugin option `fx_c`.", "No authentication, nonce or capability.", "On a local test site, post to admin-post.php unauthenticated and read the option.",
          "Same as above."),
        F("update_option( 'fx_a'", "FX_Admin::ajax_a", "wp_ajax_fx_a", "missing-authz", "contributor", "low",
          "nonce + current_user_can('edit_posts') (via verify()) -> update_option('fx_a')", dict(PR="L", I="L"),
          "A contributor can change `fx_a`, which would matter only if the option is administrative.",
          "`edit_posts` is the capability of a post author, not of whoever manages plugin settings.",
          "Not reproduced: depends on what `fx_a` controls.", "Use `manage_options` if the option is a setting.", cwe="CWE-863",
          note="Judgement call: the capability may be intended.")],
        "refuted": [
            R("FX_Admin::rest_open (route fx/v1/open)", "not-html-response", "public by design (`__return_true`); returns the request parameter as JSON, which REST serves as application/json."),
            R("fx_rest_missing (route fx/v1/missing)", "trivial-effect", "no `permission_callback`, so the route is public, but it returns a constant and changes nothing."),
            R("fx_init_reads_get (init)", "trivial-effect", "reads `$_GET['fx_export']` and returns a constant JSON value."),
            R("{closure} on wp_ajax_fx_closure", "guard-escape-context", "nonce checked; no side effect; output is `esc_html( $_POST['m'] )`."),
            R("FX_Admin::shortcode, fx_block_render, FX_Widget::widget", "guard-escape-context", "attributes and instance values escaped with `esc_html` at output."),
            R("FX_Admin::post_d (admin_post_fx_d)", "guard-capability", "`check_admin_referer` and `current_user_can( 'manage_options' )` before `update_option`."),
            R("FX_Admin::rest_guarded", "guard-capability", "`permission_callback` checks `manage_options`."),
            R("menu pages page_main, page_sub", "no-input", "print constant markup; menu capability gates the page."),
            R("fx_cron, fx_xmlrpc_hello", "trivial-effect", "scheduled and XML-RPC handlers that read no request data.")]},
    "edge": {"findings": [], "refuted": [
        R("Fetcher::run, wp_remote_get( $url ) (line of `QUALIFIED`)", "source-not-controlled", "registered on `wp_ajax_edge_real`; `$url` is a method parameter and WordPress passes no argument to AJAX callbacks, so the request controls nothing."),
        R("closure in Fetcher::helper, unserialize( $x )", "source-not-controlled", "reached only through `run( $url )`, which has no attacker-controlled argument."),
        R("render_inline, echo $_GET (two lines)", "dead-code", "`wp_xref.py` shows no caller and no registration for `render_inline`."),
        R("strings, comments, heredoc and HTML before `<?php`", "not-code", "contain sink-like text; the parser does not treat them as code.")]},
}

# Reasons for the safe twins (negative controls): which guard accounts for each marked line.
SAFE = {
    "xss-safe": [("esc_html( $_GET['q'] )", "guard-escape-context", "escaped for a text node at output"), ("esc_attr( $_GET['v'] )", "guard-escape-context", "escaped for a quoted attribute")],
    "sqli-safe": [("$wpdb->get_results( $wpdb->prepare(", "guard-prepared", "value passed as `%d` after `absint`"), ("get_var( \"SELECT COUNT", "no-input", "only the `$wpdb->posts` property in the query")],
    "authz-safe": [("update_option( 'fx_title'", "guard-capability", "`manage_options` and nonce before the write")],
    "csrf-safe": [],
    "file-ops-safe": [("move_uploaded_file(", "guard-allowlist", "name through `sanitize_file_name`, type through `wp_check_filetype`, capability `upload_files`"),
                      ("include __DIR__", "guard-allowlist", "template chosen by strict `in_array` against a fixed list"),
                      ("unlink(", "guard-path-containment", "`basename()` on the request value inside a fixed directory")],
    "object-injection-safe": [("unserialize( $raw", "guard-allowlist", "`allowed_classes => false`; `json_decode` for the second field")],
    "ssrf-safe": [("wp_safe_remote_get(", "guard-safe-client", "`wp_safe_remote_get` after `wp_http_validate_url`"), ("wp_remote_get( $url )", "guard-safe-client", "URL validated with `wp_http_validate_url` in the same function")],
    "open-redirect-safe": [("wp_safe_redirect(", "guard-validated-redirect", "`wp_safe_redirect`"), ("wp_validate_redirect(", "guard-validated-redirect", "`wp_validate_redirect` with `home_url()` fallback")],
    "privesc-safe": [("wp_update_user(", "guard-capability", "`promote_users`, nonce, and a two-role allow-list")],
    "rce-safe": [("shell_exec(", "guard-capability", "`manage_options` and `escapeshellarg` on the host; output escaped"), ("call_user_func(", "guard-allowlist", "strict `in_array` against two handler names")],
    "info-disclosure-safe": [("get_users( array", "guard-capability", "`list_users` check and only `display_name` requested")],
    "xxe-safe": [("simplexml_load_string(", "guard-parser-defaults", "default flags, no entity substitution"), ("$dom->loadXML(", "guard-parser-defaults", "default flags")],
}


def locate(fixture: str, sel: str) -> int:
    lines = (FIXTURES / fixture / f"{fixture}.php").read_text().splitlines()
    hits = [i + 1 for i, line in enumerate(lines) if sel in line and not line.lstrip().startswith(("//", "*", "/*"))]
    if len(hits) != 1:
        raise SystemExit(f"selector {sel!r} in {fixture}: {len(hits)} matches")
    return hits[0]


def vector(metrics: dict | None) -> tuple[str, float] | None:
    if metrics is None:
        return None
    m = {**BASE, **metrics, "AV": "N"}
    m.setdefault("PR", "N")
    score = cvss31(m)
    return f"CVSS:3.1/AV:N/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}", score


# Fixtures added after the dry run, to test the scripts only (dispatch, URL fetching, account functions). The dry run covers the other 26.
SCRIPT_ONLY = frozenset({"dynamic-call-vuln", "dynamic-call-safe", "url-fetch-vuln", "url-fetch-safe", "account-vuln", "account-safe"})


def build() -> dict:
    out: dict[str, list[dict]] = {}
    for d in sorted(p.name for p in FIXTURES.iterdir() if p.name not in SCRIPT_ONLY):
        items = []
        for f in ANALYSIS.get(d, {}).get("findings", []):
            line = locate(d, f["sel"])
            items.append({**f, "file": f"{d}.php", "line": line, "vec": vector(f["metrics"])})
        items.sort(key=lambda x: (ORDER_CONF[x["confidence"]], x["line"]))
        out[d] = items
    return out


def bench_json(items: list[dict]) -> dict:
    return {"findings": [{
        "file": i["file"], "line_start": i["line"], "line_end": i["line"], "function": i["function"].split("::")[-1],
        "entry_point": i["entry_point"], "cwe": i["cwe"], "class": i["cls"], "auth_required": i["auth"], "data_flow": i["data_flow"],
        "confidence": i["confidence"]} for i in items]}


def report(found: dict[str, list[dict]]) -> str:
    allf = [(d, i) for d, items in found.items() for i in items]
    confirmed = [(d, i) for d, i in allf if i["status"] == "confirmed"]
    pending = [(d, i) for d, i in allf if i["status"] != "confirmed"]
    n_safe = sum(1 for d in found if d.endswith("-safe"))
    sev = lambda x: -(x[1]["vec"][1] if x[1]["vec"] else 0)  # noqa: E731
    ordered = sorted(allf, key=lambda x: (x[1]["status"] != "confirmed", sev(x), x[0], x[1]["line"]))
    L = ["# Security audit: synthetic fixture suite (dry run)", "",
         "**Mode:** audit. **Component:** the 26 fixture plugins under `skills/hookhunter/tests/fixtures/` (written for this repository, not derived from any real plugin).",
         "**Date:** 2026-11-01. **Method:** the workflow of `SKILL.md` followed by hand; scripts for candidates, reading and `wp_xref.py` for refutation.",
         "**Not applicable:** version and prior-art checks, disclosure (synthetic code, no vendor). No payloads are included; reproduction steps are for a local test site.", "",
         "## Summary", "",
         f"{len(confirmed)} confirmed findings and {len(pending)} needing a runtime check across {sum(1 for d in found if not d.endswith('-safe') and found[d])} plugins. "
         f"All {n_safe} safe twins produced no finding. Candidates that were refuted are listed at the end with the reason.", "",
         "| # | Fixture | Class | CWE | CVSS 3.1 | Privilege | Location | Status |", "|---|---|---|---|---|---|---|---|"]
    for n, (d, i) in enumerate(ordered, 1):
        v = i["vec"]
        L.append(f"| {n} | {d} | {i['cls']} | {i['cwe']} | {f'{v[1]}' if v else 'not scored'} | {i['auth']} | `{i['file']}:{i['line']}` | {i['status']} |")
    L += ["", "## Findings", ""]
    for n, (d, i) in enumerate(ordered, 1):
        v = i["vec"]
        L += [f"### {n}. {d}: {i['cls']} at `{i['file']}:{i['line']}`", "",
              f"- **Entry point:** `{i['entry_point']}` in `{i['function']}`", f"- **Privilege required:** {i['auth']}",
              f"- **Data flow:** {i['data_flow']}", f"- **Why the guards fail:** {i['fail']}", f"- **Impact:** {i['impact']}",
              f"- **CVSS:** {f'`{v[0]}` = {v[1]}' if v else 'not scored (impact depends on a gadget that was not found in the audited tree)'}",
              f"- **Reproduction (local test site only):** {i['repro']}", f"- **Suggested fix:** {i['fix']}",
              f"- **Verification status:** {i['status']}" + (f" ({i['note']})" if i["note"] else ""), ""]
    L += ["## Variants checked", "",
          "- Each confirmed sink was searched across the fixture it belongs to. `file-ops-vuln`, `rce-vuln`, `xxe-vuln`, `xss-vuln`, `sqli-vuln` and `object-injection-vuln` each contain two or three locations of the same weakness, reported separately.",
          "- Safe twins were read for the incomplete-fix patterns of `verification.md` section 5 (guard on one handler but not a sibling; escaping on one of two outputs); none applies.", "",
          "## Refuted candidates", "", "| Where | Reason | Why |", "|---|---|---|"]
    for d, a in ANALYSIS.items():
        for r in a.get("refuted", []):
            L.append(f"| {d}: {r['where']} | `{r['reason']}` | {r['text']} |")
    L += ["", "### Negative controls (safe twins)", "", "| Fixture | Marked line | Reason | Why |", "|---|---|---|---|"]
    for d, rows in SAFE.items():
        for sel, reason, text in rows:
            L.append(f"| {d} | `{d}.php:{locate(d, sel)}` | `{reason}` | {text} |")
    L += ["| csrf-safe | `csrf-safe.php` handler | `guard-nonce` | `check_admin_referer` before `update_option`, with `manage_options` |", "",
          "## Coverage", "",
          "- `wp_map.py` and `wp_sinks.py` ran on all 26 plugins with the tree-sitter backend; `skipped` lists were empty.",
          "- Every entry point of every fixture was reviewed. `surface` was read as a whole: 16 entry points, 3 findings, the rest refuted above.",
          "- Not covered: JavaScript, `vendor/` (none present), and runtime behaviour (no code was executed). Result: **complete for the fixtures, static only**.", "",
          "## Disclosure", "", "Synthetic code; nothing to disclose. No public posting was made."]
    return "\n".join(L) + "\n"


def main() -> int:
    found = build()
    bench = HERE / "bench"
    bench.mkdir(exist_ok=True)
    for d, items in found.items():
        (bench / f"{d}.json").write_text(json.dumps(bench_json(items), indent=1, ensure_ascii=False) + "\n")
    (HERE / "REPORT.md").write_text(report(found))
    total = sum(len(v) for v in found.values())
    print(f"wrote {len(found)} bench files and REPORT.md; {total} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
