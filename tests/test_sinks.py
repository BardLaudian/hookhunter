from __future__ import annotations

import pytest
from conftest import marker_lines
from wp_sinks import scan_sinks

# fixture class -> sink classes that the VULN lines must be reported under
EXPECTED = {
    "xss": "xss",
    "sqli": "sqli",
    "authz": "authz",
    "file-ops": {"file-ops", "file-inclusion"},
    "object-injection": "object-injection",
    "ssrf": "ssrf",
    "open-redirect": "open-redirect",
    "privesc": "privesc",
    "rce": "rce",
    "info-disclosure": "info-disclosure",
    "xxe": "xxe",
    "dynamic-call": "rce",
    "url-fetch": "ssrf",
    "account": {"privesc", "authz"},
}


def _wanted(cls: str) -> set[str]:
    w = EXPECTED[cls]
    return {w} if isinstance(w, str) else set(w)


@pytest.mark.parametrize("cls", sorted(EXPECTED))
def test_vulnerable_fixture_has_unguarded_sink_on_every_marked_line(cls, index_of):
    name = f"{cls}-vuln"
    sinks = scan_sinks(index_of(name))
    lines = marker_lines(name, "VULN")
    assert lines, "fixture has no VULN markers"
    for line in lines:
        hits = [s for s in sinks if s["line"] == line and s["risk"] == "unguarded" and _wanted(cls) & set(s["classes"])]
        assert hits, f"{name}:{line} not reported as unguarded {cls}: {[s for s in sinks if s['line'] == line]}"


@pytest.mark.parametrize("cls", sorted(set(EXPECTED) | {"csrf"}))
def test_safe_twin_has_no_unguarded_sink(cls, index_of):
    name = f"{cls}-safe"
    sinks = scan_sinks(index_of(name))
    assert [s for s in sinks if s["risk"] == "unguarded"] == []


@pytest.mark.parametrize("cls", sorted(EXPECTED))
def test_safe_twin_marked_lines_are_inspected_not_skipped(cls, index_of):
    name = f"{cls}-safe"
    sinks = scan_sinks(index_of(name))
    for line in marker_lines(name, "SAFE"):
        assert any(s["line"] == line and s["risk"] in ("guarded", "constant") for s in sinks), f"{name}:{line}"


def test_sink_records_function_guards_and_hint(index_of):
    sinks = scan_sinks(index_of("file-ops-safe"))
    move = next(s for s in sinks if s["call"] == "move_uploaded_file")
    assert move["function"] == "fx_files"
    assert {"sanitize_file_name", "wp_check_filetype"} <= set(move["sanitizers_in_function"])
    assert move["hint"]


def test_partial_escaping_is_still_unguarded(tmp_path, backend):
    from _php import build_index

    (tmp_path / "p.php").write_text("<?php function f() { echo '<a>' . esc_html($_GET['a']) . $_GET['b']; }")
    [s] = [s for s in scan_sinks(build_index(tmp_path, backend)) if s["call"] == "echo"]
    assert s["risk"] == "unguarded"


def test_stored_value_echo_is_flagged_through_getters(tmp_path, backend):
    from _php import build_index

    (tmp_path / "p.php").write_text("<?php function f() { echo get_option('t'); echo esc_html(get_option('t')); echo 'x'; }")
    risks = [s["risk"] for s in scan_sinks(build_index(tmp_path, backend)) if s["call"] == "echo"]
    assert risks == ["unguarded", "guarded", "constant"]


def test_prepare_with_bare_variable_query_is_not_flagged(tmp_path, backend):
    from _php import build_index

    (tmp_path / "p.php").write_text(
        "<?php function f($sql, $id) { global $wpdb; return $wpdb->get_results($wpdb->prepare($sql, $id)); }"
    )
    assert [s for s in scan_sinks(build_index(tmp_path, backend)) if s["risk"] == "unguarded"] == []


def test_curl_setopt_only_matters_for_curlopt_url(tmp_path, backend):
    from _php import build_index

    (tmp_path / "p.php").write_text("<?php function f($ch, $t) { curl_setopt($ch, CURLOPT_TIMEOUT, $t); }")
    assert scan_sinks(build_index(tmp_path, backend)) == []


# --- dispatch, URL fetching and account functions (sinks added after S3) -----------------------------

def _sinks(tmp_path, backend, php):
    from _php import build_index

    (tmp_path / "p.php").write_text("<?php function f() { " + php + " }")
    return scan_sinks(build_index(tmp_path, backend))


@pytest.mark.parametrize(
    ("php", "sink"),
    [
        ("$f = $_GET['f']; $f();", "dynamic-callee"),
        ("$_GET['g']( 1 );", "dynamic-callee"),
        ("$m = $_POST['m']; $o->$m();", "dynamic-callee"),
        ("$m = $_POST['m']; A::$m();", "dynamic-callee"),
        ("$c = $_POST['c']; $o = new $c();", "dynamic-class"),
        ("usort( $rows, $_GET['cmp'] );", "callable-param"),
        ("array_filter( $rows, $_POST['cb'] );", "callable-param"),
        ("add_action( 'init', $_POST['cb'] );", "callable-param"),
        ("apply_filters( $_GET['f'], 1 );", "hook-dispatch"),
        ("$r = $request->get_param( 'cb' ); $r();", "dynamic-callee"),
        ("foreach ( $_POST['cbs'] as $cb ) { $cb(); }", "dynamic-callee"),
    ],
)
def test_request_chosen_dispatch_is_unguarded(tmp_path, backend, php, sink):
    hits = [s for s in _sinks(tmp_path, backend, php) if s["sink"] == sink]
    assert hits and all(h["risk"] == "unguarded" for h in hits), hits


@pytest.mark.parametrize(
    "php",
    [
        "$cb = function () {}; $cb();",
        "$h = array( 'a' => 'fa' ); $f = $h[ $_POST['k'] ] ?? null; $f();",
        "$f = $this->callbacks[ $_GET['k'] ]; $f();",
        "usort( $rows, 'strcmp' );",
        "array_map( 'trim', $_POST['list'] );",
        "do_action( 'fx_ready' );",
        "$f = $_GET['f']; if ( in_array( $f, array( 'a' ), true ) ) { $f(); }",
    ],
)
def test_internal_or_allow_listed_dispatch_is_not_unguarded(tmp_path, backend, php):
    assert [s for s in _sinks(tmp_path, backend, php) if s["risk"] == "unguarded"] == []


def test_immediately_invoked_closure_is_not_a_dispatch_sink(tmp_path, backend):
    assert [s for s in _sinks(tmp_path, backend, "( function () {} )();") if s["sink"] == "dynamic-callee"] == []


def test_casting_the_user_id_does_not_make_an_account_function_safe(tmp_path, backend):
    [s] = [s for s in _sinks(tmp_path, backend, "wp_set_auth_cookie( absint( $_POST['u'] ) );") if s["sink"] == "account-control"]
    assert s["risk"] == "unguarded"


def test_privileged_and_request_named_options(tmp_path, backend):
    sinks = _sinks(tmp_path, backend, "update_option( 'users_can_register', 1 ); update_option( $wpdb->prefix . 'user_roles', $v ); update_option( $_POST['n'], 1 );")
    assert [s["risk"] for s in sinks if s["sink"] == "privileged-option"] == ["unguarded", "unguarded"]
    assert [s["risk"] for s in sinks if s["sink"] == "option-name"] and any(s["sink"] == "option-name" and s["risk"] == "unguarded" for s in sinks)


def test_taint_follows_assignments_and_stops_at_map_lookups():
    from wp_sinks import tainted_vars

    body = "$a = $_POST['x']; $b = trim( $a ); $c = $map[ $b ]; $d = $c . 'x'; $e = $map[ $b ] ?? $_GET['y'];"
    assert tainted_vars(body) == frozenset({"$a", "$b", "$e"})
