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
