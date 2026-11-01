from __future__ import annotations

import pytest
from wp_map import build_map


def _by_name(entries):
    return {e["name"]: e for e in entries}


def test_surface_entry_points(index_of):
    e = _by_name(build_map(index_of("surface")))
    assert e["wp_ajax_nopriv_fx_b"]["tier"] == "unauth"
    assert e["wp_ajax_nopriv_fx_b"]["handler"] == "FX_Admin::ajax_b"
    assert {"no-nonce", "no-cap-check"} <= set(e["wp_ajax_nopriv_fx_b"]["flags"])
    assert e["admin_post_nopriv_fx_c"]["tier"] == "unauth"
    assert e["admin_post_nopriv_fx_c"]["handler"] == "fx_post_c"
    assert e["admin_post_fx_d"]["handler"] == "FX_Admin::post_d"
    assert e["admin_post_fx_d"]["tier"] == "admin"
    assert e["fx_sc"]["type"] == "shortcode"
    assert e["fx/block"]["handler"] == "fx_block_render"
    assert e["xmlrpc_methods"]["type"] == "xmlrpc"
    assert e["FX_Widget"]["type"] == "widget" and e["FX_Widget"]["handler"] == "FX_Widget::widget"


def test_guards_in_callee_are_reported_as_callee(index_of):
    e = _by_name(build_map(index_of("surface")))["wp_ajax_fx_a"]
    assert e["nonce_check"] == "callee" and e["cap_check"] == "callee"
    assert e["capability"] == "edit_posts" and e["tier"] == "author+"


def test_closure_handler_is_resolved(index_of):
    e = _by_name(build_map(index_of("surface")))["wp_ajax_fx_closure"]
    assert e["handler"] == "{closure}"
    assert e["nonce_check"] == "handler"


def test_rest_permission_callbacks(index_of):
    e = _by_name(build_map(index_of("surface")))
    assert e["fx/v1/open"]["tier"] == "unauth"
    assert "permission-callback-true" in e["fx/v1/open"]["flags"]
    assert e["fx/v1/missing"]["tier"] == "unauth"
    assert "missing-permission-callback" in e["fx/v1/missing"]["flags"]
    assert e["fx/v1/guarded"]["tier"] == "admin"
    assert e["fx/v1/guarded"]["handler"] == "FX_Admin::rest_guarded"


def test_menu_pages_use_their_capability(index_of):
    e = _by_name(build_map(index_of("surface")))
    assert e["fx-main"]["tier"] == "admin" and e["fx-main"]["handler"] == "FX_Admin::page_main"
    assert e["fx-sub"]["tier"] == "author+" and e["fx-sub"]["capability"] == "edit_posts"


def test_request_hooks_only_when_they_read_input(index_of):
    entries = build_map(index_of("surface"))
    hook_handlers = {e["handler"] for e in entries if e["type"] == "request-hook"}
    assert hook_handlers == {"fx_init_reads_get"}


def test_cron_handler_is_system_tier(index_of):
    e = _by_name(build_map(index_of("surface")))["fx_cron_task"]
    assert e["type"] == "cron" and e["tier"] == "system"


def test_ranking_puts_unauthenticated_unguarded_first(index_of):
    entries = build_map(index_of("surface"))
    assert entries[0]["tier"] == "unauth"
    tiers = [e["tier"] for e in entries]
    order = ["unauth", "subscriber", "author+", "admin", "system"]
    assert tiers == sorted(tiers, key=order.index)
    assert [e["id"] for e in entries] == list(range(1, len(entries) + 1))


@pytest.mark.parametrize(
    ("name", "nonce", "cap"),
    [("csrf-vuln", None, "handler"), ("csrf-safe", "handler", "handler"),
     ("authz-vuln", "handler", None), ("authz-safe", "handler", "handler")],
)
def test_nonce_and_capability_hints_separate_vulnerable_from_safe(name, nonce, cap, index_of):
    [e] = build_map(index_of(name))
    assert (e["nonce_check"], e["cap_check"]) == (nonce, cap)


def test_csrf_handler_on_admin_init_is_listed_because_it_reads_post(index_of):
    [e] = build_map(index_of("csrf-vuln"))
    assert e["type"] == "request-hook" and e["superglobals"] == ["$_POST"]
    assert e["tier"] == "admin"  # capability check found in handler (static hint)


def test_unauthenticated_nopriv_fixtures_rank_as_unauth(index_of):
    for name in ("sqli-vuln", "rce-vuln", "ssrf-vuln", "xxe-vuln"):
        [e] = build_map(index_of(name))
        assert e["tier"] == "unauth", name


def test_dynamic_hook_names_are_reported(tmp_path, backend):
    from _php import build_index

    (tmp_path / "p.php").write_text(
        "<?php function h() { update_option('a', $_POST['a']); } foreach (['x'] as $a) { add_action('wp_ajax_nopriv_' . $a, 'h'); }"
    )
    [e] = build_map(build_index(tmp_path, backend))
    assert e["name"] == "wp_ajax_nopriv_*" and e["dynamic"] is True and e["tier"] == "unauth"
