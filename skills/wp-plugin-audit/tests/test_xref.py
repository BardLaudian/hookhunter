from __future__ import annotations

from wp_xref import xref


def test_function_definition_callers_and_registration(index_of):
    r = xref(index_of("surface"), "fx_post_c")
    assert [d["function"] for d in r["definitions"]] == ["fx_post_c"]
    assert {(x["hook"], x["registrar"]) for x in r["registered_as"]} == {("admin_post_nopriv_fx_c", "add_action")}


def test_method_registered_through_array_callback(index_of):
    r = xref(index_of("surface"), "FX_Admin::ajax_b")
    assert [x["hook"] for x in r["registered_as"]] == ["wp_ajax_nopriv_fx_b"]
    assert any(c["name"] == "update_option" for c in r["callees"])


def test_callers_with_receiver(index_of):
    r = xref(index_of("surface"), "verify")
    assert [(c["function"], c["receiver"]) for c in r["callers"]] == [("FX_Admin::ajax_a", "$this")]


def test_hook_name_returns_its_handlers(index_of):
    r = xref(index_of("surface"), "wp_ajax_nopriv_fx_b")
    assert r["hook_handlers"][0]["handler"] == "FX_Admin::ajax_b"
    assert r["definitions"] == []


def test_rest_callback_registration(index_of):
    r = xref(index_of("surface"), "fx_rest_missing")
    assert [x["hook"] for x in r["registered_as"]] == ["rest:fx/v1/missing"]


def test_unknown_name_is_empty_not_an_error(index_of):
    r = xref(index_of("surface"), "does_not_exist")
    assert r["definitions"] == r["callers"] == r["registered_as"] == []
