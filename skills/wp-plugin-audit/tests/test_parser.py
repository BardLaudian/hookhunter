from __future__ import annotations

import pytest
from _php import build_index, split_args, tree_sitter_available, unparen
from conftest import FIXTURES, marker_lines


def _sig(idx):
    calls = sorted(
        (c.file, c.line, c.name, c.kind, c.recv, c.args, idx.funcs[c.func].qualname if c.func >= 0 else "")
        for c in idx.calls
    )
    funcs = sorted((f.file, f.qualname, f.line, f.end_line) for f in idx.funcs)
    return calls, funcs


@pytest.mark.skipif(not tree_sitter_available(), reason="tree-sitter not installed")
def test_backends_agree_on_every_fixture():
    ts = build_index(FIXTURES, "treesitter")
    rx = build_index(FIXTURES, "regex")
    assert ts.files == rx.files
    assert _sig(ts) == _sig(rx)


def test_auto_falls_back_to_regex_without_tree_sitter(monkeypatch):
    import _php

    monkeypatch.setattr(_php, "tree_sitter_available", lambda: False)
    assert build_index(FIXTURES / "xss-vuln").backend == "regex"


def test_comments_strings_heredocs_and_html_are_not_code(index_of):
    idx = index_of("edge")
    by_line = {(c.line, c.name) for c in idx.calls}
    assert not any(line <= 14 and name in ("add_action", "echo", "eval", "wp_remote_get") for line, name in by_line)
    assert not any(c.name == "echo" and "html" in " ".join(c.args) for c in idx.calls)


def test_qualified_calls_and_closures(index_of):
    idx = index_of("edge")
    [remote] = [c for c in idx.calls if c.name == "wp_remote_get"]
    assert remote.line == marker_lines("edge", "QUALIFIED")[0]
    assert idx.func_of(remote).qualname == "Fetcher::run"
    [unser] = [c for c in idx.calls if c.name == "unserialize"]
    assert idx.func_of(unser).name == "{closure}"
    assert any(c.kind == "new" and c.name == "fetcher" for c in idx.calls)


def test_inline_echo_tag_is_an_echo(index_of):
    idx = index_of("edge")
    inline = [c for c in idx.calls if c.name == "echo" and "name" in " ".join(c.args)]
    assert [c.func for c in inline] and idx.func_of(inline[0]).name == "render_inline"
    after = [c for c in idx.calls if c.name == "echo" and "after_inline" in " ".join(c.args)]
    assert after


def test_method_receivers_and_static_calls(index_of):
    idx = index_of("surface")
    helper = [c for c in idx.calls if c.name == "verify"]
    assert helper and helper[0].kind == "method" and helper[0].recv == "$this"


def test_unparseable_file_does_not_crash(tmp_path, backend):
    (tmp_path / "broken.php").write_text("<?php function ( { echo $x; add_action('a', ")
    idx = build_index(tmp_path, backend)
    assert idx.files == ["broken.php"]


def test_vendor_and_oversized_files_are_reported_as_skipped(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.php").write_text("<?php echo $_GET['x'];")
    (tmp_path / "main.php").write_text("<?php echo 1;")
    idx = build_index(tmp_path, "regex")
    assert idx.files == ["main.php"]
    assert {"path": "vendor", "reason": "skipped-dir"} in idx.skipped


def test_split_args_ignores_commas_in_strings_and_nesting():
    assert split_args("'a,b', array(1, 2), f($x, $y)") == ["'a,b'", "array(1, 2)", "f($x, $y)"]
    assert split_args("") == []


def test_unparen_only_strips_a_wrapping_pair():
    assert unparen("(__DIR__ . '/x')") == "__DIR__ . '/x'"
    assert unparen("(a) . (b)") == "(a) . (b)"
