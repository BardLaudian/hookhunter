from __future__ import annotations

from pathlib import Path

from wpbench.diff import changed_lines, diff_trees


def tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_only_php_changes_are_reported_with_statuses_and_counts(tmp_path):
    old = tree(tmp_path / "old", {"a.php": "<?php\necho $x;\n", "gone.php": "<?php\n", "same.php": "<?php\n", "readme.txt": "1", "app.js": "a"})
    new = tree(tmp_path / "new", {"a.php": "<?php\necho esc_html( $x );\n", "added.inc": "<?php\n", "same.php": "<?php\n", "readme.txt": "2", "app.js": "b"})
    diffs = diff_trees(old, new)
    assert [(d.path, d.status) for d in diffs] == [("a.php", "modified"), ("added.inc", "added"), ("gone.php", "removed")]
    a = diffs[0]
    assert (a.added, a.removed) == (1, 1) and "--- vuln/a.php" in a.text and "+echo esc_html( $x );" in a.text
    assert changed_lines(diffs) == 4  # a.php +1 -1, added.inc +1, gone.php -1


def test_changed_line_total(tmp_path):
    old = tree(tmp_path / "old", {"a.php": "1\n2\n3\n"})
    new = tree(tmp_path / "new", {"a.php": "1\nX\n3\n4\n"})
    assert changed_lines(diff_trees(old, new)) == 3  # -2, +X, +4


def test_identical_trees_and_crlf_differences_produce_nothing(tmp_path):
    old = tree(tmp_path / "old", {"a.php": "<?php\r\necho 1;\r\n"})
    new = tree(tmp_path / "new", {"a.php": "<?php\necho 1;\n"})
    assert diff_trees(old, new) == []


def test_missing_trailing_newline_and_odd_bytes_do_not_crash(tmp_path):
    old = tmp_path / "old"
    old.mkdir()
    (old / "a.php").write_bytes(b"<?php \xff\xfe")
    new = tree(tmp_path / "new", {"a.php": "<?php echo 1;"})
    [d] = diff_trees(old, new)
    assert "No newline at end of file" in d.text


def test_subdirectories_use_forward_slashes(tmp_path):
    old = tree(tmp_path / "old", {"inc/deep/a.php": "1\n"})
    new = tree(tmp_path / "new", {"inc/deep/a.php": "2\n"})
    assert diff_trees(old, new)[0].path == "inc/deep/a.php"
