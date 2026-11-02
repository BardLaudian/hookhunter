from __future__ import annotations

import re
import tomllib

import pytest
from helpers import case_block, make_dataset
from typer.testing import CliRunner

import wpbench.cli as cli
from wpbench.cases import load_cases
from wpbench.diff import FileDiff
from wpbench.review import ReviewError, check_truth, drop_version_noise, excerpt, hunk_ranges, sign_text

runner = CliRunner()
ANSI = re.compile(r"\x1b\[[0-9;]*m")

PHP = "<?php\n" + "\n".join(f"// line {i}" for i in range(2, 30)) + "\nfunction save_settings() {\n    echo $_POST['t'];\n}\n"
TRUTH_BLOCK = '''[case.truth]
file = "a.php"
function = "save_settings"
line_start = {start}
line_end = {end}
entry_point = "ajax"
data_flow = "x -> y"
notes = "fix adds esc_html()"
drafted_by = "claude"
'''


def one_case(tmp_path, start=31, end=32, **over):
    path = make_dataset(tmp_path)(case_block(1, **over) + TRUTH_BLOCK.format(start=start, end=end), case_block(2))
    cases, _ = load_cases(path)
    return path, cases[0]


def diff_for(path, line):
    return FileDiff(path, "modified", 1, 1, f"--- a\n+++ b\n@@ -{line},2 +{line},2 @@\n-x\n+y\n")


def test_hunk_ranges_use_old_file_lines():
    text = "@@ -10,3 +10,4 @@\n a\n@@ -40 +41,2 @@\n b\n@@ -7,0 +8 @@\n"
    assert hunk_ranges(text) == [(10, 12), (40, 40), (7, 7)]


def test_drop_version_noise_keeps_the_security_change():
    text = "-Version: 1.0\n+Version: 1.1\n-echo $x;\n+echo esc_html($x);\n context\n"
    assert drop_version_noise(text) == "-echo $x;\n+echo esc_html($x);\n context\n"


def test_excerpt_marks_labelled_lines_and_truncates(tmp_path):
    f = tmp_path / "a.php"
    f.write_text(PHP)
    out = excerpt(f, 31, 32, context=2)
    assert "<-- label" in out and out.count("<-- label") == 2 and "line 29" in out
    assert "more line(s)" in excerpt(f, 2, 30, context=0, max_lines=5)


def test_checks_pass_on_a_consistent_label(tmp_path):
    _, c = one_case(tmp_path)
    vuln = tmp_path / "v"
    vuln.mkdir()
    (vuln / "a.php").write_text(PHP)
    found = {f.name: f for f in check_truth(c, vuln, [diff_for("a.php", 31)])}
    assert found["function"].level == "ok" and found["fix"].level == "ok" and found["lines"].level == "ok"


def test_checks_flag_a_missing_file_bad_lines_and_a_far_fix(tmp_path):
    _, c = one_case(tmp_path)
    vuln = tmp_path / "v"
    vuln.mkdir()
    assert check_truth(c, vuln, [])[0].level == "error"
    (vuln / "a.php").write_text(PHP)
    far = {f.name: f for f in check_truth(c, vuln, [diff_for("a.php", 3)])}
    assert far["fix"].level == "warn"
    none = {f.name: f for f in check_truth(c, vuln, [diff_for("other.php", 31)])}
    assert "does not change the labelled file" in none["fix"].detail
    _, beyond = one_case(tmp_path, start=500, end=510)
    assert any(f.level == "error" and f.name == "lines" for f in check_truth(beyond, vuln, []))


def test_checks_report_draft_doubts_and_a_missing_function(tmp_path):
    path = make_dataset(tmp_path)(case_block(1) + TRUTH_BLOCK.format(start=31, end=32).replace("fix adds esc_html()", "fix adds esc_html()\\nDraft: not traced").replace("save_settings", "nothing_here"))
    cases, _ = load_cases(path)
    vuln = tmp_path / "v"
    vuln.mkdir()
    (vuln / "a.php").write_text(PHP)
    names = {f.name: f for f in check_truth(cases[0], vuln, [diff_for("a.php", 31)])}
    assert names["function"].level == "warn" and "open doubt" in names["notes"].detail


def test_sign_text_adds_the_review_fields_and_only_for_that_case(tmp_path):
    path, _ = one_case(tmp_path)
    text = path.read_text()
    out = sign_text(text, "wp-0001", "Ana", "2026-11-03")
    data = tomllib.loads(out)["case"]
    assert data[0]["truth"]["reviewed_by"] == "Ana" and data[0]["truth"]["reviewed_on"] == "2026-11-03"
    assert "truth" not in data[1]
    again = sign_text(out, "wp-0001", "Luis", "2026-11-04")
    assert tomllib.loads(again)["case"][0]["truth"]["reviewed_by"] == "Luis" and again.count("reviewed_by") == 1


def test_sign_text_refuses_bad_input(tmp_path):
    path, _ = one_case(tmp_path)
    text = path.read_text()
    for args in (("wp-0009", "Ana", "2026-11-03"), ("wp-0002", "Ana", "2026-11-03"), ("wp-0001", "", "2026-11-03"), ("wp-0001", 'A"b', "2026-11-03"), ("wp-0001", "Ana", "3/11/2026")):
        with pytest.raises(ReviewError):
            sign_text(text, *args)


def fetched(tmp_path):
    path, _ = one_case(tmp_path)
    for role, body in (("vuln", PHP), ("fixed", PHP.replace("echo $_POST['t'];", "echo esc_html( $_POST['t'] );"))):
        d = tmp_path / "cases" / "wp-0001" / role
        d.mkdir(parents=True)
        (d / "a.php").write_text(body)
    return path


def run(*args):
    result = runner.invoke(cli.app, [str(a) for a in args])
    return result.exit_code, ANSI.sub("", result.output)


def test_review_cli_lists_shows_and_signs(tmp_path):
    path = fetched(tmp_path)
    cdir = tmp_path / "cases"
    code, out = run("review", "--pending", "--dataset", path)
    assert code == 0 and "wp-0001" in out and "0 of 2 labels signed" in out
    code, out = run("review", "wp-0001", "--dataset", path, "--cases-dir", cdir)
    assert code == 0 and "<-- label" in out and "ok    function" in out and "+    echo esc_html( $_POST['t'] );" in out
    code, out = run("review", "wp-0001", "--sign", "--dataset", path, "--cases-dir", cdir)
    assert code == 2 and "--by" in out
    code, out = run("review", "wp-0001", "--sign", "--by", "Ana", "--dataset", path, "--cases-dir", cdir, "--yes", "--on", "2026-11-03")
    assert code == 0 and "signed wp-0001 as Ana" in out
    cases, _ = load_cases(path)
    assert cases[0].signed
    code, out = run("review", "wp-0001", "--sign", "--by", "Ana", "--dataset", path, "--cases-dir", cdir, "--yes")
    assert code == 1 and "already signed" in out


def test_review_cli_asks_for_confirmation_and_blocks_on_errors(tmp_path):
    path = fetched(tmp_path)
    cdir = tmp_path / "cases"
    result = runner.invoke(cli.app, ["review", "wp-0001", "--sign", "--by", "Ana", "--dataset", str(path), "--cases-dir", str(cdir)], input="n\n")
    assert result.exit_code == 1 and not load_cases(path)[0][0].signed
    (cdir / "wp-0001" / "vuln" / "a.php").unlink()
    code, out = run("review", "wp-0001", "--sign", "--by", "Ana", "--dataset", path, "--cases-dir", cdir, "--yes")
    assert code == 1 and "automatic checks found errors" in out and not load_cases(path)[0][0].signed


def test_review_cli_checks_every_case(tmp_path):
    path = fetched(tmp_path)
    code, out = run("review", "--checks", "--dataset", path, "--cases-dir", tmp_path / "cases")
    assert code == 0 and "wp-0002: not fetched" in out and "finding(s) from the automatic checks" in out
