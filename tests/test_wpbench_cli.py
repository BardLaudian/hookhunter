from __future__ import annotations

import re

import pytest
from helpers import TRUTH, case_block, make_dataset, make_zip, many_cases, sha
from typer.testing import CliRunner

import wpbench.cli as cli
from wpbench.cases import load_cases

runner = CliRunner()
ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture
def dataset(tmp_path):
    return make_dataset(tmp_path)


def run(*args):
    result = runner.invoke(cli.app, [str(a) for a in args])
    return result.exit_code, ANSI.sub("", result.output)


def test_version_and_help():
    assert run("--version")[1].strip() == "0.1.0"
    code, out = run("--help")
    assert code == 0 and all(c in out for c in ("validate", "fetch", "diff", "split"))


def test_validate_reports_valid_and_invalid(dataset):
    code, out = run("validate", "--dataset", dataset(case_block(1)))
    assert code == 0 and "valid" in out and "1 case(s)" in out
    code, out = run("validate", "--dataset", dataset(case_block(1, cve="nope")))
    assert code == 1 and "invalid" in out and "cve" in out


def test_validate_json_output(dataset):
    code, out = run("validate", "--json", "--dataset", dataset(case_block(1) + TRUTH))
    assert code == 0 and '"signed_labels": 0' in out and "not signed" in out


def test_commands_refuse_an_invalid_dataset(dataset, tmp_path):
    path = dataset(case_block(1, cve="nope"))
    for args in (("fetch", "--cases-dir", tmp_path / "c"), ("diff", "wp-0001", "--cases-dir", tmp_path / "c"), ("split", "--seed", "1")):
        code, out = run(*args, "--dataset", path)
        assert code == 1 and "wpbench validate" in out


def test_fetch_diff_flow_with_a_fake_downloader(dataset, tmp_path, monkeypatch):
    old = make_zip({"plugin.php": "<?php\necho $_GET['x'];\n"})
    new = make_zip({"plugin.php": "<?php\necho esc_html( $_GET['x'] );\n"})
    path = dataset(case_block(1, vuln_sha256=sha(old), fixed_sha256=sha(new), split="dev"), case_block(2, split="test"))
    blobs = {
        "https://downloads.wordpress.org/plugin/fake-plugin-1.1.0.0.zip": old,
        "https://downloads.wordpress.org/plugin/fake-plugin-1.1.0.1.zip": new,
    }
    monkeypatch.setattr(cli, "http_download", lambda url: blobs[url])
    cdir = tmp_path / "cases"
    code, out = run("fetch", "--split", "dev", "--dataset", path, "--cases-dir", cdir)
    assert code == 0 and "downloaded" in out and (cdir / "wp-0001" / "vuln" / "plugin.php").is_file()
    assert not (cdir / "wp-0002").exists()
    code, out = run("fetch", "--split", "dev", "--dataset", path, "--cases-dir", cdir)
    assert code == 0 and "cached" in out
    advisories = path.parent / "advisories"
    advisories.mkdir()
    (advisories / "wp-0001.md").write_text("Reflected XSS in plugin.php")
    code, out = run("diff", "wp-0001", "--dataset", path, "--cases-dir", cdir)
    assert code == 0 and "Reflected XSS in plugin.php" in out and "+echo esc_html( $_GET['x'] );" in out and "1 file(s), 2 changed line(s)" in out
    code, out = run("diff", "wp-0001", "--stat", "--dataset", path, "--cases-dir", cdir)
    assert code == 0 and "modified" in out and "+echo" not in out


def test_fetch_failures_and_bad_arguments(dataset, tmp_path, monkeypatch):
    path = dataset(case_block(1, split="dev", vuln_sha256="e" * 64))
    monkeypatch.setattr(cli, "http_download", lambda url: make_zip({"a.php": "x"}))
    code, out = run("fetch", "--dataset", path, "--cases-dir", tmp_path / "c")
    assert code == 1 and "SHA-256 mismatch" in out
    assert run("fetch", "--split", "train", "--dataset", path)[0] == 2
    assert run("fetch", "--case", "wp-9999", "--dataset", path)[0] == 2
    assert run("diff", "wp-9999", "--dataset", path)[0] == 2
    code, out = run("diff", "wp-0001", "--dataset", path, "--cases-dir", tmp_path / "none")
    assert code == 1 and "not fetched" in out


def test_split_dry_run_then_write(dataset):
    path = dataset(*many_cases(10))
    before = path.read_text()
    code, out = run("split", "--seed", "abc", "--dataset", path)
    assert code == 0 and "dry run" in out and path.read_text() == before and not path.with_name("splits.toml").exists()
    code, out = run("split", "--seed", "abc", "--write", "--dataset", path)
    assert code == 0 and path.with_name("splits.toml").is_file()
    cases, issues = load_cases(path)
    assert [i for i in issues if i.level == "error"] == [] and all(c.split in ("dev", "test") for c in cases)
    code, out = run("validate", "--dataset", path)
    assert code == 0
    code, out = run("split", "--seed", "abc", "--write", "--dataset", path)
    assert code == 1 and "frozen" in out


@pytest.mark.parametrize("module", ["wpbench.__main__"])
def test_module_entry_point_exists(module):
    import importlib.util

    assert importlib.util.find_spec(module) is not None
