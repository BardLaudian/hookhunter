from __future__ import annotations

import json
import zipfile

import pytest
from helpers import case_block, make_dataset, make_zip, sha

from wpbench.cases import load_cases
from wpbench.fetch import FetchError, fetch_case, fetch_release, safe_unpack

OLD = make_zip({"plugin.php": "<?php echo 1;", "inc/a.php": "<?php // old"})
NEW = make_zip({"plugin.php": "<?php echo 2;", "inc/a.php": "<?php // old"})


@pytest.fixture
def dataset(tmp_path):
    return make_dataset(tmp_path)


def case(dataset, **over):
    over = {"vuln_sha256": sha(OLD), "fixed_sha256": sha(NEW), **over}
    return load_cases(dataset(case_block(1, **over)))[0][0]


class Downloader:
    def __init__(self, blobs):
        self.blobs, self.calls = blobs, []

    def __call__(self, url):
        self.calls.append(url)
        return self.blobs[url]


def blobs(c):
    return {c.zip_url(c.vuln_version): OLD, c.zip_url(c.fixed_version): NEW}


def test_downloads_verifies_and_unpacks_without_the_top_directory(dataset, tmp_path):
    c = case(dataset)
    dl = Downloader(blobs(c))
    results = fetch_case(c, tmp_path / "cases", dl)
    assert [r.status for r in results] == ["downloaded", "downloaded"]
    assert (tmp_path / "cases/wp-0001/vuln/plugin.php").read_text() == "<?php echo 1;"
    assert (tmp_path / "cases/wp-0001/fixed/inc/a.php").is_file()
    assert dl.calls == ["https://downloads.wordpress.org/plugin/fake-plugin-1.1.0.0.zip", "https://downloads.wordpress.org/plugin/fake-plugin-1.1.0.1.zip"]
    marker = json.loads((tmp_path / "cases/wp-0001/.vuln.ok").read_text())
    assert marker["sha256"] == sha(OLD) and marker["files"] == 2


def test_second_fetch_uses_the_cache(dataset, tmp_path):
    c = case(dataset)
    dl = Downloader(blobs(c))
    fetch_case(c, tmp_path, dl)
    again = fetch_case(c, tmp_path, dl)
    assert [r.status for r in again] == ["cached", "cached"] and len(dl.calls) == 2


def test_hash_mismatch_refuses_and_unpacks_nothing(dataset, tmp_path):
    c = case(dataset, vuln_sha256="c" * 64)
    with pytest.raises(FetchError, match="SHA-256 mismatch"):
        fetch_release(c, "vuln", tmp_path, Downloader(blobs(c)))
    assert not (tmp_path / "wp-0001" / "vuln").exists()


def test_cached_tree_is_not_trusted_if_the_recorded_hash_changed(dataset, tmp_path):
    c = case(dataset)
    fetch_release(c, "vuln", tmp_path, Downloader(blobs(c)))
    c.vuln_sha256 = "d" * 64
    with pytest.raises(FetchError, match="mismatch"):
        fetch_release(c, "vuln", tmp_path, Downloader(blobs(c)))


def test_unhashed_release_needs_an_explicit_flag(dataset, tmp_path):
    c = case(dataset, vuln_sha256="")
    with pytest.raises(FetchError, match="no SHA-256 recorded"):
        fetch_release(c, "vuln", tmp_path, Downloader(blobs(c)))
    r = fetch_release(c, "vuln", tmp_path, Downloader(blobs(c)), allow_unhashed=True)
    assert r.sha256 == sha(OLD) and not r.hashed


def test_download_errors_propagate(dataset, tmp_path):
    c = case(dataset)

    def boom(url):
        raise FetchError("offline")

    with pytest.raises(FetchError, match="offline"):
        fetch_release(c, "vuln", tmp_path, boom)


@pytest.mark.parametrize("name", ["../evil.php", "plugin/../../evil.php", "/abs/evil.php", "C:/evil.php", "a\\..\\evil.php"])
def test_unsafe_member_names_are_rejected(tmp_path, name):
    buf = make_zip({}, top=None, extra=[zipfile.ZipInfo(name)])
    with pytest.raises(FetchError, match="unsafe archive member"):
        safe_unpack(buf, tmp_path / "out")
    assert not (tmp_path / "out").exists() and not (tmp_path.parent / "evil.php").exists()


def test_symlink_members_are_rejected(tmp_path):
    info = zipfile.ZipInfo("fake-plugin/link.php")
    info.external_attr = (0o120777) << 16
    with pytest.raises(FetchError, match="symbolic link"):
        safe_unpack(make_zip({"a.php": "x"}, extra=[info]), tmp_path / "out")


def test_not_a_zip_and_oversized_archives_are_rejected(tmp_path, monkeypatch):
    with pytest.raises(FetchError, match="not a valid zip"):
        safe_unpack(b"nope", tmp_path / "out")
    import wpbench.fetch as f

    monkeypatch.setattr(f, "MAX_UNPACKED_BYTES", 5)
    with pytest.raises(FetchError, match="expands beyond"):
        safe_unpack(make_zip({"a.php": "0123456789"}), tmp_path / "out2")
    monkeypatch.setattr(f, "MAX_ENTRIES", 1)
    with pytest.raises(FetchError, match="entries"):
        safe_unpack(make_zip({"a.php": "1", "b.php": "2"}), tmp_path / "out3")


def test_archive_with_several_top_level_entries_keeps_its_layout(tmp_path):
    n = safe_unpack(make_zip({"a.php": "1", "b/c.php": "2"}, top=None), tmp_path / "out")
    assert n == 2 and (tmp_path / "out/b/c.php").is_file()


def test_file_modes_are_not_restored(tmp_path):
    info = zipfile.ZipInfo("fake-plugin/run.sh")
    info.external_attr = 0o100755 << 16
    safe_unpack(make_zip({}, extra=[info]), tmp_path / "out")
    assert not (tmp_path / "out/run.sh").stat().st_mode & 0o111
