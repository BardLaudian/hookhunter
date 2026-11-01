"""Download plugin releases from wordpress.org, verify their SHA-256 and unpack them safely.

Nothing here runs plugin code: archives are only read and written to disk. The dataset stores slugs, versions and hashes, never source;
the unpacked trees live under cases/ (git-ignored).
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import shutil
import stat
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from wpbench.cases import Case

Downloader = Callable[[str], bytes]
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
MAX_ENTRIES = 50_000
USER_AGENT = "wpbench/0.1 (static-analysis research; fetches released plugin zips)"


class FetchError(Exception):
    """A release could not be fetched, verified or unpacked."""


def http_download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL built from validated slug and version
            data: bytes = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise FetchError(f"download failed for {url}: {exc}") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise FetchError(f"{url} is larger than {MAX_DOWNLOAD_BYTES // 1024 // 1024} MB")
    return data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member_error(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    if "\\" in name or ":" in name or name.startswith("/"):
        return "absolute or non-portable path"
    if ".." in posixpath.normpath(name).split("/"):
        return "path escapes the destination"
    mode = info.external_attr >> 16
    if mode and stat.S_ISLNK(mode):
        return "symbolic link"
    return None


def safe_unpack(data: bytes, dest: Path) -> int:
    """Unpack a zip into dest (created fresh). Rejects traversal, links and oversized archives. Returns the number of files written."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise FetchError(f"not a valid zip archive: {exc}") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise FetchError(f"archive has {len(infos)} entries (limit {MAX_ENTRIES})")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
        raise FetchError(f"archive expands beyond {MAX_UNPACKED_BYTES // 1024 // 1024} MB")
    for info in infos:
        problem = _member_error(info)
        if problem:
            raise FetchError(f"unsafe archive member {info.filename!r}: {problem}")
    tops = {posixpath.normpath(i.filename).split("/")[0] for i in infos}
    strip = len(tops) == 1 and all(i.is_dir() or "/" in i.filename for i in infos)
    tmp = dest.with_name(dest.name + ".partial")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    root = tmp.resolve()
    written = 0
    for info in infos:
        parts = posixpath.normpath(info.filename).split("/")
        rel = "/".join(parts[1:] if strip else parts)
        if info.is_dir() or not rel:
            continue
        target = (root / rel).resolve()
        if not target.is_relative_to(root):
            raise FetchError(f"unsafe archive member {info.filename!r}: path escapes the destination")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(info))  # file modes are not restored: nothing becomes executable
        written += 1
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    return written


@dataclass(frozen=True)
class FetchResult:
    case_id: str
    role: str  # "vuln" | "fixed"
    status: str  # "downloaded" | "cached"
    sha256: str
    path: Path
    files: int
    hashed: bool


def _marker(cases_dir: Path, case_id: str, role: str) -> Path:
    return cases_dir / case_id / f".{role}.ok"


def fetch_release(case: Case, role: str, cases_dir: Path, download: Downloader = http_download, allow_unhashed: bool = False) -> FetchResult:
    version = case.vuln_version if role == "vuln" else case.fixed_version
    expected = case.vuln_sha256 if role == "vuln" else case.fixed_sha256
    if not expected and not allow_unhashed:
        raise FetchError(f"{case.id} {role}: no SHA-256 recorded; fetch once with --allow-unhashed, review the printed hash and record it in the dataset")
    dest = cases_dir / case.id / role
    marker = _marker(cases_dir, case.id, role)
    if expected and dest.is_dir() and marker.is_file():
        info = json.loads(marker.read_text())
        if info.get("sha256") == expected:
            return FetchResult(case.id, role, "cached", expected, dest, int(info.get("files", 0)), True)
    url = case.zip_url(version)
    data = download(url)
    actual = sha256_hex(data)
    if expected and actual != expected:
        raise FetchError(
            f"{case.id} {role}: SHA-256 mismatch for {url}\n  expected {expected}\n  actual   {actual}\n"
            "wordpress.org may have regenerated the zip; re-verify before updating the dataset. Nothing was unpacked."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    files = safe_unpack(data, dest)
    marker.write_text(json.dumps({"sha256": actual, "url": url, "files": files}) + "\n")
    return FetchResult(case.id, role, "downloaded", actual, dest, files, bool(expected))


def fetch_case(case: Case, cases_dir: Path, download: Downloader = http_download, allow_unhashed: bool = False) -> list[FetchResult]:
    return [fetch_release(case, role, cases_dir, download, allow_unhashed) for role in ("vuln", "fixed")]
