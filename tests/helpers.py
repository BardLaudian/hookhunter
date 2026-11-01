from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from wpbench.vocab import CLASSES


def make_zip(files: dict[str, str], top: str | None = "fake-plugin", extra: list[zipfile.ZipInfo] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(f"{top}/{name}" if top else name, text)
        for info in extra or []:
            zf.writestr(info, "x")
    return buf.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def case_block(n: int = 1, **over: object) -> str:
    """TOML text of one valid [[case]]; override any field with a keyword (None removes it)."""
    fields: dict[str, object] = {
        "id": f"wp-{n:04d}", "cve": f"CVE-2026-{1000 + n}", "source": "wordfence", "source_url": f"https://example.invalid/advisory/{n}",
        "retrieved": "2026-11-02", "slug": f"fake-plugin-{n}", "vuln_version": "1.0.0", "fixed_version": "1.0.1",
        "vuln_sha256": "a" * 64, "fixed_sha256": "b" * 64, "cwe": "CWE-79", "class": "stored-xss", "auth": "subscriber",
        "published": "2026-07-15", "after_cutoff": True,
    }
    fields.update(over)
    lines = ["[[case]]"]
    for key, value in fields.items():
        if value is None:
            continue
        lines.append(f"{key} = {str(value).lower() if isinstance(value, bool) else (value if isinstance(value, int) else repr(value).replace(chr(39), chr(34)))}")
    return "\n".join(lines) + "\n"


TRUTH = '''[case.truth]
file = "includes/class-admin.php"
function = "save_settings"
line_start = 120
line_end = 134
entry_point = "wp_ajax_save_settings"
data_flow = "$_POST['title'] -> update_option -> echo"
notes = "fix adds esc_html()"
'''


def make_dataset(tmp_path: Path):
    """Return a function that writes the given [[case]] blocks to tmp_path/dataset/cases.toml and returns its path."""

    def _write(*blocks: str) -> Path:
        path = tmp_path / "dataset" / "cases.toml"
        path.parent.mkdir(exist_ok=True)
        path.write_text("\n".join(blocks))
        return path

    return _write


def many_cases(n: int, classes: tuple[str, ...] | None = None) -> list[str]:
    classes = classes or CLASSES[:5]
    return [case_block(i, **{"class": classes[i % len(classes)]}) for i in range(1, n + 1)]
