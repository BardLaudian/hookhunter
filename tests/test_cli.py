from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import BACKENDS, FIXTURES

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("script", ["wp_map.py", "wp_sinks.py"])
def test_cli_emits_json(script):
    p = run(script, str(FIXTURES / "sqli-vuln"))
    assert p.returncode == 0, p.stderr
    data = json.loads(p.stdout)
    assert data["files_parsed"] == 1 and data["backend"] in ("treesitter", "regex")


def test_xref_cli():
    p = run("wp_xref.py", str(FIXTURES / "surface"), "fx_cron")
    assert json.loads(p.stdout)["registered_as"][0]["hook"] == "fx_cron_task"


@pytest.mark.parametrize("script", ["wp_map.py", "wp_sinks.py"])
def test_cli_rejects_missing_directory(script, tmp_path):
    p = run(script, str(tmp_path / "nope"))
    assert p.returncode == 2 and "not a directory" in p.stderr


def test_map_top_n_reports_truncation():
    data = json.loads(run("wp_map.py", str(FIXTURES / "surface"), "--top", "3").stdout)
    assert data["entry_points_shown"] == 3 and data["truncated"] is True and data["entry_points_total"] > 3


def test_sinks_filters_by_class_and_risk():
    data = json.loads(run("wp_sinks.py", str(FIXTURES / "sqli-vuln"), "--class", "sqli", "--risk", "unguarded").stdout)
    assert data["sinks"] and all(s["risk"] == "unguarded" and "sqli" in s["classes"] for s in data["sinks"])


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("script", ["wp_map.py", "wp_sinks.py"])
def test_large_tree_finishes_well_under_30_seconds(script, backend, tmp_path):
    """1,000-file synthetic plugin, as required by SKILL-DESIGN.md section 3."""
    body = (FIXTURES / "surface" / "surface.php").read_text()
    for i in range(1000):
        (tmp_path / f"f{i}.php").write_text(
            body.replace("FX_", f"FX{i}_").replace("fx_", f"fx{i}_") + ("\n// pad\n" * 20)
        )
    start = time.monotonic()
    p = run(script, str(tmp_path), "--backend", backend)
    elapsed = time.monotonic() - start
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["files_parsed"] == 1000
    assert elapsed < 30, f"{script} [{backend}] took {elapsed:.1f}s"
