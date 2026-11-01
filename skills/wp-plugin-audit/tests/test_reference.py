"""Checks on the knowledge files in reference/ (S2): layout, links to code, scoring tables, safety rules.

External links are checked only when WPBENCH_CHECK_URLS=1 (slow, needs network).
"""

from __future__ import annotations

import math
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import pytest
from wp_sinks import RULES

SKILL = Path(__file__).resolve().parents[1]
REFERENCE = SKILL / "reference"
SCRIPTS = SKILL / "scripts"
REPO = SKILL.parents[1]

# Layout from docs/SKILL-DESIGN.md section 1, plus the index added in S2.
EXPECTED = [
    "README.md", "surface.md", "sanitizers.md", "wp-traps.md", "verification.md", "severity.md", "report.md",
    *(f"classes/{c}.md" for c in (
        "xss", "sqli", "authz", "csrf", "file-ops", "object-injection", "ssrf", "open-redirect", "privesc",
        "rce", "info-disclosure", "xxe")),
]
FILES = sorted(REFERENCE.rglob("*.md"))
CONTENT_FILES = [f for f in FILES if f.name != "README.md"]
CLASS_FILES = sorted((REFERENCE / "classes").glob("*.md"))
# Documents outside reference/ (or written later) that the reference files may name.
EXTERNAL_DOCS = {"SPEC.md", "DATASET.md", "DECISIONS.md", "PLAN.md", "SKILL-DESIGN.md", "SKILL.md"}
# CVE identifiers allowed in the reference: FIRST's published CVSS examples (not WordPress plugins).
ALLOWED_CVES = {"CVE-2019-7551", "CVE-2015-0970"}


def rel(path: Path) -> str:
    return str(path.relative_to(REFERENCE))


def test_layout_is_complete():
    missing = [name for name in EXPECTED if not (REFERENCE / name).is_file()]
    assert missing == []
    extra = sorted(rel(f) for f in FILES if rel(f) not in EXPECTED)
    assert extra == [], "new reference files must be added to EXPECTED and to README.md"


@pytest.mark.parametrize("path", FILES, ids=rel)
def test_file_is_at_most_200_lines(path):
    assert len(path.read_text().splitlines()) <= 200


@pytest.mark.parametrize("path", CONTENT_FILES, ids=rel)
def test_file_ends_with_a_sources_section(path):
    headings = [line for line in path.read_text().splitlines() if line.startswith("## ")]
    assert headings and headings[-1].strip() == "## Sources"


@pytest.mark.parametrize("path", CLASS_FILES, ids=rel)
def test_class_file_has_the_sections_the_design_requires(path):
    text = path.read_text()
    for needle in ("Refutation checklist", "Typical CVSS", "What triagers reject", "Traps specific", "Vulnerable and safe shapes", "## Sources"):
        assert needle in text, f"{rel(path)} lacks '{needle}'"
    assert "```" in text, "no generic code example"


@pytest.mark.parametrize("path", FILES, ids=rel)
def test_markdown_file_references_resolve(path):
    names = set(re.findall(r"`(?:[\w./-]*/)?([\w-]+\.md)`", path.read_text()))
    known = {f.name for f in FILES} | EXTERNAL_DOCS
    assert sorted(names - known) == []


@pytest.mark.parametrize("path", FILES, ids=rel)
def test_script_references_exist(path):
    names = set(re.findall(r"`([\w]+\.py)", path.read_text()))
    shipped = {p.name for p in SCRIPTS.glob("*.py")} | {p.name for p in (SKILL / "tests").glob("*.py")}
    assert sorted(names - shipped) == []


def test_wp_sinks_class_flags_name_real_rule_classes():
    rule_classes = {c for rule in RULES for c in rule.classes}
    used: set[str] = set()
    for path in FILES:
        for flag in re.findall(r"--class ([\w,-]+)", path.read_text()):
            used.update(flag.split(","))
    assert used, "expected at least one --class example"
    assert sorted(used - rule_classes) == []


def test_only_allowed_cve_ids_appear():
    found = {m for f in FILES for m in re.findall(r"CVE-\d{4}-\d+", f.read_text())}
    assert found <= ALLOWED_CVES, sorted(found - ALLOWED_CVES)


def test_reference_has_no_content_from_benchmark_cases():
    """docs/SKILL-DESIGN.md section 4: no plugin names, CVEs or snippets from dev or test cases."""
    cases = REPO / "dataset" / "cases.toml"
    if not cases.is_file():
        pytest.skip("no dataset yet")
    import tomllib

    data = tomllib.loads(cases.read_text())
    needles = {c[k] for c in data.get("case", []) for k in ("slug", "cve") if c.get(k)}
    blob = "\n".join(f.read_text() for f in FILES).lower()
    assert sorted(n for n in needles if n.lower() in blob) == []


PAYLOAD_PATTERNS = [
    r"alert\s*\(", r"\bonerror\s*=", r"\bonload\s*=", r"<script[^>]*>[^<`]+</script>", r"\bunion\s+(all\s+)?select\b",
    r"\bor\s+1\s*=\s*1\b", r"\bsleep\s*\(\s*\d", r"<\?php\s+(system|eval|exec|passthru|shell_exec)\b",
    r"javascript:\s*\w+\(", r"\bphpinfo\s*\(\s*\)\s*;?\s*\?>",
]


@pytest.mark.parametrize("path", FILES, ids=rel)
def test_no_weaponised_payloads(path):
    text = path.read_text()
    hits = [p for p in PAYLOAD_PATTERNS if re.search(p, text, re.I)]
    assert hits == []


# --- CVSS tables ---------------------------------------------------------------------------------

_W = {
    "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62}, "CIA": {"N": 0.0, "L": 0.22, "H": 0.56},
    "PRU": {"N": 0.85, "L": 0.62, "H": 0.27}, "PRC": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31(v: dict[str, str]) -> float:
    """CVSS 3.1 base score for a network-vector metric dict (AV is always N in this skill)."""
    iss = 1 - (1 - _W["CIA"][v["C"]]) * (1 - _W["CIA"][v["I"]]) * (1 - _W["CIA"][v["A"]])
    pr = (_W["PRC"] if v["S"] == "C" else _W["PRU"])[v["PR"]]
    exploit = 8.22 * 0.85 * _W["AC"][v["AC"]] * pr * _W["UI"][v["UI"]]
    if iss <= 0:
        return 0.0
    if v["S"] == "U":
        return _roundup(min(6.42 * iss + exploit, 10))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return _roundup(min(1.08 * (impact + exploit), 10))


# Metrics that a class file states once above its table instead of in every row.
_BASE = {"AC": "L", "UI": "N", "S": "U"}
_FILE_DEFAULTS = {"csrf.md": {"UI": "R"}, "xss.md": {"UI": "R"}, "open-redirect.md": {"UI": "R", "PR": "N"}}
_ROW = re.compile(r"\|(.*)\|\s*`([A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])*)`\s*\|\s*(\d+\.\d)\s*\|\s*$")


def _cvss_rows():
    rows = []
    for path in CLASS_FILES:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            m = _ROW.match(line)
            if m:
                vec = {**_BASE, **_FILE_DEFAULTS.get(path.name, {})}
                vec.update(dict(kv.split(":") for kv in m.group(2).split("/")))
                rows.append(pytest.param(vec, float(m.group(3)), id=f"{path.name}:{lineno}"))
    return rows


CVSS_ROWS = _cvss_rows()


def test_cvss_formula_reproduces_published_scores():
    base = {"AC": "L", "UI": "N", "S": "U", "PR": "N", "C": "H", "I": "H", "A": "H"}
    assert cvss31(base) == 9.8
    assert cvss31({**base, "I": "N", "A": "N"}) == 7.5
    # FIRST examples: stored XSS CVE-2019-7551 and CSRF CVE-2015-0970
    assert cvss31({**base, "PR": "L", "UI": "R", "S": "C"}) == 9.0
    assert cvss31({**base, "UI": "R"}) == 8.8


def test_cvss_tables_were_found():
    assert len(CVSS_ROWS) >= 60


@pytest.mark.parametrize(("vec", "listed"), CVSS_ROWS)
def test_cvss_table_row_matches_the_formula(vec, listed):
    assert cvss31(vec) == listed


# --- External links (slow, optional) ---------------------------------------------------------------

_URL = re.compile(r"https?://[^\s)`>\"']+")
_PLACEHOLDER = ("example", "<slug", "{", "evil", "localhost")
# The Wordfence programme page answers every automated request with an empty 202 (documented in authz.md).
_ACCEPT_202 = ("wordfence.com",)


def _urls() -> list[str]:
    seen: set[str] = set()
    for path in FILES:
        for u in _URL.findall(path.read_text()):
            u = u.rstrip(".,;:")
            if not any(p in u for p in _PLACEHOLDER):
                seen.add(u)
    return sorted(seen)


def _status(url: str) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (wpbench reference link check)"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < 4:
                retry_after = exc.headers.get("Retry-After", "")
                time.sleep(int(retry_after) if retry_after.isdigit() else 15 * (attempt + 1))
                continue
            return exc.code
        except (urllib.error.URLError, TimeoutError):
            if attempt < 4:
                time.sleep(5)
                continue
            return 0
    return 0


def _check_host(urls: list[str]) -> dict[str, int]:
    """Requests to one host go one at a time with a pause, so rate limits are not triggered."""
    out: dict[str, int] = {}
    for u in urls:
        out[u] = _status(u)
        time.sleep(1.0)
    return out


@pytest.mark.network
@pytest.mark.skipif(os.environ.get("WPBENCH_CHECK_URLS") != "1", reason="set WPBENCH_CHECK_URLS=1 to check external links")
def test_external_links_resolve():
    urls = _urls()
    assert len(urls) > 50
    by_host: dict[str, list[str]] = {}
    for u in urls:
        by_host.setdefault(urlparse(u).netloc, []).append(u)
    statuses: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=len(by_host)) as pool:
        for result in pool.map(_check_host, by_host.values()):
            statuses.update(result)
    bad = {u: s for u, s in statuses.items() if not (200 <= s < 400 or (s == 202 and any(h in u for h in _ACCEPT_202)))}
    assert bad == {}
