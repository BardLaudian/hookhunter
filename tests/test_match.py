from __future__ import annotations

from wpbench.cwe_families import compatible, family, family_of_cwe
from wpbench.match import Truth, match, norm_function, norm_path, ranked, score_findings

T = Truth("includes/class-admin.php", "save_settings", 120, 134, "CWE-79", "stored-xss")


def f(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"file": "includes/class-admin.php", "line_start": 125, "line_end": 130, "function": "other", "cwe": "CWE-79", "class": "stored-xss", "confidence": "high"}
    return base | over


def test_overlap_and_tolerance_boundaries() -> None:
    assert match(f(), T).matched
    assert match(f(line_start=144, line_end=150), T).matched  # starts 10 lines after the end
    assert not match(f(line_start=145, line_end=150), T).matched  # 11 lines after
    assert match(f(line_start=100, line_end=110), T).matched  # ends 10 lines before the start
    assert not match(f(line_start=100, line_end=109), T).matched
    assert match(f(line_start=130, line_end=125), T).matched  # reversed range is tolerated


def test_same_function_matches_nearby_lines_only() -> None:
    assert match(f(line_start=200, line_end=210, function="save_settings"), T).matched
    assert match(f(line_start=200, line_end=210, function="Admin::Save_Settings()"), T).matched
    assert not match(f(line_start=900, line_end=910, function="save_settings"), T).matched  # beyond the 100-line cap
    assert not match(f(line_start=900, line_end=910, function=""), T).matched  # an empty name is not "the same function"


def test_file_must_match_after_normalisation() -> None:
    assert match(f(file="plugin/includes/class-admin.php"), T).matched
    assert match(f(file="./includes\\class-admin.php"), T).matched
    assert not match(f(file="includes/class-other.php"), T).matched
    assert not match(f(file="class-admin.php"), T).matched


def test_family_must_be_compatible() -> None:
    assert match(f(cwe="CWE-80"), T).matched  # XSS family
    assert not match(f(cwe="CWE-89", **{"class": "sqli"}), T).matched
    r = match(f(cwe="CWE-89", **{"class": "sqli"}), T)
    assert r.same_file and r.location and not r.family


def test_families() -> None:
    assert family_of_cwe("CWE-862") == family_of_cwe("CWE-863") == family_of_cwe("CWE-285") == "authorization"
    assert family_of_cwe("CWE-79") == "xss" and family_of_cwe("CWE-99999") is None
    assert family("CWE-99999", "reflected-xss") == "xss"  # unknown CWE: the class slug decides
    assert compatible("CWE-862", "missing-authz", "CWE-269", "privesc")  # documented leniency
    assert not compatible("CWE-99999", None, "CWE-99998", None)  # two unknowns never match
    assert not compatible("CWE-79", "stored-xss", "CWE-89", "sqli")


def test_normalisers() -> None:
    assert norm_path("/work/plugin/a/B.php") == "a/b.php" and norm_function("Foo::bar()") == "bar" and norm_function("$x->run") == "run"


def test_recall_at_3_uses_confidence_not_list_order() -> None:
    hit = f(confidence="low")
    others = [f(file="x.php", confidence=c) for c in ("high", "high", "medium")]
    s = score_findings([*others, hit], T)
    assert s.hit and not s.hit_at_3  # the match is the 4th most confident
    assert score_findings([hit, *others[:1]], T).hit_at_3
    assert [x["confidence"] for x in ranked([hit, *others])] == ["high", "high", "medium", "low"]


def test_no_findings_is_a_miss_not_an_error() -> None:
    s = score_findings([], T)
    assert not s.hit and not s.hit_at_3 and s.unmatched == ()


def test_function_cap_stops_a_giant_function_matching_everything() -> None:
    far = f(line_start=900, line_end=910, function="save_settings")
    assert not match(far, T).matched  # the default is the SPEC cap
    assert match(far, T, function_cap=None).matched  # the old rule, for sensitivity analysis
    assert not match(far, T, function_cap=100).matched
    assert match(f(line_start=200, line_end=210, function="save_settings"), T, function_cap=100).matched  # 66 lines away
    assert match(f(line_start=125, line_end=130, function="other"), T, function_cap=0).matched  # overlap is never capped
