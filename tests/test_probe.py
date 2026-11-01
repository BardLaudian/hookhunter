from __future__ import annotations

from wpbench.cases import Case
from wpbench.probe import build_prompt, judge


def case() -> Case:
    t = {"file": "includes/module-base.php", "function": "dienow", "line_start": 1, "line_end": 2}
    return Case("wp-0005", "CVE-1", "nvd", "u", "2026-11-01", "newsletter", "9.3.8", "9.3.9", "a" * 64, "b" * 64, "CWE-79", "reflected-xss", "unauthenticated", "2026-09-18", True, None, t)


def test_prompt_never_names_the_truth() -> None:
    p = build_prompt(case())
    assert "newsletter" in p and "9.3.9" in p and "dienow" not in p and "xss" not in p.lower() and "module-base" not in p


def test_judge_distinguishes_class_only_from_memorised() -> None:
    assert not judge(case(), "It was a cross-site scripting issue.").positive  # a common class proves nothing
    assert judge(case(), "It was an XSS in dienow() in module-base.php").positive
    assert judge(case(), "The wp_die message in module-base.php was unescaped").positive
    assert not judge(case(), "I do not know. Maybe dienow?").positive  # admitted ignorance wins
    assert not judge(case(), "A rename of dienowhere").names_function  # whole identifiers only
