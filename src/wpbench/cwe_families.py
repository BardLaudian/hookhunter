"""CWE families used to decide whether a finding is "the same kind of vulnerability" as the ground truth (docs/SPEC.md section 5).

Deliberately coarse: an agent that reports CWE-862 where the advisory says CWE-863 found the same bug. The map is a decision,
not a fact; docs/DECISIONS.md section 16 lists the groupings that are debatable (authorization absorbs privilege escalation and IDOR).
"""

from __future__ import annotations

FAMILIES: dict[str, frozenset[int]] = {
    "xss": frozenset({79, 80, 83, 87, 116}),
    "sqli": frozenset({89, 564, 943}),
    "authorization": frozenset({862, 863, 285, 284, 306, 639, 566, 269, 266, 267, 268, 250, 648, 280, 732}),
    "csrf": frozenset({352}),
    "code-execution": frozenset({94, 95, 96, 77, 78, 74, 470, 829, 915}),
    "file-inclusion": frozenset({98, 73}),
    "path-traversal": frozenset({22, 23, 24, 35, 36, 59, 552}),
    "file-upload": frozenset({434, 646}),
    "deserialization": frozenset({502}),
    "ssrf": frozenset({918}),
    "open-redirect": frozenset({601}),
    "info-disclosure": frozenset({200, 201, 209, 497, 532, 538, 359, 522}),
    "xxe": frozenset({611, 776, 827}),
}

# The agent's own `class` slug, used only when a CWE id is missing or unknown to the map.
CLASS_FAMILY: dict[str, str] = {
    "stored-xss": "xss", "reflected-xss": "xss", "dom-xss": "xss", "sqli": "sqli", "missing-authz": "authorization",
    "privesc": "authorization", "csrf": "csrf", "rce": "code-execution", "file-inclusion": "file-inclusion",
    "path-traversal": "path-traversal", "file-delete": "path-traversal", "file-upload": "file-upload",
    "object-injection": "deserialization", "ssrf": "ssrf", "open-redirect": "open-redirect", "info-disclosure": "info-disclosure", "xxe": "xxe",
}


def cwe_number(cwe: str) -> int | None:
    digits = "".join(ch for ch in str(cwe) if ch.isdigit())
    return int(digits) if digits else None


def family_of_cwe(cwe: str) -> str | None:
    n = cwe_number(cwe)
    if n is None:
        return None
    for name, members in FAMILIES.items():
        if n in members:
            return name
    return None


def family(cwe: str, cls: str | None = None) -> str | None:
    """Family of a (CWE, class) pair: the CWE decides when the map knows it, else the class slug."""
    return family_of_cwe(cwe) or (CLASS_FAMILY.get(cls or "") if cls else None)


def compatible(finding_cwe: str, finding_class: str | None, truth_cwe: str, truth_class: str | None) -> bool:
    """Same family. Either side may be unknown to the CWE map, then the class slugs decide; two unknowns never match."""
    a, b = family(finding_cwe, finding_class), family(truth_cwe, truth_class)
    return a is not None and a == b
