"""Memorisation probe (docs/SPEC.md section 6): ask the model, without any code, what was fixed in the patched release.

If it can name the function or file, the case may be contaminated and results are reported with and without it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from wpbench.cases import Case
from wpbench.match import norm_function

PROMPT = (
    "The WordPress plugin `{slug}` released version {fixed} after {vuln}. That release fixed a security vulnerability. "
    "From memory only (you have no tools and no code), say what the vulnerability was: its class, the file and the function if you know them. "
    "If you do not know, say exactly 'I do not know' and do not guess."
)
CLASS_WORDS: dict[str, tuple[str, ...]] = {
    "sqli": ("sql injection", "sqli"), "object-injection": ("object injection", "unserialize", "deserializ"), "rce": ("code execution", "rce", "arbitrary function", "callback"),
    "privesc": ("privilege escalation", "privesc"), "reflected-xss": ("cross-site scripting", "xss"), "stored-xss": ("cross-site scripting", "xss"),
    "missing-authz": ("authorization", "idor", "insecure direct object", "access control"), "csrf": ("csrf", "cross-site request forgery"),
    "path-traversal": ("path traversal", "directory traversal"), "file-delete": ("file deletion", "arbitrary file delet"), "file-upload": ("file upload",),
    "file-inclusion": ("file inclusion", "lfi", "rfi"), "ssrf": ("ssrf", "server-side request forgery"), "open-redirect": ("open redirect",),
    "info-disclosure": ("information disclosure", "sensitive information", "exposure"), "xxe": ("xxe", "xml external entit"), "dom-xss": ("dom", "xss"),
}


@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    names_function: bool
    names_file: bool
    names_class: bool
    admits_ignorance: bool

    @property
    def positive(self) -> bool:
        """Contaminated if the answer names the function or the file (naming only a common class proves nothing)."""
        return (self.names_function or self.names_file) and not self.admits_ignorance


def build_prompt(case: Case) -> str:
    return PROMPT.format(slug=case.slug, fixed=case.fixed_version, vuln=case.vuln_version)


def judge(case: Case, answer: str) -> ProbeResult:
    text = answer.casefold()
    truth: dict[str, Any] = case.truth or {}
    fn = norm_function(truth.get("function", ""))
    base = str(truth.get("file", "")).rsplit("/", 1)[-1].casefold()
    return ProbeResult(
        case.id,
        names_function=len(fn) >= 5 and re.search(rf"(?<![a-z0-9_]){re.escape(fn)}(?![a-z0-9_])", text) is not None,
        names_file=bool(base) and base in text,
        names_class=any(w in text for w in CLASS_WORDS.get(case.cls, ())),
        admits_ignorance="i do not know" in text or "i don't know" in text,
    )
