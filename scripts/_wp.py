"""WordPress-specific helpers shared by wp_map, wp_sinks and wp_xref."""

from __future__ import annotations

import re
from dataclasses import dataclass

from _php import SUPERGLOBALS_RE, Call, Func, Index, split_args

NONCE_RE = re.compile(r"\b(?:check_ajax_referer|check_admin_referer|wp_verify_nonce|wp_nonce_ays)\s*\(")
CAP_RE = re.compile(r"\b(?:current_user_can(?:_for_blog)?|user_can|is_super_admin)\s*\(")
CAP_NAME_RE = re.compile(r"\b(?:current_user_can(?:_for_blog)?|user_can)\s*\(\s*(?:[^,()]+,\s*)?['\"]([\w\-]+)['\"]")

TIER_ORDER = {"unauth": 0, "subscriber": 1, "author+": 2, "admin": 3, "system": 4}
_SUBSCRIBER_CAPS = {"read"}
_AUTHOR_CAPS = {
    "edit_posts", "publish_posts", "upload_files", "edit_published_posts", "edit_others_posts",
    "edit_pages", "delete_posts", "moderate_comments", "manage_categories", "edit_comment",
}


def tier_for_capability(cap: str) -> str:
    if cap in _SUBSCRIBER_CAPS:
        return "subscriber"
    if cap in _AUTHOR_CAPS:
        return "author+"
    return "admin"


@dataclass(frozen=True)
class Callback:
    kind: str  # function | method | closure | unknown
    name: str = ""
    cls: str = ""  # "" = the class of the registering code (``$this``/``self``)
    raw: str = ""


def parse_callback(text: str) -> Callback:
    t = text.strip()
    if re.match(r"(?:static\s+)?(?:function|fn)\b", t):
        return Callback("closure", "{closure}", raw=t)
    m = re.fullmatch(r"""['"]([\w\\]+)::(\w+)['"]""", t)
    if m:
        return Callback("method", m.group(2), m.group(1).lstrip("\\").rsplit("\\", 1)[-1], t)
    m = re.fullmatch(r"""['"]([\w\\]+)['"]""", t)
    if m:
        return Callback("function", m.group(1).lstrip("\\").rsplit("\\", 1)[-1], raw=t)
    arr = re.fullmatch(r"(?:array\s*\(|\[)(.*)(?:\)|\])", t, re.S)
    if arr:
        parts = split_args(arr.group(1))
        if len(parts) == 2:
            mm = re.fullmatch(r"""['"](\w+)['"]""", parts[1])
            if mm:
                first = parts[0]
                if re.fullmatch(r"\$this|__CLASS__|self|static|self::class|static::class", first):
                    return Callback("method", mm.group(1), "", t)
                cm = re.fullmatch(r"""['"]?\\?([\w\\]+?)(?:::class)?['"]?""", first)
                if cm and not first.startswith("$"):
                    return Callback("method", mm.group(1), cm.group(1).rsplit("\\", 1)[-1], t)
                nm = re.match(r"new\s+\\?([\w\\]+)", first)
                if nm:
                    return Callback("method", mm.group(1), nm.group(1).rsplit("\\", 1)[-1], t)
                return Callback("method", mm.group(1), "?", t)
    return Callback("unknown", raw=t)


def resolve(idx: Index, cb: Callback, site: Call) -> Func | None:
    """Find the Func a callback points to, given the call that registers it."""
    if cb.kind == "closure":
        cands = [f for f in idx.by_name("{closure}") if f.file == site.file and site.line <= f.line <= site.end_line]
        return min(cands, key=lambda f: f.line) if cands else None
    if cb.kind not in ("function", "method"):
        return None
    cands = idx.by_name(cb.name)
    if cb.kind == "function":
        plain = [f for f in cands if not f.cls]
        found = plain or cands
        return found[0] if found else None
    want = cb.cls
    if not want:
        owner = idx.func_of(site)
        want = owner.cls if owner else ""
        if not want:  # registered at file level with $this/self: use the file's class
            want = next((f.cls for f in idx.by_name(cb.name) if f.file == site.file and f.cls), "")
    exact = [f for f in cands if f.cls.lower() == want.lower()]
    found = exact or cands
    return found[0] if found else None


def array_pairs(text: str) -> list[tuple[str, str]]:
    """Top-level ``'key' => value`` pairs of a PHP array literal (one list level deep)."""
    t = text.strip()
    m = re.fullmatch(r"(?:array\s*\(|\[)(.*)(?:\)|\])", t, re.S)
    if not m:
        return []
    out: list[tuple[str, str]] = []
    for item in split_args(m.group(1)):
        km = re.match(r"""['"]([\w\-]+)['"]\s*=>\s*(.*)""", item, re.S)
        if km:
            out.append((km.group(1), km.group(2).strip()))
        elif re.match(r"(?:array\s*\(|\[)", item):
            out.extend(array_pairs(item))
    return out


def superglobals_of(f: Func) -> list[str]:
    return sorted({m.group() for m in SUPERGLOBALS_RE.finditer(f.body)})


def guards_of(idx: Index, f: Func) -> dict[str, str | None]:
    """Static hint: is a nonce / capability check present in the handler or one level below?"""
    out: dict[str, str | None] = {"nonce": None, "cap": None, "capability": None}
    texts: list[tuple[str, str]] = [("handler", f.body)]
    for c in idx.calls_in(f):
        if c.kind == "construct" or c.name in ("current_user_can", "check_ajax_referer"):
            continue
        for g in idx.by_name(c.name):
            if g is f:
                continue
            if c.kind in ("method", "static") and c.recv.lower() in ("$this", "self", "static") and g.cls != f.cls:
                continue
            texts.append(("callee", g.body))
    for where, body in texts:
        if out["nonce"] is None and NONCE_RE.search(body):
            out["nonce"] = where
        if out["cap"] is None and CAP_RE.search(body):
            out["cap"] = where
            m = CAP_NAME_RE.search(body)
            out["capability"] = m.group(1) if m else None
    return out


def literal(text: str) -> str | None:
    m = re.fullmatch(r"""\s*(['"])([^'"\\]*)\1\s*""", text)
    return m.group(2) if m else None


def names_in(text: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted({m.group().rstrip("( \t").strip() for m in pattern.finditer(text)})
