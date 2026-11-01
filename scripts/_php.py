"""Shared PHP indexing layer for the hookhunter scripts.

Two interchangeable backends produce the same model (functions and call sites):

* ``treesitter`` - tree-sitter + tree-sitter-php (pinned in requirements.txt).
* ``regex``      - dependency-free fallback: a comment/string-aware masker, bracket
                   matching and call-site regexes. Known gaps: backtick shell
                   execution and PHP 8 attribute syntax are not indexed.

Static analysis only: nothing here executes or includes the code it reads.
"""

from __future__ import annotations

import bisect
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PHP_EXTENSIONS = (".php", ".inc", ".phtml")
SKIP_DIRS = frozenset({"vendor", "node_modules", ".git", ".svn"})
MAX_FILE_BYTES = 2_000_000
# Names that look like calls but are syntax; both backends drop them.
NOT_CALLS = frozenset(
    {"if", "elseif", "while", "for", "foreach", "switch", "catch", "function", "fn", "array",
     "list", "isset", "empty", "unset", "declare", "match", "use", "and", "or", "return"}
)
# Name given to calls whose callee is an expression, not an identifier: $fn(), $o->$m(), A::$m(), new $class().
DYNAMIC = "<dynamic>"
NEW_DYNAMIC = "<new-dynamic>"
SUPERGLOBALS_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b")


@dataclass
class Func:
    name: str  # "{closure}" for anonymous functions
    cls: str  # enclosing class/trait name, "" for plain functions
    file: str
    line: int
    end_line: int
    body: str = field(repr=False, default="")
    index: int = -1  # position in Index.funcs, set by build_index

    @property
    def qualname(self) -> str:
        return f"{self.cls}::{self.name}" if self.cls else self.name


@dataclass
class Call:
    name: str  # lower-cased callee; language constructs use echo/print/include/...; DYNAMIC / NEW_DYNAMIC when the callee is an expression
    kind: str  # func | method | static | new | construct | dynamic
    recv: str  # receiver source for method/static calls; the callee expression for dynamic calls
    args: tuple[str, ...]
    file: str
    line: int
    end_line: int
    func: int  # index into Index.funcs, -1 at top level


@dataclass
class Index:
    root: str
    backend: str
    files: list[str] = field(default_factory=list)
    funcs: list[Func] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def func_of(self, call: Call) -> Func | None:
        return self.funcs[call.func] if call.func >= 0 else None

    def by_name(self, name: str) -> list[Func]:
        """Functions/methods called ``name`` (case-insensitive); lookup table built once."""
        table: dict[str, list[Func]] | None = getattr(self, "_by_name", None)
        if table is None:
            table = {}
            for f in self.funcs:
                table.setdefault(f.name.lower(), []).append(f)
            self._by_name = table
        return table.get(name.lower(), [])

    def calls_in(self, f: Func) -> list[Call]:
        table: dict[int, list[Call]] | None = getattr(self, "_calls_in", None)
        if table is None:
            table = {}
            for c in self.calls:
                table.setdefault(c.func, []).append(c)
            self._calls_in = table
        return table.get(f.index, [])


# --------------------------------------------------------------------------- discovery


def discover(root: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """PHP files under root (sorted) plus what was deliberately not read."""
    files: list[Path] = []
    skipped: list[dict[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for d in list(dirnames):
            if d in SKIP_DIRS:
                dirnames.remove(d)
                skipped.append({"path": str((Path(dirpath) / d).relative_to(root)), "reason": "skipped-dir"})
        for fn in sorted(filenames):
            if not fn.lower().endswith(PHP_EXTENSIONS):
                continue
            p = Path(dirpath) / fn
            if p.is_symlink():
                skipped.append({"path": str(p.relative_to(root)), "reason": "symlink"})
            elif p.stat().st_size > MAX_FILE_BYTES:
                skipped.append({"path": str(p.relative_to(root)), "reason": "too-large"})
            else:
                files.append(p)
    return files, skipped


def tree_sitter_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_php  # noqa: F401
    except ImportError:
        return False
    return True


def build_index(root: str | Path, backend: str = "auto") -> Index:
    root = Path(root)
    if backend == "auto":
        backend = "treesitter" if tree_sitter_available() else "regex"
    if backend not in ("treesitter", "regex"):
        raise ValueError(f"unknown backend: {backend}")
    parse = _treesitter_parser() if backend == "treesitter" else _parse_regex
    paths, skipped = discover(root)
    idx = Index(root=str(root), backend=backend, skipped=skipped)
    for p in paths:
        rel = str(p.relative_to(root))
        try:
            src = p.read_bytes()
        except OSError as exc:
            idx.skipped.append({"path": rel, "reason": f"unreadable: {exc.strerror}"})
            continue
        idx.files.append(rel)
        funcs, calls = parse(src, rel)
        base = len(idx.funcs)
        for k, f in enumerate(funcs):
            f.index = base + k
        idx.funcs.extend(funcs)
        for c in calls:
            if c.func >= 0:
                c.func += base
            idx.calls.append(c)
    return idx


# --------------------------------------------------------------------------- shared helpers


def split_args(text: str) -> list[str]:
    """Split call arguments at top-level commas (string-aware)."""
    out: list[str] = []
    depth = 0
    quote = ""
    cur: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    last = "".join(cur).strip()
    if last or out:
        out.append(last)
    return [a for a in out if a != ""]


def unparen(text: str) -> str:
    """Strip one pair of parentheses that wraps the whole expression."""
    text = text.strip()
    if not (text.startswith("(") and text.endswith(")")):
        return text
    depth = 0
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote and text[i - 1] != "\\":
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(text) - 1:
                return text
    return text[1:-1].strip()


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# --------------------------------------------------------------------------- tree-sitter backend

_FUNC_NODES = {"function_definition", "method_declaration", "anonymous_function"}
_CLASS_NODES = {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}
_CONSTRUCTS = {
    "print_intrinsic": "print",
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
    "shell_command_expression": "shell_exec",
}


def _treesitter_parser() -> Any:
    import tree_sitter_php
    from tree_sitter import Language, Parser

    parser = Parser(Language(tree_sitter_php.language_php()))

    def parse(src: bytes, rel: str) -> tuple[list[Func], list[Call]]:
        return _parse_treesitter(parser, src, rel)

    return parse


def _text(src: bytes, node: Any) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _flatten_sequence(node: Any) -> Iterator[Any]:
    if node.type == "sequence_expression":
        for c in node.named_children:
            yield from _flatten_sequence(c)
    else:
        yield node


def _ts_args(src: bytes, args_node: Any) -> tuple[str, ...]:
    return tuple(_text(src, a.named_children[-1] if a.named_children else a).strip() for a in args_node.named_children)


def _parse_treesitter(parser: Any, src: bytes, rel: str) -> tuple[list[Func], list[Call]]:
    tree = parser.parse(src)
    funcs: list[Func] = []
    calls: list[Call] = []

    def add(name: str, kind: str, recv: str, args: tuple[str, ...], node: Any, fi: int) -> None:
        calls.append(
            Call(name.lower(), kind, recv, tuple(_norm(a) if len(a) < 400 else a for a in args), rel,
                 node.start_point[0] + 1, node.end_point[0] + 1, fi)
        )

    # Explicit stack of (node, enclosing func index, enclosing class name).
    stack: list[tuple[Any, int, str]] = [(tree.root_node, -1, "")]
    while stack:
        node, fi, cls = stack.pop()
        t = node.type
        if t in _CLASS_NODES:
            nm = node.child_by_field_name("name")
            cls = _text(src, nm) if nm is not None else ""
        elif t in _FUNC_NODES:
            nm = node.child_by_field_name("name")
            name = _text(src, nm) if nm is not None else "{closure}"
            funcs.append(Func(name, cls if t == "method_declaration" else "", rel,
                              node.start_point[0] + 1, node.end_point[0] + 1, _text(src, node)))
            fi = len(funcs) - 1
        elif t == "function_call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None and args is not None and fn.type in ("name", "qualified_name"):
                name = _text(src, fn).lstrip("\\").rsplit("\\", 1)[-1]
                if name.lower() not in NOT_CALLS:
                    add(name, "func", "", _ts_args(src, args), node, fi)
            elif fn is not None and args is not None and fn.type != "parenthesized_expression":
                add(DYNAMIC, "dynamic", _norm(_text(src, fn)), _ts_args(src, args), node, fi)  # $fn(), $_GET['f'](), $this->cb[0]()
        elif t in ("member_call_expression", "nullsafe_member_call_expression"):
            nm = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            obj = node.child_by_field_name("object")
            if nm is not None and args is not None and nm.type == "name":
                add(_text(src, nm), "method", _norm(_text(src, obj)) if obj is not None else "", _ts_args(src, args), node, fi)
            elif nm is not None and args is not None and obj is not None:
                add(DYNAMIC, "dynamic", _norm(f"{_text(src, obj)}->{_text(src, nm)}"), _ts_args(src, args), node, fi)  # $o->$method()
        elif t == "scoped_call_expression":
            nm = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            scope = node.child_by_field_name("scope")
            if nm is not None and args is not None and nm.type == "name":
                add(_text(src, nm), "static", _norm(_text(src, scope)) if scope is not None else "", _ts_args(src, args), node, fi)
            elif nm is not None and args is not None and scope is not None:
                add(DYNAMIC, "dynamic", _norm(f"{_text(src, scope)}::{_text(src, nm)}"), _ts_args(src, args), node, fi)  # A::$method()
        elif t == "object_creation_expression":
            nm = next((c for c in node.named_children if c.type in ("name", "qualified_name")), None)
            args = node.child_by_field_name("arguments") or next((c for c in node.named_children if c.type == "arguments"), None)
            if nm is not None:
                add(_text(src, nm).lstrip("\\"), "new", "", _ts_args(src, args) if args is not None else (), node, fi)
            else:
                cls_node = next((c for c in node.named_children if c.type in ("variable_name", "dynamic_variable_name", "member_access_expression", "subscript_expression")), None)
                if cls_node is not None:
                    add(NEW_DYNAMIC, "new", _norm(_text(src, cls_node)), _ts_args(src, args) if args is not None else (), node, fi)  # new $class()
        elif t == "echo_statement":
            exprs = [e for c in node.named_children for e in _flatten_sequence(c)]
            add("echo", "construct", "", tuple(_text(src, e).strip() for e in exprs), node, fi)
        elif t in _CONSTRUCTS:
            kids = node.named_children
            arg = _text(src, kids[0]).strip() if kids else ""
            if t == "shell_command_expression":
                arg = _text(src, node).strip("`")
            if t != "shell_command_expression":
                arg = unparen(arg)
            add(_CONSTRUCTS[t], "construct", "", (arg,), node, fi)
        elif t == "expression_statement":
            prev = node.prev_sibling
            if prev is not None and prev.type == "text_interpolation" and prev.children:
                prev = prev.children[-1]  # `?> html <?=` inside a block ends with the php_tag
            if prev is not None and prev.type == "php_tag" and _text(src, prev) == "<?=":
                add("echo", "construct", "", (_text(src, node).strip(),), node, fi)
        for c in reversed(node.children):
            stack.append((c, fi, cls))
    calls.sort(key=lambda c: (c.line, c.end_line))
    return funcs, calls


# --------------------------------------------------------------------------- regex backend

_OPEN_RE = re.compile(r"<\?php\b|<\?=")
_TOKEN_RE = re.compile(
    r"""(?P<lc>//[^\n]*?(?=\?>|\n|$)|\#(?!\[)[^\n]*?(?=\?>|\n|$))
      |(?P<bc>/\*.*?\*/)
      |(?P<hd><<<[ \t]*(?P<q>['"]?)(?P<tag>[A-Za-z_]\w*)(?P=q)\r?\n.*?\r?\n[ \t]*(?P=tag)\b)
      |(?P<sq>'(?:\\.|[^'\\])*')
      |(?P<dq>"(?:\\.|[^"\\])*")
      |(?P<close>\?>)""",
    re.S | re.X,
)
_BRACKET_RE = re.compile(r"[(){}\[\]]")
_CALL_RE = re.compile(r"(?P<arrow>\?->|->|::)?[ \t\r\n]*(?<![\w$\\])(?P<name>\\?[A-Za-z_][\w\\]*)[ \t\r\n]*\(")
_CONSTRUCT_RE = re.compile(r"(?<![\w$>:\\])(?P<kw>echo|print|include_once|include|require_once|require|\x01{3})(?![\w])")
_FUNC_RE = re.compile(r"(?<![\w$>:])function\b[ \t\r\n]*&?[ \t\r\n]*(?P<name>[A-Za-z_]\w*)?[ \t\r\n]*\(")
_CLASS_RE = re.compile(r"(?<![\w$>:])(?:class|trait|interface|enum)[ \t\r\n]+(?P<name>[A-Za-z_]\w*)")


def _mask(src: str) -> tuple[str, str]:
    """Return (code, skeleton), both the same length as src.

    code     - HTML and comments blanked, string literals intact.
    skeleton - additionally string contents blanked; ``?>`` becomes ``; `` and
               ``<?=`` becomes three \\x01 bytes (inline echo marker).
    """
    code = list(src)
    skel = list(src)

    def blank(arr: list[str], a: int, b: int) -> None:
        for i in range(a, b):
            if arr[i] not in "\n\r":
                arr[i] = " "

    pos = 0
    n = len(src)
    while pos < n:
        m = _OPEN_RE.search(src, pos)
        html_end = m.start() if m else n
        blank(code, pos, html_end)
        blank(skel, pos, html_end)
        if not m:
            break
        tag_end = m.end()
        if m.group() == "<?=":
            for i in range(m.start(), tag_end):
                code[i] = " "
                skel[i] = "\x01"
        else:
            blank(code, m.start(), tag_end)
            blank(skel, m.start(), tag_end)
        pos = tag_end
        while pos < n:
            t = _TOKEN_RE.search(src, pos)
            if not t:
                pos = n
                break
            kind = t.lastgroup
            if t.group("close"):
                kind = "close"
            elif t.group("hd"):
                kind = "hd"
            if kind in ("lc", "bc"):
                blank(code, t.start(), t.end())
                blank(skel, t.start(), t.end())
                pos = t.end()
            elif kind in ("sq", "dq", "hd"):
                blank(skel, t.start() + 1, t.end() - 1)
                pos = t.end()
            elif kind == "close":
                code[t.start()] = code[t.start() + 1] = " "
                skel[t.start()], skel[t.start() + 1] = ";", " "
                pos = t.end()
                break
            else:  # pragma: no cover - lastgroup of a named inner group
                pos = t.end()
    return "".join(code), "".join(skel)


def _match_brackets(skel: str) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    closing = {")": "(", "}": "{", "]": "["}
    for m in _BRACKET_RE.finditer(skel):
        ch = m.group()
        if ch in "({[":
            stack.append((ch, m.start()))
        elif stack and stack[-1][0] == closing[ch]:
            _, o = stack.pop()
            pairs[o] = m.start()
            pairs[m.start()] = o
    return pairs


def _receiver(skel: str, code: str, end: int, pairs: dict[int, int]) -> str:
    """Source text of the expression to the left of ``->``/``::`` ending at ``end``."""
    return _norm(code[_receiver_start(skel, end, pairs) : end])


def _receiver_start(skel: str, end: int, pairs: dict[int, int]) -> int:
    i = end
    while True:
        while i > 0 and skel[i - 1] in " \t\r\n":
            i -= 1
        if i > 0 and skel[i - 1] in ")]" and (i - 1) in pairs:
            i = pairs[i - 1]
            continue
        j = i
        while j > 0 and (skel[j - 1].isalnum() or skel[j - 1] in "_$\\"):
            j -= 1
        if j == i:
            break
        i = j
        k = i
        while k > 0 and skel[k - 1] in " \t\r\n":
            k -= 1
        if skel[max(0, k - 2) : k] in ("->", "::"):
            i = k - 2
            if i > 0 and skel[i - 1] == "?":
                i -= 1
            continue
        break
    return i


def _parse_regex(src_bytes: bytes, rel: str) -> tuple[list[Func], list[Call]]:
    src = src_bytes.decode("utf-8", "replace")
    code, skel = _mask(src)
    pairs = _match_brackets(skel)
    nl = [m.start() for m in re.finditer("\n", src)]

    def line_of(off: int) -> int:
        return bisect.bisect_left(nl, off) + 1

    # classes -> (start, end, name)
    classes: list[tuple[int, int, str]] = []
    for m in _CLASS_RE.finditer(skel):
        ob = skel.find("{", m.end())
        semi = skel.find(";", m.end())
        if ob != -1 and (semi == -1 or ob < semi) and ob in pairs:
            classes.append((ob, pairs[ob], m.group("name")))

    # functions -> body range
    func_ranges: list[tuple[int, int, Func]] = []
    for m in _FUNC_RE.finditer(skel):
        op = m.end() - 1
        if op not in pairs:
            continue
        j = pairs[op] + 1
        # skip `use (...)` and a return type up to the body `{` or terminating `;`
        while j < len(skel) and skel[j] not in "{;":
            if skel[j] == "(" and j in pairs:
                j = pairs[j]
            j += 1
        if j >= len(skel) or skel[j] != "{" or j not in pairs:
            continue
        name = m.group("name")
        owner = ""
        if name:
            inner = [c for c in classes if c[0] < m.start() < c[1]]
            owner = max(inner, key=lambda c: c[0])[2] if inner else ""
        f = Func(name or "{closure}", owner, rel, line_of(m.start()), line_of(pairs[j]), src[m.start() : pairs[j] + 1])
        func_ranges.append((j, pairs[j], f))
    func_ranges.sort(key=lambda r: r[0])
    funcs = [r[2] for r in func_ranges]

    raw: list[tuple[int, Call]] = []

    def mk(off: int, name: str, kind: str, recv: str, args: list[str], end: int) -> None:
        raw.append((off, Call(name.lower(), kind, recv, tuple(_norm(a) if len(a) < 400 else a for a in args),
                              rel, line_of(off), line_of(end), -1)))

    for m in _CALL_RE.finditer(skel):
        name = m.group("name")
        base = name.lstrip("\\").rsplit("\\", 1)[-1]
        if base.lower() in NOT_CALLS:
            continue
        op = m.end() - 1
        if op not in pairs:
            continue
        before = skel[max(0, m.start("name") - 12) : m.start("name")]
        if re.search(r"function[ \t\r\n]*&?[ \t\r\n]*$", before):
            continue  # definition, not a call
        args = split_args(code[op + 1 : pairs[op]])
        arrow = m.group("arrow")
        if arrow:
            kind = "method" if "->" in arrow else "static"
            recv = _receiver(skel, code, m.start("arrow"), pairs)
            mk(m.start("name"), base, kind, recv, args, pairs[op])
        elif re.search(r"(?<![\w$])new[ \t\r\n]+$", before):
            mk(m.start("name"), base, "new", "", args, pairs[op])
        else:
            mk(m.start("name"), base, "func", "", args, pairs[op])

    # Calls whose callee is an expression: `$fn(`, `$_GET['f'](`, `$o->$m(`, `A::$m(`, `$this->cb[0](`, `new $cls(`.
    for op in (m.start() for m in re.finditer(r"\(", skel)):
        if op not in pairs:
            continue
        k = op
        while k > 0 and skel[k - 1] in " \t\r\n":
            k -= 1
        if k == 0 or not (skel[k - 1] == "]" or skel[k - 1].isalnum() or skel[k - 1] in "_$\\"):
            continue
        start = _receiver_start(skel, k, pairs)
        callee = _norm(code[start:k])
        last = callee.split("->")[-1].split("::")[-1].split("[")[0]
        token = bool(re.match(r"\$+[A-Za-z_]\w*", last))  # the callee ends in a variable, not in a plain name
        if skel[k - 1] != "]" and not token:
            continue  # a plain name: handled by the named-call scan
        if re.search(r"(?<![\w$])new[ \t\r\n]+$", skel[:start]):
            mk(start, NEW_DYNAMIC, "new", callee, split_args(code[op + 1 : pairs[op]]), pairs[op])
        elif not re.search(r"(?<![\w$])function[ \t\r\n]*&?[ \t\r\n]*$", skel[:start]):
            mk(start, DYNAMIC, "dynamic", callee, split_args(code[op + 1 : pairs[op]]), pairs[op])

    for m in _CONSTRUCT_RE.finditer(skel):
        kw = "echo" if m.group("kw").startswith("\x01") else m.group("kw")
        i = m.end()
        depth = 0
        while i < len(skel):
            ch = skel[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif ch == ";" and depth == 0:
                break
            i += 1
        body = code[m.end() : i].strip()
        if kw not in ("echo", "print"):
            body = unparen(body)
        args = split_args(body) if kw in ("echo", "print") else [body]
        mk(m.start(), kw, "construct", "", args, i)

    raw.sort(key=lambda r: r[0])
    # Attach the innermost enclosing function by sweeping both sorted sequences.
    calls: list[Call] = []
    stack: list[int] = []
    fi = 0
    for off, call in raw:
        while fi < len(func_ranges) and func_ranges[fi][0] <= off:
            stack.append(fi)
            fi += 1
        while stack and func_ranges[stack[-1]][1] < off:
            stack.pop()
        call.func = stack[-1] if stack else -1
        calls.append(call)
    calls.sort(key=lambda c: (c.line, c.end_line))
    return funcs, calls
