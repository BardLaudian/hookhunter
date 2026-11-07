#!/usr/bin/env python3
"""Validate a bench findings JSON against schemas/findings.schema.json (no third-party library needed).

Usage: hh_validate.py <findings.json | ->     prints {"valid": bool, "errors": [...], "findings": N}; exit 0 if valid, 1 if not.

The harness counts an invalid answer as a missed case, so a missing `confidence` or `auth_required: "author"`
costs as much as not finding the bug. Run this before the final answer, or let the Stop hook run it for you.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "findings.schema.json"
_ITEM: dict[str, Any] = json.loads(SCHEMA.read_text())["properties"]["findings"]["items"]
REQUIRED: list[str] = _ITEM["required"]
PROPS: dict[str, Any] = _ITEM["properties"]
# Frequent near-misses mapped to the value the schema expects (reported as a hint, never applied silently).
HINTS = {
    ("auth_required", "author"): "contributor", ("auth_required", "editor"): "admin", ("auth_required", "administrator"): "admin",
    ("auth_required", "none"): "unauthenticated", ("auth_required", "unauth"): "unauthenticated", ("auth_required", "authenticated"): "subscriber",
    ("class", "xss"): "stored-xss or reflected-xss", ("class", "authz"): "missing-authz", ("class", "idor"): "missing-authz",
    ("class", "lfi"): "file-inclusion", ("class", "sql-injection"): "sqli", ("class", "deserialization"): "object-injection",
    ("class", "file-ops"): "path-traversal, file-delete, file-upload or file-inclusion", ("confidence", "certain"): "high",
}


def extract(text: str) -> tuple[Any, str | None]:
    """Parse a findings object out of free text (whole text, a fenced block, or the first {"findings" ... })."""
    t = text.strip()
    try:
        return json.loads(t), None
    except ValueError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.S)
    if m:
        try:
            return json.loads(m.group(1)), "the JSON is inside a code fence; bench mode wants the bare object only"
        except ValueError:
            pass
    i = t.find('{"findings"')
    if i < 0:
        i = t.find("{\n  \"findings\"")
    if i >= 0:
        dec = json.JSONDecoder()
        try:
            obj, _ = dec.raw_decode(t[i:])
            return obj, "there is text around the JSON object; bench mode wants the bare object only"
        except ValueError as e:
            return None, f"JSON does not parse: {e}"
    return None, "no {\"findings\": [...]} object found"


def validate(obj: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(obj, dict):
        return ["top level must be an object {\"findings\": [...]}"]
    extra = set(obj) - {"findings"}
    if extra:
        errs.append(f"top level has extra keys {sorted(extra)}; only \"findings\" is allowed")
    fs = obj.get("findings")
    if not isinstance(fs, list):
        return errs + ["\"findings\" must be a list"]
    for n, f in enumerate(fs):
        where = f"findings[{n}]"
        if not isinstance(f, dict):
            errs.append(f"{where} is not an object")
            continue
        for k in REQUIRED:
            if k not in f:
                errs.append(f"{where} lacks \"{k}\"")
        for k in set(f) - set(PROPS):
            errs.append(f"{where} has extra key \"{k}\" (not allowed)")
        for k, spec in PROPS.items():
            if k not in f:
                continue
            v = f[k]
            if "enum" in spec and v not in spec["enum"]:
                hint = HINTS.get((k, str(v).lower()))
                errs.append(f"{where}.{k} = {v!r} is not one of {spec['enum']}" + (f" (use {hint})" if hint else ""))
            t = spec.get("type")
            if t == "integer" and not (isinstance(v, int) and not isinstance(v, bool)):
                errs.append(f"{where}.{k} must be an integer")
            elif t == "integer" and v < spec.get("minimum", -10**9):
                errs.append(f"{where}.{k} must be >= {spec['minimum']}")
            if t == "string":
                if not isinstance(v, str):
                    errs.append(f"{where}.{k} must be a string")
                    continue
                if len(v) < spec.get("minLength", 0):
                    errs.append(f"{where}.{k} must not be empty")
                if "pattern" in spec and not re.search(spec["pattern"], v):
                    errs.append(f"{where}.{k} = {v!r} does not match {spec['pattern']}" + (" (path relative to the plugin root, forward slashes, no leading /)" if k == "file" else ""))
        if isinstance(f.get("line_start"), int) and isinstance(f.get("line_end"), int) and f["line_end"] < f["line_start"]:
            errs.append(f"{where}: line_end < line_start")
    return errs


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    text = sys.stdin.read() if args[0] == "-" else Path(args[0]).read_text()
    obj, warn = extract(text)
    errs = [warn] if (obj is None and warn) else validate(obj)
    out = {"valid": not errs, "errors": errs, "findings": len(obj.get("findings", [])) if isinstance(obj, dict) else 0}
    if warn and obj is not None:
        out["warning"] = warn
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0 if not errs else 1


if __name__ == "__main__":
    raise SystemExit(main())
