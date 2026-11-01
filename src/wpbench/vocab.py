"""Closed vocabularies shared with schemas/findings.schema.json (a test keeps them in sync)."""

from __future__ import annotations

CLASSES = (
    "stored-xss", "reflected-xss", "dom-xss", "sqli", "missing-authz", "csrf", "path-traversal", "file-delete", "file-upload",
    "file-inclusion", "object-injection", "ssrf", "open-redirect", "privesc", "rce", "info-disclosure", "xxe",
)
AUTH_LEVELS = ("unauthenticated", "subscriber", "contributor", "admin")
CONFIDENCE = ("high", "medium", "low")
SOURCES = ("wordfence", "wpscan", "patchstack", "nvd")
SPLITS = ("dev", "test")
PHP_SUFFIXES = (".php", ".inc", ".phtml")
