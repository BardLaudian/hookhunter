"""Per-session state shared by hh_ledger.py and the skill hooks (hooks/*.py).

The state lives in a directory outside the audited plugin (which may be read-only):
  $HH_STATE_DIR, else $TMPDIR, /tmp, /out or ~/.cache, the first one that is writable,
  then hookhunter/<session>/ under it.

<session> is the Claude Code session id. SKILL.md passes it to the scripts as --session ${CLAUDE_SESSION_ID};
hooks read it from their JSON input. When the id is missing or was not substituted, "default" is used, and the
hooks fall back to "default" too, so the pair still meets.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

_SAFE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def session_name(raw: str | None) -> str:
    raw = (raw or "").strip()
    return raw if _SAFE.match(raw) else "default"


def _writable(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".hh_probe"
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def base_dir() -> Path | None:
    cands = [os.environ.get("HH_STATE_DIR"), os.environ.get("TMPDIR"), "/tmp", "/out", str(Path.home() / ".cache")]
    for c in cands:
        if not c:
            continue
        p = Path(c) / "hookhunter"
        if _writable(p):
            return p
    return None


def state_dir(session: str | None, create: bool = True) -> Path | None:
    base = base_dir()
    if base is None:
        return None
    d = base / session_name(session)
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def find_ledger(session: str | None) -> Path | None:
    """Ledger for this session, else the 'default' one if it was touched in the last 12 hours."""
    base = base_dir()
    if base is None:
        return None
    for name in (session_name(session), "default"):
        p = base / name / "ledger.json"
        if p.is_file() and (name != "default" or time.time() - p.stat().st_mtime < 12 * 3600):
            return p
    return None


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def save(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(path)
