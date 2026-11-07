#!/usr/bin/env python3
"""PostToolUse hook (matcher: Read). Records which file ranges were opened, so that `hh_ledger.py mark ... clean`
can refuse to clear a function nobody read. Never blocks and never prints to the model; any error is swallowed."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


def main() -> int:
    try:
        from _state import find_ledger

        data = json.load(sys.stdin)
        led = find_ledger(data.get("session_id"))
        if led is None:  # no audit worklist in this session: nothing to track
            return 0
        ti = data.get("tool_input") or {}
        rec = {"file_path": ti.get("file_path"), "offset": ti.get("offset"), "limit": ti.get("limit")}
        with open(led.parent / "reads.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:  # noqa: BLE001 - a tracking hook must never disturb the session
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
