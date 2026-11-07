#!/usr/bin/env python3
"""Stop hook. Before the agent ends its turn, check the two things measured runs got wrong most often:

1. Coverage. If this session has an audit worklist (hh_ledger.py init) and required rows still lack a verdict,
   block the stop and hand back the next rows. Runs used about 10 of 40 available calls and stopped "by choice".
2. Output. If the final message carries a findings JSON, validate it against the bench schema and check that every
   row marked `finding`/`needs-check` in the ledger appears in it. An invalid answer scores as a miss.

Safety valves: nothing happens without a ledger or a findings object; the gate blocks at most MAX_BLOCKS times per
session; `hh_ledger.py abandon --reason=...` turns it off. Errors never block.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

MAX_BLOCKS = 4


def block(reason: str) -> int:
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    try:
        from _state import find_ledger, load, save
        from hh_validate import extract, validate

        msg = str(data.get("last_assistant_message") or "")
        led_path = find_ledger(data.get("session_id"))
        led = load(led_path) if led_path else None
        problems: list[str] = []

        if led is not None and not led.get("abandoned"):
            pending = [r for r in led["rows"] if r.get("required") and not r.get("verdict")]
            if pending:
                nxt = "; ".join(f"{r['id']} {r['function']} ({r['file']}:{r['lines']}, tier {r['tier']})" for r in pending[:5])
                problems.append(
                    f"{len(pending)} required worklist rows have no verdict yet. Open each one and mark it "
                    f"(hh_ledger.py mark <id> finding|needs-check|clean|skip ...). Next: {nxt}. "
                    "If budget really is exhausted, mark the rest `skip --reason=budget` so coverage is honest.")

        has_json = '"findings"' in msg
        if has_json:
            obj, warn = extract(msg)
            errs = [warn] if obj is None and warn else validate(obj)
            if errs:
                problems.append("The findings JSON is invalid and would score as a failed run: " + "; ".join(errs[:8]))
            elif led is not None:
                listed = {(f.get("file", ""), f.get("class", "")) for f in obj.get("findings", [])}
                files = {f for f, _ in listed}
                missing = [r for r in led["rows"] if (r.get("verdict") or {}).get("status") in ("finding", "needs-check") and r["file"] not in files]
                if missing:
                    problems.append("Rows marked as findings in the worklist are missing from the JSON: "
                                    + ", ".join(f"{r['id']} {r['file']}:{r['verdict'].get('lines', r['lines'])} {r['verdict']['class']}" for r in missing[:6])
                                    + ". Add them, or re-mark them clean with evidence.")

        if not problems:
            return 0
        if led is not None:
            if led.get("stop_blocks", 0) >= MAX_BLOCKS:
                return 0
            led["stop_blocks"] = led.get("stop_blocks", 0) + 1
            save(led_path, led)
        elif data.get("stop_hook_active"):
            return 0  # no ledger to count blocks in: never block twice in a row
        tail = " Then give the final answer again (bench mode: only the JSON object)." if has_json or (led and "bench" in str(led.get("mode", ""))) else ""
        return block(" ".join(problems) + tail)
    except Exception:  # noqa: BLE001 - a broken gate must not trap the session
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
