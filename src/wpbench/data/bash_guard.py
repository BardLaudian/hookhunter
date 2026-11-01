#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool in condition C-full (docs/DECISIONS.md section 15).

Claude Code auto-approves read-only shell commands (grep, cat, sed -n...), which would give C-full more tools than
A and B. This hook lets exactly one shape through: ``python3 .claude/skills/<skill>/scripts/<name>.py [args]`` with
no shell metacharacters. Anything else is blocked (exit code 2, reason on stderr).
"""

import json
import re
import sys

ALLOWED = re.compile(r"^python3 \.claude/skills/hookhunter/scripts/[A-Za-z0-9_]+\.py(?: [A-Za-z0-9_./=,:@+-]+)*$")


def main() -> int:
    try:
        command = str(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
    except ValueError:
        command = ""
    if ".." in command.split() or not ALLOWED.match(command):
        print("Bash is limited to the skill's own scripts: python3 .claude/skills/hookhunter/scripts/<name>.py <args>. Use Read, Grep and Glob for everything else.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
