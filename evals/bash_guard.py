#!/usr/bin/env python3
"""PreToolUse hook for Bash in the skill condition: only the skill's own scripts, plain arguments, nothing else.

Accepts the relative form `python3 .claude/skills/hookhunter/scripts/<name>.py ...` and the absolute form that
${CLAUDE_SKILL_DIR} expands to (`python3 /any/path/.claude/skills/hookhunter/scripts/<name>.py ...`), so the
condition with the skill gets no shell beyond the scripts (Claude Code auto-approves read-only commands otherwise).
"""

import json
import re
import sys

ALLOWED = re.compile(r"^python3 (?:/[A-Za-z0-9_./-]*/)?\.claude/skills/hookhunter/scripts/[A-Za-z0-9_]+\.py(?: [A-Za-z0-9_./=,:@+-]+)*$")


def main() -> int:
    try:
        command = str(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
    except ValueError:
        command = ""
    if ".." in command or not ALLOWED.match(command.strip()):
        print("Bash is limited to the skill's own scripts: python3 .claude/skills/hookhunter/scripts/<name>.py <plain args>. "
              "Use Read, Grep and Glob for everything else.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
