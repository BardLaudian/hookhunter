# hookhunter

A [Claude Code](https://claude.com/claude-code) skill that audits the PHP source of a WordPress plugin or theme for security
vulnerabilities, with **static analysis only** (it reads and searches code; it never runs it and never sends traffic anywhere).

It covers missing authorization, CSRF and nonces, XSS, SQL injection, file upload / traversal / inclusion, object injection, SSRF,
open redirect, privilege escalation, code execution, information disclosure and XXE, and can review a diff between two versions for
incomplete patches. In `bench` mode it emits only a findings JSON (no proof-of-concept).

## Install

```bash
git clone https://github.com/BardLaudian/hookhunter.git ~/.claude/skills/hookhunter
# optional, for the tree-sitter parser (a regex backend is used without it)
pip install -r ~/.claude/skills/hookhunter/scripts/requirements.txt
```

Then ask Claude Code to audit a plugin directory. Use it only on code you are allowed to audit.

## Layout

| Path | What |
|---|---|
| `SKILL.md` | the workflow the agent follows |
| `scripts/` | `wp_map.py` (entry points), `wp_sinks.py` (dangerous calls), `wp_xref.py` (callers and registrations) |
| `reference/` | per-class knowledge files and sources the workflow opens step by step |

This branch is the version `v1.0`, frozen before any benchmark case was run.

## How well does it work?

Measured, not claimed. On the 15 development cases of the benchmark (old, already-patched plugin versions with public CVEs),
2 repeats per case, Claude Haiku 5.5: **recall 30 % (9/30 runs, 95 % CI 10–53 %)**, against 37 % (CI 13–60 %) for the same agent
with no skill. The difference is within the noise; the skill was about 3.7 times cheaper per run. The held-out test split has not been run yet.
Treat the skill as an experiment, not as proven to find more bugs.

The benchmark, dataset labels, harness, results and design documents are on the
[`benchmark`](https://github.com/BardLaudian/hookhunter/tree/benchmark) branch. Paths such as `docs/SPEC.md` mentioned inside
`reference/` refer to that branch.

## Safety

Only for authorized security research on versions that are already patched or code you own. It produces vulnerability class,
location and data flow, not exploits.
