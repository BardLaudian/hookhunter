---
name: hookhunter
description: >-
  Audit the PHP source of a WordPress plugin or theme for security vulnerabilities with static analysis only: missing authorization or
  capability checks, CSRF and nonces, XSS, SQL injection, file upload, path traversal and inclusion, object injection, SSRF, open redirect,
  privilege escalation, code execution, information disclosure and XXE. Reports each finding with file:line evidence, entry point, required
  privilege, CWE and CVSS, or as a findings JSON. Also reviews a diff between two plugin versions for incomplete patches. Use when asked to
  audit, review, or look for vulnerabilities, CVEs or security bugs in the source code of a WordPress plugin or theme, or to write up a
  vulnerability found in one (vulnerability or disclosure report). En español: auditar, revisar la seguridad o buscar vulnerabilidades en
  el código de un plugin o tema de WordPress, redactar el informe de una vulnerabilidad. Not for writing or refactoring plugins, general
  PHP questions, hardening a live site, or scanning sites you do not own.
allowed-tools: Read Grep Glob Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/*)
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: 'for d in "$CLAUDE_PROJECT_DIR/.claude/skills/hookhunter" "$HOME/.claude/skills/hookhunter"; do [ -f "$d/hooks/track_reads.py" ] && exec python3 "$d/hooks/track_reads.py"; done; exit 0'
  Stop:
    - hooks:
        - type: command
          command: 'for d in "$CLAUDE_PROJECT_DIR/.claude/skills/hookhunter" "$HOME/.claude/skills/hookhunter"; do [ -f "$d/hooks/stop_gate.py" ] && exec python3 "$d/hooks/stop_gate.py"; done; exit 0'
---

# WordPress plugin security audit

Static review of a plugin or theme's source for vulnerabilities. Everything stays on local files: never run the target's code, install
WordPress, send requests, or touch a live site.

## Modes

Choose one at the start and keep it.

- **bench**: the task asks for `findings.json`, a JSON schema, or says it is a benchmark. Output only the JSON described under Output. No report prose, no reproduction steps, no payloads.
- **diff**: the task gives two versions of a plugin, or a patch. Review the change: is the fix complete, did it introduce a regression, do siblings of the fixed code share the flaw?
- **audit** (default): a report for a person who will act on it, following `reference/report.md`.

## Hard rules

1. **Static only.** Read files and run the bundled scripts. Do not execute or include the target, and do not use the network.
2. **Never invent a finding.** Every claim cites code you read (`file:line`); quote at most five lines.
3. **Evidence is the code in front of you,** not memory of known CVEs, plugin names, or what the class usually looks like.
4. **A finding is a hypothesis** until the refutation pass fails to kill it (step 3). Unfinished reading goes to coverage, never to "clean".
5. **Name the privilege.** Separate unauthenticated from authenticated and give the lowest role that works on every path.
6. **No payloads or proof-of-concept.** Describe vulnerability class, location and data flow. In audit mode a request-level description for the user's own local test site is allowed (`reference/report.md`).
7. **Never edit the target,** never post or publish findings. If a finding may affect a current release of a public plugin, do not share it and tell the user.

## Workflow

Open the named reference file at the step that needs it, not before. `reference/README.md` indexes all of them.

### 0. Gate

Find the plugin root (main file with a `Plugin Name:` header; `style.css` for a theme) and the version. Confirm the source is local and not a live site.
In audit mode for a disclosure report, do the version and prior-art checks of `reference/report.md` section 1 if network access is available. In bench mode skip them (no network).

### 1. Build the worklist

Run `python3 ${CLAUDE_SKILL_DIR}/scripts/hh_ledger.py --session ${CLAUDE_SESSION_ID} init <plugin-dir>`. One parse runs the map, the join and the walk and
merges them into **rows**: one function per row (an entry-point handler, or the function holding a dangerous call), ranked unauthenticated and
unconfirmed tiers first, request-tainted sinks first. The first 15 rows are **required** (quotas: half from the global ranking, a third from
functions no mapped entry reaches, the rest from request handlers). For a large plugin raise or lower `--required` to fit the budget and say so.
Read `meta.skipped` (`vendor/`, large files) and put it in coverage; if the main file's dispatcher or a `lib/` directory looks like the plugin's own code,
Grep it by hand. Open `reference/surface.md` once.

### 2. Work the rows

Repeat until no required row is left:

1. `hh_ledger.py --session ${CLAUDE_SESSION_ID} next` gives the next rows, each with the exact `Read` to make, its entry points, sinks and the class files to consult.
2. **Read the function** (the `open` line) and, when the tier matters, the registration line. A row's hints are not proof: a check can live in a callee, a base class or an earlier hook,
   and `is_admin()` is true for visitors on `admin-ajax.php`, so it is never authorization.
3. Judge it with the class file (`reference/classes/<class>.md`) plus `reference/wp-traps.md` and `reference/sanitizers.md` when a guard decides it. Write the candidate as one sentence:
   **[tier]** reaches **[entry point, file:line]**, whose **[source]** flows to **[sink, file:line]** without **[missing or inadequate guard]**, giving **[effect]**.
4. Mark it, with plain tokens (no quotes needed):
   - `mark U7 finding --class=sqli --lines=120-134`
   - `mark U7 needs-check --class=ssrf --gap=filter`
   - `mark U7 clean --reason=cap-check --evidence=includes/ajax.php:88` (reasons: `cap-check`, `nonce`, `nonce-and-cap`, `not-reachable`, `sanitized`, `escaped`,
     `prepared`, `safe-destination`, `same-privilege`, `constant-input`, `dead-code`, `intended-feature`)
   - `mark U7 skip --reason=budget`
   `clean` is refused unless the cited line exists and holds a guard of that kind, and refused for a function you never opened with `Read`. That is the
   evidence rule of `reference/verification.md` section 3b, enforced. If you cannot cite the line, the row is not clean: mark it `needs-check` or `skip`.
5. After a `finding`, do the variant step (4 below) before the next row.

A **Stop hook** checks the worklist when you try to finish: while a required row has no verdict it sends you back with the next rows, and it validates the
findings JSON (an invalid answer scores as a failed run). If the budget really is gone, mark the remaining rows `skip --reason=budget`; `abandon --reason=<slug>`
turns the gate off when the task is not an audit after all. `examples/worked-rows.md` shows four rows worked end to end, including two wrong dismissals.

**Beyond the rows.** The scripts do not follow a value through a wrapper object, a function argument, a stored option, a returned URL or SQL fragment, a custom DB
wrapper or a loader object. After the required rows, spend the remaining budget on:
- `wp_sinks.py <dir> --class <classes> --risk unguarded,guarded` for the classes the rows touched. For `sqli`, open every `guarded` row whose only guard is
  `prepare`, `esc_sql` or `esc_like` and read the format string (a value outside a placeholder, `ORDER BY`, `LIMIT`, `IN (...)` is not protected). For
  `file-ops`, `file-inclusion`, `ssrf`, `open-redirect` and `xxe`, open `guarded` rows that carry `function_guard_accepted` (`reference/wp-traps.md` trap 20).
- `wp_sinks.py --sink <name>` for checks that are not one call: `html-build`, `sql-build` (quoted or unquoted variable in SQL built as text), `unchecked-guard-result`,
  `meta-key`, `safety-flag-disabled`, `filetype-override`. Rows with `origin: stored` read an option, meta, cart or session value: find who writes it.
- `wp_xref.py <dir> <name>` for callers, registrations and callees; recursive Grep for `vendor/`, JavaScript, `$wpdb` wrappers and `->loader->add_action`.
- The surface the scripts do not list (`reference/surface.md` section 4): files without an `ABSPATH` guard, `save_post`, profile and comment hooks, `heartbeat_received`,
  upload hooks, query vars. Optional rows (`next` after the required ones) come next.

Class order and files (open the one for the class being checked, plus `reference/wp-traps.md` and `reference/sanitizers.md` when you judge a guard):

| Order | Class | File |
|---|---|---|
| 1 | missing authorization, IDOR | `reference/classes/authz.md` |
| 2 | privilege escalation, account takeover | `reference/classes/privesc.md` |
| 3 | SQL injection | `reference/classes/sqli.md` |
| 4 | object injection | `reference/classes/object-injection.md` |
| 5 | file upload, traversal, read, delete, inclusion | `reference/classes/file-ops.md` |
| 6 | code and command execution | `reference/classes/rce.md` |
| 7 | SSRF | `reference/classes/ssrf.md` |
| 8 | XXE | `reference/classes/xxe.md` |
| 9 | XSS | `reference/classes/xss.md` |
| 10 | CSRF | `reference/classes/csrf.md` |
| 11 | open redirect | `reference/classes/open-redirect.md` |
| 12 | information disclosure | `reference/classes/info-disclosure.md` |

### 3. Refute

The ledger's `clean` verdict is the refutation; apply `reference/verification.md` to every candidate before you mark it. **Dropping a candidate as "admin only", "sanitised" or "permissions fine" requires recorded evidence (`verification.md` section 3b): the registering hook line and the capability check, the sanitiser line and the characters it allows, or the permission function read in every branch. Without it the candidate is `not-reviewed` and goes to coverage, not to `refuted`.** A denylist, or protection that depends on the server (`.htaccess`, `chmod`, a random directory), is not enough to mark `refuted`: use `needs-dynamic-check` and name the gap (check 5b). Try to kill it: dead code, wrong tier, source not attacker-controlled, a guard that fits the sink's context and stops execution,
expected functionality, the privilege already held. Assign a status:

- `confirmed` (`mark finding`): every link holds, with `file:line` for entry point, source, each guard and why it fails, and sink.
- `needs-dynamic-check` (`mark needs-check --gap=`): complete except one named runtime fact (a filter, constant, server rule, library or PHP version, another plugin).
- `refuted` (`mark clean --reason= --evidence=`): a reason with the `file:line` that refutes it.

"I could not find the bug" is not `refuted`. Do not upgrade a status because the class is serious.

### Provenance (only when the task asks for it)

When a task measures the skill, record beside the findings, never inside the bench JSON, which allows no extra keys, one line per reported finding with `found_by`: `join` (a `wp_join.py` candidate), `walk` (a `wp_walk.py` function row or checklist entry), `sinks` (`wp_sinks.py` row), `map` (`wp_map.py` entry), `ledger` (a required row you would otherwise have skipped), `refutation-rule` (a `clean` refused by the evidence check that turned out real) or `none` (found by reading or Grep), plus `hinted` if the plugin's own text (changelog, advisory title) named the place.

### 4. Variants

For each `confirmed` finding, Grep the same sink, helper and parameter name across the plugin and open the matches. Read the changelog or readme for earlier security fixes
and check whether neighbouring code got the same fix (`reference/verification.md` section 5).

### 5. Coverage

`hh_ledger.py --session ${CLAUDE_SESSION_ID} status` prints the coverage note (rows reviewed, required done, skipped, files and directories not parsed). Add anything you know was not read. If anything is unverified the result is **partial**, and you say so.
A report with no findings and partial coverage must not read as "no vulnerabilities".

### 6. Report

Per mode, see Output. Rank by confidence and severity (`reference/severity.md`) so the most reliable findings come first.

## Output

### bench

Write only JSON to the path the task names (normally `/out/findings.json`); if none is named, print it. No comments, no extra keys:

```json
{"findings": [{
  "file": "includes/class-admin.php", "line_start": 120, "line_end": 134, "function": "save_settings",
  "entry_point": "wp_ajax_save_settings", "cwe": "CWE-79", "class": "stored-xss",
  "auth_required": "subscriber",
  "data_flow": "$_POST['title'] -> update_option -> echo in settings page without esc_html",
  "confidence": "high"
}]}
```

- **One finding per vulnerable location and class.** Findings with `refuted` status are not written.
- `file`: path relative to the plugin root, forward slashes. `line_start`/`line_end`: the vulnerable code where the fix belongs (the sink or the unguarded statement), a few lines, not the whole file.
- `function`: the enclosing function or method name without the class (`""` at top level). `entry_point`: the hook name, route, shortcode or action as registered (`""` if none).
- `cwe`: `CWE-<n>` from the table below. `class`: exactly one of the slugs below. `data_flow`: one line, source -> guards -> sink.
- `auth_required`: `unauthenticated`, `subscriber`, `contributor` (also for author-level) or `admin`; for stored XSS the role that plants the value.
- `confidence`: `high` for `confirmed`; `medium` or `low` for `needs-dynamic-check` depending on how much is unverified.
- Order the array by confidence, then impact. `{"findings": []}` is valid when nothing survives. Print a one-line coverage note in your reply, outside the file,
  unless the task says the final message must be only the JSON. `python3 ${CLAUDE_SKILL_DIR}/scripts/hh_validate.py <file|->` checks it against `schemas/findings.schema.json`; the Stop hook runs the same check.

| `class` | CWE | `class` | CWE |
|---|---|---|---|
| `stored-xss`, `reflected-xss`, `dom-xss` | CWE-79 | `file-inclusion` | CWE-98 |
| `sqli` | CWE-89 | `object-injection` | CWE-502 |
| `missing-authz` | CWE-862 (wrong check 863, by object id 639) | `ssrf` | CWE-918 |
| `csrf` | CWE-352 | `open-redirect` | CWE-601 |
| `path-traversal`, `file-delete` | CWE-22 | `privesc` | CWE-269 |
| `file-upload` | CWE-434 | `rce` | CWE-94 (commands CWE-78) |
| `info-disclosure` | CWE-200 | `xxe` | CWE-611 |

In bench mode report every finding you can support with evidence, including classes that disclosure programmes decline (open redirect, blind SSRF).

### audit

Follow `reference/report.md` section 4: summary table, then per finding the entry point, privilege, data flow with `file:line`, why the guards fail, impact, CVSS vector
and assumptions (`reference/severity.md`), a request-level reproduction for a local test site, and a suggested fix. Add variants checked, coverage, unverified items and prior art.
Sort by severity. Programme acceptance rules in the class files tell the user what a bounty programme would decline; they do not remove a real finding.
You write the report; you do not send it anywhere.

### diff

Compare the two versions with Read and Grep (and `wp_sinks.py` on both trees); if a patch file is supplied, read it. Report: which dangerous behaviour the change removes, whether
the removal is complete for every path and sibling, regressions the change introduces, and variants. Use the audit format, or the bench JSON if the task asks for it.

## Scripts

All are read-only, offline and print JSON. Use `--backend regex` if tree-sitter is not installed (it is chosen automatically). They parse `.php`, `.inc` and `.phtml` files and skip
`vendor/`, `node_modules/`, `.git/` and files over 2 MB, listing them under `skipped`.

| Script | Use |
|---|---|
| `hh_ledger.py [--session S] init <dir> [--required N]` / `next` / `show <id>` / `mark` / `status` / `abandon` | the worklist: rows, verdicts, evidence checks, coverage (step 1-2) |
| `hh_validate.py <file\|->` | bench JSON against `schemas/findings.schema.json`, with hints for near-miss values |
| `wp_map.py <dir> [--top N]` | entry points ranked by tier, with nonce and capability hints, request input read up to three calls down, boot-time code and file-level request reads |
| `wp_sinks.py <dir> [--class a,b] [--risk unguarded,guarded,constant]` | dangerous calls, enclosing function, guards in arguments, `risk`, `origin`, `request_tainted`, `function_guard_accepted`, `weak_gates_in_function`; `--sink` filters by sink name (`html-build`, `sql-build`, `safety-flag-disabled`, `filetype-override`, `unchecked-guard-result`, `meta-key`, ...) |
| `wp_join.py <dir> [--risk unguarded,guarded] [--depth N] [--top N]` | map x sinks: ranked (entry point, reachable sink) candidates; unconfirmed tiers rank up; `unresolved_entries` and `unreached_sinks` are always listed |
| `wp_walk.py <dir> [--depth N] [--classes ...] [--top N]` | request-built values reaching unguarded sinks per function (reached or not), plus a `checklist` of every admin page / ajax / admin-post / rest / shortcode entry to open and tick off |
| `wp_xref.py <dir> <name>` | definitions, callers, registrations, hook handlers, callees |

A `guarded` sink is a hint: check that the guard fits the context (`function_guard_accepted` says which guard was accepted). An `unguarded` sink is a candidate, not a finding. Gaps are listed in each class file.

## Other files

- `hooks/`: `stop_gate.py` (Stop: coverage and JSON gate) and `track_reads.py` (PostToolUse on Read: which ranges were opened). Registered by this file's frontmatter
  when the skill is invoked; they do nothing in a session without a worklist. State lives outside the plugin, in `$HH_STATE_DIR` or the temp directory.
- `examples/worked-rows.md`: rows worked end to end, with the evidence a `clean` needs and two dismissals that were wrong. Read it once before the first `mark`.
- `agents/refuter.md`: prompt for a second, cold reader of every `clean` row on a high-tier entry, when the Agent tool is available (audit mode). Not used in bench runs.
- `schemas/findings.schema.json`: the bench output contract.

## Reference files

`reference/README.md` maps workflow steps to files. Shared ones: `surface.md` (entry points and tiers), `wp-traps.md` (checks that look safe but are not), `sanitizers.md` (which function
neutralises which class in which context), `verification.md` (refutation and statuses), `severity.md` (CVSS and programme rules), `report.md` (audit-mode report and disclosure).

## Style

Be brief and concrete. State facts with `file:line`, say what you did not verify, and keep one finding per root cause and location. Do not pad a clean result with speculative findings.
