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

### 1. Map

Run `python3 ${CLAUDE_SKILL_DIR}/scripts/wp_map.py <plugin-dir>` and read the ranked entry points: type, tier (`unauth`, `subscriber`, `author+`, `admin`, `system`),
`nonce_check`, `cap_check`, `superglobals`, `flags`. The hints are not proof: a check can live in a callee, a base class or an earlier hook.
Open `reference/surface.md`. Read the `skipped` list (`vendor/`, large files) and put it in coverage. For a large plugin start with `--top 40` and say what remains.
Grep for surface the script does not list (`reference/surface.md` section 4): files without an `ABSPATH` guard, `save_post`, profile and comment hooks, `heartbeat_received`, upload hooks, query vars, JavaScript files.

### 2. Hunt by class

Take entry points from the top of the map (unauthenticated first). Follow request data to sinks:

- `python3 ${CLAUDE_SKILL_DIR}/scripts/wp_sinks.py <dir> --class <classes> --risk unguarded` lists dangerous calls with the guards found in their arguments and function.
- `python3 ${CLAUDE_SKILL_DIR}/scripts/wp_xref.py <dir> <function-method-or-hook>` gives definitions, callers, registrations and callees.
- Read each handler in full. Then Grep for what the scripts cannot see: `vendor/`, JavaScript, dynamic dispatch, `$fn()` calls, `curl_init( $url )`, `download_url`, `do_shortcode`/`do_action` with request values.

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

Write each candidate as one sentence: **[tier]** reaches **[entry point, file:line]**, whose **[source]** flows to **[sink, file:line]** without **[missing or inadequate guard]**, giving **[effect]**.

### 3. Refute

Apply `reference/verification.md` to every candidate. Try to kill it: dead code, wrong tier, source not attacker-controlled, a guard that fits the sink's context and stops execution,
expected functionality, the privilege already held. Assign a status:

- `confirmed`: every link holds, with `file:line` for entry point, source, each guard and why it fails, and sink.
- `needs-dynamic-check`: complete except one named runtime fact (a filter, constant, server rule, library or PHP version, another plugin).
- `refuted`: a one-line reason with the `file:line` that refutes it.

"I could not find the bug" is not `refuted`. Do not upgrade a status because the class is serious.

### 4. Variants

For each `confirmed` finding, Grep the same sink, helper and parameter name across the plugin and open the matches. Read the changelog or readme for earlier security fixes
and check whether neighbouring code got the same fix (`reference/verification.md` section 5).

### 5. Coverage

List every entry point from step 1 as reviewed or skipped, with the reason, plus anything unparsed or unread. If anything is unverified the result is **partial**, and you say so.
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
- Order the array by confidence, then impact. `{"findings": []}` is valid when nothing survives. Print a one-line coverage note in your reply, outside the file.

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
| `wp_map.py <dir> [--top N]` | entry points ranked by tier, with nonce and capability hints |
| `wp_sinks.py <dir> [--class a,b] [--risk unguarded,guarded,constant]` | dangerous calls, enclosing function, guards in arguments, `risk` |
| `wp_xref.py <dir> <name>` | definitions, callers, registrations, hook handlers, callees |

A `guarded` sink is a hint: check that the guard fits the context. An `unguarded` sink is a candidate, not a finding. Gaps are listed in each class file.

## Reference files

`reference/README.md` maps workflow steps to files. Shared ones: `surface.md` (entry points and tiers), `wp-traps.md` (checks that look safe but are not), `sanitizers.md` (which function
neutralises which class in which context), `verification.md` (refutation and statuses), `severity.md` (CVSS and programme rules), `report.md` (audit-mode report and disclosure).

## Style

Be brief and concrete. State facts with `file:line`, say what you did not verify, and keep one finding per root cause and location. Do not pad a clean result with speculative findings.
