# hookhunter — Design of the new skill (built from scratch)

The old `wp-plugin-triage` stays as condition B (baseline); this new skill is
condition C. Goal: the most effective white-box audit skill for WordPress plugins we can build from
**public, general knowledge** — then let the benchmark decide what actually helps.

## 0. Principles (where they come from)
| Principle | Source of the idea |
|---|---|
| Map the attack surface before hunting; rank by reachability | Shannon ("map before hunting"), ToB `audit-context-building` |
| One focused pass per vulnerability class | Shannon's specialised agents |
| Every candidate is a hypothesis until a refuting pass fails to kill it | ToB `fp-check`, `insecure-defaults` (refuting verifier) |
| "Incomplete" must never look like "clean": report coverage | Shannon, ToB `c-review` (coverage against a parse) |
| After one bug, hunt its variants; check old fixes for incomplete patches | ToB `variant-analysis`, `post-patch-validation` |
| Deterministic helpers for navigation (entry points, callers, sinks) instead of making the model grep blindly | Reverse-engineering MCPs (GhidraMCP / IDA Pro MCP give the model xrefs and function lists), ToB `trailmark` |
| Reportable, remotely reachable bugs; skip what triagers reject | ECC `security-bounty-hunter` |
| Short SKILL.md, detail in files loaded on demand, scripts executed not read | Claude Code skill authoring docs (SKILL.md < 500 lines, progressive disclosure, `${CLAUDE_SKILL_DIR}` scripts) |

Not taken: live exploitation (Shannon validates by attacking a running app). This skill is static
only; anything that would need a running site is reported as `needs-dynamic-check`.

## 1. Layout
```
skills/hookhunter/
├── SKILL.md                      # ≤ 250 lines: modes, workflow, gates, output contract
├── reference/
│   ├── surface.md                # WordPress entry points and how each is reached (auth, nonce, caps)
│   ├── sanitizers.md             # which WP function neutralises which class, in which context
│   ├── wp-traps.md               # WordPress-specific mistakes (is_admin, unfiltered_html, nopriv, …)
│   ├── classes/
│   │   ├── xss.md  sqli.md  authz.md  csrf.md  file-ops.md  object-injection.md
│   │   ├── ssrf.md  open-redirect.md  privesc.md  rce.md  info-disclosure.md  xxe.md
│   ├── verification.md           # refutation checklist per class
│   ├── severity.md               # CVSS 3.1 guidance for WP + what Wordfence/Patchstack accept
│   └── report.md                 # disclosure report template (outside bench mode)
├── scripts/
│   ├── wp_map.py                 # attack-surface map → JSON
│   ├── wp_xref.py                # callers/callees/definitions of a function or hook
│   └── wp_sinks.py               # sink inventory with enclosing function and nearby guards
└── tests/                        # fixtures (tiny synthetic plugins) + pytest for the scripts
```

## 2. SKILL.md content
**Frontmatter:** `name: hookhunter`; description leading with the use case ("Audit the PHP source
of a WordPress plugin or theme for vulnerabilities …"), trigger phrases (EN + ES);
`allowed-tools` limited to Read, Grep, Glob and `Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/*)`.
Only portable keys if it must also run on claude.ai (check SKILL authoring docs).

**Modes:** `audit` (default, full report for disclosure), `bench` (task asks for `findings.json`:
no PoC, schema output only), `diff` (review a version-to-version change: patch validation /
regression).

**Workflow (each step says which reference file to open):**
0. **Gate:** source is local; target is not a live third-party site; for disclosure, confirm the
   version is the latest and check public advisories (skip in bench mode — no network).
1. **Map:** run `wp_map.py <dir>`; read its ranked list (unauthenticated first). For large plugins,
   restrict to top-N entry points and say so in coverage.
2. **Hunt by class:** for each entry point, follow data to sinks (`wp_sinks.py`, `wp_xref.py`),
   opening `reference/classes/<class>.md` for the class being checked. Order: authz/privesc,
   sqli, object-injection, file-ops, rce, ssrf, xss, csrf, open-redirect, info-disclosure.
3. **Refute:** for every candidate apply `reference/verification.md` — upstream capability check,
   hook only reachable by privileged users, nonce verified elsewhere, sanitiser actually adequate for
   the sink context, `unfiltered_html`, dead code. Status: `confirmed` (full chain with file:line
   evidence) / `needs-dynamic-check` / `refuted` (keep a one-line reason).
4. **Variants:** grep the same pattern across the plugin for each confirmed finding; read the
   changelog for past security fixes and check whether siblings of the fixed code are still
   vulnerable (incomplete patches are a common real source of CVEs).
5. **Coverage:** list every entry point from step 1 as reviewed / skipped (+ why). If coverage is
   partial, the report must say "partial", never "no vulnerabilities".
6. **Report:** findings sorted by severity with: file:line, entry point, auth level, data flow,
   why the guards fail, CWE, CVSS vector (from `severity.md`), fix. In `audit` mode, a minimal,
   non-destructive reproduction description for the maintainer, intended for the user's own local
   test install. In `bench` mode, only the JSON schema of SPEC §4.

**Hard rules:** never invent a finding; quote real code; distinguish authenticated vs
unauthenticated; static only; never target live sites; no weaponised payloads.

## 3. Scripts (deterministic, tested)
- Parse PHP with **tree-sitter** (`tree-sitter` + `tree-sitter-php`, pinned) with a regex fallback if
  unavailable; Python ≥ 3.10; no network; output JSON; run in < 30 s on a 1,000-file plugin.
- `wp_map.py`: entry points — `wp_ajax_*` / `wp_ajax_nopriv_*`, `admin_post_*` / `admin_post_nopriv_*`,
  `register_rest_route` (+ value of `permission_callback`, flag `__return_true` or missing),
  `add_shortcode`, block `render_callback`, `add_menu_page`/`add_submenu_page` (+ capability),
  handlers on `init`, `admin_init`, `wp_loaded`, `template_redirect`, `parse_request` that read
  superglobals, cron hooks, widgets, XML-RPC methods. For each: handler function, file:line, whether
  a nonce check / `current_user_can` appears in the handler (static hint, not proof), superglobals
  read, reachability tier (unauth / subscriber / author+ / admin).
- `wp_sinks.py`: echo/print/printf/`_e` of variables, `$wpdb->query|get_*|prepare` misuse,
  include/require, `unserialize`/`maybe_unserialize`, upload/copy/move/unlink/file_put_contents,
  `wp_remote_*`/curl/file_get_contents with variables, `update_option`/`update_user_meta`/
  `wp_update_user`/`wp_insert_user`, `wp_redirect`/`header('Location')`, `call_user_func*`,
  `extract`, `eval`, `system|exec|passthru|shell_exec|proc_open`, `simplexml_load_*`/`DOMDocument`
  loads; each with enclosing function and nearby sanitisers/escapers.
- `wp_xref.py <name>`: where a function/method is defined, who calls it, which hooks register it.
- Tests: 10–15 tiny synthetic plugins (one per class + safe twins) written for this repo;
  defanged; assert the scripts find the entry points/sinks and do not flag the safe twins.

## 4. Reference content rules
- Written from public, general documentation (WordPress developer handbook on security —
  sanitising, escaping, nonces, capabilities; OWASP; CWE) and the author's own knowledge. Cite
  sources at the bottom of each file.
- **No content derived from the benchmark cases** (no plugin names, functions or snippets from
  `dev` or `test`) — otherwise the benchmark measures memorisation of our own hints.
- Each class file: sources, sinks, WP-specific traps, safe vs vulnerable pattern (generic code),
  refutation checklist, typical CVSS range, what triagers usually reject.
- Keep each file focused (≤ ~200 lines); the agent opens only what it needs.

## 5. Evaluation plan for the skill (feeds SPEC conditions)
- **C-full:** the whole skill.
- **Ablations** (the interesting research result): C-min = SKILL.md only; C-noscripts = SKILL.md +
  reference without scripts; C-full. Answers "which part helps?" and whether "hypercomplete" pays
  off or just costs tokens.
- Trigger evals: the skill activates for audit requests (EN/ES) and not for unrelated PHP work.
- Freeze rule: the skill is written and frozen (git tag `skill-v1.0`) **before** running it on any
  benchmark case. Later improvements use `dev` only and get new tags; `test` runs only on frozen tags.
