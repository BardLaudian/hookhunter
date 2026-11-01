# Decisions and Phase 0 findings

Phase 0 (no code). Date: 2026-11-01. Items marked **UNVERIFIED** came only from search snippets or
third-party pages and must be confirmed before they are relied on.

## 1. Plugin source download
- **Verified** (HTTP 200, `akismet` 5.0): `https://downloads.wordpress.org/plugin/<slug>.<version>.zip`
  (zip, `Last-Modified` present), `https://plugins.svn.wordpress.org/<slug>/tags/<version>/`, and
  `https://api.wordpress.org/plugins/info/1.0/<slug>.json`.
- Decision: zip is primary (single artefact, hashable). SVN tags are the fallback and the way to
  list versions. Caveat: closed/removed plugins disappear from both; a case needs both versions
  downloadable at fetch time (already a DATASET.md criterion).
- Caveat: the SHA-256 is of the zip. wordpress.org may regenerate zips, so a hash mismatch on
  re-download must be treated as "re-verify", not silently accepted. Consider also hashing the
  unpacked tree.

## 2. Vulnerability data sources
- **Wordfence Intelligence:** v1/v2 of the feed carried a notice that they would be disabled on
  2026-03-09; v3 needs a free API key from a wordfence.com account. Terms (updated 2026-01-26):
  free, keys are confidential and not transferable. Rate limits are not published. **UNVERIFIED:**
  the current v3 terms on redistribution. Decision: store only IDs, URLs and our own labels, never
  a copy of the feed.
- **WPScan:** free tier 25 requests/day, custom licence that requires a fee for commercial use.
  **UNVERIFIED** (partly from a 2021 snapshot). Decision: use only as a manual cross-reference.
- NVD for CVE metadata (no key needed for light use). Patchstack: not checked.

## 3. Claude Code headless
Local CLI: `claude 2.1.316`. Confirmed from `claude --help`:
`-p/--print`, `--output-format text|json|stream-json`, `--allowedTools`, `--disallowedTools`,
`--tools` (restricts the built-in set; `""` disables all), `--model`, `--max-budget-usd`,
`--no-session-persistence`, `--setting-sources`, `--settings`, `--strict-mcp-config`,
`--disable-slash-commands`, `--permission-mode`, `--add-dir`, `--plugin-dir`, `--bare`,
`--restricted`, `--effort`.
- Decision: restrict tools with `--tools "Read,Grep,Glob"` (removes Bash/web from the set) rather than
  only `--allowedTools`, which just pre-approves. Also pass `--strict-mcp-config`,
  `--setting-sources project` (or `--bare`) and `--no-session-persistence` so user settings,
  global CLAUDE.md and memory don't leak between conditions.
- **Conflict to resolve in Phase 3:** SKILL-DESIGN.md gives the skill `Bash(python3 …/scripts/*)`
  but CLAUDE.md and SPEC.md say agent runs have no Bash. Condition C-full needs a scoped Bash, so
  either Bash is allowed only for those scripts (and A/B/C-min lose nothing but Bash) or the
  scripts can't run in the harness. This must be decided before Phase 3 (see open questions).
- Skills: project skills live in `.claude/skills/<name>/SKILL.md`; `${CLAUDE_SKILL_DIR}` resolves to
  the skill folder and is substituted in skill markdown and in `allowed-tools` Bash rules; the skill
  `allowed-tools` grant applies only to the turn that invokes the skill. Sources: Claude Code docs
  (skills page). **UNVERIFIED locally:** exact discovery with `-p`, and whether skills are
  auto-invoked in headless mode. Needs a 5-minute empirical test in Phase 3 with a dummy skill
  (this is the one thing that would silently invalidate conditions B/C if wrong).
- Name clash: SPEC says B copies the skill to `.claude/skills/wp-plugin-triage/`, but a
  `wp-plugin-triage` skill is also installed in this environment's user scope. The harness must
  isolate the user scope (`--setting-sources project`/`--bare`, clean `HOME`) or condition A is contaminated.
- JSON output: community sources list `result`, `session_id`, `duration_ms`, `num_turns`,
  `total_cost_usd`; token usage fields **UNVERIFIED**. Check with one real call in Phase 3.

## 4. Container network
- `--network none` blocks the model API too. Anthropic's reference devcontainer uses a default-deny
  firewall (`init-firewall.sh`, needs `NET_ADMIN`/`NET_RAW`) with an allowlist that includes more
  than `api.anthropic.com` (npm, GitHub, telemetry hosts).
- Decision: custom allowlist limited to the API endpoint (plus whatever Claude Code strictly needs,
  found by test; telemetry can be disabled by env var). Alternative: a user-defined Docker network
  with an egress proxy that allows only the API host. Docs warn this does not stop exfiltration of
  reachable data, which is acceptable because the mounted plugin code is public.
- Docker is present at `/usr/bin/docker`; semgrep is not installed.

## 5. Model
- `claude-sonnet-5-5` (Sonnet 5.5). Training data cutoff **June 2026**, reliable knowledge cutoff
  June 2026 (Claude Platform docs, models overview). Cases for `after_cutoff = true` must be
  published after 2026-06-30, so with today's date (2026-11-01) there is a window of about four
  months of CVEs. This limits the number of clean cases; expect many flagged older cases and rely
  on the memorisation probe.
- Open: the model that will actually be used for the experiment is the user's call; record it
  in every run regardless.

## 6. Prior art (does something already answer our question?)
| Work | What it does | How we differ |
|---|---|---|
| Tashenova et al., *A Real CVE-Backed Benchmark for WordPress Plugin Vulnerability Detection*, Big Data Cogn. Comput. 2026, 10(9), 303; repo `Aisultan05/wordpress-cve-benchmark` | 1,757 plugin CVEs, function-level labels from vuln→patch diffs, leakage-controlled splits; evaluates static and learned detectors (best macro-F1 0.601) | Function classification of learned models, not an agent reading a whole plugin; no skill ablation. Possible source of candidate CVEs and a method to cite. |
| Jungnickel and Neef, *Evaluating LLMs for Real-World Web Vulnerability Detection*, arXiv 2606.21397 | Six LLMs on four WP plugins with known vulns; Opus 4.6 about 63 % detection, many false positives, inconsistent across runs (figures from a conference page, not the paper) | Compares models and prompts on 4 plugins; we compare skill vs no skill, with negative controls, ablations and CIs on 40 cases. Closest competitor; read it fully before Phase 1. |
| CVE-Bench (arXiv 2503.17332) | Agents *exploiting* web-app CVEs, including WP plugins | Exploitation in a running app; we are static-only. |
| RealVul (EMNLP 2024) | LLM framework for PHP vulnerability detection | Method, not an agent-skill evaluation. |
| nullcon 2022 *Raining CVEs on WordPress plugins with Semgrep*; CodeVigilant semgrep rules (117 rules, 30 WP-specific) | Public Semgrep rules for WP | Candidate for condition D. |
| Wpsec blog and Medium posts on hunting WP CVEs with Claude and Semgrep | Anecdotal workflows | No measurement. |

**Conclusion:** nothing found measures *whether a skill improves* an agent's recall, precision and
cost against a no-skill baseline on WordPress plugins, so the project is not redundant. The
neighbouring work (above all arXiv 2606.21397) means we must position it as "skill effect", not "LLMs can find WP bugs".
Not searched: other WordPress audit skills (only one search done). Do that before S2.

## 7. Condition D (non-LLM baseline)
- A usable public rule set exists (CodeVigilant, plus the Semgrep registry PHP rules; the content of
  an official WordPress ruleset was not confirmed). Decision: keep D as optional; run it only after
  Phase 3, pin the rule set by commit, and report its output as file/line findings mapped to the same
  schema. Drop it if the rules produce thousands of findings per plugin.

## 8. Open questions for the user
1. Scoped Bash for the skill scripts in C-full (see §3), or no-Bash everywhere?
2. Model for the experiment: Sonnet 5.5 (cheapest 5.x) or a stronger one?
3. Wordfence v3 key: are you willing to create one (and read its terms) before Phase 2?
4. `docs/v0.2.1/` and `docs/v0.3/` describe a different project (ghostrules). Move or ignore?

## 9. Decisions taken while writing `reference/` (S2)

- **Sources.** Reference files cite public documentation only. WordPress core behaviour was read from `trunk` on 2026-11-01 and each file says so;
  re-check a point against the plugin's supported core version before relying on it.
- **Wordfence scope not verified.** `wordfence.com/threat-intel/bug-bounty-program/` returned an empty HTTP 202 to every automated fetch, so Wordfence rules appear
  only as unverified summaries. Patchstack's Alliance rules were read in full and are quoted. Revisit if the page becomes readable.
- **Report versus find.** The reference files describe what bounty programmes accept (for example Patchstack: open redirect "inherently out of scope",
  SSRF only with concrete impact). That guidance belongs to `audit` mode reports. In `bench` mode the skill reports every finding in the class list
  of `docs/SPEC.md` it can support with evidence, whether or not a programme would accept it, because ground truth comes from patched CVEs.
  To be reflected in `SKILL.md` (S3).
- **CVSS tables.** All scores in the class files were computed with the FIRST v3.1 base formula (checked against known values 9.8, 9.9, 8.8, 7.5),
  not copied from advisories.
- **Open items (closed after S3, see section 13).** `wp_sinks.py` did not yet cover: `wp_create_user`, `wp_set_password`, `add_user_to_blog`, `grant_super_admin`, variable function calls,
  callable parameters (`array_map`, `usort`, …), `do_shortcode`/`do_action` with variable names, `curl_init( $url )`, `download_url`,
  `media_sideload_image`. The reference files list these as Grep tasks; extend the script before the S4 freeze if the dry run shows they matter.
- **Findings status to output (decided with the maintainer, 2026-11-01).** `confirmed` is written to `findings.json` with `confidence: "high"`;
  `needs-dynamic-check` is written with `"medium"` or `"low"` depending on how much of the chain is unverified; `refuted` is not written.
  `docs/SPEC.md` section 4 shows only `"high"` as an example of `confidence`, so the three-value set is a proposal to confirm in S3 and to add to the schema.
  Recall@3 ranks by this field, so the choice affects the benchmark.
- **Reference index and checks (S2 close).** `reference/README.md` was added as an index; it is not in the layout of `docs/SKILL-DESIGN.md` section 1.
  `tests/test_reference.py` checks the 18 files: line limit, `## Sources` last, required sections in class files, cross-references to files, scripts and `--class` values,
  CVE allow-list, absence of weaponised payloads, absence of benchmark-case slugs and CVEs once `dataset/cases.toml` exists, and every CVSS table row against the formula.
  Link liveness runs only with `WPBENCH_CHECK_URLS=1 pytest -m network`.

## 10. S3: SKILL.md, output schema and activation evals

- **Output schema.** `schemas/findings.schema.json` is the machine-readable form of `docs/SPEC.md` section 4 and is the contract that `SKILL.md`, the dry-run artifacts and (in Phases 3 and 4) the harness
  and scorer share. Value sets fixed in S3, to be reviewed: `class` is one of 17 slugs (`stored-xss`, `reflected-xss`, `dom-xss`, `sqli`, `missing-authz`, `csrf`, `path-traversal`, `file-delete`,
  `file-upload`, `file-inclusion`, `object-injection`, `ssrf`, `open-redirect`, `privesc`, `rce`, `info-disclosure`, `xxe`); `auth_required` is `unauthenticated`, `subscriber`, `contributor` (also author-level)
  or `admin`; `confidence` is `high`, `medium`, `low`. Extra keys are rejected (there is no PoC field). The CWE family map of `docs/SPEC.md` section 5 still has to be written in Phase 4 for these slugs.
- **Frontmatter.** `name`, `description` and `allowed-tools` only, so the file stays valid for other agents that read the standard fields. `allowed-tools` pre-approves tools for the turn; it does not restrict them
  (Claude Code documentation). In the benchmark the restriction to Read, Grep and Glob is enforced by the harness (`--tools`), as in `docs/SPEC.md` section 3.
- **Phase 0 questions answered by the S3 evals (2026-11-01, Claude Code 2.1.316).** A skill placed in `.claude/skills/<name>/` of the working directory is discovered and invoked in headless `-p` mode.
  `--setting-sources project` removes the user-level skills (31 loaded by default, 17 left, none from the user's account), which is how a condition is isolated. The `json` and `stream-json` outputs carry
  `total_cost_usd`, `usage` (input, output, cache creation and read tokens), `duration_ms`, `num_turns` and `modelUsage` with the model id. A minimal call cost 0.017 to 0.047 USD depending on what was loaded.
  Authentication in this environment is the logged-in account (no API key); the Docker image of Phase 3 will need its own credentials.
- **Activation evals** (`tests/evals/triggers.json`, runner `tests/run_trigger_evals.py`, results in `tests/evals/results-*.json`): 32 prompts, English and Spanish, 16 that should load the skill and 16 that should not
  (other PHP and WordPress work, a security audit of non-WordPress code, a live-site scan, site hardening). Dev split before tuning: 6 of 8 positives, 0 of 9 false triggers; both misses were "write the vulnerability
  report" requests, so the description was extended and the dev split rerun (8 of 8, 0 of 9). Held-out split, run once afterwards: 8 of 8 positives (4 English, 4 Spanish), 0 of 7 false triggers. One run per prompt,
  one assistant turn each, model alias `sonnet` (claude-sonnet-5-5), about 0.90 USD in total. Limits: small sample, first move only, no repeats, and no competing skill: with the user's `wp-plugin-triage` installed both
  would match the same requests.
- **Dry run on the synthetic fixtures** (`tests/dry_run/`: `build_dry_run.py`, `bench/*.json`, `REPORT.md`). The workflow was followed by hand. It exposed three fixture defects and one gap in the reference, all fixed:
  the cURL handle in `ssrf-vuln` was never executed; the nonces checked in `authz-*` and `privesc-*` were never created; and three labelled payloads needed quotes that `wp_magic_quotes` escapes (a variable inside a
  `prepare()` template, a serialized string, XML), so `reference/wp-traps.md` trap 19 and the refutation reason `source-still-slashed` were added, and the fixtures now unslash the value.
  The artifacts are checked by `tests/test_dry_run.py` (schema, labelled lines, safe twins, freshness against the generator).
- **Dependencies.** `requirements-dev.txt` lists the packages used by the scripts' tests (jsonschema and PyYAML were added in S3).

## 11. Skill name

- The skill is named `hookhunter` (directory `skills/hookhunter/`, `name: hookhunter`), chosen by the maintainer on 2026-11-01. The description is unchanged and still opens with the use case; the
  name is not repeated in it.
- `docs/SPEC.md` said that for conditions B and C the skill is copied to `.claude/skills/wp-plugin-triage/`; that is only right for B. It now says `.claude/skills/<skill-name>/` with both names.
- The activation results recorded before the rename (dev 6/8 then 8/8, held-out 8/8, 0 false triggers) were produced under the previous name; those result files were removed from the working tree and remain in git
  history at commit `0b74cf0`, the last one with the previous name. The evals were rerun under the new name (section 12).

## 12. Activation evals rerun under the new name (2026-11-01)

Same 32 prompts, same runner, no change to the description between the earlier runs and these. Dev split: 8 of 8 positives, 0 of 9 false triggers. Held-out split (second use, as a rename
regression check and not for tuning): 8 of 8 positives, 0 of 7 false triggers. Cost about 0.57 USD. Results: `skills/hookhunter/tests/evals/results-dev.json` and `results-heldout.json`.

## 13. wp_sinks.py gaps closed before the freeze

Added to `wp_sinks.py` and the parser: calls whose callee is an expression (`$fn()`, `$_GET['f']()`, `$o->$m()`, `A::$m()`, `new $class`) in both backends; rules `dynamic-callee`, `dynamic-class`,
`callable-param`, `hook-dispatch`, `parse-str`, `mail-params`, `url-fetch`, `soap-client`, `account-control`, `privileged-option` and `option-name`. The dispatch rules use a one-function request-taint
heuristic (documented in the script's help and in `reference/classes/rce.md`) so that internal callbacks are not reported. `wp_set_current_user` and `wp_set_auth_cookie` moved from `user-write` to
`account-control` because a cast of the user id was wrongly treated as a guard. Three fixture pairs (`dynamic-call`, `url-fetch`, `account`) with tests for both backends; the dry run still covers the
original 26 fixtures. Performance on the 1,000-file tree is unchanged in practice (4.8 s regex, 2.7 s tree-sitter for `wp_sinks.py`).
