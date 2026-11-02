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

## 14. Phase 1: scaffold and dataset tooling

- **Package.** `src/wpbench/` (hatchling, Python 3.11+, typer and rich) with `vocab.py` (closed vocabularies), `cases.py` (parser and validator), `fetch.py`, `diff.py`, `split.py`, `cli.py`. The vocabularies
  are duplicated from `schemas/findings.schema.json` on purpose and a test fails if they drift.
- **Validator strictness.** Errors: malformed id (`wp-NNNN`), CVE (`CVE-YYYY-NNNN+`), CWE, slug, versions, dates, https `source_url`, source outside wordfence/wpscan/patchstack/nvd, class or auth outside the vocabularies,
  duplicate ids or CVE-in-plugin pairs, `fixed_version` equal to `vuln_version`, malformed hashes, bad truth ranges or paths. Warnings: hash not recorded yet, unsigned label (excluded from metrics), unexpected fields,
  notes over five lines. `after_cutoff` is only checked for type: the model and its cutoff are not decided (Phase 0 question 2), so no date rule is hard-coded.
- **fetch.** Builds `https://downloads.wordpress.org/plugin/<slug>.<version>.zip` (verified in Phase 0), refuses a release with no recorded SHA-256 unless `--allow-unhashed` (it then prints the hash for the maintainer to
  review and record), refuses and unpacks nothing on a mismatch, and writes a marker so repeated fetches are cached. Unpacking rejects absolute or non-portable names, `..`, symbolic links, more than 50,000 entries or more than
  400 MB, strips a single top-level folder, and does not restore file modes. The zip itself is not kept.
- **Not enforced yet:** the rule "never run on the latest version of a plugin" needs a live check against the plugin API; it belongs to case selection in Phase 2 (`api.wordpress.org/plugins/info/1.2/`).
- **diff.** PHP files only (`.php`, `.inc`, `.phtml`), line endings normalised, warns above about 300 changed lines. Advisory text is read from `dataset/advisories/<id>.md` (to be saved by the maintainer; `docs/DATASET.md`
  did not say where it comes from).
- **split.** Stratified by class, per-class shuffle seeded with `seed:class`, remainders to the largest fractional share, independent of input order. It writes `split` into `cases.toml` in place (comments and layout kept) and the
  seed into `dataset/splits.toml`, and refuses to touch a dataset that already has assignments unless `--force`, because the test split is frozen once committed. `wpbench validate` cross-checks the two files.
- **Tests.** `tests/` (68 tests for the package, 521 in the whole suite) use a fake zip and an injected downloader: no network. Shared helpers live in `tests/helpers.py` rather than a `conftest.py` because the skill's tests import their own
  `conftest`; the module `test_cli.py` of the package is named `test_wpbench_cli.py` for the same reason.

## 15. Phase 3: harness plan and dry run (2026-11-01, work in progress)
- **Done:** `prompts/task.md`, `runplan.py` (`--dry-run`), `execute.py` (staging, container run, record, schema validation, resume, spend cap), `env.py` + `proxy.py` + `docker/` (images, internal network, allow-list proxy), tests with a fake runner. **Not done / not verified:** no run has been made against the API from inside a container (no `ANTHROPIC_API_KEY` in this environment, only a subscription login); the 5-minute dummy-skill test of section 3 is covered by the S3 activation evals on the host (section 12), not inside the container.
- **Verified without spending:** the agent container has no route to the internet (`Network is unreachable`); through the proxy `api.anthropic.com:443` gets `200` and `example.com:443` gets `403`; plugin and work dir are read-only, root fs read-only, user 1000, `claude 2.1.316` and tree-sitter run in the image; hookhunter's `wp_map.py` runs inside it. Claude Code may need hosts other than the API; the proxy logs every `DENY` so the allow-list can be widened only as far as needed.
- **One real call on the host (about $0.011, 2 turns)** fixed the stream-json shape used by the parser: events `system/assistant/user/rate_limit_event/result`; the `result` event has `total_cost_usd`, `usage` (input, output, cache read/creation), `num_turns`, `duration_ms`, `terminal_reason`, `permission_denials`. Observed base context was about 11k tokens without a skill (the estimate assumes 14k). Tool calls are counted from `tool_use` blocks; `Skill` calls set `skill_invoked`, so a B/C run in which the skill never loaded can be detected.
- **Findings are returned in the final message, not written to `/out/findings.json`.** SPEC section 3 asks for a file, but the agent has only Read/Grep/Glob (no Write), so it cannot create one. The harness will extract the JSON from the `result` field of `--output-format json` and write `/out/findings.json` itself, then validate it against the schema. Invalid output = failed run, counted.
- **Scoped Bash for C-full (accepted by the user, 2026-11-01).** CLAUDE.md and SPEC say "no Bash"; hookhunter's scripts need it. The plan gives C-full `Bash(python3 .claude/skills/hookhunter/scripts/*)` and nothing else; A, B, C-min and C-noscripts have no Bash. This is a deviation from CLAUDE.md. Mitigation: container with read-only mounts, no capabilities, egress only to the API proxy. Residual risk: a scoped Bash rule may be bypassed by shell syntax; not tested.
- **Egress.** `--network none` blocks the API. The command uses a user-defined network `wpbench-egress` and an allow-list proxy `wpbench-proxy` for `api.anthropic.com` only. Neither exists yet; the dry run prints NOT READY.
- **Condition B source.** `wp-plugin-triage` is not in this repo; the harness copies it from the user scope (first match under `~/.claude/skills`) and will record its tree hash with every run. Its redistribution status is not checked.
- **Model and price.** `claude-sonnet-5-5`, $2/$10 per million tokens, cache read $0.20 (Claude API model table cached 2026-10-06). The experiment model is still the user's decision.
- **The cost estimate is a model, not a measurement.** Low/mid/high assume the agent reads 15/35/70 % of the PHP (vendor excluded) in 25/45/80 calls with 8k/20k/40k output tokens, prompt caching working. No real audit run has been made yet; the pilot replaces these numbers. The $3/run cap can cut the largest plugin (wp-0002) short in the high scenario.
- **pilot-1 (2026-11-02, claude-haiku-5-5, 36 runs, $5.94) is NOT a valid comparison. Do not score it for B or C.** Three defects, all found by reading the transcripts:
  1. `--tools Read,Grep,Glob` removed the **Skill tool**: the `init` event listed `tools: Glob, Grep, Read`, so the model could not load the skill (`skill_invoked` 0/24 for B and C-full). Fixed: conditions with a skill get `Skill` in `--tools` and `Skill(<name>)` in `--allowedTools` (other bundled skills stay unapproved; the one tried, `debug`, was refused).
  2. C-full had **more tools than A and B**: Claude Code auto-approves read-only shell commands, so C-full made ~170 `grep`/`sed`/`cat` calls through Bash on top of the scripts, even with the scoped allow rule (also confirmed with `--permission-mode dontAsk`). Fixed: a `PreToolUse` hook (`src/wpbench/data/bash_guard.py`, installed in the C-full work dir) lets through only `python3 .claude/skills/hookhunter/scripts/<name>.py <plain args>`; checked on the host with the real model (`ls`, `grep` blocked, the script ran) and with 11 unit cases. The "scoped Bash" the user accepted therefore now means exactly that.
  3. **15 of 36 runs failed with "Credit balance is too low"** (all of wp-0004 fixed, wp-0005, wp-0006 for every condition, plus wp-0004 fixed). Condition A is usable for 7 runs but the plan is incomplete. One more run, wp-0001 fixed C-full, ended `invalid_output` (no `confidence` field).
  Also learned: with Haiku 5.5 a run cost about $0.12 and took about 2.5 minutes (the estimate said $0.30); the proxy saw only `api.anthropic.com:443`; Claude Code needs no other host.

## 16. Phase 4: scoring (2026-11-02, local, no API calls)
- **Done:** `cwe_families.py`, `match.py`, `stats.py`, `score.py`, `probe.py`; `wpbench score` (recall, recall@3, fixed-version false alarms, cost and cost per hit, skill-loaded rate, paired bootstrap CIs, labelling sheet) and `wpbench probe`; 30 tests. The probe is **written but not run** (about a cent per case, needs the API key).
- **Match rule** is SPEC section 5 literally: same file (paths normalised: `./`, `plugin/`, backslashes, case) AND (line ranges within +-10 OR same function name, empty names never match) AND compatible family. Family = the CWE's family when the map knows it, else the agent's class slug; two unknowns never match.
- **Debatable family choices (a decision, not a fact):** `authorization` absorbs privilege escalation (269) and IDOR (639) because agents report the same bug as 862/863/269 interchangeably; code execution groups 94/95/77/78/470/829. A stricter map would lower every recall.
- **Known weakness of the "same function" clause:** when the truth function is a giant dispatcher (wp-0004: `execute_tool`, thousands of lines) any authorization finding inside it matches, even 800 lines away. One condition-A hit on wp-0004 was a second finding of this kind next to the genuine one; the genuine one matched on location anyway. Fix at labelling time: truth `function` should name the smallest unit (here there is none), or add a line cap to the function clause. Not changed, because SPEC defines the rule.
- **Truth has one location.** wp-0002 (four unserialize sites) and wp-0003 (sink vs `eval_shortcode`) have more than one defensible location; a finding at an alternative site counts as a miss. Report recall as a lower bound for those cases.
- **What counts as a miss.** `invalid_output` = miss (the agent failed to deliver, SPEC). `error`/`timeout`/`budget` are infrastructure: excluded and listed. Records of an experiment marked `INVALID.txt` count only for condition A. A later experiment replaces the same run id.
- **Unsigned labels** are excluded and named in the output (CLAUDE.md).
- **Unmatched findings** go to `unmatched_sheet.csv` (all if at most 50, else a seeded sample) for the human to label `fp` / `plausible` / `real-but-other`; re-scoring keeps labels already entered. Precision is reported only as that breakdown.
- **Bootstrap:** resample cases with replacement (10,000, seed 20261101), mean over repeats per case first. With fewer than 10 cases the output says the interval only describes resampling a handful of cases.
- **Result on the data in hand (`results/pilot`)** is not a finding about the skill: A has 4 cases (recall 3 of 4, 0 false alarms on 3 fixed runs, 0% skill loaded by definition); B and C-full have one case each (wp-0003, vulnerable version only) and B never loaded its skill. wp-0003 vulnerable, condition A: the matching finding was the 10th of 10 by confidence order, so recall@3 missed it.
- **Step 2 (2026-11-02, Haiku 5.5, wp-0001..wp-0004, vulnerable version, 1 repeat, `runs/pilot-2`, $0.70 for 6 new runs).** Skill activation when the agent decides: **C-full 4/4**, **B 1/4** (only wp-0001; wp-0002..wp-0004 never called the Skill tool although it was listed). B's description is Spanish and the task prompt English; whether that explains it was not tested. Recall is 3 of 4 for A, B and C-full alike, with the same three cases hit (wp-0001, wp-0003, wp-0004) and wp-0002 missed by all; recall@3 A 50 %, B 25 %, C-full 50 %. With 4 cases and 1 repeat no difference is shown (paired CI [0, 0] means all four paired cases were identical, not that the estimate is precise). Per-run cost is not comparable across conditions here: A's runs include fixed versions and were made earlier, and Haiku's price tier depends on context size.
- **Fixed-version controls (2026-11-02, B and C-full, wp-0001..wp-0004, $1.25).** Condition A has only 3 controls (its wp-0004 control failed for lack of credit in pilot-1), so false-alarm denominators are 3 for A and 4 for B and C-full. SPEC-literal result: A 0 of 3, B 1 of 4, C-full 1 of 4. Reading the two hits: **B / wp-0003 fixed** is a low-confidence finding on the same sink describing a residual case (an administrator renders the page); debatable, counted. **C-full / wp-0004 fixed** is two findings about post publication status at lines 1397 and 3091 that match only through the same-function clause (`execute_tool`), i.e. a measurement artifact. `wpbench score --function-cap 100` limits that clause to findings within 100 lines of the truth: C-full drops to 0 of 4, nothing else changes, recall is identical. The default stays the SPEC literal rule; the cap is a sensitivity analysis, and the report should show both until the user decides whether SPEC section 5 gets the cap.
- **SPEC section 5 changed (user decision, 2026-11-02):** the same-function clause only counts when the finding lies within 100 lines of the truth range. `match.FUNCTION_CAP = 100` is the default; `wpbench score --no-function-cap` reproduces the old rule as a sensitivity analysis.
- **Condition B-invoked** (added 2026-11-02): identical to B (same skill, tools, copy) except that the task prompt starts with "Use the wp-plugin-triage skill for this audit." It separates "the skill does not help" from "the model did not load the skill". B stays as the agent-decides measurement. Two of its 12 runs ended `invalid_output` (wp-0001 vuln: no `confidence`; wp-0004 fixed: `auth_required` "author"), counted as misses by rule, so its recall is a lower bound.
- **Six-case pilot, repeat 1, SPEC cap on (Haiku 5.5, 3 conditions + B-invoked, `results/pilot`):** recall A 4/6, B 4/6, C-full 4/6, B-invoked 2/6; false alarms A 0/6, B 1/6, C-full 0/6, B-invoked 0/6; skill loaded B 33 %, B-invoked and C-full 100 %. No difference shown (paired CIs include 0; 6 cases, 1 repeat). Cost per run: A about $0.23, B $0.12, C-full $0.08, B-invoked $0.04.
- **Six cases, two repeats, Haiku 5.5, SPEC cap on (`results/pilot`, experiments pilot-1/2/3; repeat 2 cost $4.32).** Recall (cases hit at least once per repeat, mean over repeats): A 50 %, B 58 %, C-full 50 %, B-invoked 33 % (1 repeat); paired differences to A: B +8 points CI [0, +25], C-full 0 [0, 0], B-invoked -17 [-58, +17]; none supports a difference. recall@3 33 % for A, B, C-full. False alarms on the fixed versions: A 0/6, B 8 %, C-full 0/6, B-invoked 0/6 (A and C-full 1/6 and B 1/6 without the 100-line cap, `--no-function-cap`). Findings per vulnerable run: A 5.1, B 5.0, C-full 2.7. Cost per run: A about $0.20, B $0.12, C-full $0.07; per hit A $0.82, B $0.42, C-full $0.27. Skill loaded: B 29 %, C-full 96 %, B-invoked 100 %.
- **Reading, with the limits stated.** (1) Run-to-run noise is large: A hit wp-0001 in repeat 1 and missed it in repeat 2; with 6 cases and 2 repeats a single case moves recall by 8 points. (2) wp-0002 and wp-0005 were missed by every condition in every repeat. (3) A and C-full hit exactly the same (case, repeat) cells; C-full produced half as many findings and cost about a third per run, but whether those findings are fewer false positives needs the labelling sheet (41+ unmatched findings, `results/pilot/unmatched_sheet.csv`), and the cheaper cost may partly be Haiku's context-size price tier, not only the skill. (4) One more C-full run ended `invalid_output` (wp-0002 r2, no `confidence`), counted as a miss. (5) Cases are post-cutoff only if Haiku 5.5's cutoff is June 2026 or earlier, unverified; the memorisation probe has not been run.

## 17. Phase 5: full dataset (2026-11-02, in progress)
- **Candidate pool and filters.** NVD (CNA Wordfence) CVEs, plugin slug from the trac links, last vulnerable version from the description, fixed version = first later release, and at least two later releases must exist (never the latest). Diff measured on PHP without `vendor/`: 3 to 300 changed lines. Every diff was read before a case was drafted; 36 candidates were dropped with a reason in `dataset/dropped.toml`.
- **Older CVEs allowed (user decision, 2026-11-02), only to fill missing classes (CSRF, open redirect, file upload, XXE, SSRF, SQL injection).** Window: published 2026-01-01 to 2026-06-30. They carry `after_cutoff = false` for Sonnet 5.5 (cutoff June 2026) and are to be reported separately. The cutoff of Haiku 5.5 (the pilot model) is still unverified; the memorisation probe has not been run.
- **Labels signed on the maintainer's instruction (2026-11-02):** wp-0007 to wp-0040 were signed as `reviewed_by = "BardLaudian"`, `reviewed_on = "2026-11-02"` after the maintainer said they had read all diffs. The notes keep the drafter's open doubts (`Draft:` lines); `wpbench review --checks` lists them.
- **Known weak labels (a single truth location cannot express them):** wp-0002 (four sinks), wp-0003, wp-0013 (signing step), wp-0014 (sinks in several views, label on the fix site), wp-0015 (duplicated code in two classes), wp-0017 (four identical sinks, one labelled), wp-0020, wp-0030, wp-0031 (several sinks). Matching rewards the labelled location only, so recall on these cases is a lower bound.
- **wp-0036 (wp-mail-logging):** the sink is in a bundled library (`lib/vendor/...`), the fix is in another file. Kept and signed as is; it is the first candidate to drop if the report should only score plugin code.
- **Case count and mix (40):** 20 unauthenticated, 12 contributor, 5 admin, 3 subscriber; 18 after the cutoff and 22 before. Classes: sqli 4, object-injection 4, rce 4, path-traversal 4, reflected-xss 3, missing-authz 3, info-disclosure 3, file-upload 3, ssrf 3, privesc 2, file-inclusion 2, stored-xss 2, csrf 1, open-redirect 1, xxe 1. CSRF, open redirect and XXE have a single case each.
- **`wpbench review`** (new): lists signature status, shows advisory, label, labelled code, automatic checks and fix diff for a case, and signs with `--sign --by NAME` after a confirmation. It refuses to sign when the checks find errors or the case is already signed unless `--force`. The checks are file exists, lines inside the file, function defined near the lines, fix touches the lines, open `Draft:` doubts. They never sign by themselves.
- **Split assigned and test frozen (2026-11-02, user decision).** `wpbench split --seed 20261102 --pin-dev wp-0001..wp-0006 --write`: dev 15, test 25, stratified by class, the six pilot cases pinned to dev because their failures were read. The seed was proposed before looking at the result and kept after seeing it. SHA-256 of `dataset/splits.toml` at the freeze: `313de4a9ad66db1b859f9685d15248bfb32b92685018e91eb6866da8865a605c`. Tag `test-frozen`. From now on the test split is used only for the final measurement, at most twice, and never to tune the skill (docs/DATASET.md); if its failures are used to change the skill, the split is burned and must be rebuilt.
- **Consequences of the draw, known before freezing:** dev has no CSRF, open-redirect or XXE case (one case each, all in test), so Phase 6 cannot tune on those classes and the report shows them as unseen. wp-0036 (sink in a bundled library) landed in dev and was kept by the user.
