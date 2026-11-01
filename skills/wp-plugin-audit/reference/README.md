# reference/: knowledge files for `wp-plugin-audit`

Written from public documentation (WordPress developer handbooks, WordPress core `trunk`, the PHP manual, OWASP, MITRE CWE, FIRST CVSS and programme rules),
each file ending with its sources. They contain no material from benchmark cases (`docs/SKILL-DESIGN.md` section 4). `SKILL.md` tells the agent which file to open
at each step; nothing here is meant to be read in full in one pass. Every file is at most 200 lines.

Core behaviour was read from `trunk` on 2026-11-01. Re-check a point against the core version a plugin supports before relying on it.

## Which file at which step

| Workflow step (`docs/SKILL-DESIGN.md` section 2) | Open |
|---|---|
| 0 Gate | `report.md` section 1 (audit mode only) |
| 1 Map | `surface.md` (entry points, tiers, what core checks, surface the scripts do not list) |
| 2 Hunt by class | `classes/<class>.md` for the class being checked, with `wp-traps.md` (checks that look safe but are not) and `sanitizers.md` (which function neutralises which class in which context) |
| 3 Refute | `verification.md` (common procedure, statuses, reason vocabulary), then the "Refutation checklist" of the class file |
| 4 Variants | `verification.md` section 5 |
| 5 Coverage | `verification.md` section 7, `surface.md` section 5 |
| 6 Report | `severity.md` (vectors, `auth_required`, programme rules); `report.md` (template, audit mode only) |

## Class files

| File | Weakness (CWE) | Scripts and rules that feed it |
|---|---|---|
| `classes/authz.md` | missing or incorrect authorization (862, 863, 639) | `wp_map.py` flags; `wp_sinks.py --class authz` |
| `classes/csrf.md` | cross-site request forgery (352) | `wp_map.py` `no-nonce` |
| `classes/privesc.md` | privilege escalation, account takeover (269, 266, 915, 288, 640) | `wp_sinks.py --class privesc` |
| `classes/xss.md` | cross-site scripting (79) | `wp_sinks.py --class xss` |
| `classes/sqli.md` | SQL injection (89) | `wp_sinks.py --class sqli` |
| `classes/file-ops.md` | upload, traversal, read, write, delete, inclusion (434, 22, 73, 98) | `wp_sinks.py --class file-ops,file-inclusion` |
| `classes/object-injection.md` | insecure deserialization (502) | `wp_sinks.py --class object-injection` |
| `classes/ssrf.md` | server-side request forgery (918) | `wp_sinks.py --class ssrf` |
| `classes/open-redirect.md` | open redirect (601) | `wp_sinks.py --class open-redirect` |
| `classes/rce.md` | code and command execution (94, 95, 78, 88, 470) | `wp_sinks.py --class rce` |
| `classes/info-disclosure.md` | information disclosure (200, 209, 532, 538) | `wp_sinks.py --class info-disclosure` |
| `classes/xxe.md` | XML external entities (611, 776) | `wp_sinks.py --class xxe` |

Every class file has the same sections: facts that decide exploitability, where it lives, how to hunt, traps specific to the class, vulnerable and safe shapes,
a refutation checklist, typical CVSS, and what triagers reject. `test_reference.py` enforces this.

## Shared vocabulary

- **Tiers** (`surface.md`): `unauth`, `subscriber`, `author+`, `admin`, `system`; the same names `wp_map.py` prints.
- **Statuses** (`verification.md`): `confirmed`, `needs-dynamic-check`, `refuted`, and the reason slugs used for `refuted`.
- **Modes:** `audit` (full report for disclosure) and `bench` (schema output only). Programme-acceptance guidance in the class files applies to `audit` reports;
  in `bench` mode every supportable finding of the listed classes is reported (`docs/DECISIONS.md` section 9).
- **Markers in the text:** *(pattern)* is a consequence of the code that core does not document; *(PHP)* comes from the PHP manual; "not verified" marks a statement whose source could not be read.

## Conventions and limits

- **Scores** in all class tables are computed with the FIRST v3.1 base formula, which reproduces FIRST's published examples; `test_reference.py` recomputes every row.
- **Wordfence** rules could not be read (the programme page returns an empty response to automated requests) and appear only as unverified notes.
  Patchstack's Alliance rules were read in full and are quoted.
- **Scripts** (`scripts/`) do not parse `vendor/`, JavaScript, or non-PHP entry points, and the regex fallback misses backtick execution. Each class file lists what to Grep instead.
  Known gaps are recorded in `docs/DECISIONS.md` section 9.
- **Fixed in S3:** `SKILL.md` sets the value sets of `class`, `auth_required` and `confidence` in the findings schema (`schemas/findings.schema.json`) and includes `xxe` in the class order.
- **Not yet exercised:** no benchmark case has been run against these files. They are frozen with the skill at tag `skill-v1.0` and change afterwards only through Phase 6 of the plan.

## Maintaining the files

- Keep each file at or below 200 lines and end it with `## Sources`.
- Cite only public sources, with the date core or a page was read. State what could not be verified.
- Do not add plugin names, CVEs, functions or snippets taken from `dev` or `test` cases. The test checks this against `dataset/cases.toml` once it exists.
- Add new files to `EXPECTED` in `tests/test_reference.py` and to this index.
- Check external links with `WPBENCH_CHECK_URLS=1 pytest -m network`.
