# hookhunter: changelog and freeze record

The skill is frozen at each tag below. After `skill-v1.0` it changes only through Phase 6 of `docs/PLAN.md`: for each idea, write the hypothesis, make a **general** change (no case-specific hints,
nothing derived from `dev` or `test` cases), run `dev`, record the result here, and cut a new tag for each accepted version. `test` runs only on frozen tags (`docs/DATASET.md`).

## skill-v1.0 (2026-11-01)

Built and frozen before any benchmark case existed (`docs/SKILL-DESIGN.md` section 5).

| Item | Value |
|---|---|
| Skill tree (`git rev-parse skill-v1.0:skills/hookhunter`) | `699ba4aa78ea514ba77ccdb6fe9a47fa170afc0d` |
| `SKILL.md` blob | `bfc72f98c3160013718ff54fd754a740fef58b5b` |
| Output schema blob (`schemas/findings.schema.json`, outside the skill folder but part of the contract) | `8690d84447d901c3328f951a0e819f2f6606fc46` |
| Contents | `SKILL.md` (173 lines); `scripts/` (`wp_map.py`, `wp_sinks.py`, `wp_xref.py`, shared parser with tree-sitter and regex backends); `reference/` (19 files); tests, fixtures (32 synthetic plugins), activation evals and dry-run artifacts |
| Model used for the activation evals | `sonnet` alias (claude-sonnet-5-5) |

State at the freeze:
- Test suite, `ruff` and `mypy` clean. The reference files, SKILL.md, schema, fixtures and dry-run artifacts are checked by tests; link liveness by `WPBENCH_CHECK_URLS=1 pytest -m network` (236 URLs, passed).
- Activation evals (32 prompts, English and Spanish): dev 8/8 with 0/9 false triggers; held-out 8/8 with 0/7 false triggers, rerun after the rename with the description unchanged (`docs/DECISIONS.md` sections 10 to 12).
- Dry run on the 26 original fixtures: 27 findings, every labelled line matched, all 12 safe twins clean. Not evidence of agent performance (written and analysed by the same author).
- Known limits recorded in `docs/DECISIONS.md`: Wordfence rules unverified; scripts do not parse `vendor/`, JavaScript or non-PHP entry points; dispatch rules use a one-function taint heuristic;
  no benchmark case has been run against the skill.
