# Improvement loop

Paste this file as the prompt of a `/loop` session (or follow it by hand). It runs measure → diagnose → change → measure until
`evals/CRITERION.md` says USEFUL or the stop rules fire. It never tunes on held-out cases.

## Setup (once)

- Cases: `cases/<id>/{vuln,fixed}/` for every case in `dataset/cases.toml` (`wpbench fetch --split dev` / `--split test`). The shell needs
  `downloads.wordpress.org` reachable; if it is blocked, stop and ask for the zips.
- `DEV` = the dev split. `HOLDOUT` = the frozen test split plus a fresh batch of ≥ 15 CVEs chosen before the current freeze.
- Model fixed for the whole loop (default `claude-haiku-5-5`). Budget per run fixed (`--budget 2`).

## One iteration

1. **Inner metric (free).** `python3 evals/script_recall.py --cases cases --truth dataset/cases.toml` on DEV. Record `in_required`.
2. **Dev measurement.** `python3 evals/loop.py run --cases cases --truth dataset/cases.toml --ids <DEV> --repeats 2 --out runs/dev-<tag>`, then
   `loop.py score --out runs/dev-<tag>`. Record recall A and C, paired diff and CI, cost ratio, invalid rate, ledger stats.
3. **Diagnose misses** (C misses only, DEV only). For each: was the truth row required? opened? marked how? did the Stop hook fire? did the
   agent ignore the worklist? Classify the miss: *not surfaced* (scripts), *surfaced, not opened* (budget/ranking), *opened, wrongly cleared*
   (judgment/evidence rule), *found, wrong location/class* (output), *invalid output*.
4. **Change one thing** that addresses the largest miss class with a **general** rule: no plugin names, functions or strings from any case.
   Write the hypothesis and the expected effect in `docs/SKILL-CHANGELOG.md` before running.
5. **Re-measure** steps 1 and 2. Keep the change only if dev recall C − A improved or stayed equal with lower cost/noise; else revert.
6. **Freeze and hold out** when dev C − A ≥ 15 points for two consecutive iterations: tag the skill, run HOLDOUT once (A and C, 2 repeats),
   score. That number, and only that number, goes to the verdict.

## Stop rules

- **USEFUL** on HOLDOUT → stop, write the result in README.
- **HOLDOUT not useful** → the held-out cases used become dev; select a new fresh batch before the next freeze. At most 2 freezes per month of new CVEs.
- **5 iterations without dev improvement** → stop and report "not useful with this design"; the next step is a design change (e.g. per-row subagents,
  `agents/refuter.md` in bench), not more tuning.
- **Spend cap** reached (set it before starting) → stop and report where it stands.

## Order of experiments already suggested by the data

1. Required-row count (`--required` 0 / 8 / 15 / 25): the gate helps only if the truth is usually in the required rows; otherwise it diverts budget.
2. Ranking of functions no entry reaches (templates, query builders): in the 4 local dev cases every truth sat there, ranked 60 to 115.
3. Tighten evidence for `constant-input`, `dead-code` and `intended-feature` (today any line is accepted).
4. Condition C-fanout: one subagent per required row (needs Agent in `--tools`); costs more, measures whether fresh context per row helps.
