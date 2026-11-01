# wp-audit-bench — project memory for Claude Code

## What this project is
A **benchmark that measures whether an AI agent skill actually helps find vulnerabilities in
WordPress plugins**. It runs Claude Code headless on old, already-patched plugin versions with public
CVEs, with and without the `wp-plugin-triage` skill, and scores the findings against ground truth
built from the vulnerable→patched diff.

Question it answers: *"Does this skill improve recall, precision and cost compared with no skill
(and with a non-LLM baseline)?"* — something almost no skill/prompt pack measures.

Deliverables: a new skill `wp-plugin-audit` (in `skills/`), the dataset (metadata + labels, no plugin
code redistributed), the harness, a results report with ablations, and a blog post.

## Source-of-truth documents
- `docs/SPEC.md` — harness, conditions, output schema, scoring, metrics. The contract.
- `docs/DATASET.md` — case selection, splits, labelling protocol (human-signed labels).
- `docs/SKILL-DESIGN.md` — the new skill `wp-plugin-audit` (built from scratch): layout, workflow,
  scripts, reference rules, ablations, freeze rule.
- `docs/PLAN.md` — phases and acceptance criteria.
If code and docs disagree, docs win; ambiguities go to `docs/DECISIONS.md`.

## Tech stack
- Python 3.11+, `pyproject.toml` (hatchling), src layout `src/wpbench/`.
- CLI with `typer`, output with `rich`; data in TOML/JSONL; analysis with `pandas` + `matplotlib`.
- Claude Code is invoked as an external process (`claude -p … --output-format json`).
- Tests: `pytest`; lint: `ruff`; types: `mypy` (lenient).

## Safety and ethics rules (non-negotiable)
- **Only versions that are already patched** and whose vulnerability is **publicly disclosed**.
  Never run the harness on the latest version of any plugin.
- **Static analysis only.** Never execute plugin code, never install WordPress, never send traffic to
  any site. Agent runs are restricted to `Read`, `Grep`, `Glob` (no Bash, no web) inside a container
  with networking disabled.
- **No exploit payloads.** The benchmark output schema has no PoC field; the skill has a `bench mode`
  that skips the PoC step. Reports describe vulnerability class, location and data flow only.
- **Do not redistribute plugin source code.** The dataset stores slugs, versions, hashes and labels;
  the harness downloads the code from wordpress.org at run time and verifies the hash.
- If a run appears to find a vulnerability that might still affect the **current** version of a
  plugin: stop, do not publish it, tell the user; it goes through responsible disclosure
  (WPScan / Wordfence / Patchstack) first.
- Ground-truth labels are **signed by a human** (the maintainer or a named reviewer). Claude may
  draft a label, but a label without `reviewed_by` is not used for any reported metric.

## Commands
```bash
pip install -e ".[dev]"
pytest -q && ruff check . && mypy src
wpbench fetch --split dev          # download + hash-check cases
wpbench run --split dev --condition skill-v1 --repeats 2
wpbench score --run runs/<id>
wpbench report --runs runs/<a> runs/<b>
```

## Workflow
Phase by phase per `docs/PLAN.md`; after each phase: tests + ruff + mypy, commit (conventional
commits), stop and summarise. README in English.
