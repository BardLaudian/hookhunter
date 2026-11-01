# wp-audit-bench — Build plan

One phase at a time; tests + ruff + mypy; commit; stop and report.
Order matters: the new skill is **built and frozen before it ever sees a benchmark case**.

## Phase 0 — Verify assumptions (no code, 30–45 min)
- Confirm: plugin zip/SVN URLs for specific versions; Wordfence Intelligence / WPScan data access
  and terms; Claude Code headless flags (`-p`, `--output-format json`, `--allowedTools`), how project
  skills are discovered, skill frontmatter keys, `${CLAUDE_SKILL_DIR}`, what the JSON output reports
  (tokens, cost); how to give the container access only to the model API.
- Prior art: existing benchmarks/papers on LLMs for PHP/WordPress vulnerability detection, existing
  WordPress audit skills, public Semgrep rules for WordPress. Summarise in `docs/DECISIONS.md` (name,
  link, how we differ). If something already answers our question, stop and tell the user.
- Record the model to use and its training cutoff (with source).

## Part S — The skill (before any benchmark case exists)

### S1 — Scripts (2–3 h)
`skills/hookhunter/scripts/` per SKILL-DESIGN.md §3 with tree-sitter (pinned) and a regex
fallback. Write the synthetic fixture plugins first (one per class + safe twins), then the scripts,
test-first. Performance check on a large synthetic tree.

### S2 — Reference files (1 weekend, with the user)
Per SKILL-DESIGN.md §4, from public documentation only, each with sources. The user reviews every
class file: it must be accurate WordPress knowledge he can explain in an interview.

### S3 — SKILL.md (2 h)
Per SKILL-DESIGN.md §2, ≤ 250 lines. Trigger evals (EN/ES positive prompts, unrelated PHP negative
prompts). Dry-run the full workflow on the synthetic fixtures only.

### S4 — Freeze
Tag `skill-v1.0`. From now on the skill changes only through Phase 6 rules.

## Part B — The benchmark

### Phase 1 — Scaffold + dataset tooling (1.5 h)
`pyproject`, CLI skeleton, `dataset/cases.toml` schema + validator, `wpbench fetch` (download,
hash, unpack, git-ignored), `wpbench diff`, `wpbench split --seed`. Tests with a tiny fake zip.

### Phase 2 — Pilot cases (with the user, 1–2 h)
Claude proposes ~15 candidate CVEs meeting DATASET.md criteria; the user picks 6; fetch, diff,
Claude drafts truth; **the user reviews and signs each label**.

### Phase 3 — Harness (2 h)
Docker image, run orchestration, prompt file, schema validation, per-run records, repeats, resume,
cost/time capture, `--dry-run`. Pilot: conditions A, B and C-full, 1 repeat. Show the user cost and
time per run before going further, and an estimate for the full experiment including ablations.

### Phase 4 — Scoring (1.5 h)
Matching (unit-tested), recall, recall@3, fixed-version false alarms, unmatched-finding labelling
sheet (human), bootstrap CIs, memorisation probe.

### Phase 5 — Full dataset (with the user, 1 weekend)
Grow to 15 dev + 25 test; human-signed labels; **commit and freeze the test split**.

### Phase 6 — Iterate the skill on dev only (1 weekend)
Run A, B, C-full on dev. For each idea: hypothesis → general change (no case-specific hints) → dev
run → result, logged in `docs/SKILL-CHANGELOG.md`. New tag per accepted version.

### Phase 7 — Final measurement + report (1 day)
Test split with the latest frozen tag: A, B, C-full, C-min, C-noscripts (and D if kept), ≥ 2
repeats, same model. Generated REPORT.md: recall with CIs, by class and by auth level, false alarms on
fixed versions, precision breakdown, cost per true finding, ablation table, memorisation probe,
limitations. README headline table — honest, including "no significant difference" if so.

### Phase 8 — Publish
Repo public (skill in `skills/`, dataset metadata, harness, report). Blog post (ES/EN):
"I built a WordPress audit skill from scratch and measured whether it helps." Install instructions
for the skill as a Claude Code plugin/skill.
