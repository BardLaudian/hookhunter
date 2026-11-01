# wp-audit-bench — Specification (v0.1)

## 1. Research question
For WordPress plugin source code with a known, patched vulnerability, how well does an AI coding
agent find it

- **A. without a skill** (a plain audit prompt),
- **B. with `wp-plugin-triage` v1** (the current skill),
- **C. with the new `hookhunter` skill** (built from scratch, see SKILL-DESIGN.md), plus its
  ablations C-min (SKILL.md only) and C-noscripts (no helper scripts),
- **D. with a non-LLM baseline** (Semgrep with public WordPress/PHP rules, if a reasonable rule set
  exists — Phase 0 decides; otherwise drop D and say why),

measured by recall, precision, false alarms on the patched version, and cost/time?

## 2. Cases
Each case = one CVE in one plugin: a **vulnerable version** and the **first patched version**
(details in DATASET.md). The harness also runs every condition on the patched version as a
**negative control**: reporting the same bug there is a false alarm.

## 3. Execution
- Code is fetched from `https://downloads.wordpress.org/plugin/<slug>.<version>.zip` (verify this
  and the SVN alternative `plugins.svn.wordpress.org/<slug>/tags/<version>/` in Phase 0), unpacked
  into `cases/<id>/{vuln,fixed}/`, and checked against the SHA-256 recorded in the dataset.
  The `cases/` directory is git-ignored.
- One run = one condition × one case version × one repeat. Each run executes inside a Docker
  container: `--network none`, read-only bind mount of the plugin directory, a writable `/out`.
- Inside, Claude Code is invoked headless, e.g.
  `claude -p "<task prompt>" --output-format json --allowedTools "Read,Grep,Glob"` (confirm the
  exact flags with `claude --help` in Phase 0 and record them in DECISIONS.md). For condition A no
  skill is present; for B/C the skill is copied to `.claude/skills/<skill-name>/` (`wp-plugin-triage` for B,
  `hookhunter` for C) in the working directory (confirm how Claude Code discovers project skills in Phase 0).
  Networking: the model API must still be reachable — if `--network none` blocks it, use a network
  that allows **only** the API endpoint (document how), never general internet.
- The task prompt is identical across conditions except for the skill, stored in
  `prompts/task.md`, and asks for findings as JSON matching §4 written to `/out/findings.json`.
  It never names the CVE, the vulnerable function or the vulnerability class.
- Model: one fixed model per experiment, recorded with every run. Repeats: ≥ 2 per run (LLM output
  varies); report mean and spread.
- Record per run: tokens in/out and cost as reported by the JSON output, wall time, tool calls,
  exit status, the raw transcript (for debugging; git-ignored).

## 4. Findings schema (`findings.json`)
```json
{"findings": [{
  "file": "includes/class-admin.php",
  "line_start": 120, "line_end": 134,
  "function": "save_settings",
  "entry_point": "wp_ajax_save_settings",
  "cwe": "CWE-79",
  "class": "stored-xss",
  "auth_required": "subscriber",
  "data_flow": "$_POST['title'] -> update_option -> echo in settings page without esc_html",
  "confidence": "high"
}]}
```
No exploit payloads, no PoC field. Validate with a JSON Schema; invalid output = run failed
(counted, not silently dropped).

## 5. Scoring
- **Match** between a finding and the ground truth: same file **and** (line ranges overlap within a
  tolerance of ±10 lines **or** same function name) **and** compatible vulnerability family
  (CWE family map in `src/wpbench/cwe_families.py`, e.g. CWE-79/80/83 → XSS; CWE-862/863/285 →
  authorization). Matching code is unit-tested with hand-made cases.
- **Recall** = cases where at least one finding matches / cases.
  Also **recall@3** (match among the 3 highest-confidence findings) — what a human would read first.
- **False alarm on fixed version** = the fixed-version run reports a finding that matches the
  ground truth location and family.
- **Unmatched findings** on the vulnerable version may be real bugs, not false positives. Sample them
  (all if ≤ 50) and label by hand: `fp` / `plausible` / `real-but-other`. Precision is reported
  with this breakdown, never as a single unexplained number.
- **Cost** per case and **cost per true finding**.
- Uncertainty: N is small, so report bootstrap 95 % confidence intervals for recall and the
  difference between conditions (paired by case). Do not claim a difference the interval doesn't
  support.

## 6. Contamination
Models may have memorised famous CVEs. Mitigations, all reported:
1. Prefer CVEs **published after** the model's training cutoff (record the cutoff and its source).
2. A **memorisation probe** per case: ask the model, without code, "what vulnerability was fixed
   in <plugin> <version>?" and record if it names the class/function. Report results with and
   without probed-positive cases.

## 7. Outputs
- `results/<experiment>/summary.csv`, per-case JSONL, charts (recall by condition with CIs, recall
  by vulnerability class, cost vs recall), `results/<experiment>/REPORT.md` generated from the data.
- README shows the latest table and links the report. Every number reproducible from committed
  data (except plugin code and transcripts).
