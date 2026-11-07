# When is hookhunter useful?

A skill is useful when **the same agent, with the same model, prompt, tools and budget, finds clearly more real bugs with it than without it,
at a cost and noise level a person would accept.** Recall alone against a list of CVEs, measured by the agent that chose the CVEs, is not that.

## The verdict (what `loop.py score` prints)

Measured on paired runs (condition A = no skill, C = hookhunter) over cases **the skill was not tuned on**:

| Check | Threshold | Why |
|---|---|---|
| Cases | at least 40 distinct CVEs, 2 repeats each | with 15 cases the 95 % interval is about ±25 points; rounds 3 to 6 (60, 73, 67, 47 %) cannot be told apart. 40 paired cases detect a gain of about 20 points with 80 % power; 15 points needs about 80 |
| Recall gain C − A | ≥ 15 points | below that, a person is better served by plain Claude plus their own judgment; it is also the smallest gain this sample size can resolve |
| Gain is not noise | lower bound of the paired bootstrap 95 % CI > 0 | paired by case, so plugin difficulty cancels out |
| Absolute recall of C | ≥ 60 % | a tool that misses most known bugs is not worth its setup, whatever the baseline |
| Noise | ≤ 6 findings per run (proxy), and labelled precision ≥ 50 % on the unmatched sheet | every finding costs a person minutes to check |
| Cost | C ≤ 2 × A per run | the skill must not buy its recall only by reading more |
| Valid output | ≤ 5 % invalid answers | an invalid answer is a miss for a pipeline too |

Labels: **USEFUL** (all checks pass), **PROMISING** (gain ≥ 15 points but the interval still crosses 0: add cases), **NOT YET USEFUL**,
**HARMFUL** (the whole interval is below 0), **INCONCLUSIVE** (fewer than 40 cases).

Two numbers to report alongside, never instead: recall@3 (what a person reads first) and false alarms on the patched version
(wp-audit-bench runs both versions; a finding that still "matches" on the fixed code is noise).

## What counts as evidence

- **Cold runs.** Each run is a fresh headless session that sees only `./plugin` and the task prompt (`/root/bench/prompts/task.md`), never the CVE,
  the advisory, the class or the patch. The in-chat rounds 3 to 6 do not meet this: the same model picked the CVEs, wrote the ground truth,
  ran the skill and scored it, and 7 of 10 hits in round 5 had a hint from the advisory. They are useful for finding failure modes, not for the verdict.
- **Automatic scoring.** `wpbench.match` (same file AND lines within ±10 or same function within 100 lines AND compatible CWE family).
- **A baseline every time.** The only formal measurement so far (README: Haiku 5.5, 15 dev cases × 2) gave 30 % with the skill and 37 % without.
  Without condition A in the same batch, no number says whether the skill helps.
- **Held-out data.** Tune on `dev`. Judge on cases never used to change the skill: the frozen `test` split (25) plus a fresh batch (≥ 15),
  selected before the skill version is frozen. Once a held-out case's failure is used to change the skill, it moves to `dev`.

## Cheap signals for the inner loop (not the verdict)

- `script_recall.py`: is the ground-truth function among the ledger's required rows? No model calls, seconds per plugin. If the truth is not in
  the required rows on most dev cases, the gate spends the agent's budget on noise and C will not beat A.
- Per-run `ledger` stats in `runs.jsonl`: required rows done, Stop-hook blocks, verdict mix (a run where every row is `clean --reason=constant-input`
  is rubber-stamping).
