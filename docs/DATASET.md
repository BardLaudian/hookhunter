# wp-audit-bench — Dataset and labelling protocol

## Sources
Public vulnerability databases for WordPress: Wordfence Intelligence (it offers a vulnerability data
feed/API — check its current terms and whether an API key is needed in Phase 0), WPScan, Patchstack,
and NVD for CVE metadata. Record the source and retrieval date of every case.

## Selection criteria (one case = one CVE)
- Plugin available on wordpress.org with both the **last vulnerable** and the **first patched**
  version downloadable.
- The fix is visible in the diff between those versions (not a rewrite of half the plugin; diff of
  the relevant files ≤ ~300 changed lines). Skip cases where you can't point at the vulnerable code.
- Mix of classes, roughly: stored/reflected XSS, SQL injection, missing authorization / capability
  check, CSRF (missing nonce), path traversal / LFI, arbitrary file upload, insecure deserialization,
  SSRF, open redirect. Record CWE.
- Mix of authentication levels (unauthenticated, subscriber, contributor/author, admin) and plugin
  sizes (small < 20 PHP files, medium, large > 200 PHP files).
- Prefer publication dates after the model's training cutoff (SPEC §6). Older cases allowed but
  flagged.
- Target: **pilot 6 cases**, then **dev split 15** and **test split 25** (40 total).

## Splits — learned the hard way in ghostrules
- `dev`: used to improve the skill (SKILL-DESIGN.md, Phase 6 of PLAN.md). You may look at results as often as you like.
- `test`: **frozen and committed before any skill-v2 work starts**. Run on it only for final
  measurements, at most twice. Never tune on it. If you do look at test failures to change the
  skill, the test split is burned: say so and build a new one.
- Assign cases to splits randomly (seeded), stratified by vulnerability class; commit the seed.

## Case record (`dataset/cases.toml`)
```toml
[[case]]
id = "wp-0001"
cve = "CVE-2026-XXXXX"
source = "wordfence"            # where the metadata came from
source_url = "https://…"
retrieved = "2026-11-02"
slug = "example-plugin"
vuln_version = "1.4.2"
fixed_version = "1.4.3"
vuln_sha256 = "…"               # of the downloaded zip
fixed_sha256 = "…"
cwe = "CWE-79"
class = "stored-xss"
auth = "contributor"
published = "2026-07-15"
after_cutoff = true
split = "test"

[case.truth]                    # filled during labelling
file = "includes/class-admin.php"
function = "save_settings"
line_start = 120
line_end = 134
entry_point = "wp_ajax_save_settings"
data_flow = "…"
notes = "fix adds esc_html() in render_settings()"
drafted_by = "claude"           # optional
reviewed_by = "Pablo Seoane"    # REQUIRED for the case to count
reviewed_on = "2026-11-03"
```

## Labelling protocol
1. Script produces the diff between vulnerable and fixed versions (`wpbench diff <id>`), filtered to
   PHP files, plus the advisory text.
2. Claude may draft `[case.truth]` from the diff and advisory (mark `drafted_by = "claude"`).
3. **A human reads the diff and the vulnerable code and confirms or corrects every field**, then sets
   `reviewed_by` and `reviewed_on`. Cases without `reviewed_by` are excluded from metrics and the
   report says how many were excluded.
4. If the advisory and the diff disagree, or the vulnerable code can't be located with confidence,
   drop the case and record why in `dataset/dropped.toml`.
5. Never store plugin source in the repo; short code excerpts (≤ 5 lines) in notes are fine.
