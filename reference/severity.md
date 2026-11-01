# Severity: how to score a finding, and what programmes accept

Open this at step 6 (Report) of `audit` mode, and whenever a finding needs a CVSS vector or a judgement about whether a programme would take it.
The class files (`classes/*.md`) hold the scenario tables; this file holds the rules they follow.

In `bench` mode the output schema has no score field (`docs/SPEC.md` section 4), so do not spend effort on vectors there. What matters for bench is `class`,
`cwe` and `auth_required`; section 4 shows how to choose `auth_required`.

## 1. Scoring rules (CVSS v3.1)

Rules quoted from the FIRST specification, read 2026-11-01. Vector string form: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.

| Metric | WordPress rule |
|---|---|
| **AV** | `N` for anything reached through HTTP. |
| **AC** | `L` unless exploitation "depends on conditions beyond the attacker's control", meaning the attacker must gather knowledge of the target, prepare the environment (win a race), or sit in the network path. **A required configuration does not raise AC:** "If a specific configuration is required for an attack to succeed, the Base metrics should be scored assuming the vulnerable component is in that configuration." An optional plugin, library or PHP version a chain needs is therefore `AC:L`. Target-specific mitigations (a firewall rule) belong to the Environmental group, not the Base score. |
| **PR** | `N`: a visitor. The spec says PR is usually None for reflected XSS and CSRF, where the victim performs the action. `L`: "basic user capabilities that could normally affect only settings and files owned by a user" (Subscriber, Customer, Contributor, Author). `H`: "significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files" (Administrator, Super Admin). Editor and Shop Manager sit between: choose by what the exploit needs, and say so; programmes may treat them as high-privilege. |
| **UI** | `R` when another person must act: following a link (reflected XSS, CSRF, open redirect), opening a page (stored XSS, per FIRST's own example). `N` when the attacker alone can trigger it. |
| **S** | `C` when the impact reaches a component under a different security authority: the **victim's browser** (XSS, open redirect), an **internal service** (SSRF). `U` for SQL injection, file operations and code execution inside WordPress: the spec's own example says a database used solely by one application is part of that application's scope. |
| **C/I/A** | Constrain impact "to a reasonable, final outcome which they are confident an attacker is able to achieve", counting "only the increase in access, privileges gained, or other negative outcome as a result of successful exploitation". The spec also says Base Scores assume "the reasonable worst case impact across different deployed environments". |

Qualitative scale (spec): None 0.0; Low 0.1-3.9; Medium 4.0-6.9; High 7.0-8.9; Critical 9.0-10.0.

Calibration: the formula used for every table in this skill reproduces FIRST's published examples (stored XSS CVE-2019-7551 = 9.0; CSRF CVE-2015-0970 = 8.8), and every score
in the class files was recomputed against the same formula (68 rows, no mismatch).

## 2. Choosing impact

- Score the **effect of the request you showed**, not the worst thing the product can do. Administrator-level code execution is `C:H/I:H/A:H`; a limited read is `C:L`.
- FIRST scores its stored-XSS example at the worst case (`C:H/I:H/A:H`, 9.0) because the victim can be an administrator and script then acts as that administrator. Reflected
  XSS is commonly scored `C:L/I:L/A:N` (6.1). Use the high row only if the victim is privileged **and** you state what the script can do (`classes/xss.md`).
- Do not add `A:H` for "could crash". Do not raise `C` for data the plugin does not hold.
- Score one vulnerability at a time. A chain (open redirect to token leak, file write to code execution) is described in the text, and each link is scored as the
  weakness it is; claim the chain's impact only when you can show every link.
- Always write the assumptions next to the vector: site type (single or multisite), the role used, the version, the setting that must be on.

## 3. Default vectors by class

Start from these and adjust to the facts. Every line is a row of the class file named; the scenario text is there.

| Class | Typical vectors (score) | File |
|---|---|---|
| Missing authorization | unauth write `PR:N/I:H` 7.5 · subscriber write `PR:L/I:H` 6.5 · unauth minor read/write `C:L/I:L` 6.5 | `authz.md` |
| CSRF | minor setting `PR:N/UI:R/I:L` 4.3 · important write `I:H` 6.5 · takeover `C:H/I:H/A:H` 8.8 | `csrf.md` |
| Privilege escalation | unauth to admin 9.8 · subscriber to admin 8.8 · to contributor/author, limited 5.4 (subscriber) / 6.5 (unauth) | `privesc.md` |
| XSS | reflected or unauth stored `PR:N/S:C/C:L/I:L` 6.1 · subscriber-written 5.4 · admin-written 4.8 · admin victim, script acts as admin 9.0 | `xss.md` |
| SQL injection | unauth read `C:H` 7.5 · unauth read/write 9.8 · subscriber read 6.5 · admin only 4.9 | `sqli.md` |
| File operations | unauth executable upload / write 9.8 · unauth read 7.5 · unauth delete 9.1 · subscriber read 6.5 | `file-ops.md` |
| Object injection | unauth with a chain to code execution 9.8 · subscriber 8.8 · file-delete chain 9.1 | `object-injection.md` |
| SSRF | unauth, response returned `S:C/C:H` 8.6 · limited 7.2 · blind 5.8 · admin only 5.5 | `ssrf.md` |
| Open redirect | `UI:R/S:C/C:L/I:L` 6.1 · redirect only 4.7 | `open-redirect.md` |
| Code / command execution | unauth 9.8 · subscriber 8.8 · admin only 7.2 | `rce.md` |
| Information disclosure | unauth secrets or hashes 7.5 · limited 5.3 · subscriber 6.5 / 4.3 | `info-disclosure.md` |
| XXE | unauth file read 7.5 · SSRF-only (blind) 5.8 | `xxe.md` |

## 4. Who can exploit it: `auth_required` and tiers

Use the **lowest** role that works on every path of the exploit. `docs/DATASET.md` lists the levels unauthenticated, subscriber, contributor/author and admin (its example record uses `contributor`); `docs/SPEC.md` shows `subscriber`. The exact value set of the schema field is for `SKILL.md` to fix in S3.

| Evidence | Value |
|---|---|
| Reachable with no login (`wp_ajax_nopriv_*`, `admin_post_nopriv_*`, public REST route, front-end form, request-time hook) | `unauthenticated` |
| Any logged-in account passes (`wp_ajax_*` without a capability check, `read`) | `subscriber` |
| Needs `edit_posts`, `publish_posts`, `upload_files` or similar | `contributor` (the dataset does not separate contributor from author) |
| Needs `manage_options` or another administrative capability | `admin` |

For stored XSS, use the role that **plants** the value, not the role that views it (a rule of this skill, chosen so that `auth_required` matches what the attacker needs).

## 5. What programmes accept

Use this to decide how to present a finding in `audit` mode and which ones to expect to be declined. It does not change whether a weakness exists; in `bench` mode keep real findings
(`DECISIONS.md` section 9).

**Patchstack Alliance** (rules read in full, 2026-11-01):
- Eligible: components with **1,000 or more active installs** (except the mVDP programme), the **latest** version (not older than three years), publicly distributed; exploitable by **unauthenticated users or default Subscriber/Customer roles**; scored with the **CVSS v3.1 base metrics** only.
- Accepted types and their conditions: SQL injection; XSS ("must have an impact on the entire site, or be reflected"); arbitrary file upload, deletion or download ("full control over the path and extension"); remote/arbitrary code execution; PHP object injection; arbitrary settings change ("significant impact on the site"); privilege escalation ("must lead to contributor access or higher"); local/remote file inclusion ("full control over the path and extension"); broken access control ("significant or sensitive objects"); IDOR ("significant security impact"); CSRF (only if it produces one of the accepted write outcomes).
- Rejected by scoring: any report with **Attack Complexity High**; Subscriber-or-higher findings with minor data leakage, modification or availability impact (CVSS 5.4 with two impacts Low, 6.3 with three Low); unauthenticated findings with a single Low impact (CVSS 5.3); race conditions below CVSS 7.1.
- Rejected by kind: open redirect; blind SSRF without concrete impact; contributor-level (or higher) stored XSS; HTML-only or CSS injection; 2FA bypass, missing brute-force protection, registration with a role below Contributor; full path disclosure and private/draft content disclosure; DoS unless high availability impact on any environment; vulnerabilities that exist only because a high-privilege user configured the component that way; expected functionality; "unrealistic pre-requisites or exploitation scenarios"; multi-step CSRF; reports on closed or non-public components; self-submissions are not eligible for bounties.
- Process: findings of the same type in one component are consolidated into one report; each must be new.

**Wordfence Intelligence bug bounty:** not verified. The programme page returned an empty HTTP 202 to every automated fetch. A search summary said that vulnerabilities requiring `PR:H` (listed as Administrator, Editor, Shop Manager and roles with `unfiltered_html`) are out of the bounty's scope but may still receive a CVE. Treat that as a lead and check the live page before relying on it.

**Other databases** (WPScan, NVD, CVE numbering authorities) were not read for this skill; do not assume their acceptance criteria match Patchstack's.

## 6. Scoring mistakes to avoid

- Raising `AC` to `H` because a configuration, library or plugin is needed (the spec says to score as if configured).
- Using `PR:L` for CSRF or reflected XSS; the spec says `PR:N` because the victim performs the action.
- Using `S:C` for SQL injection or code execution inside WordPress; use it for browser-side and cross-service impact.
- Giving `C:H/I:H/A:H` to every issue because the site "could be taken over"; score the shown effect.
- Dropping `UI:R` from stored XSS and open redirect.
- Mixing the roles in one vector: if the same bug is reachable by a visitor and by a subscriber, score the visitor path.
- Reporting a score without the assumption that drives it.
- Treating a programme's rejection as "not a vulnerability", or a programme's acceptance as proof; both are separate from the evidence in `verification.md`.

## Sources

- [FIRST CVSS v3.1 specification document](https://www.first.org/cvss/v3.1/specification-document) (metric definitions, scope, base score assumptions, qualitative scale, vector string) and [CVSS v3.1 examples](https://www.first.org/cvss/v3.1/examples) (CVE-2019-7551 stored XSS, CVE-2015-0970 CSRF) and [calculator](https://www.first.org/cvss/calculator/3.1)
- [MITRE CWE: CVE to CWE mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [Wordfence Intelligence bug bounty programme](https://www.wordfence.com/threat-intel/bug-bounty-program/) (not readable by automated fetch; see section 5)
- `classes/*.md` for the scenario tables and their cited sources; `docs/DATASET.md` for the `auth` values
