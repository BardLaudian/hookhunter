# Disclosure report (audit mode only)

Open this at step 6 (Report) when the mode is `audit`, and at step 0 (Gate) before writing anything intended for a vendor or a programme.
**Never use it in `bench` mode:** bench output is the JSON schema of `docs/SPEC.md` section 4, with no reproduction steps and no payloads.

The skill **writes** the report for the user. It does not send it, post it, open an issue or a pull request, or contact the vendor or any
programme. The user decides what to send, where, and when.

## 1. Before writing: the gate

1. **Static, local, authorised.** The code is local. Any reproduction was or will be done by the user on a **local installation they own**, never on a live third-party site.
2. **Version.** Record the version audited and check it against the latest release. The plugin API gives both:
   `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>&request[fields][active_installs]=1` returns `version`, `last_updated`, `tested`, `requires_php` and `active_installs`
   (checked with a live plugin on 2026-11-01). If the finding is in an older version and you did not read the latest, say so and do not claim the latest is affected.
3. **Is it already known or fixed?** Read the changelog (`readme.txt`) of the latest version, and search the public databases (Patchstack, Wordfence Intelligence, WPScan) for the plugin and the class.
   A fix that already shipped makes the report a statement about old versions. Patchstack's rules say publicly disclosed incomplete patches are not new vulnerabilities, so check whether a "fix" is publicly known to be incomplete.
4. **Does it affect a current release?** If it might, **stop: do not publish it, and tell the user** (project rule). It goes to the vendor or a programme privately first.
5. **Does it meet the programme's bar?** Patchstack's bounty requires 1,000 or more active installs (except mVDP) and a latest version not older than three years; see `severity.md` section 5. Wordfence's bar could not be read.
6. **One channel at a time.** Patchstack's rules warn that submitting duplicates across different bounty programmes may lead to penalties. Ask the user which channel they want before drafting for a specific one.

## 2. Where reports go

| Destination | What the sources say | Read? |
|---|---|---|
| **WordPress.org Plugin Team**, `plugins@wordpress.org` | Send a clear description, a link to the plugin, and whether you validated the issue. Try the developer first if you can; if you cannot reach them privately, contact the team. Do not post about it publicly anywhere. Most plugins are closed to new downloads until fixed. **The team does not help with CVEs.** Core issues do not go to this team. | Yes (Plugin Handbook, updated 2026-01-02) |
| **WordPress core** | WPScan's submission page points core issues to HackerOne for WordPress; the Plugin Handbook points to the core security page. | Yes |
| **Patchstack** (Alliance bug bounty) | Patchstack is a CVE Numbering Authority; valid, unique, in-scope reports get a CVE and are published in its database. A report already sent to the vendor first is accepted only if the vendor contacts `triage@patchstack.com` to confirm it and show willingness to patch. Components owned by Automattic go through Automattic's HackerOne programme. Support is by Discord ticket or `triage@patchstack.com`. | Yes (Alliance rules). Its separate "Vulnerability Disclosure Policy" page covers **Patchstack's own** systems and does not apply to reports about third-party plugins |
| **WPScan** | A CNA since January 2021 (WP Tavern). Submissions at `wpscan.com/submit`; the page warns to disallow `unfiltered_html` when testing stored XSS with administrator or editor roles, points core to HackerOne and Automattic products to HackerOne. Its disclosure policy (last updated 2022-07-26) gives vendors **30 days** to patch, extendable to **120 days** after first contact, and escalates to the marketplace if the vendor does not reply. | Yes |
| **Wordfence** | Authorised as a CNA for WordPress core, plugins and themes (WP Tavern, 2021). Its bug bounty page returned an empty response to every automated fetch, so reporting address, rules and timelines are **not verified**. | No: check the live page |
| **The vendor** | Look in the plugin header, `readme.txt`, and the vendor site for a security contact. | n/a |

The policy figures above are each programme's own windows; there is no universal one. Quote the policy of the channel actually used.

## 3. Writing rules

- **Facts first.** State what the code does, with `file:line`, and what an attacker controls. No adjectives about severity beyond the vector.
- **Real code only,** at most a few lines per excerpt, copied from the audited version. Never paraphrase code you did not read.
- **No payloads.** Describe the request (endpoint or action name, method, parameter names, which values change) and the observable difference. Do not include
  working exploit strings, shell code, data-extraction queries, or anything built to be run against a site you do not own.
- **Reproduction is minimal and non-destructive,** intended for the user's own local test installation, and ends at the first observable proof (a response difference,
  an unescaped marker, a denied versus allowed result). Never delete, overwrite or read real data.
- **Say what you did not verify.** Name any runtime fact that was not tested (`needs-dynamic-check`), the PHP and WordPress versions assumed, and unparsed parts of the plugin.
- **Scope and assumptions.** Role used, single site or multisite, settings that must be on, plugin version. Follow `severity.md` for the vector and `classes/<class>.md` for CWE choice.
- **No personal data.** Do not include real site names, addresses, user data or secrets found in the code; refer to them by role or file.
- **Consolidate.** Findings of the same type in one component go in one report with several locations (Patchstack's rules ask for this).
- **Do not publish.** Nothing from the report goes in a public issue, forum post, gist, social post or blog before the vendor has fixed it and the channel's disclosure terms allow it.

## 4. Template

Fill every field; write "not determined" rather than leaving one empty.

````markdown
# <Plugin name> (<slug>) <class>: <one-line summary>

**Reporter:** <name or handle chosen by the user>      **Date:** <YYYY-MM-DD>
**Component:** <slug>, audited version <x.y.z>; latest version at report date <x.y.z> (<source and date checked>); active installs <n>
**Affected versions:** <range, or "audited version only; latest not reviewed">
**Distribution:** <WordPress.org / vendor site>      **Channel:** <programme or vendor chosen by the user>

## Summary
<two or three sentences: who can do what, through which entry point, with what effect>

## Findings
| # | Class | CWE | CVSS 3.1 | Privilege | Location | Status |
|---|---|---|---|---|---|---|
| 1 | <e.g. missing authorization> | CWE-862 | 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | unauthenticated | `includes/x.php:120` | confirmed |

### Finding 1: <title>
**Entry point:** <hook, route or shortcode; `file:line`; tier from `surface.md`>
**Privilege required:** <lowest role that works>
**Data flow:** <source `file:line`> → <guards, each with `file:line`, and why it does not stop this> → <sink `file:line`>
**Code:**
```php
<up to five lines copied from the audited version>
```
**Why the guards fail:** <specific, referring to the code above>
**Impact:** <what is read, written, executed or reached; for XSS, who plants and who views>
**CVSS:** <vector> = <score>. Assumptions: <role, site type, settings, version>
**Reproduction (local test installation only):** <numbered steps at request level: action or route, method, parameter names, which value to change, and the observable result.
No exploit strings, no destructive steps.>
**Suggested fix:** <the specific WordPress function or check, for example "call `current_user_can( 'manage_options' )` before `update_option`" or "use `$wpdb->prepare()` with `%d`", in a few lines of generic code>
**Verification status:** <confirmed | needs-dynamic-check: <the single runtime fact>>

## Variants checked
<where else in the plugin the same pattern appears; which locations are affected; which are fine and why>

## Coverage
<entry points reviewed and skipped, with reasons; directories not parsed (`vendor/`, files over the size limit); statement "partial" or "complete">

## Prior art checked
<changelog entries read; databases searched with the date; related advisories, if any>

## Disclosure
Tested only on a local installation. No public disclosure has been made. Contact: <reporter's contact chosen by the user>.
Requested handling: <coordinated disclosure after a fix, under the channel's policy>.
````

## 5. Pre-send checklist (for the user)

- The latest version was read (or the report says it was not), and the finding is still present or the report states the affected range.
- No duplicate already exists in the public databases; the plugin meets the channel's install threshold.
- Every excerpt is copied from the audited version; every `file:line` was checked; no payloads or secrets are in the text.
- The vector matches `severity.md`; the assumptions are written next to it.
- One channel chosen; the vendor contact attempted where the channel expects it.
- Nothing about it has been posted publicly.

## Sources

- [Reporting Plugin Security Issues (Plugin Handbook)](https://developer.wordpress.org/plugins/wordpress-org/plugin-security/reporting-plugin-security-issues/) and [WordPress core security](https://wordpress.org/about/security/)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/) (CNA, vendor-first exception, duplicates, uniqueness) and [Patchstack Vulnerability Disclosure Policy](https://patchstack.com/vulnerability-disclosure-policy) (covers Patchstack's own systems)
- [WPScan: submit a vulnerability](https://wpscan.com/submit), [WPScan vulnerability disclosure policy](https://wpscan.com/vulnerability-disclosure-policy/) and [WP Tavern: WPScan can now assign CVE numbers](https://wptavern.com/wpscan-can-now-assign-cve-numbers-for-wordpress-core-plugin-and-theme-vulnerabilities)
- [WP Tavern: Wordfence now authorized as a CVE Numbering Authority](https://wptavern.com/wordfence-now-authorized-as-a-cve-numbering-authority)
- [Wordfence Intelligence bug bounty programme](https://www.wordfence.com/threat-intel/bug-bounty-program/) (not readable by automated fetch)
- [HackerOne: WordPress](https://hackerone.com/wordpress) (core and Automattic products, as named by WPScan's submission page)
- WordPress.org plugin information API, checked 2026-11-01: `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>`
- `severity.md` for scoring and programme rules; `verification.md` for statuses; `classes/*.md` for class-specific evidence
