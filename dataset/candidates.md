# Phase 2 candidates (2026-11-01)

Proposed for the pilot of 6 cases (`docs/PLAN.md` Phase 2). Metadata only: no plugin source is stored. The maintainer chooses; nothing here is in `cases.toml` yet.

## How they were found

1. NVD API (`services.nvd.nist.gov/rest/json/cves/2.0`), keyword "WordPress plugin", published 2026-07-01 to 2026-10-28: 3,518 CVEs (1,637 from Wordfence, 1,814 from WPScan). Wordfence-style descriptions
   ("in all versions up to, and including, X") give the last vulnerable version; the plugin slug comes from the reference links.
2. A seeded random sample per class (seeds 20261101 to 20261103) was checked against `api.wordpress.org/plugins/info/1.2/`: the vulnerable version must be listed, and **at least two later releases must exist**, so the
   fixed version is never the latest release of the plugin (project safety rule).
3. For each survivor (121 pairs) both zips were downloaded and unpacked to a scratch directory, never executed, and the PHP diff measured with `wpbench.diff`. The fixed version is the **first release after the last
   vulnerable one**; for the 15 below the diff was read to check that it contains a security change.
4. Dropped after reading the diff: fixes that are not in PHP (`add-search-to-menu`, `jetformbuilder`, `woo-stripe-payment`: only a version bump or vendor files differ), fixes that delete a whole feature
   (`mailin`), and fixes mixed with large unrelated changes (`ai-engine`, `give`, `wp-event-solution`).

All candidates are published **after 2026-06-30**, i.e. after the training cutoff recorded for Sonnet 5.5 (June 2026, `docs/DECISIONS.md` section 5); `after_cutoff` is true only if that is the experiment model.

## Not verified

- The vulnerability itself: privilege, class and CWE come from the NVD text, and the "fix" from the diff. Nobody has read the vulnerable code yet; that is the labelling step.
- Wordfence's own advisory pages could not be read (empty responses to automated requests), so the advisory text must be pasted by the maintainer into `dataset/advisories/<id>.md`.
- PHP file counts include bundled `vendor/` code. Active installs are the bucketed figure from wordpress.org.
- The SHA-256 of each zip is not computed yet (`wpbench fetch --allow-unhashed` prints it).

## Candidates

Fix quality: **A** one focused change in PHP; **B** the fix is visible but spread over several places, or mixed with minor unrelated edits; **C** large or mixed with unrelated features.
"Php" = PHP files in the vulnerable release; "diff" = changed PHP lines between the two releases.

| # | CVE | Plugin (slug) | Class | Privilege | CWE | Vulnerable to fixed | Latest | Installs | Php | Diff | Fix | What the fix changes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-15335 | Booking Package (`booking-package`) | sqli | unauthenticated | 89 | 1.7.20 to 1.7.21 | 1.7.36 | 10,000 | 13 | 14 | A | `lib/Schedule.php`: two queries that concatenated `$email` into a `LIKE` become prepared `%s` |
| 2 | CVE-2026-18855 | Link Library (`link-library`) | file-delete | unauthenticated | 22 | 7.9.4 to 7.9.5 | 7.10.1 | 10,000 | 41 | 46 | A | `link-library-admin.php`: removes `ll_delete_link_fields`, a `before_delete_post` hook that deletes a path built from a stored URL |
| 3 | CVE-2026-4703 | WS Form (`ws-form`) | object-injection | unauthenticated | 502 | 1.10.80 to 1.10.82 | 1.12.15 | 10,000 | 162 | 105 | A | several `unserialize()` calls on stored submission meta replaced by `WS_Form_Common::maybe_unserialize()` |
| 4 | CVE-2026-92807 | Save as PDF by Pdfcrowd (`save-as-pdf-by-pdfcrowd`) | rce | contributor | 94 | 4.6.1 to 4.6.2 | 4.6.3 | 1,000 | 20 | 23 | A | shortcode attribute `pdf_created_callback` is dropped unless `current_user_can( 'manage_options' )` |
| 5 | CVE-2026-10865 | Cost Calculator Builder (`cost-calculator-builder`) | info-disclosure | unauthenticated | 200 | 4.0.11 to 4.0.12 | 4.0.20 | 20,000 | 182 | 44 | A | frontend template stops copying payment-gateway secret keys into the settings; new helper strips them |
| 6 | CVE-2026-93746 | WebToffee PDF Invoices, Packing Slips (`print-invoices-packing-slip-labels-for-woocommerce`) | missing-authz | unauthenticated | 639 | 5.0.2 to 5.0.3 | 5.0.4 | 50,000 | 472 | 53 | A | guest mail-link document handler now needs a valid nonce or an access key before it runs |
| 7 | CVE-2026-19807 | BCS MCP Manager (`bcs-mcp-manager`) | privesc | subscriber | 269 | 1.2.3 to 1.2.4 | 1.3.0 | 10 | 32 | 46 | A | `includes/MCP/Server.php`: user-meta write and delete tools no longer gated only by `edit_user` |
| 8 | CVE-2026-8790 | Football Pool (`football-pool`) | reflected-xss | unauthenticated | 79 | 2.13.4 to 2.13.5 | 2.13.6 | 900 | 56 | 12 | A | shoutbox widget: `esc_attr()` and `esc_textarea()` on the re-displayed text |
| 9 | CVE-2026-90981 | Newsletter (`newsletter`) | reflected-xss | unauthenticated | 79 | 9.3.8 to 9.3.9 | 9.5.3 | 200,000 | 235 | 24 | A | `includes/module-base.php`: message passed to `wp_die()` is escaped with `esc_html()` |
| 10 | CVE-2026-18488 | Blocksy Companion (`blocksy-companion`) | stored-xss | contributor | 79 | 2.1.51 to 2.1.52 | 2.1.61 | 300,000 | 171 | 116 | B | dynamic-data block: `tagName` attribute checked against an allow-list; other unrelated edits in the same release |
| 11 | CVE-2026-15401 | VikBooking (`vikbooking`) | stored-xss | unauthenticated | 79 | 1.8.13 to 1.8.14 | 1.8.20 | 8,000 | 999 | 45 | B | escaping added in several admin and site templates (`esc_attr`, `esc_textarea`, `htmlspecialchars`) |
| 12 | CVE-2026-19991 | UsersWP (`userswp`) | file-delete | subscriber | 22 | 1.2.70 to 1.2.71 | 1.2.79 | 20,000 | 327 | 52 | B | `includes/class-forms.php`: file-field values that did not come from a real upload are discarded; the deleting handler is unchanged |
| 13 | CVE-2026-78006 | The Events Calendar (`the-events-calendar`) | object-injection | unauthenticated | 502 | 6.17.4 to 6.17.4.1 | 6.18.3 | 600,000 | 2838 | 127 | B | widget service provider: signs and stores the sanitized instance instead of checking the submitted serialized bytes |
| 14 | CVE-2026-103367 | ShopMagic (`shopmagic-for-woocommerce`) | file-inclusion | unauthenticated | 98 | 4.9.0 to 4.9.1 | 4.9.3 | 10,000 | 2473 | 102 | B | `src/Workflow/Placeholder/PlaceholderProcessor.php` rewritten (repeated placeholder replacement removed); reading inferred from the diff |
| 15 | CVE-2026-12123 | All-in-One Video Gallery (`all-in-one-video-gallery`) | ssrf | subscriber | 918 | 4.8.5 to 4.9.0 | 5.0.0 | 20,000 | 235 | 316 | C | adds URL validation (http/https only, rejects loopback and private hosts, checks redirects) used by `public/video.php`; the release also bundles unrelated features and SDK updates |

Alternates: **16** CVE-2026-13228 LatePoint (`latepoint`), privesc via IDOR in `create_or_update()`, subscriber-level, 5.6.3 to 5.6.4, diff 201, fix B; **17** CVE-2026-18325 Forminator (`forminator`), stored XSS unauthenticated
via a forged upload record, 1.56.1 to 1.56.2, diff 42 on a 2,103-file plugin, fix is indirect (mime blocklist logic); **18** CVE-2026-76006 Photo Gallery by Ays (`gallery-photo-gallery`), SQL injection with
administrator access, 6.8.2 to 6.8.3, diff 102, fix B (nonce changes mixed in), the only administrator-level case in the pool.

## Mix and gaps

- Classes: sqli 1, file-delete 2, object-injection 2, rce 1, info-disclosure 1, missing-authz 1, privesc 1, reflected-xss 2, stored-xss 2, file-inclusion 1, ssrf 1.
- Privilege: unauthenticated 10, subscriber 3, contributor 2. No administrator-level case among the 15 (alternate 18).
- Size (PHP files): small under 20: 1 (booking-package; save-as-pdf has 20). Medium: link-library, football-pool, bcs-mcp-manager, ws-form, blocksy-companion, cost-calculator-builder. Large: the rest, where the count includes `vendor/`.
- Not found: **CSRF** (candidates exist, such as `ai-engine`, `give`, but their fixes are mixed with large feature changes), **open redirect** (one CVE in the whole window) and a clean **file-upload** case
  (`one-user-avatar`, CVE-2026-18983, 2.5.4 to 2.5.5, is mixed: diff 197 with reformatting). If these classes matter for the 40-case dataset they need a wider search, for example older CVEs, which `docs/DATASET.md` allows when flagged.

## Suggested pilot

If you want a first six that are all fix quality A and cover different classes, privileges and sizes: **1** (SQL injection, unauthenticated, tiny), **3** (object injection, medium), **4** (arbitrary function call,
contributor, tiny), **7** (privilege escalation, subscriber), **9** (reflected XSS, large), **6** (IDOR, large).
