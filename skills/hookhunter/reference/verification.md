# Verification: try to kill every candidate

Open this at step 3 (Refute), for **every** candidate from the hunt, whatever its class. A candidate is a hypothesis. It becomes a
finding only if a genuine attempt to refute it fails, and the attempt leaves evidence.

Each class file (`classes/<class>.md`) has its own refutation checklist; this file is the common procedure those checklists plug into,
the rules for choosing a status, and the mistakes that most often produce false positives and false negatives.

## Statuses

| Status | Meaning | Evidence required |
|---|---|---|
| `confirmed` | Every link of the chain holds and no refutation applies | `file:line` for the entry point registration, the source read, each guard examined (and why it fails or is absent), and the sink; the reasoning in prose, **no payload** |
| `needs-dynamic-check` | The chain is complete statically except for one named runtime fact | The same chain, plus the single unknown named exactly (a filter, a constant, a server rule, a PHP or library version, another plugin) |
| `refuted` | A specific check kills the candidate | A one-line reason from the vocabulary below, with `file:line` of the code that refutes it |

"I could not find the bug" is not `refuted`. A candidate you cannot finish reading is `needs-dynamic-check` with the unread part named,
or goes to the coverage list (step 5 of the workflow), never to `refuted`.

## 1. Write the claim first

A candidate is stated as one sentence with five slots; if a slot is empty, the candidate is not ready:

> **[tier]** can reach **[entry point, file:line]**, whose input **[source]** flows to **[sink, file:line]** without **[missing or inadequate guard]**, giving **[effect]** (**[class, CWE]**).

Fill the slots from the code, not from the plugin's description or from what the class usually looks like.

## 2. The checks, cheapest first

Stop at the first check that refutes. Record which one.

1. **It exists.** The function is defined, loaded and registered. `wp_xref.py <name>` shows a definition and a registration; Grep that the file is
   `require`d or autoloaded; look for dead branches (`if ( false )`, a feature flag or constant that is never set, code after an unconditional `return`/`exit`).
2. **It is reachable at the claimed tier.** Re-derive the tier from the hook (`surface.md`): `wp_ajax_nopriv_*`, `wp_ajax_*`, `admin_post_*`, REST
   `permission_callback`, menu capability, shortcode, request-time hook. Look for **upstream** gating: an early `return`/`wp_die` in a base-class constructor or an earlier
   hook, a `permission_callback` that really denies (`authz.md`, strict `false`/`null`/`WP_Error`), a role map.
3. **The attacker controls the value.** Follow the source to the sink. Is it cast, narrowed to a fixed list, read from a field only privileged users can write, or
   replaced by a server-side value? Is it still slashed? Payloads that need quotes (SQL strings, serialized data, XML, JSON, code strings) need a step that restores them (`wp-traps.md` 19; `sqli.md`).
4. **Guards on every path.** Capability, nonce, other checks: before the first side effect, on all branches, and **stopping execution** on failure (`wp-traps.md` 4 and 10).
   Look one call down (`wp_map.py` `callee`) and in parents and hooks.
5. **Guard adequacy.** For escapers, sanitisers, validators: does this function neutralise this class **in this context** for **the value that reaches the sink**
   (`sanitizers.md`)? Was the value changed after the guard? Is the guard applied to every variable in the expression (`wp_sinks.py` strips only the wrapped part)?
6. **The sink does what the claim says.** The echo is in an HTML response, not JSON with a header (`wp-traps.md` 11); the include has a controllable path, not only a fixed
   path with a fixed suffix; the deserialiser sees a PHP-serialised string; the parser has entity handling on; the request goes to a host the attacker picks.
7. **Environment and version.** Does the outcome depend on a constant (`DISALLOW_UNFILTERED_HTML`, `WP_HTTP_BLOCK_EXTERNAL`), a filter, multisite, PHP below 8,
   libxml, a web-server rule, another plugin? That is `needs-dynamic-check`, with the dependency named.
8. **Impact and intent.** Is this the feature (a code-snippet tool, a webhook field, a public form)? Does the attacker already hold the privilege the effect gives
   (an administrator on a default single site)? Is the effect trivial (dismissing a notice, reordering)? These refute a *vulnerability* even if the code path is real.
9. **Root cause and duplicates.** Several sinks guarded by the same missing check are one finding with several locations.

## 3. Choosing the status

- Run checks 1-8 in order. If one kills the candidate, `refuted` with that reason.
- If all pass and you can fill every slot of the claim with `file:line`, `confirmed`.
- If all pass except one fact only the running site can settle (check 7, or a library you could not read), `needs-dynamic-check`.
- Never upgrade a status because the class is serious, because a famous bug looks similar, or because the plugin is large.

One-line reasons for `refuted` (use one, add the location):

| Reason | Means |
|---|---|
| `dead-code` | never loaded or registered |
| `not-reachable` | the claimed tier cannot reach it (upstream gate, wrong hook, real `permission_callback`) |
| `source-not-controlled` | fixed, cast, allow-listed, or written only by trusted code |
| `source-still-slashed` | a quote-dependent payload arrives slashed and nothing restores the quotes |
| `guard-capability` / `guard-nonce` | a check fits the action, runs first on every path, and stops execution |
| `guard-escape-context` | escaped for this exact context at output |
| `guard-prepared` / `guard-cast` / `guard-allowlist` | parameterised, narrowed, or limited to a fixed list |
| `guard-path-containment` | `realpath` plus prefix test with separator, or a server-chosen name |
| `guard-mac` | verified signature before use |
| `guard-validated-redirect` / `guard-safe-client` | `wp_validate_redirect` / `wp_safe_remote_*` or equivalent on the same string |
| `guard-parser-defaults` | XML parsed with default flags on a safe libxml |
| `not-html-response` | output is not rendered as HTML |
| `self-only` | only the same user can set and see the value |
| `admin-only` | the caller already holds the privilege the effect grants |
| `expected-functionality` | the behaviour is the feature, correctly gated |
| `trivial-effect` | no meaningful change of state or data |

## 4. Where each class is usually refuted

Full lists are in the class files. This is the order to try.

| Class | Try first | Then |
|---|---|---|
| `authz` | capability check before the first effect, on all paths | tier unreachable; public by design; unguessable id; trivial effect |
| `csrf` | nonce enforced before the effect | not cookie-authenticated or unauthenticated (report `authz`); secret in the request; Settings API or cookie REST; trivial or multi-step |
| `privesc` | `promote_users` + `promote_user` + editable role | role, id, key from server state; own non-privileged fields; proved login secret; resulting role is Subscriber |
| `xss` | escaped for the context at output | narrowed value; non-HTML response; self-XSS or `unfiltered_html` writer; no victim |
| `sqli` | placeholders only, no variable in the template | cast, allow-list, `sanitize_key`; quoted value still slashed; `esc_like` and per-item `IN` |
| `file-ops` | server-chosen name or `realpath` containment | extension allow-list on the written name; destination not served as code; own temp files |
| `object-injection` | source not attacker-controlled; MAC first | `json_decode`; admin only. **No gadget found is not a refutation** |
| `ssrf` | fixed or allow-listed URL | `wp_safe_remote_*` on the same string with redirects; result unused and no side effect; admin-set webhook |
| `open-redirect` | `wp_safe_redirect` / `wp_validate_redirect` on the exact string | key-selected target; admin-set; not a redirect for the attacker |
| `rce` | no request data in the executed text | array command or `escapeshellarg` plus `--`; fixed handler map; admin tool by design; PHP version |
| `info-disclosure` | capability check on the read | data not sensitive; own data only; debug off by default; file not served |
| `xxe` | default flags, safe libxml | resolver callback; source not attacker-controlled; library options safe |

## 5. Reading a fix, and variants

Use this when the code you are reading already contains a guard (a patched version, a later release, or a sibling handler that looks fixed).

- **Do not report the bug the guard fixes** when the guard holds. Check it with checks 4 and 5 rather than by its name.
- **Look for the incomplete fix.** Typical shapes: the check added to one handler but not to its siblings or to the REST twin of an AJAX action; the nonce added but not the
  capability (or the reverse); escaping on one output of the value but not the other; a blacklist added; the validation done on one string and the use on another; a check that
  stops one branch while another still reaches the sink; a client-side check only.
- **Variants.** For each `confirmed` finding, Grep for the same pattern (same sink, same helper, same parameter name) across the plugin and open the matches; read the
  changelog or readme for earlier security fixes and check whether the neighbouring code was fixed too (step 4 of the workflow).
- **Diff mode.** Compare the two versions of the guard line by line: what input did the old code accept that the new code rejects? If nothing, the change may be cosmetic.

## 6. Mistakes to avoid

False positives:
- Treating a sink with a variable as a finding without tracing the source (check 3).
- Treating `wp_map.py` or `wp_sinks.py` output as proof. `no-cap-check`, `no-nonce`, `unguarded` are hints; the check may live two calls down, in a parent class or in an earlier hook.
- Reporting what a programme would reject (section "What triagers reject" in each class file) as a vulnerability in `audit` mode; in `bench` mode keep the finding and mark the reason.
- Counting a theoretical gadget, a debug setting, a version string or an administrator-only effect as impact.

False negatives:
- Marking `refuted` because a safe-sounding function is present (`sanitize_text_field`, `esc_url_raw`, a nonce, `is_admin()`). Ask what it guarantees for this context.
- Believing `current_user_can( 'edit_posts' )` protects an action on a specific post (`wp-traps.md` 5).
- Stopping the hunt after one finding in a file. The same author usually repeats the pattern.
- Skipping `vendor/`, JavaScript files and non-PHP entry points, which the scripts do not parse.
- Resolving doubt in favour of `refuted`. If a runtime fact decides it, say `needs-dynamic-check`.

General:
- Quote real code, at most a few lines, with `file:line`. Do not paraphrase code you have not read.
- Do not use knowledge of famous CVEs as evidence; the evidence is in the code in front of you.
- Do not write payloads or reproduction requests in `bench` mode.

## 7. Record what you did not verify

For each candidate and for the run as a whole, keep the list of things you did not read or could not settle (unparsed directories, files over the size limit, libraries
not opened, dynamic hook names not resolved). It feeds the coverage section (step 5): a run with unverified parts is **partial**, never "clean".

## Sources

- Per-class refutation checklists and triage rules: `classes/*.md`, with their cited sources; guard behaviour in `sanitizers.md`; tiers in `surface.md`; mistakes in `wp-traps.md`.
- [Trail of Bits `fp-check` plugin README](https://github.com/trailofbits/skills/tree/main/plugins/fp-check): public description of a per-bug false-positive verification process with data-flow and exploitability phases and a documented verdict. Used as an idea source for the claim-then-refute structure only; no text copied.
- [MITRE CWE: CVE to CWE mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html) (for choosing the most specific weakness rather than a discouraged parent such as CWE-285)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
