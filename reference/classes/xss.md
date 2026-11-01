# Cross-site scripting

CWE-79 (also reported as CWE-80/83 for basic and attribute cases; the scorer treats them as one family).
Three shapes: **reflected** (the request value is in the response), **stored** (it was saved, then rendered later,
often to a different person) and **DOM-based** (client-side JavaScript moves a value into an HTML sink).

The question is never "is there an `esc_*` call?" but: **who can inject, who sees it, and in which context does
the value land?** Open `sanitizers.md` section 2 for which escaper fits which context, `surface.md` for who
reaches the handler, and `wp-traps.md` 11-13.

## 1. Where it lives

- **Output in PHP:** `echo`, `print`, `printf`, `vprintf`, `_e`, `<?= … ?>`, `wp_die()`, `die()`, heredoc templates,
  strings returned by shortcodes, block `render_callback`s, widgets, `the_content`/`the_title` filters, admin
  notices. `wp_sinks.py --class xss` lists the first group; `get_option()`, `get_post_meta()`, `get_user_meta()`,
  `get_transient()` and `get_query_var()` count as user-influenced values there.
- **Not in `wp_sinks.py`:** plugin JavaScript (`.js` files), HTML fragments returned in JSON and inserted by script,
  `wp_localize_script` / `wp_add_inline_script` data, `settings_errors()` messages. Use Grep.
- **Stored XSS needs two halves.** The *write* is a handler from `wp_map.py` that saves request data
  (`update_option`, `update_post_meta`, `$wpdb->insert`, `wp_insert_post`, comments, form entries, logs, transients) and
  the *read* is the sink that prints it. Establish the tier of the write and the role of whoever views the page.
- **DOM sources:** `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data, values in
  `data-*` attributes or in `wp_localize_script` objects. **DOM sinks:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, jQuery `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()` with strings, `$(string)` when the
  string starts with `<`, `eval`, `new Function`, `setTimeout(string)`, `href`/`src` assignments from user data.

## 2. How to hunt

1. Take unguarded `echo`-family sinks from `wp_sinks.py` and read the surrounding markup to name the **context**
   (text node, quoted or unquoted attribute, URL attribute, inline handler, `<script>` block, CSS, `<textarea>`).
2. Trace the value back to its **source**: request superglobal (reflected), `get_option` / meta / table row (stored),
   a REST or AJAX response (DOM).
3. For stored values, follow the write: which entry point, which tier, which sanitiser at write time?
4. Name the **victim**: a visitor, a logged-in user, an administrator. Script that runs in an administrator's browser
   can create users and edit plugin files, so unauthenticated-writes-admin-reads is the strongest shape.
5. Check that the response is HTML. JSON with `Content-Type: application/json` (`wp_send_json`), `text/plain` and
   downloads do not execute script (trap 11 in `wp-traps.md` when the header is missing).
6. For JavaScript files, search for the sinks in section 1 and trace their inputs to server-provided data.

## 3. Traps specific to this class

- **`_e()` and `__()` do not escape.** They translate (core: "Displays translated text"). Use `esc_html_e()`,
  `esc_html__()`, `esc_attr__()`. A translated string can contain markup, so `echo __( … )` is not output-safe;
  `printf( __( 'Hello %s' ), $name )` leaves `$name` unescaped.
- **Sanitised at input, output in another context.** `sanitize_text_field()` strips tags and keeps quotes, so the same
  value is usually safe in a text node and injectable in `value="…"` or `onclick="…"`. Judge the context at the sink.
- **Right escaper, wrong context.** `esc_attr()` in `href` (a `javascript:` URL survives), `esc_html()` in an unquoted
  attribute, `esc_js()` in a `<script>` block, `esc_url()` inside a JS string, `esc_html()` around a URL used in `src`.
- **Escaped, then changed.** `html_entity_decode`, `htmlspecialchars_decode`, `stripslashes`, `urldecode`,
  `base64_decode`, `str_replace` or concatenation with a second raw value *after* the escaper.
- **`add_query_arg()`, `$_SERVER['REQUEST_URI']`, `PHP_SELF`** in `action=""`/`href=""` without `esc_url` (trap 12).
- **Messages that are HTML.** `wp_die( $msg )` puts the string inside `<div class="wp-die-message">` unescaped, so a
  request value there is reflected XSS in an HTML response. `settings_errors()` wraps the `add_settings_error()` message
  in `<strong>` as HTML, but in `trunk` `wp_admin_notice()` prints it through `wp_kses_post()`, which removes script and
  event-handler attributes: on current core that is HTML injection, not XSS. Older releases were not read; check the
  core version the plugin supports before claiming it.
- **`wp_localize_script` data.** Core decodes HTML entities in top-level scalar values (`html_entity_decode`) and
  encodes the object with `JSON_HEX_TAG | JSON_UNESCAPED_SLASHES`. So it cannot be used to close the `<script>` tag, but an
  entity-encoded value becomes real markup in the JavaScript string; if the script then calls `.html()`, that is DOM XSS.
- **`wp_add_inline_script()` / manual `<script>` output with concatenated data.** Nothing escapes it. Build the data with
  `wp_json_encode( $data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT )` or use `wp_localize_script`.
- **HTML fragments in JSON.** `wp_send_json_success( $html )` is safe on the wire, then `element.innerHTML = response.data`
  or `.html()` makes the value live. Escape on the server or insert with `.text()` / `textContent`.
- **Shortcode and block attributes.** `shortcode_atts()` does not sanitise. Authors write the attributes and visitors
  see the output (`surface.md`); output must be escaped at render time.
- **Admin pages that echo the request.** `$_GET['page']`, `$_GET['tab']`, `$_REQUEST['s']`, `$_GET['paged']` reused in
  `class=""`, `value=""` and form URLs.
- **`wp_kses_post()` output reused elsewhere.** It guarantees HTML body content, not attribute or script content.
- **Reflected values on POST.** A POST-only reflection is still exploitable: an attacker's page can auto-submit a form (`UI:R`).
- **Self-XSS.** A value only the same user can set and see is not a vulnerability.

## 4. Vulnerable and safe shapes (generic)

```php
// vulnerable: reflected, text node and attribute
echo '<p>' . $_GET['q'] . '</p>';
echo '<input value="' . sanitize_text_field( $_GET['q'] ) . '">';       // quotes survive
// safe
echo '<p>' . esc_html( wp_unslash( $_GET['q'] ) ) . '</p>';
echo '<input value="' . esc_attr( wp_unslash( $_GET['q'] ) ) . '">';
```

```php
// vulnerable: stored, any visitor can write, admin reads
$wpdb->insert( $table, array( 'name' => $_POST['name'] ) );              // later: echo $row->name;
// safe: escape late, at output
echo esc_html( $row->name );
```

```php
// vulnerable: wrong context for the JS string
echo '<a href="#" onclick="go(\'' . esc_attr( $x ) . '\')">';
// safe
echo '<a href="#" onclick="go(\'' . esc_js( $x ) . '\')">';
```

```js
// vulnerable (DOM)
$('#out').html( response.data.message );
// safe
$('#out').text( response.data.message );
```

## 5. Refutation checklist

Mark `refuted` and record which holds:
1. The value is escaped **for the sink's context**, at output, with nothing modifying it afterwards.
2. The value is narrowed first: an integer cast, `absint()`, a strict `in_array()` allow-list, `sanitize_key()` / `sanitize_html_class()` for a class name.
3. The value is sanitised on input in a way that fits the context (`sanitize_text_field` and a text node; `wp_kses` with a tag list and an HTML body context). Confirm the quote and context rules in section 3.
4. The response is not HTML (JSON with a proper header, `text/plain`, a download), or the browser will not run script there (`<textarea>`/`<title>` without a breakout the code allows).
5. Only the same user can set and view the value (self-XSS), or only users who already have `unfiltered_html` (administrators and editors on a default single site) can write it. Check the site-type rules in trap 6.
6. The value is not reachable: dead code, unregistered handler, or reflected only into a field the browser does not render.
7. No victim exists: the page that prints it is not visited by anyone other than the writer.

`needs-dynamic-check` for filters that change output (`the_title`, `the_content`, custom `esc_*` filters) or a theme that
re-prints the value. `confirmed` needs file:line for the write (if stored), the sink, the context and the missing or wrong escaper.

## 6. Typical CVSS 3.1

Scope changes because script runs in the victim's browser, outside the web application's own security authority (`S:C`). `AV:N/AC:L/UI:R` in all rows; computed with the FIRST formula.

Impact is the part that varies. FIRST's own stored-XSS example (CVE-2019-7551, a low-privileged user stores script that runs when an administrator opens the page) scores the
**worst case**, `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` = 9.0, because script running as an administrator can create users and install code. The more common practice for reflected XSS is
`C:L/I:L/A:N` (6.1). State which one you used and why; use the high-impact row only when the victim is an administrator (or another privileged user) and you say what the script can do.

| Scenario | Vector | Score |
|---|---|---|
| Reflected or DOM, unauthenticated, limited impact | `PR:N/S:C/C:L/I:L/A:N` | 6.1 |
| Stored, written without an account, limited impact | `PR:N/S:C/C:L/I:L/A:N` | 6.1 |
| Stored, written by a subscriber/customer, limited impact | `PR:L/S:C/C:L/I:L/A:N` | 5.4 |
| Stored, written by a contributor or author, limited impact | `PR:L/S:C/C:L/I:L/A:N` | 5.4 |
| Stored, written by an administrator | `PR:H/S:C/C:L/I:L/A:N` | 4.8 |
| Stored, written by a low-privileged user, victim is an administrator, script acts as the administrator | `PR:L/S:C/C:H/I:H/A:H` | 9.0 |

## 7. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- XSS is accepted when it "must have an impact on the entire site, or be reflected".
- Out of scope: "Contributor-level (or higher) stored XSS"; "HTML-only injection without JavaScript execution – e.g. injection into emails or rendered output where script execution is not possible"; "CSS injection"; "Authenticated shortcode issues without sensitive data disclosure"; any report with Attack Complexity High.
- Only unauthenticated or Subscriber/Customer exploitation is eligible, so stored XSS written by anyone with more capabilities is excluded.
- Reports on components with fewer than 1,000 active installs are outside the programme (except under mVDP).
- WPScan's submission page tells testers to disallow `unfiltered_html` when testing stored XSS with administrator or editor roles, since those roles may use JavaScript in content.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7. The reasoning about
`unfiltered_html` in `wp-traps.md` trap 6 explains why administrator-written stored XSS is usually weak.

Practical rule: prefer reports where an unauthenticated or Subscriber-level request plants the value and an
administrator or a visitor renders it, or where a URL reflects it. Name the writer, the viewer and the context.

## Sources

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) and [DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [Escaping data (APIs handbook)](https://developer.wordpress.org/apis/security/escaping/) and [Plugin Handbook: Securing output](https://developer.wordpress.org/plugins/security/securing-output/)
- [`_e()`](https://developer.wordpress.org/reference/functions/_e/), [`esc_html_e()`](https://developer.wordpress.org/reference/functions/esc_html_e/), [`wp_die()`](https://developer.wordpress.org/reference/functions/wp_die/), [`add_settings_error()`](https://developer.wordpress.org/reference/functions/add_settings_error/), [`settings_errors()`](https://developer.wordpress.org/reference/functions/settings_errors/), [`wp_localize_script()`](https://developer.wordpress.org/reference/functions/wp_localize_script/), [`wp_add_inline_script()`](https://developer.wordpress.org/reference/functions/wp_add_inline_script/)
- WordPress core `trunk`, read 2026-11-01: [`class-wp-scripts.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-scripts.php) (`localize`), [`l10n.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/l10n.php) (`_e`, `esc_html_e`), [`wp-admin/includes/template.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/includes/template.php) (`settings_errors`), [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`_default_wp_die_handler`)
- [jQuery: `jQuery( html )` and string handling](https://api.jquery.com/jQuery/)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
