# Information disclosure

CWE-200 (exposure of sensitive information), CWE-209 (error messages that reveal details), CWE-215 (debug information), CWE-532 (sensitive
information in a log), CWE-538 (sensitive file placed where it can be fetched), CWE-359 (private personal data).

Boundary with `authz.md`: if the cause is a **missing capability or ownership check** on a read, report `authz` (CWE-862/863/639). This file covers
**what** leaves the application and **through which channel**: too much data in a response, secrets in page output, error and debug output, logs,
exports and backups in web-accessible places, and cross-origin readability.

Open `surface.md` for who reaches the handler, `file-ops.md` for arbitrary file read, and `sqli.md` when the data comes out of a query.

## 1. WordPress facts that decide exploitability

Core `trunk` read on 2026-11-01.

- **A `WP_User` holds the whole `users` row.** `WP_User::get_data_by()` runs `SELECT * FROM $wpdb->users`, and `to_array()` returns
  `get_object_vars( $this->data )`. So `get_userdata()`, `get_user_by()`, `wp_get_current_user()` and `get_users()` (default `fields`) carry
  `user_pass` (the password hash), `user_email`, `user_activation_key` and the other columns. Passing such an object, or its array form, to
  `wp_send_json()`, `rest_ensure_response()`, `wp_localize_script()`, `print_r()` or a template discloses them.
- **Core's REST API sends credentialed CORS headers.** `rest_send_cors_headers()` sets `Access-Control-Allow-Origin` to the request's
  `Origin`, `Access-Control-Allow-Credentials: true` and `Vary: Origin`. Cookie-authenticated REST requests are then protected only by the `wp_rest` nonce (`surface.md`).
  A plugin endpoint outside the REST server that copies this behaviour, or reflects `Origin` with credentials while relying on the login cookie
  and no nonce, can be **read** from another site by a logged-in victim's browser.
- **Debug output is configured by constants.** With `WP_DEBUG_LOG` true, PHP errors go to `WP_CONTENT_DIR . '/debug.log'` (a string value sets another path);
  `WP_DEBUG_DISPLAY` decides whether errors are printed into responses. `wp-content/debug.log` is a file under the web root unless the server blocks it.
- **`wp_localize_script()` and inline script data are public.** The data is printed in the page HTML to every visitor who gets that page.
- **`post_password_required()`** is the core check that a password-protected post's content may be shown; functions such as `get_post()` or direct queries return
  posts of any status without applying it *(function behaviour from the reference documentation; not re-read in source here)*.
- `wp_sinks.py` rules: `debug-output` (`phpinfo`, `var_dump`, `debug_print_backtrace`, `debug_zval_dump`), `print_r` (`print_r`/`var_export` with one argument)
  and `user-data` (`get_users`, `get_userdata`, `get_user_by`, `get_user_meta`); each counts as guarded when the function contains a `current_user_can`/`user_can`/`is_super_admin`
  call. It does **not** see what is later printed or returned, error handlers, log writers, `show_in_rest` settings, files written to the uploads directory, or CORS headers.

## 2. Where it lives

| Channel | Look for |
|---|---|
| Response bodies | `wp_send_json*`, `rest_ensure_response`, `echo json_encode`, rows from `$wpdb->get_results` returned whole, `WP_User`/`WP_Post`/order objects returned whole |
| Page and script output | `wp_localize_script`, `wp_add_inline_script`, `<script>` blocks, `data-*` attributes carrying keys, nonces, emails, tokens, or server paths |
| Errors and debug | `phpinfo()`, `var_dump`, `print_r`, `debug_print_backtrace`, `$wpdb->last_error`, `$e->getMessage()`/`getTraceAsString()` in output, `wp_die( $e->getMessage() )`, `ini_set( 'display_errors', 1 )`, `error_reporting( E_ALL )` |
| Logs | `error_log( … )` and custom logging to files under `wp-content/`, `wp-content/uploads/`, or the plugin directory; logs that contain request bodies, tokens, passwords, API responses |
| Generated files | exports (CSV, SQL, ZIP), backups, invoices, reports, caches and temporary files written into the uploads directory or the plugin directory with predictable names |
| Stored secrets | API keys and tokens in options printed on the front end, returned by REST (`register_setting` with `show_in_rest`), or included in an export |
| Private content | shortcodes, blocks and endpoints that load a post, comment, order or form entry by id with no status or ownership test |
| Headers and CORS | `Access-Control-Allow-Origin` taken from `$_SERVER['HTTP_ORIGIN']`, `Allow-Credentials: true`, `Access-Control-Allow-Origin: *` on authenticated data |

## 3. How to hunt

1. For each response path, name **the data** it carries and its sensitivity: secrets and hashes, personal data, private content, internal details (paths, versions, queries).
2. Name **who receives it**: any visitor, a logged-in user, or an administrator. Compare with who should (`authz.md`).
3. For generated files, find the **path** and whether the web server serves it. A random, unguessable name in an unlisted directory is weaker than a fixed name such as `uploads/<plugin>/export.csv`; directory listing makes any name discoverable.
4. For debug and error output, check whether it is conditional on `WP_DEBUG`, an administrator capability, or a setting that is off by default.
5. For cross-origin issues, check the headers sent and whether authentication is by cookie, with or without a nonce.
6. Record the **sensitivity** in the finding. A bare "stack trace" or "version" is not a finding; the data disclosed is.

## 4. Traps specific to this class

- **Returning the object.** `wp_send_json_success( $user )`, `wp_send_json( get_userdata( $id ) )`, `wp_send_json( get_users() )`, `$wpdb->get_results( "SELECT * FROM {$wpdb->users}" )`: the password hash and
  activation key leave with the rest. Prefer `get_users( array( 'fields' => array( 'ID', 'display_name' ) ) )` or build the array field by field.
- **Secrets in `wp_localize_script`.** Server-side keys passed to the page for a script that only needs a public identifier.
- **`show_in_rest` on a secret option,** or a custom REST field that returns it, with a permissive `permission_callback` (`authz.md`).
- **Verbose errors to the client.** Exception messages, `$wpdb->last_error` (it reveals the query), file paths and stack traces in AJAX or REST responses. Often the first step of an SQL injection (`sqli.md`).
- **Debug leftovers.** `phpinfo()`, `var_dump` or `print_r` in handlers reachable without a capability check.
- **Predictable export and backup names.** `uploads/<plugin>/backup.sql`, `export-2024.csv`, `…-<timestamp>.zip` with a guessable timestamp, files left after the job, and directories without an `index.php` or a server rule.
- **Logs with secrets.** Request bodies, tokens, passwords or full API responses written to a web-accessible `.log`/`.txt`, and `debug.log` left enabled in production.
- **Private content loaded by id.** `get_post( $id )` returns drafts, private and password-protected posts; a shortcode or endpoint that prints `post_content` needs a status, capability or `post_password_required()` test.
- **User enumeration and "does this email exist" responses.** Distinct messages or timing for valid and invalid users. Treat it as a finding only when it exposes something significant; see section 8.
- **CORS.** `Access-Control-Allow-Origin` reflected from `Origin` together with `Access-Control-Allow-Credentials: true` on a cookie-authenticated endpoint, or `*` on a response that contains private data.
- **Email to the wrong recipient.** A confirmation, reset or notification sent to an address from the request (`wp_mail( $_POST['to'], … )`) discloses the content to that address.
- **Metadata.** Plugin version in `readme.txt`, asset `?ver=` strings, directory listings of public assets: not findings by themselves.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: whole user row, including password hash, to anyone
add_action( 'wp_ajax_nopriv_fx_user', function () { wp_send_json_success( get_userdata( absint( $_GET['id'] ) ) ); } );

// safe: capability check, then only the needed fields
if ( ! current_user_can( 'list_users' ) ) { wp_send_json_error( null, 403 ); }
$u = get_userdata( absint( $_GET['id'] ) );
wp_send_json_success( array( 'id' => $u->ID, 'name' => $u->display_name ) );
```

```php
// vulnerable: server secret in page data for every visitor
wp_localize_script( 'fx', 'fxData', array( 'apiSecret' => get_option( 'fx_api_secret' ) ) );
// safe: expose only what the browser needs
wp_localize_script( 'fx', 'fxData', array( 'siteId' => get_option( 'fx_site_id' ) ) );
```

```php
// vulnerable: predictable file in the web root
file_put_contents( wp_upload_dir()['basedir'] . '/fx/export.csv', $csv );
// better: unpredictable name and a download endpoint that checks capability; or store outside the web root
$name = wp_generate_password( 32, false ) . '.csv';
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. A capability or ownership check that fits the data runs before the data is read or returned, on every path (`authz.md`).
2. The data returned is not sensitive: public by design (published content, a public identifier), or a version or path with no security use.
3. The output is limited to the requester's own data, with a verified owner test.
4. The channel is administrator-only and the data is already available to administrators (a debug page in the admin area behind `manage_options`).
5. The debug or error output only appears when `WP_DEBUG`/`WP_DEBUG_DISPLAY` is on and the plugin does not force it.
6. The generated file is outside the web root or in a path the web server denies, or has an unguessable name and no listing. If this depends on server configuration use `needs-dynamic-check`.
7. The entry point is unreachable at the claimed tier, or is dead code (`wp_xref.py`).

`confirmed` needs file:line for the entry point and the code that reads and returns (or writes) the data, a statement of **exactly which fields** leave, and who can reach them.

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N/S:U`, integrity and availability unaffected; computed with the FIRST formula. Rate confidentiality by the data, not by the technique.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, secrets or password hashes (C:H) | `PR:N/C:H/I:N/A:N` | 7.5 |
| Unauthenticated, limited or low-sensitivity data (C:L) | `PR:N/C:L/I:N/A:N` | 5.3 |
| Subscriber, secrets or password hashes | `PR:L/C:H/I:N/A:N` | 6.5 |
| Subscriber, limited data | `PR:L/C:L/I:N/A:N` | 4.3 |
| Administrator only | `PR:H/C:H/I:N/A:N` | 4.9 |

Cross-origin read of an authenticated response adds `UI:R`: `PR:N/UI:R/C:H/I:N/A:N` is 6.5.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- Broken access control is accepted when it "must result in access to significant or sensitive objects, for example: API keys or secret values, including a demonstration of their impact; password hashes; backup files or SQL files".
- Examples not accepted: "PII leakage alone, without broader security impact"; "interactions with attachments, tickets, events, orders, or appointments".
- Out of scope (information disclosure): "Full path disclosure"; "Private or draft post, page, or content disclosure – unless the post type can leak extremely sensitive data (PII data set or any data that can lead to complete website takeover)"; "Enumeration that does not expose significant information (only confidentiality at Low impact)"; "API key leakage that does not result in significant impact".
- Scoring exclusions apply too: unauthenticated reports with only one Low impact (CVSS 5.3), `AC:H`, components with fewer than 1,000 active installs outside mVDP.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: state the exact fields or file that are exposed and why they matter (hash, key, backup), who can fetch them, and the path or request. Do not
report "debug mode", "version disclosure" or "stack trace" without the sensitive data they reveal.

## Sources

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-538](https://cwe.mitre.org/data/definitions/538.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) and [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [Debugging in WordPress](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/)
- [`WP_User`](https://developer.wordpress.org/reference/classes/wp_user/), [`get_users()`](https://developer.wordpress.org/reference/functions/get_users/), [`post_password_required()`](https://developer.wordpress.org/reference/functions/post_password_required/), [`wp_localize_script()`](https://developer.wordpress.org/reference/functions/wp_localize_script/), [`rest_send_cors_headers()`](https://developer.wordpress.org/reference/functions/rest_send_cors_headers/)
- WordPress core `trunk`, read 2026-11-01: [`class-wp-user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-user.php) (`get_data_by`, `to_array`), [`rest-api.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api.php) (`rest_send_cors_headers`), [`load.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/load.php) (`wp_debug_mode`)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
