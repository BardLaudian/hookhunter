# Security audit: synthetic fixture suite (dry run)

**Mode:** audit. **Component:** the 26 fixture plugins under `skills/wp-plugin-audit/tests/fixtures/` (written for this repository, not derived from any real plugin).
**Date:** 2026-11-01. **Method:** the workflow of `SKILL.md` followed by hand; scripts for candidates, reading and `wp_xref.py` for refutation.
**Not applicable:** version and prior-art checks, disclosure (synthetic code, no vendor). No payloads are included; reproduction steps are for a local test site.

## Summary

24 confirmed findings and 3 needing a runtime check across 13 plugins. All 12 safe twins produced no finding. Candidates that were refuted are listed at the end with the reason.

| # | Fixture | Class | CWE | CVSS 3.1 | Privilege | Location | Status |
|---|---|---|---|---|---|---|---|
| 1 | rce-vuln | rce | CWE-94 | 9.8 | unauthenticated | `rce-vuln.php:7` | confirmed |
| 2 | rce-vuln | rce | CWE-78 | 9.8 | unauthenticated | `rce-vuln.php:8` | confirmed |
| 3 | sqli-vuln | sqli | CWE-89 | 9.8 | unauthenticated | `sqli-vuln.php:10` | confirmed |
| 4 | file-ops-vuln | file-delete | CWE-22 | 9.1 | unauthenticated | `file-ops-vuln.php:10` | confirmed |
| 5 | privesc-vuln | privesc | CWE-269 | 8.8 | subscriber | `privesc-vuln.php:11` | confirmed |
| 6 | privesc-vuln | privesc | CWE-269 | 8.8 | subscriber | `privesc-vuln.php:12` | confirmed |
| 7 | ssrf-vuln | ssrf | CWE-918 | 8.6 | unauthenticated | `ssrf-vuln.php:7` | confirmed |
| 8 | file-ops-vuln | file-upload | CWE-434 | 7.5 | unauthenticated | `file-ops-vuln.php:8` | confirmed |
| 9 | file-ops-vuln | file-inclusion | CWE-98 | 7.5 | unauthenticated | `file-ops-vuln.php:9` | confirmed |
| 10 | info-disclosure-vuln | info-disclosure | CWE-200 | 7.5 | unauthenticated | `info-disclosure-vuln.php:8` | confirmed |
| 11 | sqli-vuln | sqli | CWE-89 | 7.5 | unauthenticated | `sqli-vuln.php:9` | confirmed |
| 12 | xxe-vuln | xxe | CWE-611 | 7.5 | unauthenticated | `xxe-vuln.php:7` | confirmed |
| 13 | rce-vuln | rce | CWE-94 | 7.3 | unauthenticated | `rce-vuln.php:9` | confirmed |
| 14 | open-redirect-vuln | open-redirect | CWE-601 | 6.1 | unauthenticated | `open-redirect-vuln.php:8` | confirmed |
| 15 | open-redirect-vuln | open-redirect | CWE-601 | 6.1 | unauthenticated | `open-redirect-vuln.php:12` | confirmed |
| 16 | xss-vuln | reflected-xss | CWE-79 | 6.1 | unauthenticated | `xss-vuln.php:7` | confirmed |
| 17 | xss-vuln | reflected-xss | CWE-79 | 6.1 | unauthenticated | `xss-vuln.php:8` | confirmed |
| 18 | ssrf-vuln | ssrf | CWE-918 | 5.8 | unauthenticated | `ssrf-vuln.php:9` | confirmed |
| 19 | xxe-vuln | xxe | CWE-611 | 5.8 | unauthenticated | `xxe-vuln.php:9` | confirmed |
| 20 | info-disclosure-vuln | info-disclosure | CWE-200 | 5.3 | unauthenticated | `info-disclosure-vuln.php:7` | confirmed |
| 21 | surface | missing-authz | CWE-862 | 5.3 | unauthenticated | `surface.php:35` | confirmed |
| 22 | surface | missing-authz | CWE-862 | 5.3 | unauthenticated | `surface.php:97` | confirmed |
| 23 | authz-vuln | missing-authz | CWE-862 | 4.3 | subscriber | `authz-vuln.php:11` | confirmed |
| 24 | csrf-vuln | csrf | CWE-352 | 4.3 | unauthenticated | `csrf-vuln.php:11` | confirmed |
| 25 | surface | missing-authz | CWE-863 | 4.3 | contributor | `surface.php:31` | needs-dynamic-check |
| 26 | object-injection-vuln | object-injection | CWE-502 | not scored | unauthenticated | `object-injection-vuln.php:7` | needs-dynamic-check |
| 27 | object-injection-vuln | object-injection | CWE-502 | not scored | unauthenticated | `object-injection-vuln.php:8` | needs-dynamic-check |

## Findings

### 1. rce-vuln: rce at `rce-vuln.php:7`

- **Entry point:** `wp_ajax_nopriv_fx_run` in `fx_run`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['code'] -> eval; nopriv, no nonce, no capability
- **Why the guards fail:** Request text is evaluated; nothing restricts it.
- **Impact:** A visitor runs PHP code on the server.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8
- **Reproduction (local test site only):** On a local test site, post a harmless expression such as the arithmetic `1+1` to the action and observe that it is evaluated.
- **Suggested fix:** Delete the handler; never evaluate request text.
- **Verification status:** confirmed

### 2. rce-vuln: rce at `rce-vuln.php:8`

- **Entry point:** `wp_ajax_nopriv_fx_run` in `fx_run`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['host'] -> concatenated into the command line of shell_exec
- **Why the guards fail:** No `escapeshellarg()` and the shell parses the whole line.
- **Impact:** A visitor runs operating-system commands as the web user.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8
- **Reproduction (local test site only):** On a local test site, request the action with a `host` value containing a harmless extra command that writes a marker file inside wp-content.
- **Suggested fix:** Build the command with `proc_open( array( 'ping', '-c1', '--', $host ) )` or at least `escapeshellarg( $host )`, and require a capability.
- **Verification status:** confirmed

### 3. sqli-vuln: sqli at `sqli-vuln.php:10`

- **Entry point:** `wp_ajax_nopriv_fx_find` in `fx_find`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['id'] -> wp_unslash -> interpolated inside the quoted template passed to prepare() (no placeholder)
- **Why the guards fail:** `prepare()` only protects values passed as arguments; a variable inside the template is concatenated as is.
- **Impact:** The same value ends inside a quoted string of a DELETE; `wp_unslash` removed the slashes that would have protected it.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8
- **Reproduction (local test site only):** On a local test site, send an `id` containing a single quote and observe the database error or changed behaviour.
- **Suggested fix:** Pass the value as a placeholder argument: `$wpdb->prepare( '... WHERE name = %s', $id )`.
- **Verification status:** confirmed

### 4. file-ops-vuln: file-delete at `file-ops-vuln.php:10`

- **Entry point:** `wp_ajax_nopriv_fx_files` in `fx_files`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['file'] -> WP_CONTENT_DIR . '/' . value -> unlink; no basename or realpath
- **Why the guards fail:** The value is concatenated into the path unvalidated.
- **Impact:** A visitor deletes any file the web user can delete inside or outside wp-content through `../`; deleting configuration files can lead to site takeover.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` = 9.1
- **Reproduction (local test site only):** On a local test site, create a scratch file inside wp-content, post its relative name to the action and confirm it is removed.
- **Suggested fix:** Use `wp_delete_file_from_directory( $path, $base )` with a file name from `basename()` and require a capability.
- **Verification status:** confirmed

### 5. privesc-vuln: privesc at `privesc-vuln.php:11`

- **Entry point:** `wp_ajax_fx_role` in `fx_role`
- **Privilege required:** subscriber
- **Data flow:** $_POST['role'] -> wp_update_user(array('role'=>...)); nonce only, no promote_users, no role allow-list
- **Why the guards fail:** `wp_insert_user` and `wp_update_user` do not check the caller; the handler checks a nonce but no capability and accepts any role.
- **Impact:** A subscriber sets any user's role, including their own, to administrator.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8
- **Reproduction (local test site only):** On a local test site, as a subscriber, post the action with the nonce, your own user id and `role=administrator`; reload your profile.
- **Suggested fix:** Require `promote_users` and `promote_user` for the id, and accept only roles from `get_editable_roles()`.
- **Verification status:** confirmed

### 6. privesc-vuln: privesc at `privesc-vuln.php:12`

- **Entry point:** `wp_ajax_fx_role` in `fx_role`
- **Privilege required:** subscriber
- **Data flow:** $_POST['caps'] -> update_user_meta(id, 'wp_capabilities', value); same missing checks
- **Why the guards fail:** The meta key that stores roles is written from request data without a capability check.
- **Impact:** Direct write of the capabilities meta key, an alternative route to the same escalation.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8
- **Reproduction (local test site only):** On a local test site, as a subscriber, post the action with a `caps` value naming the administrator role and reload your profile.
- **Suggested fix:** Remove the write; change roles only through `WP_User::set_role()` after the checks above.
- **Verification status:** confirmed

### 7. ssrf-vuln: ssrf at `ssrf-vuln.php:7`

- **Entry point:** `wp_ajax_nopriv_fx_fetch` in `fx_fetch`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['url'] -> wp_remote_get (no wp_http_validate_url) -> response body returned via wp_send_json
- **Why the guards fail:** `wp_remote_get` does not validate the host, and the body is returned.
- **Impact:** A visitor makes the server request any URL, including loopback and internal addresses, and reads the response.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = 8.6
- **Reproduction (local test site only):** On a local test site, post the URL of a second local service you own and observe its response in the JSON.
- **Suggested fix:** Use `wp_safe_remote_get()` with `wp_http_validate_url()`, require a capability, and do not return the body.
- **Verification status:** confirmed

### 8. file-ops-vuln: file-upload at `file-ops-vuln.php:8`

- **Entry point:** `wp_ajax_nopriv_fx_files` in `fx_files`
- **Privilege required:** unauthenticated
- **Data flow:** $_FILES['f']['name'] -> $dest in wp-content/uploads -> move_uploaded_file; no extension or type check, no capability
- **Why the guards fail:** Name and type come from the client; nothing validates the extension and the handler is registered for visitors.
- **Impact:** An unauthenticated visitor stores a file with an attacker-chosen name and extension in the uploads directory. Whether it can be executed depends on the web server (not verified); with PHP execution allowed the score becomes 9.8.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = 7.5
- **Reproduction (local test site only):** On a local test site, post a harmless text file named `probe.txt` to the action and confirm it appears under uploads with the same name.
- **Suggested fix:** Require `upload_files`, pass the file through `wp_handle_upload()` with an allow-list of types, and use `wp_unique_filename()`.
- **Verification status:** confirmed

### 9. file-ops-vuln: file-inclusion at `file-ops-vuln.php:9`

- **Entry point:** `wp_ajax_nopriv_fx_files` in `fx_files`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['tpl'] -> include, no allow-list, no containment
- **Why the guards fail:** The request value is the whole path; there is no allow-list, `basename` or `realpath` containment.
- **Impact:** A visitor chooses the file that PHP includes; PHP files execute, other readable files are printed. Combined with the upload finding this reaches code execution.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5
- **Reproduction (local test site only):** On a local test site, request the action with `tpl` set to a harmless readable text file and observe its content in the response.
- **Suggested fix:** Select the template from a fixed array (`in_array( $tpl, $allowed, true )`) and build the path from constants.
- **Verification status:** confirmed

### 10. info-disclosure-vuln: info-disclosure at `info-disclosure-vuln.php:8`

- **Entry point:** `wp_ajax_nopriv_fx_dump` in `fx_dump`
- **Privilege required:** unauthenticated
- **Data flow:** get_users() (WP_User objects with user_pass) -> wp_send_json_success; no capability
- **Why the guards fail:** `get_users()` returns full `WP_User` objects (the whole users row, `SELECT *`) and the response is sent unfiltered.
- **Impact:** Any visitor receives every user row, including email addresses and password hashes.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5
- **Reproduction (local test site only):** On a local test site, request the action unauthenticated and compare the JSON fields with the users table columns.
- **Suggested fix:** Check `current_user_can( 'list_users' )` and request only the needed fields: `get_users( array( 'fields' => array( 'ID', 'display_name' ) ) )`.
- **Verification status:** confirmed

### 11. sqli-vuln: sqli at `sqli-vuln.php:9`

- **Entry point:** `wp_ajax_nopriv_fx_find` in `fx_find`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['id'] -> wp_unslash -> concatenated in a numeric position of $wpdb->get_results; no prepare, no cast
- **Why the guards fail:** The value sits unquoted in the query, so quote escaping is irrelevant; there is no placeholder and no integer cast.
- **Impact:** A visitor reads any table (users, options) through UNION or boolean/time-based techniques.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5
- **Reproduction (local test site only):** On a local test site, request the action with `id` set to a value whose truth changes the number of rows returned and compare the responses.
- **Suggested fix:** Use `$wpdb->prepare( '... WHERE id = %d', $id )` with `absint()`.
- **Verification status:** confirmed

### 12. xxe-vuln: xxe at `xxe-vuln.php:7`

- **Entry point:** `wp_ajax_nopriv_fx_xml` in `fx_xml`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['x'] -> wp_unslash -> simplexml_load_string(LIBXML_NOENT) -> value returned via wp_send_json
- **Why the guards fail:** `LIBXML_NOENT` enables entity substitution; no resolver guard.
- **Impact:** A visitor submits XML whose entities are resolved, reading local files; the parsed value is returned.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5
- **Reproduction (local test site only):** On a local test site, post a document defining an internal entity and observe the substituted value in the response.
- **Suggested fix:** Parse with default flags; if flags are needed, install `libxml_set_external_entity_loader( fn() => null )` for the parse.
- **Verification status:** confirmed

### 13. rce-vuln: rce at `rce-vuln.php:9`

- **Entry point:** `wp_ajax_nopriv_fx_run` in `fx_run`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['fn'] -> call_user_func; no allow-list
- **Why the guards fail:** The callable is chosen by the request.
- **Impact:** A visitor calls any PHP function that takes no arguments (information disclosure, state changes). Limited next to the findings above.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` = 7.3
- **Reproduction (local test site only):** On a local test site, post the name of a harmless zero-argument function and observe its effect.
- **Suggested fix:** Select from a fixed map of handlers keyed by a validated string.
- **Verification status:** confirmed

### 14. open-redirect-vuln: open-redirect at `open-redirect-vuln.php:8`

- **Entry point:** `template_redirect` in `fx_go`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['next'] -> wp_redirect; no wp_validate_redirect
- **Why the guards fail:** `wp_redirect` does not validate the host.
- **Impact:** A link on the site's own domain sends the visitor to any external address.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1
- **Reproduction (local test site only):** On a local test site, open a front-end URL with `next` set to an external address and observe the Location header.
- **Suggested fix:** Use `wp_safe_redirect()` (or `wp_validate_redirect()`) and keep the `exit`.
- **Verification status:** confirmed

### 15. open-redirect-vuln: open-redirect at `open-redirect-vuln.php:12`

- **Entry point:** `template_redirect` in `fx_go`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['to'] -> header('Location: ' . value); no validation
- **Why the guards fail:** The raw header is built from the request value.
- **Impact:** Same effect through a second parameter.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1
- **Reproduction (local test site only):** On a local test site, open a front-end URL with `to` set to an external address and observe the Location header.
- **Suggested fix:** Replace with `wp_safe_redirect( $_GET['to'] )` followed by `exit`.
- **Verification status:** confirmed

### 16. xss-vuln: reflected-xss at `xss-vuln.php:7`

- **Entry point:** `fx_search` in `fx_xss_render`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['q'] -> echo in a text node of the [fx_search] shortcode, no esc_html
- **Why the guards fail:** The request value is printed without output escaping.
- **Impact:** On any page that contains the shortcode, a crafted link runs script in the visitor's browser.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1
- **Reproduction (local test site only):** On a local test site, publish a page with `[fx_search]`, open it with `q` containing a harmless unique marker string and confirm it appears unescaped in the page source.
- **Suggested fix:** Escape at output: `esc_html( wp_unslash( $_GET['q'] ) )`.
- **Verification status:** confirmed

### 17. xss-vuln: reflected-xss at `xss-vuln.php:8`

- **Entry point:** `fx_search` in `fx_xss_render`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['v'] -> printf into a double-quoted attribute, no esc_attr
- **Why the guards fail:** No `esc_attr` for the attribute context.
- **Impact:** The same page lets a crafted link break out of the `value` attribute.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1
- **Reproduction (local test site only):** On a local test site, open the page with `v` containing a double quote and observe the attribute closing in the page source.
- **Suggested fix:** Escape with `esc_attr( wp_unslash( $_GET['v'] ) )`.
- **Verification status:** confirmed

### 18. ssrf-vuln: ssrf at `ssrf-vuln.php:9`

- **Entry point:** `wp_ajax_nopriv_fx_fetch` in `fx_fetch`
- **Privilege required:** unauthenticated
- **Data flow:** $_GET['u'] -> CURLOPT_URL -> curl_exec; response not returned (blind)
- **Why the guards fail:** The URL is not validated and cURL is not restricted to http(s).
- **Impact:** A visitor makes the server send a request to any URL (all cURL protocols); the response is discarded.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N` = 5.8
- **Reproduction (local test site only):** On a local test site, post a URL of a listener you own and watch for the request.
- **Suggested fix:** Use the WordPress HTTP API with validation; set `CURLOPT_PROTOCOLS` and block private ranges if cURL must be used.
- **Verification status:** confirmed

### 19. xxe-vuln: xxe at `xxe-vuln.php:9`

- **Entry point:** `wp_ajax_nopriv_fx_xml` in `fx_xml`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['y'] -> wp_unslash -> DOMDocument::loadXML(LIBXML_NOENT | LIBXML_DTDLOAD); result not returned (blind)
- **Why the guards fail:** `LIBXML_NOENT` and `LIBXML_DTDLOAD` both enabled.
- **Impact:** A visitor makes the parser fetch external entities and DTDs (requests to chosen URLs); content is not returned.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N` = 5.8
- **Reproduction (local test site only):** On a local test site, post a document referencing an external DTD on a listener you own and watch for the request.
- **Suggested fix:** Remove the flags.
- **Verification status:** confirmed

### 20. info-disclosure-vuln: info-disclosure at `info-disclosure-vuln.php:7`

- **Entry point:** `wp_ajax_nopriv_fx_dump` in `fx_dump`
- **Privilege required:** unauthenticated
- **Data flow:** nopriv handler -> phpinfo(), no capability check
- **Why the guards fail:** A debug function is reachable without authentication.
- **Impact:** Any visitor reads PHP configuration, loaded extensions, paths and environment variables.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 5.3
- **Reproduction (local test site only):** On a local test site, request the action unauthenticated and observe the PHP information page.
- **Suggested fix:** Remove the call, or require an administrator capability.
- **Verification status:** confirmed

### 21. surface: missing-authz at `surface.php:35`

- **Entry point:** `wp_ajax_nopriv_fx_b` in `FX_Admin::ajax_b`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['b'] -> update_option('fx_b'); nopriv, no nonce, no capability
- **Why the guards fail:** No authentication, nonce or capability.
- **Impact:** A visitor changes the plugin option `fx_b`.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` = 5.3
- **Reproduction (local test site only):** On a local test site, post the action unauthenticated and read the option.
- **Suggested fix:** Register only `wp_ajax_` and add `current_user_can()`; never expose option writes to visitors.
- **Verification status:** confirmed

### 22. surface: missing-authz at `surface.php:97`

- **Entry point:** `admin_post_nopriv_fx_c` in `fx_post_c`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['c'] -> update_option('fx_c'); admin_post_nopriv, no nonce, no capability
- **Why the guards fail:** No authentication, nonce or capability.
- **Impact:** A visitor changes the plugin option `fx_c`.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` = 5.3
- **Reproduction (local test site only):** On a local test site, post to admin-post.php unauthenticated and read the option.
- **Suggested fix:** Same as above.
- **Verification status:** confirmed

### 23. authz-vuln: missing-authz at `authz-vuln.php:11`

- **Entry point:** `wp_ajax_fx_save` in `fx_save`
- **Privilege required:** subscriber
- **Data flow:** $_POST['t'] -> sanitize_text_field -> update_option('fx_title'); check_ajax_referer only, no current_user_can
- **Why the guards fail:** `check_ajax_referer` proves the request came from a page the user loaded, not that the user may change options (wp-traps 2).
- **Impact:** Any logged-in user holding the action nonce changes the plugin option `fx_title`; severity depends on what the option controls.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3
- **Reproduction (local test site only):** On a local test site, log in as a subscriber, take the nonce the plugin prints for `fx_save`, send the AJAX action with a changed `t`, and read the option back.
- **Suggested fix:** Call `current_user_can( 'manage_options' )` and stop with `wp_send_json_error( null, 403 )` before `update_option`.
- **Verification status:** confirmed

### 24. csrf-vuln: csrf at `csrf-vuln.php:11`

- **Entry point:** `admin_init` in `fx_handle_form`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['fx_opt'] -> sanitize_text_field -> update_option('fx_opt'); current_user_can present, no nonce
- **Why the guards fail:** The handler checks the capability (authority) but never a nonce (intent); `isset( $_POST )` is the only gate.
- **Impact:** A page controlled by the attacker can make a logged-in administrator's browser post the form and change `fx_opt`. `admin_init` also runs for admin-post.php and admin-ajax.php.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3
- **Reproduction (local test site only):** On a local test site, as a logged-in administrator, load a page that auto-submits a form to an admin URL with `fx_opt` set; the option changes without any nonce.
- **Suggested fix:** Print `wp_nonce_field( 'fx_form' )` in the form and call `check_admin_referer( 'fx_form' )` before `update_option`.
- **Verification status:** confirmed

### 25. surface: missing-authz at `surface.php:31`

- **Entry point:** `wp_ajax_fx_a` in `FX_Admin::ajax_a`
- **Privilege required:** contributor
- **Data flow:** nonce + current_user_can('edit_posts') (via verify()) -> update_option('fx_a')
- **Why the guards fail:** `edit_posts` is the capability of a post author, not of whoever manages plugin settings.
- **Impact:** A contributor can change `fx_a`, which would matter only if the option is administrative.
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3
- **Reproduction (local test site only):** Not reproduced: depends on what `fx_a` controls.
- **Suggested fix:** Use `manage_options` if the option is a setting.
- **Verification status:** needs-dynamic-check (Judgement call: the capability may be intended.)

### 26. object-injection-vuln: object-injection at `object-injection-vuln.php:7`

- **Entry point:** `init` in `fx_prefs`
- **Privilege required:** unauthenticated
- **Data flow:** $_COOKIE['fx_prefs'] -> base64_decode (restores quotes) -> unserialize, no allowed_classes
- **Why the guards fail:** No `allowed_classes`, no signature. `base64_decode` restores the quotes that `wp_magic_quotes` escaped, so the string is intact.
- **Impact:** Attacker-controlled data reaches `unserialize` on every request. Impact depends on a gadget class in the plugin, core, or another active plugin; the plugin defines none.
- **CVSS:** not scored (impact depends on a gadget that was not found in the audited tree)
- **Reproduction (local test site only):** Not reproduced: needs a gadget available on the site.
- **Suggested fix:** Use `json_decode()`; if serialization is unavoidable, sign it with an HMAC checked with `hash_equals()` before decoding.
- **Verification status:** needs-dynamic-check

### 27. object-injection-vuln: object-injection at `object-injection-vuln.php:8`

- **Entry point:** `init` in `fx_prefs`
- **Privilege required:** unauthenticated
- **Data flow:** $_POST['data'] -> wp_unslash (restores quotes) -> maybe_unserialize, no allowed_classes
- **Why the guards fail:** `maybe_unserialize` adds no options; the unslashed string is deserialized.
- **Impact:** Same weakness as above through a POST field; `wp_unslash` removes the slashes that would otherwise break the string.
- **CVSS:** not scored (impact depends on a gadget that was not found in the audited tree)
- **Reproduction (local test site only):** Not reproduced: needs a gadget available on the site.
- **Suggested fix:** Replace with `json_decode( wp_unslash( ... ), true )`.
- **Verification status:** needs-dynamic-check

## Variants checked

- Each confirmed sink was searched across the fixture it belongs to. `file-ops-vuln`, `rce-vuln`, `xxe-vuln`, `xss-vuln`, `sqli-vuln` and `object-injection-vuln` each contain two or three locations of the same weakness, reported separately.
- Safe twins were read for the incomplete-fix patterns of `verification.md` section 5 (guard on one handler but not a sibling; escaping on one of two outputs); none applies.

## Refuted candidates

| Where | Reason | Why |
|---|---|---|
| surface: FX_Admin::rest_open (route fx/v1/open) | `not-html-response` | public by design (`__return_true`); returns the request parameter as JSON, which REST serves as application/json. |
| surface: fx_rest_missing (route fx/v1/missing) | `trivial-effect` | no `permission_callback`, so the route is public, but it returns a constant and changes nothing. |
| surface: fx_init_reads_get (init) | `trivial-effect` | reads `$_GET['fx_export']` and returns a constant JSON value. |
| surface: {closure} on wp_ajax_fx_closure | `guard-escape-context` | nonce checked; no side effect; output is `esc_html( $_POST['m'] )`. |
| surface: FX_Admin::shortcode, fx_block_render, FX_Widget::widget | `guard-escape-context` | attributes and instance values escaped with `esc_html` at output. |
| surface: FX_Admin::post_d (admin_post_fx_d) | `guard-capability` | `check_admin_referer` and `current_user_can( 'manage_options' )` before `update_option`. |
| surface: FX_Admin::rest_guarded | `guard-capability` | `permission_callback` checks `manage_options`. |
| surface: menu pages page_main, page_sub | `no-input` | print constant markup; menu capability gates the page. |
| surface: fx_cron, fx_xmlrpc_hello | `trivial-effect` | scheduled and XML-RPC handlers that read no request data. |
| edge: Fetcher::run, wp_remote_get( $url ) (line of `QUALIFIED`) | `source-not-controlled` | registered on `wp_ajax_edge_real`; `$url` is a method parameter and WordPress passes no argument to AJAX callbacks, so the request controls nothing. |
| edge: closure in Fetcher::helper, unserialize( $x ) | `source-not-controlled` | reached only through `run( $url )`, which has no attacker-controlled argument. |
| edge: render_inline, echo $_GET (two lines) | `dead-code` | `wp_xref.py` shows no caller and no registration for `render_inline`. |
| edge: strings, comments, heredoc and HTML before `<?php` | `not-code` | contain sink-like text; the parser does not treat them as code. |

### Negative controls (safe twins)

| Fixture | Marked line | Reason | Why |
|---|---|---|---|
| xss-safe | `xss-safe.php:7` | `guard-escape-context` | escaped for a text node at output |
| xss-safe | `xss-safe.php:8` | `guard-escape-context` | escaped for a quoted attribute |
| sqli-safe | `sqli-safe.php:9` | `guard-prepared` | value passed as `%d` after `absint` |
| sqli-safe | `sqli-safe.php:10` | `no-input` | only the `$wpdb->posts` property in the query |
| authz-safe | `authz-safe.php:14` | `guard-capability` | `manage_options` and nonce before the write |
| file-ops-safe | `file-ops-safe.php:16` | `guard-allowlist` | name through `sanitize_file_name`, type through `wp_check_filetype`, capability `upload_files` |
| file-ops-safe | `file-ops-safe.php:19` | `guard-allowlist` | template chosen by strict `in_array` against a fixed list |
| file-ops-safe | `file-ops-safe.php:21` | `guard-path-containment` | `basename()` on the request value inside a fixed directory |
| object-injection-safe | `object-injection-safe.php:8` | `guard-allowlist` | `allowed_classes => false`; `json_decode` for the second field |
| ssrf-safe | `ssrf-safe.php:11` | `guard-safe-client` | `wp_safe_remote_get` after `wp_http_validate_url` |
| ssrf-safe | `ssrf-safe.php:12` | `guard-safe-client` | URL validated with `wp_http_validate_url` in the same function |
| open-redirect-safe | `open-redirect-safe.php:8` | `guard-validated-redirect` | `wp_safe_redirect` |
| open-redirect-safe | `open-redirect-safe.php:12` | `guard-validated-redirect` | `wp_validate_redirect` with `home_url()` fallback |
| privesc-safe | `privesc-safe.php:15` | `guard-capability` | `promote_users`, nonce, and a two-role allow-list |
| rce-safe | `rce-safe.php:10` | `guard-capability` | `manage_options` and `escapeshellarg` on the host; output escaped |
| rce-safe | `rce-safe.php:13` | `guard-allowlist` | strict `in_array` against two handler names |
| info-disclosure-safe | `info-disclosure-safe.php:10` | `guard-capability` | `list_users` check and only `display_name` requested |
| xxe-safe | `xxe-safe.php:7` | `guard-parser-defaults` | default flags, no entity substitution |
| xxe-safe | `xxe-safe.php:9` | `guard-parser-defaults` | default flags |
| csrf-safe | `csrf-safe.php` handler | `guard-nonce` | `check_admin_referer` before `update_option`, with `manage_options` |

## Coverage

- `wp_map.py` and `wp_sinks.py` ran on all 26 plugins with the tree-sitter backend; `skipped` lists were empty.
- Every entry point of every fixture was reviewed. `surface` was read as a whole: 16 entry points, 3 findings, the rest refuted above.
- Not covered: JavaScript, `vendor/` (none present), and runtime behaviour (no code was executed). Result: **complete for the fixtures, static only**.

## Disclosure

Synthetic code; nothing to disclose. No public posting was made.
