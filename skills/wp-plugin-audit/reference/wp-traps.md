# WordPress-specific traps

Open this at step 2 (Hunt) when a handler *looks* protected, and at step 3 (Refute) before accepting a
guard. Each trap is a check that reads as safe but is not, or a core behaviour that surprises authors.
Format: **Looks like** / **Why it fails** / **Grep** / **Safe pattern**.

Core behaviour below was read from WordPress `trunk` on 2026-11-01 unless marked *(pattern)*, which means
a logic consequence of the code rather than something core documents, or *(PHP)*, which comes from the PHP manual.

## A. Identity and authorisation

### 1. `is_admin()` as a permission check
- **Looks like:** `if ( ! is_admin() ) return;` at the top of a handler.
- **Why it fails:** `is_admin()` only says the request is for the admin interface, and core documents that
  it does not check the user. `admin-ajax.php` and `admin-post.php` both define `WP_ADMIN` and fire
  `admin_init`, so it is `true` for logged-out visitors calling them.
- **Grep:** `is_admin\(` near `$_POST`, `$_GET`, `update_option`, `wp_ajax_`.
- **Safe:** `current_user_can( $specific_capability )`.

### 2. A nonce used as authorisation
- **Looks like:** `check_ajax_referer( 'save' )` and nothing else, on a `wp_ajax_*` handler.
- **Why it fails:** a nonce proves the request came from a page the *same session* loaded, not that the
  user may perform the action. Any logged-in user who can load the page that prints the nonce can use it.
- **Safe:** nonce **and** capability (see `surface.md` section 2).

### 3. Nonces on `nopriv` endpoints
- **Looks like:** `wp_ajax_nopriv_*` handler with `check_ajax_referer()`; the nonce is printed with `wp_localize_script`.
- **Why it fails:** for logged-out visitors the nonce is built from user id `0` and an empty session
  token, so every visitor receives the same value for a given action and time window, and it is given
  to anyone who loads the page. It is no CSRF protection and no authentication.
- The Nonces handbook says the same: core generates one nonce for all guests (user id `0`), so "it does not
  prevent guests from CSRF attacks".
- **Safe:** treat the endpoint as public: validate input, rate-limit, do nothing privileged.

### 4. Nonce check that does not enforce
- **Looks like / why it fails:**
  - `check_ajax_referer( 'a', false, false )`: the third argument (`$stop`) is `false`, so on failure the
    function returns `false` instead of dying. If the return value is ignored, the check does nothing.
  - `wp_verify_nonce( $n )` without an action uses `-1`, shared by every handler that does the same.
  - *(pattern)* `if ( isset( $_POST['_wpnonce'] ) ) { verify… }` followed by the action: omit the field and the check is skipped.
  - `wp_verify_nonce` returns `1`, `2` or `false`; comparing with `=== true` is always false.
- **Grep:** `check_ajax_referer\(.*false`, `wp_verify_nonce\(` whose result is not in an `if`/`||`/`&&` that stops execution.
- **Safe:** `check_ajax_referer( 'specific_action' )` / `check_admin_referer( 'specific_action' )` unconditionally, before any side effect.

### 5. Capability for the type, not for the object
- **Looks like:** `current_user_can( 'edit_posts' )` then `wp_update_post( $_POST['id'] … )` or
  `delete_post_meta( $_POST['id'] … )`.
- **Why it fails:** `edit_posts` says the user can write posts, not that they can edit *this* post
  (another author's, a page, an order). Per-object checks use the meta capability with the id.
  Core also refuses `edit_post` without an id: `map_meta_cap` adds `do_not_allow` and a `_doing_it_wrong` notice.
- **Grep:** `current_user_can\( *['"](edit|delete|read)_posts?['"] *\)` in handlers that take an id.
- **Safe:** `current_user_can( 'edit_post', $id )`; same for `delete_post`, `read_post`, `edit_user`, `delete_user`, `promote_user`.

### 6. Admin means different things on single-site and multisite
- `is_super_admin()` on a single site is true for any user with `delete_users` (an administrator); on
  multisite only for the network's super admins.
- `unfiltered_html` is not granted to administrators on multisite, and `DISALLOW_UNFILTERED_HTML` removes
  it from everyone, even on single sites. So "an administrator can inject script" is a real privilege
  boundary on multisite and hardened sites and not one on a default single site.
- Disclosure programs do not scope by site type. Patchstack's Alliance rules accept only unauthenticated
  and Subscriber/Customer-level reports and list "Contributor-level (or higher) stored XSS" as out of
  scope; Wordfence reportedly treats `PR:H` reports, including Administrator and `unfiltered_html`
  roles, as outside its bounty (not verified at source; see `classes/authz.md`, "What triagers reject").
  WPScan's submission page says admins and editors may use JavaScript in posts, pages and comments, so the `unfiltered_html` capability "should be disallowed when testing for Stored XSS using such roles".
  A multisite-only exception is not documented in anything read for this skill.

### 7. `nopriv` versus logged-in dispatch
- `admin-ajax.php` dispatches by login state: logged-in users reach only `wp_ajax_{action}`; visitors only
  `wp_ajax_nopriv_{action}`. A `nopriv`-only action returns HTTP 400 for logged-in users.
- Consequence: authors often register one function for both hooks. The function then has to be safe for
  a visitor; a capability check inside it must return early, not just skip a branch.

### 8. Roles live in user meta
- A user's roles and capabilities are stored in user meta under `{table prefix}capabilities`.
- Any `update_user_meta()` / `add_user_meta()` whose **key** comes from the request, any `wp_update_user()` /
  `wp_insert_user()` fed a request array (so `role` can be supplied), and any option write whose **name**
  comes from the request (for example `default_role`, `users_can_register`) is privilege escalation.
- **Grep:** `update_user_meta\(.*\$_`, `wp_(update|insert)_user\(\s*\$_`, `update_option\(\s*\$_`.
- **Safe:** fixed keys, field-by-field copying, role from a short allow-list, `promote_users` check.

## B. Request handling

### 9. `$_REQUEST` is GET + POST
- Core rebuilds `$_REQUEST` as `$_GET` merged with `$_POST` (cookies excluded). `admin-ajax.php` reads its
  `action` from it, and `check_ajax_referer()` reads `_ajax_nonce` / `_wpnonce` from it.
- Consequence: a handler that reads `$_REQUEST` can be driven by a link or an `<img>` (GET), so a missing
  nonce becomes CSRF without a form. Prefer the specific superglobal.

### 10. `wp_redirect()` does not stop the script
- Core documents that `wp_redirect()` does not exit and "should almost always be followed by `exit;`".
- **Looks like:** `if ( ! current_user_can( … ) ) { wp_redirect( home_url() ); }` followed by the privileged code.
- **Grep:** `wp_(safe_)?redirect\(` whose next statement is not `exit`/`die`/`return`.

### 11. JSON echoed without a content type
- `wp_send_json*()` sends `Content-Type: application/json` and ends the request.
- **Looks like:** `echo json_encode( $data ); wp_die();` in an AJAX handler.
- **Why it fails** *(PHP)*: PHP's default content type is `text/html`, so request-controlled strings inside
  the JSON are interpreted as HTML (reflected XSS).
- **Grep:** `echo\s+(wp_)?json_encode`.

### 12. `add_query_arg()` and `$_SERVER['REQUEST_URI']` are not escaped
- Core documents that the return value of `add_query_arg()` is not escaped and must be passed through `esc_url()` when output.
- The same holds for `$_SERVER['REQUEST_URI']`, `PHP_SELF` and `QUERY_STRING` echoed into `action="…"` or `href="…"`.
- **Grep:** `add_query_arg\(` or `REQUEST_URI` inside `echo`/`printf` without `esc_url`.

### 13. Second-order data is not trusted data
- **Looks like:** `echo get_option( 'x' )`, `$wpdb->get_var( "… $meta" )` with a value read from the database.
- **Why it fails:** the value may have been written by a lower-privileged or anonymous request (a `nopriv`
  form, a comment, a REST field, a shortcode attribute). Escape and prepare on use, whatever the source.
- `wp_sinks.py` treats `get_option()`, `get_post_meta()`, `get_user_meta()`, `get_transient()` as user-influenced.

## C. Data layer

### 14. `$wpdb->insert/update/replace` escape values, not column names
- In core, `_insert_replace_helper()` builds the column list from `array_keys( $data )` inside backticks.
  Values go through formats; names do not.
- **Looks like:** `$wpdb->insert( $table, $_POST )`, `$wpdb->update( $table, $_POST['fields'], … )`.
- **Why it matters:** the request chooses which columns are written (mass assignment of `role`, `status`,
  `price`, `owner_id`). Injection through the key itself was not verified; do not report it without a trace.
- **Safe:** build `$data` from fixed keys.

### 15. Settings saved without `sanitize_callback`
- `register_setting()` without `sanitize_callback` stores the raw value. The Settings API gives
  capability and nonce for free (see `surface.md`), so the finding is usually the *value*, not access.
  Admin-only stored XSS is often rejected by triagers; see `severity.md`.

## D. PHP and WordPress runtime behaviour

### 16. Loose comparison and string equality for secrets
- *(PHP)* `==` between strings that look numeric compares them as numbers (`"0e12" == "0e34"`), so
  `md5( $x ) == $hash` and `$token == $_GET['t']` can pass for the wrong value. `in_array( $x, $list )`
  without `true` and `switch` use the same rule.
- Core itself compares nonces with `hash_equals()`. Look for `==`, `!=`, `strcmp`, `in_array(` without `true`
  on tokens, keys and hashes.

### 17. Predictable tokens
- *(PHP)* `rand()`, `mt_rand()`, `uniqid()`, `md5( time() )`, `microtime()` are not secure sources for
  reset keys, download tokens or API keys. Use `wp_generate_password()` (for human-facing strings) or
  `random_bytes()`/`bin2hex()`.
- **Grep:** `(rand|mt_rand|uniqid|time|microtime)\(` inside code that creates a token, key or password.

### 18. Client-controlled "IP address"
- `HTTP_X_FORWARDED_FOR`, `HTTP_CLIENT_IP` and similar headers are set by the client unless a trusted proxy
  rewrites them. Rate limits, IP allow-lists and "local only" checks that read them are bypassable.
- **Grep:** `HTTP_X_FORWARDED_FOR|HTTP_CLIENT_IP|HTTP_X_REAL_IP`. `REMOTE_ADDR` is the peer address.

### 19. Request data arrives slashed, so quote-bearing payloads break
- `wp_magic_quotes()` runs `addslashes()` over the strings in `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER` and rebuilds `$_REQUEST` (trap 9; `sqli.md`).
- *(consequence of that code)* Payloads that need quote characters arrive with each `"` or `'` backslash-escaped: serialized PHP (`O:3:"Foo":…`), XML with attributes or entity
  declarations, JSON, PHP code strings, SQL string literals. Passed straight from those superglobals to `unserialize`, an XML parser, `json_decode` or a quoted SQL
  string they fail to parse or stay inside their quotes. Payloads without quotes are unaffected: path traversal, shell metacharacters, numeric SQL, URLs, HTML without quoted attributes.
- Exploitation of a quote-dependent class therefore needs a step that restores the quotes: `wp_unslash`, `stripslashes`, `stripslashes_deep`, a decoder (`base64_decode`, `urldecode`,
  `hex2bin`), or an unslashed source (`php://input`, REST parameters, `$_FILES`, database values).
- **Check:** before confirming `sqli` (quoted position), `object-injection`, `xxe` or `rce` by code string, point at the line that restores the quotes. If there is none the candidate is
  `refuted` (`source-still-slashed`); if a filter or wrapper might unslash, `needs-dynamic-check`.

## Refutation shortcuts

Before dismissing a candidate because of a guard, ask which of these applies:
1. Is the guard `is_admin()`, `is_user_logged_in()` or a nonce alone? None authorises (1, 2, 3).
2. Does the guard's failure branch stop execution (`exit`, `die`, `return`, `wp_send_json_error`, `wp_die`) (4, 10)?
3. Is the capability the right one, and tied to the object when one is involved (5)?
4. Does the code run for logged-out visitors, and is it the same function as the `nopriv` hook (7)?
5. Is the site type relevant: multisite, `DISALLOW_UNFILTERED_HTML` (6)?
6. Does a quote-dependent payload arrive slashed with nothing to restore the quotes (19)?

## Sources

- [`is_admin()`](https://developer.wordpress.org/reference/functions/is_admin/), [`is_super_admin()`](https://developer.wordpress.org/reference/functions/is_super_admin/), [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/), [`map_meta_cap()`](https://developer.wordpress.org/reference/functions/map_meta_cap/)
- [Nonces (APIs handbook)](https://developer.wordpress.org/apis/security/nonces/), [`wp_verify_nonce()`](https://developer.wordpress.org/reference/functions/wp_verify_nonce/), [`check_ajax_referer()`](https://developer.wordpress.org/reference/functions/check_ajax_referer/), [`wp_create_nonce()`](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
- [Common vulnerabilities (APIs handbook)](https://developer.wordpress.org/apis/security/common-vulnerabilities/) and [Checking user capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/)
- [Roles and capabilities (Plugin Handbook)](https://developer.wordpress.org/plugins/users/roles-and-capabilities/)
- [`wp_redirect()`](https://developer.wordpress.org/reference/functions/wp_redirect/), [`wp_send_json()`](https://developer.wordpress.org/reference/functions/wp_send_json/), [`add_query_arg()`](https://developer.wordpress.org/reference/functions/add_query_arg/)
- [`wpdb::insert()`](https://developer.wordpress.org/reference/classes/wpdb/insert/), [`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/)
- WordPress core `trunk`, read 2026-11-01:
  [`wp-admin/admin-ajax.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-ajax.php) and [`admin-post.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/admin-post.php) (`WP_ADMIN`, `admin_init`, dispatch),
  [`wp-includes/load.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/load.php) (`is_admin`, `wp_magic_quotes`),
  [`wp-includes/capabilities.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/capabilities.php) (`is_super_admin`, `unfiltered_html`, `edit_post`),
  [`wp-includes/pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php) (nonces, `wp_redirect`),
  [`wp-includes/user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/user.php) (`wp_get_session_token`),
  [`wp-includes/class-wp-user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-user.php) (capabilities key),
  [`wp-includes/class-wpdb.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wpdb.php) (`_insert_replace_helper`),
  [`wp-includes/functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`add_query_arg`, `wp_send_json`)
- PHP manual: [comparison operators and type juggling](https://www.php.net/manual/en/language.operators.comparison.php), [`hash_equals`](https://www.php.net/manual/en/function.hash-equals.php), [`uniqid`](https://www.php.net/manual/en/function.uniqid.php), [`mt_rand`](https://www.php.net/manual/en/function.mt-rand.php)
- [MDN: X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) and [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
