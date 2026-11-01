# Which WordPress function neutralises which class, in which context

Open this at step 3 (Refute) whenever a candidate has a sanitiser or escaper between source and sink.
The question is never "is there a `sanitize_*` call?" but **"does this function neutralise this class
of bug for the context of this sink, on the value that actually reaches it?"**

Behaviour below was read from WordPress core `trunk` on 2026-11-01 unless the source line says otherwise.
Some `trunk` text describes behaviour newer than the plugin you audit; when a result hinges on it, check
the version.

## 1. Rules that decide adequacy

1. **Context decides.** HTML text, quoted attribute, URL attribute, inline JS, `<script>` block, CSS,
   SQL value, SQL identifier, shell argument, file path and HTTP host each need a different function.
2. **Sanitising on input is not escaping on output.** `sanitize_text_field()` keeps `"` and `'`, so a
   sanitised value printed inside `value="<?php echo $v ?>"` still breaks out of the attribute.
   Escape at the point of output with the function for that context.
3. **The guard must cover the value that reaches the sink, on every path.** Re-check after any later
   step that can undo it: `html_entity_decode`, `urldecode`, `base64_decode`, `stripslashes`,
   `str_replace`, concatenation with a second unescaped value, or a branch that skips the call.
4. **Type narrowing beats string cleaning.** A cast (`(int)`, `absint()`) or a strict `in_array()` against
   a fixed list is safe in every context; a string sanitiser is safe only in the contexts it targets.
5. **WordPress slashes input.** `wp_magic_quotes()` adds slashes to `$_GET`, `$_POST`, `$_COOKIE` and
   `$_SERVER` on every request, so `wp_unslash()` is needed before storing or escaping. Slashes are a
   storage convention, not a defence.

## 2. Output escaping (XSS)

| Sink context | Adequate | Not adequate |
|---|---|---|
| HTML text node | `esc_html()`, `wp_kses*()` if markup is allowed, an integer cast | `sanitize_text_field()` alone, `strip_tags()`, `addslashes()` |
| Quoted attribute value (`value="…"`) | `esc_attr()` | `esc_html()` is usually safe there (both encode quotes) but is the wrong contract; **unquoted** attributes are not covered by either |
| `href` / `src` / `action` | `esc_url()` (display) | `esc_attr()` alone: a `javascript:` URL passes through |
| Inline JS handler string (`onclick="f('…')"`) | `esc_js()`, string in **single quotes** | `esc_js()` inside `<script>` blocks or double-quoted strings |
| Data in a `<script>` block | `wp_json_encode()` / `wp_add_inline_script()` / `wp_localize_script()` | `esc_js()`, `esc_html()`; `json_encode()` with `JSON_UNESCAPED_SLASHES` can emit `</script>` |
| `<textarea>` content | `esc_textarea()` | `esc_html()` is similar but is not the intended function |
| CSS value / `style` attribute | allow-list: `sanitize_hex_color()`, `safecss_filter_attr()`, integer cast | No general `esc_css()`; `esc_attr()` does not stop `expression()`/`url()` abuse |
| Rich HTML the user may write | `wp_kses_post()` (post tags) or `wp_kses( $html, $allowed )` | Using the result inside an attribute, URL or script |

Details checked in core:

- `esc_html()` and `esc_attr()` both encode `& < > " '` (`ENT_QUOTES`) and drop invalid UTF-8; neither
  encodes whitespace, so neither is safe for unquoted attributes.
- `esc_url()` strips characters outside a URL allow-list, rejects any scheme not in
  `wp_allowed_protocols()` (`javascript` is not on the list; `data` is not either) and returns `''` for
  them, and encodes `&` and `'` for display. It does **not** restrict the host, so it is not an
  open-redirect or SSRF defence.
- `esc_url_raw()` is an alias for `sanitize_url()`: same cleaning **without** HTML-encoding. Use it for
  storage and for URLs passed to HTTP or redirect functions; never echo its result.
- `esc_js()` is documented for inline attribute JS with strings in single quotes.
- `sanitize_text_field()` checks UTF-8, strips tags, collapses whitespace and removes `%xx` sequences.
  It is an input cleaner, not an escaper. `sanitize_textarea_field()` is the same but keeps newlines.
- `wp_kses_post()` expects **unslashed** data and only guarantees HTML-body output.

## 3. Input sanitisers: what they guarantee

| Function | Guarantee | Typical misuse |
|---|---|---|
| `absint()`, `intval()`, `(int)` | A non-negative / signed integer | Applied to an array (cast gives `1`), or to one value while a sibling stays raw |
| `sanitize_key()` | Lower-case `[a-z0-9_-]` only | Used as if it quoted for SQL identifiers; it is safe for identifiers only because of the tiny alphabet |
| `sanitize_html_class()` | `[A-Za-z0-9_-]` only | Used for anything but class names |
| `sanitize_title()`, `sanitize_user()` | Slug / username alphabet | Assumed to be an escaper for HTML |
| `sanitize_email()` | Strips characters illegal in an address; may return a string that is not a valid address | Used as validation (`is_email()` validates) |
| `sanitize_file_name()` | Removes path separators and shell-special characters, replaces spaces | Core states it does not guarantee a name that is allowed to be uploaded; says nothing about the extension |
| `sanitize_url()` / `esc_url_raw()` | Allowed scheme and cleaned characters | Treated as host validation |
| `wp_strip_all_tags()` | Removes tags (and script/style contents) | Used as an escaper; quotes survive |
| `wp_kses*()` | Output limited to the allow-list | Allow-list too wide for the sink, or output reused in an attribute |
| `in_array( $v, $list, true )` | Value is one of a fixed list | Loose comparison (`true` omitted): `"0e1" == "0"`-style juggling, `"1abc" == 1` on old PHP |

## 4. SQL (`$wpdb`)

| Situation | Adequate | Not adequate |
|---|---|---|
| Values | `$wpdb->prepare()` with `%d`, `%f`, `%s`, placeholders **unquoted** | Variable interpolated into the query string before `prepare()`; `prepare()` with no placeholders |
| Identifiers (table, column, `ORDER BY`) | `%i` (WordPress 6.2+), or a strict allow-list (`in_array`, `match`) | `%s` (it quotes, producing a string literal, not an identifier), `esc_sql()` |
| `LIKE` | `$wpdb->esc_like( $input )` **then** `prepare()` with the wildcards added to the argument | `esc_like()` after `prepare()`; wildcards written into the query string |
| `IN (…)` | One placeholder per item, built from `count()` | `implode( ',', $_POST['ids'] )` inside the query |
| Quick numeric value | `absint()` / `(int)` | `esc_sql()` on an unquoted number: no quotes to escape, so it is injectable |

Details checked in core:

- `prepare()` documents `%d %f %s %i`, says placeholders must be left unquoted and that every placeholder
  needs an argument; literal `%` must be `%%`; wildcard `%` in `LIKE` must arrive via an argument.
- `esc_like()` is documented as the first half of `LIKE` escaping and "not SQL safe" on its own: call it
  before `prepare()` or `esc_sql()`, and "reversing the order is very bad for security".
- `esc_sql()` is `$wpdb->_escape()`: it escapes string content for use **inside quotes**.
- Safe-looking forms to still read: `$wpdb->prepare( $sql, $id )` where `$sql` was built earlier. The
  safety is whatever built `$sql`.

## 5. Files and paths

| Need | Adequate | Not adequate |
|---|---|---|
| Reject `../` | `validate_file()` returns non-zero | Treating it as an absolute-path guard (see below) |
| Only a file name | `wp_basename()` / `basename()` on that value, joined to a fixed directory | `basename()` on the whole path when the directory is also user-controlled |
| Stay inside a base directory | `realpath()` of the joined path, then check it starts with `realpath( $base ) . DIRECTORY_SEPARATOR` | A prefix check without the trailing separator (`/uploads` matches `/uploads-evil`); checking before resolving symlinks |
| Fixed set of files | `in_array( $name, $allowed, true )` | Blacklisting `..` or extensions |
| Allowed type | `wp_check_filetype_and_ext()` (extension against the allowed list, plus the detected image type, and the detected MIME type when PHP's `fileinfo` is loaded) | `wp_check_filetype()` (extension only), the browser-supplied `$_FILES['type']` |

Details checked in core:

- `validate_file()` rejects `../` sequences, Windows drive and UNC paths, and (when a list is passed)
  names not in the list. Its own documentation says absolute POSIX paths such as `/etc/passwd` are
  **not** rejected and that callers must join the validated value onto a trusted base directory.
- `sanitize_file_name()` is not a security check for uploads (see section 3).

## 6. Redirects and outgoing requests

| Need | Adequate | Not adequate |
|---|---|---|
| Redirect to a user-supplied URL | `wp_safe_redirect()`, or `wp_validate_redirect( $url, $fallback )` before `wp_redirect()` | `wp_redirect( $_GET['to'] )`, `esc_url()`, `esc_url_raw()`, a check that the string "starts with `/`" (protocol-relative `//host`) |
| Fetch a user-supplied URL | `wp_safe_remote_get/post/request/head()` (sets `reject_unsafe_urls`) | `wp_remote_get()` + `esc_url_raw()` (cleans characters, validates nothing) |
| Validate a URL yourself | `wp_http_validate_url()` | A regex on the host name; blacklisting `localhost` and `127.0.0.1` only |

Details checked in core:

- `wp_validate_redirect()` accepts only `http`/`https`, handles `//host`, and allows the site's own host
  plus whatever the `allowed_redirect_hosts` filter adds; otherwise it returns the fallback.
- `wp_http_validate_url()` requires `http`/`https`, rejects userinfo and unusual host characters,
  resolves the host and rejects private, loopback, link-local (169.254.0.0/16, cloud metadata), CGNAT,
  multicast and reserved ranges, and by default only allows ports 80, 443 and 8080. Filters
  (`http_request_host_is_external`, `http_allowed_safe_ports`) can loosen this.
- `wp_remote_*` passes `reject_unsafe_urls` as `false` by default (filter `http_request_reject_unsafe_urls`).
  `wp_safe_remote_*` sets it to `true`, which validates the URL **and every redirect location**.
- Limit (reasoning, not documented): validation resolves the host once and the request resolves it again,
  so DNS rebinding can still be a concern; do not call a `wp_safe_remote_*` call "fully safe", call it "guarded".

## 7. Commands, callables, deserialisation, XML

| Need | Adequate | Not adequate |
|---|---|---|
| Value as a shell argument | `escapeshellarg()` on **each** argument, command fixed in code | `escapeshellcmd()` on a whole line, `addslashes()`, a blacklist of `;` and `|` |
| User-chosen function or method | strict `in_array()` against a fixed map, then call from the map | `is_callable()`, `function_exists()`, `method_exists()` |
| `unserialize()` | Avoid; `json_decode()`. If unavoidable, `[ 'allowed_classes' => false ]` | `maybe_unserialize()` on request data; `allowed_classes` listing a class with a magic method that does work |
| XML | Parse without `LIBXML_NOENT` / `LIBXML_DTDLOAD` (default flags) | Setting those flags, or relying on `libxml_disable_entity_loader()` (deprecated since PHP 8.0) |

These come from the PHP manual and OWASP, not WordPress core; see the class files for context.

## 8. Not sanitisers (do not count them)

Nonces (`wp_verify_nonce`) and capability checks (`current_user_can`) protect against CSRF and
unauthorised callers, not against malicious values; see `classes/csrf.md` and `classes/authz.md`.
Also not sanitisers: `trim`, `strtolower`, `stripslashes`/`wp_unslash`, `urlencode` (right for a URL
component only), `json_encode` (right for JSON output, not for HTML), `htmlspecialchars` with default
flags on PHP < 8.1 (single quotes stay unescaped), `mysqli_real_escape_string` outside quotes.

## Sources

- [Escaping data (APIs handbook)](https://developer.wordpress.org/apis/security/escaping/)
- [Sanitizing data](https://developer.wordpress.org/apis/security/sanitizing/) and [Data validation](https://developer.wordpress.org/apis/security/data-validation/)
- [Plugin Handbook: Securing output](https://developer.wordpress.org/plugins/security/securing-output/) and [Securing input](https://developer.wordpress.org/plugins/security/securing-input/)
- [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/), [`wpdb::esc_like()`](https://developer.wordpress.org/reference/classes/wpdb/esc_like/), [`esc_sql()`](https://developer.wordpress.org/reference/functions/esc_sql/)
- [`validate_file()`](https://developer.wordpress.org/reference/functions/validate_file/), [`sanitize_file_name()`](https://developer.wordpress.org/reference/functions/sanitize_file_name/), [`wp_check_filetype_and_ext()`](https://developer.wordpress.org/reference/functions/wp_check_filetype_and_ext/)
- [`wp_validate_redirect()`](https://developer.wordpress.org/reference/functions/wp_validate_redirect/), [`wp_safe_redirect()`](https://developer.wordpress.org/reference/functions/wp_safe_redirect/), [`wp_http_validate_url()`](https://developer.wordpress.org/reference/functions/wp_http_validate_url/), [`wp_safe_remote_get()`](https://developer.wordpress.org/reference/functions/wp_safe_remote_get/)
- WordPress core `trunk`, read 2026-11-01:
  [`formatting.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/formatting.php) (`esc_*`, `sanitize_*`),
  [`class-wpdb.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wpdb.php),
  [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`validate_file`, `wp_allowed_protocols`),
  [`pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php) (`wp_validate_redirect`, `wp_safe_redirect`),
  [`http.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/http.php) and [`class-wp-http.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-http.php),
  [`load.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/load.php) (`wp_magic_quotes`)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- PHP manual: [`escapeshellarg`](https://www.php.net/manual/en/function.escapeshellarg.php), [`unserialize`](https://www.php.net/manual/en/function.unserialize.php), [`htmlspecialchars`](https://www.php.net/manual/en/function.htmlspecialchars.php), [`json_encode`](https://www.php.net/manual/en/function.json-encode.php), [`libxml_disable_entity_loader`](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php)
