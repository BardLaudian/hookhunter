# Open redirect

CWE-601. The application sends the visitor to a location taken from the request without checking that it belongs to the site. The
attacker's link carries the real site's host name, so it is used for phishing and, as a step in a chain, to leak tokens or bypass
allow-lists elsewhere (OWASP: the modified link looks trustworthy because "the server name in the modified link is identical to the
original site").

This is the class programmes accept least; read section 8 before reporting.

Open `sanitizers.md` section 6 for the redirect helpers, `wp-traps.md` 10 (`wp_redirect` does not exit), and `csrf.md` when the
redirect follows a state change.

## 1. WordPress facts that decide exploitability

Core `trunk` read on 2026-11-01.

- **`wp_redirect( $location )`** only cleans the string (`wp_sanitize_redirect`) and sends the `Location` header. It does not check the host and does
  not stop the script.
- **`wp_safe_redirect( $location )`** sanitises, then calls `wp_validate_redirect( $location, $fallback )` with the fallback `admin_url()` (filter
  `wp_safe_redirect_fallback`), then `wp_redirect()`. It does not exit either.
- **`wp_validate_redirect( $location, $fallback )`** allows only `http`/`https`; treats a leading `//` as an absolute URL (it prefixes `http:`); returns the
  fallback for a scheme, user, pass or port without a host, and for `user`, `pass` or `host` components containing `:/?#@`; then accepts the URL only if its
  parsed host is the **site's own host** or one added by the filter `allowed_redirect_hosts`. Relative paths without a host are accepted.
- **`wp_get_referer()`** returns the referer only after `wp_validate_redirect( $ref, false )`. **`wp_get_raw_referer()`** does not: it reads the request
  parameter `_wp_http_referer` first and `HTTP_REFERER` second, and core's own comment says "Do not use for redirects".
- `esc_url()` and `esc_url_raw()` check the scheme and clean characters; neither restricts the host.
- `wp_sinks.py` rules: `redirect` (`wp_redirect`), `header-location` (`header( 'Location: …' )`), `safe-redirect` (`wp_safe_redirect`, listed as guarded).
  Not covered: `Refresh:` headers, `<meta http-equiv="refresh">`, client-side `location` assignments.

## 2. Where it lives

- Parameters with names like `redirect_to`, `redirect`, `return`, `return_url`, `returnUrl`, `next`, `url`, `target`, `goto`, `back`, `dest`, and `_wp_http_referer`.
- After login, logout, registration, form submission, checkout or payment return; click-tracking, affiliate and short-link redirectors; "go to this
  external link" interstitials; SSO and OAuth callbacks.
- `wp_redirect( $_SERVER['HTTP_REFERER'] )` (the visitor's own previous page, not attacker-chosen in a link), `wp_redirect( wp_get_raw_referer() )`
  (request-controlled through `_wp_http_referer`).
- Client side: `window.location`, `location.href`, `location.assign`, `location.replace` assigned from `location.search`, `hash` or a parameter.

## 3. How to hunt

1. List redirect sinks (`wp_sinks.py --class open-redirect`) and Grep for `Refresh`, `http-equiv`, and `location` assignments in `.js` files.
2. Trace the target to its source. Is the entire URL request-controlled, or only a path appended to a fixed base?
3. Read the guard on that exact string: `wp_validate_redirect` / `wp_safe_redirect`, a fixed allow-list, or hand-written code.
4. Check what happens **after** validation: the string is changed (concatenated, `urldecode`d, `str_replace`d) before use.
5. Check the tier and whether the redirect happens without user interaction (a click on a crafted link is the usual `UI:R`).

## 4. Traps specific to this class

- **Hand-written "is local" tests.** `0 === strpos( $url, '/' )` accepts `//evil.example` and `/\evil.example`; `strpos( $url, home_url() )` accepts
  `https://evil.example/?https://site.example`; `str_ends_with( $host, 'site.example' )` accepts `evilsite.example`; comparing `parse_url()` host while the
  browser reads userinfo (`https://site.example@evil.example/`). OWASP: compare the parsed scheme, host and port with an explicit allow-list, reject
  userinfo, and "do not use raw prefix or suffix matching".
- **Validation, then modification.** `wp_validate_redirect( $u )` followed by appending a request value, decoding, or string replacement.
- **`allowed_redirect_hosts` widened from the request,** for example adding the host of `$_GET['next']` so that `wp_safe_redirect` accepts it.
- **`wp_get_raw_referer()` or `$_REQUEST['_wp_http_referer']` used as a target.** It is a request parameter.
- **Wrong sanitiser.** `esc_url_raw( $_GET['to'] )` before `wp_redirect()` is cleaning, not validation (`sanitizers.md`).
- **Fallback `false`.** `wp_validate_redirect( $u, false )` returns `false` on rejection, and `wp_redirect( false )` sends nothing and returns `false`
  (core: `if ( ! $location ) return false`). The request then continues; read what runs next, especially if the code has no `exit` (`wp-traps.md` 10).
- **No `exit` after the redirect** (`wp-traps.md` 10): not an open redirect by itself, but the privileged code after it still runs.
- **Client-side redirects.** `location.href = params.get( 'url' )` accepts `javascript:` URLs, which run script (that is XSS: `xss.md`) as well as redirect.
- **Chains.** A redirect on the same host can satisfy an OAuth or SSO `redirect_uri` allow-list, leak a token in the URL fragment or query to the final
  location, or bypass an SSRF host check that follows redirects *(reasoning; verify the other half before claiming it)*.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable
wp_redirect( $_GET['redirect_to'] );
exit;

// safe: validate on the exact string, fall back to a known page
wp_safe_redirect( wp_unslash( $_GET['redirect_to'] ?? '' ) );
exit;
```

```php
// vulnerable: "local path" test
if ( 0 === strpos( $_GET['next'], '/' ) ) { wp_redirect( $_GET['next'] ); exit; }   // //evil.example passes

// safe: build from a fixed base, reject separators that start a new authority
$path = '/' . ltrim( wp_unslash( $_GET['next'] ?? '' ), '/\\' );
wp_safe_redirect( home_url( $path ) );
exit;
```

```php
// safe: target chosen by key
$targets = array( 'account' => home_url( '/account/' ), 'cart' => home_url( '/cart/' ) );
wp_safe_redirect( $targets[ $_GET['to'] ?? '' ] ?? home_url() );
exit;
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. The target passes `wp_safe_redirect()` or `wp_validate_redirect()` on the exact string redirected to, with no change afterwards and no request-driven widening of `allowed_redirect_hosts`.
2. The target comes from a server-side allow-list selected by a key, or is a path appended to `home_url()` in a way that cannot start a new authority (`//`, `/\`, `@`).
3. The target is set by an administrator (a redirect manager, a plugin setting) and not by the visitor.
4. The response is not a redirect for the attacker's request (an error, JSON, or a redirect only after authentication that the attacker lacks).
5. The location is the visitor's own referer used for "go back" and cannot be set by a crafted link.
6. The entry point is not reachable at the claimed tier, or is dead code (`wp_xref.py`).

`confirmed` needs file:line for the entry point, the request value that becomes the location, the missing or bypassable check, and the
exact string form that gets through (for example a leading `//`).

## 7. Typical CVSS 3.1

A victim must follow the link (`UI:R`); `AV:N/AC:L/PR:N`. Computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Conventional open redirect (scope changed to the destination) | `S:C/C:L/I:L/A:N` | 6.1 |
| Redirect only, scope changed | `S:C/C:N/I:L/A:N` | 4.7 |
| Redirect only, scope unchanged | `S:U/C:N/I:L/A:N` | 4.3 |

Raise the score only with a demonstrated chain (token leakage, authentication step bypass); the redirect alone does not justify it.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01): "Open redirect is inherently out of scope." Do not submit a standalone open redirect to
that programme. Their other rules also apply: only unauthenticated or Subscriber/Customer exploitation, no `AC:H`, at least 1,000 active
installs outside mVDP.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7. Public vulnerability databases may still
list open redirects with low scores; check the one you plan to use.

Practical rule: report an open redirect only inside a chain whose second step you can show (token or credential leakage, bypass of an
authentication or SSRF check), or to the vendor as a low-severity hardening note. State the string that bypasses the check.

## Sources

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [`wp_redirect()`](https://developer.wordpress.org/reference/functions/wp_redirect/), [`wp_safe_redirect()`](https://developer.wordpress.org/reference/functions/wp_safe_redirect/), [`wp_validate_redirect()`](https://developer.wordpress.org/reference/functions/wp_validate_redirect/), [`allowed_redirect_hosts`](https://developer.wordpress.org/reference/hooks/allowed_redirect_hosts/), [`wp_get_referer()`](https://developer.wordpress.org/reference/functions/wp_get_referer/), [`wp_get_raw_referer()`](https://developer.wordpress.org/reference/functions/wp_get_raw_referer/)
- WordPress core `trunk`, read 2026-11-01: [`pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php) (`wp_redirect`, `wp_safe_redirect`, `wp_validate_redirect`), [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`wp_get_referer`, `wp_get_raw_referer`)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
