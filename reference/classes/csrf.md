# Cross-site request forgery

CWE-352. A CSRF bug exists when a request that **changes state** is accepted because the browser
attached ambient credentials (the WordPress login cookie) and nothing proves the user meant to send it.

Two things are **not** CSRF, and mislabelling them costs precision:
- A state change anyone can make **without logging in** is missing authorization (`authz.md`). CSRF needs a victim whose cookie the attacker borrows.
- Requests authenticated by something a browser does not attach on its own (an `Authorization` header, an application password, an API key in the request) cannot be forged across sites.

Open `surface.md` section 2 (what core checks), `wp-traps.md` 2-4 and 9, and `authz.md` for the
capability half of the same handlers.

## 1. Where it lives

Handlers that are reached with a cookie **and** change something:

- `wp_ajax_*`, `admin_post_*`, and `admin_init` / `init` / `template_redirect` code that reads `$_POST`, `$_GET` or `$_REQUEST`.
- Plain links that mutate state: `?action=delete&id=…`, activate, toggle, import, reset, dismiss.
- Front-end forms for logged-in users (profile, subscription, order changes) handled in PHP.
- Operations to look for are the same as in `authz.md` section 1: options, posts and meta, users and roles,
  files, plugin and theme state, the plugin's own tables, outbound mail. `wp_sinks.py --class authz,privesc`.

Already protected by core, so do not report them: the Settings API (`options.php` checks the
`{$option_page}-options` nonce) and REST requests authenticated by cookie (core runs them as logged out unless a valid `wp_rest` nonce is sent; see `surface.md`).

## 2. How to hunt

1. From `wp_map.py`, take handlers with the flag `no-nonce`. Remove the ones that are unauthenticated (`authz.md`).
2. Find the **first side effect** in the handler and the first nonce verification
   (`check_admin_referer`, `check_ajax_referer`, `wp_verify_nonce`, `wp_nonce_ays`).
3. The check counts only if it is unconditional, runs **before** the side effect, and **stops execution** on failure.
4. Check which request values drive the effect and whether `GET` reaches it (`$_REQUEST`, no method test).
5. For every `GET` state change, ask whether anything but a nonce protects it.
6. Look for a second handler that consumes the same request (an `init` hook and an `admin_post_*` handler both reading the same `$_POST` key): one may be protected and the other not.

## 3. Traps specific to this class

Numbers refer to `wp-traps.md`.

- **Nonce present, not enforced** (4): `check_ajax_referer( 'a', false, false )` whose result is ignored;
  a check inside `if ( isset( $_POST['_wpnonce'] ) )`; `wp_verify_nonce` result not tested.
- **Default action `-1`.** With no action, `check_admin_referer()` still passes a request that has no valid nonce if its
  Referer starts with the admin URL (see the `check_admin_referer` source). It also raises `_doing_it_wrong`. A single global
  action string also lets one handler's nonce unlock every other handler that uses it.
- **Guests share one nonce** (3). The Nonces handbook says core generates the same nonce for every logged-out visitor
  and that it "does not prevent guests from CSRF attacks". A nonce on a `nopriv` endpoint is not a defence.
- **Referer or Origin tests written by hand.** `strpos( $_SERVER['HTTP_REFERER'], home_url() ) !== false` matches
  `https://evil.example/?https://site.example`, and `site.example.evil.example` for a prefix test; code that runs the
  check only `if ( isset( $_SERVER['HTTP_REFERER'] ) )` skips it when the header is absent.
  *(pattern; OWASP recommends verifying Origin/Referer only as a defence-in-depth layer)*
- **"Ajax" or "JSON" treated as a defence.** `wp_doing_ajax()` and `is_admin()` are true for any request to
  `admin-ajax.php` (6, 1). A JSON body does not stop forgery: a `text/plain` form or `fetch` is a "simple request"
  that needs no preflight, and PHP can still read `php://input`. OWASP lists `text/plain` as the known gap for
  JSON APIs that do not insist on a custom header.
- **`GET` state changes.** A destructive link protected only by a capability check is forgeable with an `<img>`
  tag. The Nonces handbook uses exactly this example. `SameSite=Lax` does not stop it (OWASP: the cookie is still
  sent on top-level `GET` navigations). Core's `wp_set_auth_cookie()` passes no `SameSite` value in `trunk`
  (it sets path, domain, secure and httponly), so the browser default applies; do not argue a bug away with it.
- **`$_REQUEST`** (9) lets a form-only handler be driven by a link.
- **Action string not specific.** The handbook says to make the nonce action "as specific as possible"
  (include the object id). A generic action does not create CSRF by itself; report it only as a hardening note.
- **Custom token.** A static value, a hash of the time, or a token that is not tied to the session may still
  protect against CSRF but not against a leaked or guessable value; read how it is generated (17).

## 4. Vulnerable and safe shapes (generic)

```php
// vulnerable: capability checked, intent not
add_action( 'admin_init', function () {
	if ( current_user_can( 'manage_options' ) && isset( $_POST['fx_opt'] ) ) {
		update_option( 'fx_opt', sanitize_text_field( wp_unslash( $_POST['fx_opt'] ) ) );
	}
} );

// safe
if ( current_user_can( 'manage_options' ) && isset( $_POST['fx_opt'] ) ) {
	check_admin_referer( 'fx_save_opt' );
	update_option( 'fx_opt', sanitize_text_field( wp_unslash( $_POST['fx_opt'] ) ) );
}
```

```php
// vulnerable: destructive GET without a nonce
if ( isset( $_GET['fx_delete'] ) && current_user_can( 'manage_options' ) ) { fx_delete( absint( $_GET['fx_delete'] ) ); }
// safe: the link is built with wp_nonce_url( $url, 'fx_delete_' . $id ) and the handler calls
// check_admin_referer( 'fx_delete_' . $id ) before fx_delete()
```

## 5. Refutation checklist

Mark the candidate `refuted` if one holds, and record which:
1. A nonce check with a real action runs unconditionally before the first side effect and stops execution on failure (possibly in a callee or an earlier hook; read the code).
2. The request is not authenticated by a cookie: it needs a header, application password, signature or key that a browser would not add; or it is unauthenticated (report `authz.md` instead).
3. The request also needs a secret the attacker cannot learn (one-time token from an email, HMAC, long random id sent by the user).
4. The handler goes through the Settings API or a cookie-authenticated REST route (core protects them).
5. The effect is trivial or multi-step: dismissing a notice, UI preferences, clearing a cache, a first request that only prepares a second one.
6. The handler is dead code (`wp_xref.py` shows no registration).

Mark it `needs-dynamic-check` when protection depends on a filter, a constant, or a theme/other plugin hook.
`confirmed` needs file:line for the entry point, the first side effect, and the missing or non-enforcing check,
plus the request method that reaches it.

## 6. Typical CVSS 3.1

Victim interaction is required, so `UI:R`; the attacker needs no account (`PR:N`). `AV:N/AC:L/S:U` in all rows.
Scores computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Changes a minor setting (I:L) | `PR:N/UI:R/C:N/I:L/A:N` | 4.3 |
| Important write: options, content, users (I:H) | `PR:N/UI:R/C:N/I:H/A:N` | 6.5 |
| Limited read, write, availability (L/L/L) | `PR:N/UI:R/C:L/I:L/A:L` | 6.3 |
| Deletes data (I:H/A:H) | `PR:N/UI:R/C:N/I:H/A:H` | 8.1 |
| Leads to site takeover: new admin, plugin install, file write (H/H/H) | `PR:N/UI:R/C:H/I:H/A:H` | 8.8 |

Choose impact from the single action the forged request performs, not from what an administrator could do afterwards.

## 7. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- CSRF is accepted only when it "must result in one of the accepted write-related actions listed above" (SQL injection, XSS, arbitrary file upload/deletion/download, code execution, object injection, arbitrary settings change with significant impact, privilege escalation to contributor or higher, file inclusion with full path control).
- "CSRF must lead to one of: arbitrary file upload or deletion, privilege escalation (e.g. via an options change), RCE with a working PoC, or a settings change that leads to wider compromise."
- Out of scope: "Multi-step CSRF exploits – e.g. CSRF to an admin action that then requires the admin to perform a second action to trigger the impact"; "CSRF or access-control issues that only affect admin-notice dismissal, or IP bypass for non-critical actions"; "Re-ordering data, clearing cache, or manually triggering cronjobs / scheduled tasks"; any report with Attack Complexity High; reports on components with fewer than 1,000 active installs outside the mVDP programme.
- Logout CSRF and login CSRF are not in the accepted list.

Wordfence's CSRF rules could not be read (its programme page returned an empty response to automated fetches);
see `authz.md` section 7. Check the live page before relying on any statement about it.

Practical rule: report CSRF only when the forged request itself reaches an effect from the accepted list, name that
effect, and give the method (`GET` or `POST`) and the missing check. Do not report a missing nonce on an action whose
only effect is cosmetic.

## Sources

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) (SameSite limits, `GET`, simple requests and `text/plain`)
- [OWASP Top 10: A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Nonces (APIs handbook)](https://developer.wordpress.org/apis/security/nonces/) (why nonces, guest nonces, action specificity)
- [`check_admin_referer()`](https://developer.wordpress.org/reference/functions/check_admin_referer/), [`check_ajax_referer()`](https://developer.wordpress.org/reference/functions/check_ajax_referer/), [`wp_verify_nonce()`](https://developer.wordpress.org/reference/functions/wp_verify_nonce/), [`wp_nonce_url()`](https://developer.wordpress.org/reference/functions/wp_nonce_url/), [`wp_nonce_field()`](https://developer.wordpress.org/reference/functions/wp_nonce_field/), [`nonce_user_logged_out`](https://developer.wordpress.org/reference/hooks/nonce_user_logged_out/)
- [Plugin Handbook: Nonces](https://developer.wordpress.org/plugins/security/nonces/)
- WordPress core `trunk`, read 2026-11-01: [`pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php) (`check_admin_referer` and the `-1` Referer fallback, `wp_set_auth_cookie`), [`rest-api.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api.php) (`rest_cookie_check_errors`), [`wp-admin/options.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/options.php)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
