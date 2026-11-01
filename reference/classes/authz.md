# Missing and incorrect authorization

CWE-862 (no check), CWE-863 (check present but wrong), CWE-639 (object chosen by a request key, an
IDOR). Prefer 862/863; MITRE marks CWE-285 as discouraged for mapping, though the scorer still counts it
as the same family. Privilege escalation to a higher role has its own file (`privesc.md`); data read by
the wrong person is also in `info-disclosure.md`.

Open `surface.md` for who reaches an entry point, `wp-traps.md` 1-8 for the recurring mistakes, and
`sanitizers.md` is not needed here: this class is about *who*, not *what value*.

## 1. Where it lives

An authorization bug is a **handler that does something privileged without checking that the caller may**.
Find handlers first, then sinks.

- **Handlers:** every entry point from `wp_map.py` with `no-cap-check`, ranked `unauth` then `subscriber`.
  Add `author+` handlers that act on objects they do not own.
- **Operations to look for** (`wp_sinks.py --class authz,privesc`):
  - options and settings: `update_option`, `add_option`, `delete_option`, `update_site_option`
  - content: `wp_insert_post`, `wp_update_post`, `wp_delete_post`, `wp_delete_attachment`, `update_post_meta`, `delete_post_meta`
  - accounts: `wp_delete_user`, `wp_update_user`, `update_user_meta`, `wp_set_password`
  - plugin and theme state: `activate_plugin`, `deactivate_plugins`, `switch_theme`, `delete_plugins`
  - the plugin's own tables: `$wpdb->insert|update|delete|replace|query` with a write statement
  - side effects with reach: `wp_mail` with a request-chosen recipient, file writes, scheduled events
  - reads of data the plugin treats as private: orders, form entries, exports, logs, API keys
- **Object lookups** by request key: `get_post( $_REQUEST[...] )`, `get_userdata(...)`, `wc_get_order(...)`,
  `$wpdb->get_row( ... WHERE id = ...)`, then returned or modified.

## 2. How to hunt

1. List `unauth` and `subscriber` entry points that reach one of the operations above (`wp_xref.py` on the handler).
2. Read the handler from the top. Write down the **first side effect** and every `current_user_can`,
   `user_can`, `is_user_logged_in`, `check_*_referer`, `wp_verify_nonce`, `is_admin`, and early `return`/`exit`/`wp_die`.
3. A check counts only if it is **before** the first side effect, **on every path**, and **stops execution** on failure.
4. Name the capability the action needs (changing site options: `manage_options`; editing a post:
   `edit_post` for that id; managing users: the `*_users` capabilities) and compare it with the one that is checked.
5. If the action touches an object, check ownership or the object-level capability (trap 5, section 3 below).
6. Walk the callers: a check in `__construct`, in a base class or in a hook that runs earlier
   (`plugins_loaded`, `init`) can protect handlers that look bare. `wp_map.py` reports one level of this as `callee`.

## 3. Traps specific to this class

Cross-references use the numbering in `wp-traps.md`.

- **Check after the effect, or in one branch** (4, 10). A `wp_redirect()` without `exit`, a `wp_send_json_error()`
  (this one ends the request) versus a bare `echo` or `return` inside a nested function that the caller ignores.
- **Wrong capability.** `read` (any account), `edit_posts` (contributor) or `upload_files` guarding an administrative
  action; `is_user_logged_in()` as the only gate; a capability read from the request.
- **Wrong subject.** `user_can( $_POST['user_id'], 'manage_options' )` tests the *target*, not the caller; use `current_user_can()`.
- **REST `permission_callback` that cannot say no.** Core denies a request only if the callback returns a `WP_Error`,
  `false` or `null` (`class-wp-rest-server.php`). Any other value allows it, so a callback that returns `0`,
  `''`, `[]`, `get_current_user_id()` (0 for visitors) or `wp_get_current_user()` (an object, always truthy)
  lets everyone in. The check also runs only when the key is non-empty. Look for callbacks that return something
  other than a strict boolean.
- **Method confusion.** `'methods' => 'GET'` with a permissive callback, but the handler also writes; or a route
  registered with all methods and a callback written for reads.
- **Object-level (IDOR).** The capability matches the *type* of action (`edit_posts`) but the id comes from the
  request and is never tied to the caller (author id, order owner, share token). Core treats `edit_post`
  without an id as denied, which is why plugins that skip the id often fall back to the weaker `edit_posts`.
- **Guest flows.** Order, ticket, booking or download lookups by a guessable id plus a public field (email)
  are access control by obscurity. A long random token is a real secret; a sequential id is not.
- **Public hook, private effect.** A function registered on both `wp_ajax_` and `wp_ajax_nopriv_` that tests
  only `current_user_can( 'x' )` and then continues for visitors.
- **Plugin-level role UI.** A permissions screen that lets administrators grant a capability to a lower role
  moves the boundary but is the administrator's configuration (see "What triagers reject").
- **Direct file access.** Files without an `ABSPATH` guard that perform an action when requested by URL skip every WordPress check.

## 4. Vulnerable and safe shapes (generic)

```php
// vulnerable: nonce but no capability; any logged-in user reaches it
add_action( 'wp_ajax_fx_save', function () {
	check_ajax_referer( 'fx_save' );
	update_option( 'fx_api_key', sanitize_text_field( $_POST['k'] ) );
} );

// safe: capability first, then nonce, then the effect
add_action( 'wp_ajax_fx_save', function () {
	if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( null, 403 ); }
	check_ajax_referer( 'fx_save' );
	update_option( 'fx_api_key', sanitize_text_field( wp_unslash( $_POST['k'] ) ) );
} );
```

```php
// vulnerable (IDOR): type-level capability, object from the request
if ( current_user_can( 'edit_posts' ) ) { wp_delete_post( (int) $_POST['id'] ); }

// safe: object-level capability
$id = absint( $_POST['id'] );
if ( current_user_can( 'delete_post', $id ) ) { wp_delete_post( $id ); }
```

```php
// vulnerable: callback cannot deny
'permission_callback' => function () { return get_current_user_id(); }
// safe
'permission_callback' => function () { return current_user_can( 'manage_options' ); }
```

## 5. Refutation checklist

Mark the candidate `refuted` if one of these holds, and record which:
1. A capability check that fits the action runs before the first side effect on every path and stops execution (`exit`, `die`, `return`, `wp_send_json_*`, `wp_die`), possibly in a callee, base class or earlier hook (`wp_map.py` flags are hints; read the code).
2. The entry point is not reachable at the claimed tier (hook type, registered only for `wp_ajax_` while the claim says visitor, route with a real `permission_callback`).
3. The behaviour is the feature: a public submission form, a public read endpoint for public data, an intended guest checkout.
4. The effect is trivial: dismissing a notice, re-ordering, clearing a cache, triggering a scheduled task, changing a user's own UI preference. (Patchstack lists several of these as out of scope.)
5. The object id is a long random value the attacker cannot learn.
6. Dead code: the function is never registered or the file is never loaded (`wp_xref.py` returns no registration).
7. The only path needs a privilege the claim ignores (administrator on a default single site is the usual case).

Mark it `needs-dynamic-check` when the answer depends on a filter, a constant or a role set up at run time.
Mark it `confirmed` only with file:line for the entry point, the missing or wrong check and the first side effect.

## 6. Typical CVSS 3.1

Base scores computed with the FIRST formula (`AV:N/AC:L/UI:N/S:U` in all rows):

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, change any option or write data (I:H) | `PR:N/C:N/I:H/A:N` | 7.5 |
| Unauthenticated, read secrets or all private data (C:H) | `PR:N/C:H/I:N/A:N` | 7.5 |
| Unauthenticated, limited read and write (C:L/I:L) | `PR:N/C:L/I:L/A:N` | 6.5 |
| Unauthenticated, one Low impact (C:L) | `PR:N/C:L/I:N/A:N` | 5.3 |
| Subscriber, important write (I:H) | `PR:L/C:N/I:H/A:N` | 6.5 |
| Subscriber, limited read and write (C:L/I:L) | `PR:L/C:L/I:L/A:N` | 5.4 |
| Subscriber, C:L/I:L/A:L | `PR:L/C:L/I:L/A:L` | 6.3 |
| Subscriber, full takeover (C:H/I:H/A:H) | `PR:L/C:H/I:H/A:H` | 8.8 |
| Unauthenticated, full takeover | `PR:N/C:H/I:H/A:H` | 9.8 |
| Author-level, important write | `PR:L/C:N/I:H/A:N` | 6.5 |
| Administrator, important write | `PR:H/C:N/I:H/A:N` | 4.9 |

Pick impact from what the missing check actually allows, not from the worst thing the plugin can do.
`severity.md` holds the full guidance.

## 7. What triagers reject

From Patchstack's Alliance rules (read in full, 2026-11-01):
- Only vulnerabilities exploitable by unauthenticated users or default Subscriber/Customer roles are eligible;
  roles with more capabilities than Subscriber, and custom roles an admin must grant, are not.
- Broken access control must reach "significant or sensitive objects" (API keys or secrets with demonstrated
  impact, password hashes, backup or SQL files); IDOR "must lead to significant security impact"; examples not
  accepted include "PII leakage alone" and "interactions with attachments, tickets, events, orders, or appointments".
- Out of scope: "Subscriber-or-higher vulns leading to minor/insignificant data leakage, minor data modification,
  or minor availability impact (CVSS 5.4 with two CIA at L, 6.3 with three at L)"; "Unauthenticated vulns with
  only one CIA at Low impact (CVSS 5.3)"; any report with Attack Complexity High; "Re-ordering data, clearing cache,
  or manually triggering cronjobs / scheduled tasks"; "CSRF or access-control issues that only affect admin-notice
  dismissal, or IP bypass for non-critical actions"; actions that need "a non-guessable or unrealistic identifier";
  "Vulnerabilities where the plugin's own Permissions UI lets administrators grant a capability to a lower-priv
  role"; "Authenticated shortcode issues without sensitive data disclosure"; reports on components with fewer than
  1,000 active installs (outside the mVDP programme).
- Arbitrary settings change must involve "WordPress options or settings with significant impact on the site".

Wordfence's programme (search result summary only; the page returned an empty response to automated fetches, so
the exact wording is **not verified**): vulnerabilities requiring `PR:H`, which it says includes Administrator,
Editor, Shop Manager and any role with `unfiltered_html`, are out of scope for the bounty, and out-of-scope
reports may still receive a CVE. Check the live page before relying on this.

Practical rule for reports: state the lowest privilege that works, the concrete data or setting affected and
why it is significant, and do not submit actions from the "trivial" list in section 5.4.

## Sources

- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html), [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html), [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html), [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP Top 10: A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) and [IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [Plugin Handbook: Checking user capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/) and [Roles and capabilities](https://developer.wordpress.org/plugins/users/roles-and-capabilities/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/), [`user_can()`](https://developer.wordpress.org/reference/functions/user_can/), [`map_meta_cap()`](https://developer.wordpress.org/reference/functions/map_meta_cap/)
- [REST API: Adding custom endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/) and [REST API changes in WordPress 5.5](https://make.wordpress.org/core/2020/07/22/rest-api-changes-in-wordpress-5-5/)
- WordPress core `trunk`, read 2026-11-01: [`class-wp-rest-server.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api/class-wp-rest-server.php) (permission result handling), [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`wp_send_json` ends the request), [`capabilities.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/capabilities.php)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [Wordfence Intelligence bug bounty programme](https://www.wordfence.com/threat-intel/bug-bounty-program/) (not readable by automated fetch; see section 7)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
