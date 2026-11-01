# Privilege escalation and account takeover

CWE-269 (improper privilege management), CWE-266 (incorrect privilege assignment), CWE-915 (mass assignment of
attributes such as `role`), CWE-288 / CWE-287 (authentication bypass: becoming a user without proving it),
CWE-640 and CWE-620 (weak password recovery, unverified password change).

Scope: the **result** is a higher role or another person's account. A missing capability check on an ordinary
action is `authz.md`; a nonce problem is `csrf.md`. This file is for the handful of operations whose output is
identity or privilege.

Open `wp-traps.md` 7 and 8 (`nopriv` dispatch, roles live in user meta), `surface.md` for the tier, and
`authz.md` section 3 for the capability traps this class builds on.

## 1. How WordPress stores and changes privilege (read from core `trunk`)

- A user's roles and capabilities are user meta under `{prefix}capabilities`. `WP_User::set_role()` and
  `add_cap()` write it with `update_user_meta()`.
- Role **definitions** (which capabilities a role has) are the option `{prefix}user_roles`.
- `wp_insert_user()` takes `role` from its input array, or `default_role` if there is none, and calls `set_role()`.
  Its body contains **no capability check**. `wp_update_user()` and `wp_create_user()` go through it. The caller must authorise.
- `wp_set_auth_cookie( $user_id )` and `wp_set_current_user( $id )` act on whatever id they are given; the latter's
  own documentation warns that it "opens the ability to edit and perform actions on users who aren't signed in".
- `users_can_register` is the site setting that allows open registration; `default_role` is the role new accounts get.
- Core's own admin handler `edit_user()` is the reference for a safe role change. It requires **all** of: the
  `promote_users` capability, `promote_user` for that user id, a role present in `get_editable_roles()`, and a
  guard against removing your own ability to promote. Compare any plugin that changes roles with it.
- Password reset in core: `get_password_reset_key()` makes a 20-character random key (`wp_generate_password`),
  stores only a hash with a timestamp, and `check_password_reset_key()` validates it.

## 2. Operations to hunt (`wp_sinks.py --class privesc`, then Grep for the rest)

`wp_sinks.py` currently lists `wp_update_user`, `wp_insert_user`, `update_user_meta`, `add_user_meta`,
`wp_set_current_user`, `wp_set_auth_cookie`, `set_role`, `add_role`, `add_cap`, `remove_cap` and `update_option`.
Grep for these as well; the script does not cover them:

| Operation | Why it matters |
|---|---|
| `wp_create_user`, `wp_insert_user` (fed by a form) | Registration paths; `role` taken from the request |
| `wp_set_password`, `reset_password`, `wp_update_user( ['user_pass' => …] )` | Changing someone's password |
| `wp_update_user( ['user_email' => …] )` | Email change followed by a password reset is account takeover *(pattern)* |
| `wp_signon`, `wp_set_auth_cookie`, `wp_set_current_user` | Logging in or acting as a user |
| `add_user_to_blog`, `grant_super_admin`, `switch_to_blog( $_… )` | Multisite roles and super-admin |
| `update_option( 'default_role' \| 'users_can_register' \| '{prefix}user_roles', … )` | Changes who new users are, or what roles can do |
| `update_option( $_POST[…], … )`, `update_user_meta( $id, $_POST[…], … )` | Request-chosen option or meta **name** reaches the above |
| `foreach ( $_POST as $k => $v ) update_user_meta(…)`, `wp_update_user( $_POST )`, `wp_insert_user( $_POST )` | Mass assignment |
| Any `meta_key` or option name containing `capabilities`, `user_level` or `user_roles` | Privilege storage |

## 3. How to hunt

1. For each operation above, `wp_xref.py` the enclosing function and find the entry points that reach it.
2. Trace where the **role**, the **user id**, the **meta/option name** and the **email or password** come from. Each one
   that originates in the request needs its own control.
3. Apply core's four-part test to a role change: caller may promote users, caller may promote *this* user, the role is
   in an allow-list that excludes roles above the caller, and the target is not an unintended account.
4. For login-like features (social login, magic link, "log in as", SSO, REST token endpoints, OTP), find the line that
   calls `wp_set_auth_cookie` / `wp_set_current_user` / `wp_signon` and read what has been **proved** immediately before it.
5. For recovery flows, read how the secret is created (trap 17 in `wp-traps.md`), how long it lives, whether it is
   returned to the requester, and how it is compared (`==` against a string: trap 16).

## 4. Traps specific to this class

- **Role from the request, no allow-list.** `'role' => $_POST['role']`, a hidden `role` field, a role id in a REST body.
  A fixed allow-list that happens to include `administrator` is the same bug.
- **Allow-list correct, user id not checked.** The role is limited but `$_POST['user_id']` selects whose role changes
  (horizontal and vertical at once); or the check is `promote_users` without `promote_user` on that id.
- **Mass assignment.** Saving every submitted field as user meta or as `wp_update_user` input lets the request name
  `{prefix}capabilities`, `role`, `user_pass` or `user_email`. Look for loops over `$_POST`/`$_REQUEST` and arrays passed straight through.
- **Profile hooks.** `personal_options_update`, `edit_user_profile_update` and `profile_update` callbacks that read
  `$_POST` and write meta without a field allow-list; `show_in_rest` user meta registered without `auth_callback`.
- **Registration bypass.** Custom signup that ignores `users_can_register`, or accepts a role. Creating a low-privilege
  account on a site that allows registration is not a finding; creating one when it is off, or with a higher role, is.
- **Impersonation without proof.** The code logs in the user whose email, id or username is in the request, trusting
  a flag, a cookie or an unsigned token. A provider token must be verified server-side (signature, audience, expiry)
  before the identity is used.
- **Weak recovery secrets.** `md5( time() )`, `uniqid()`, short numeric codes with no attempt limit, tokens returned in the
  HTTP response, tokens compared with `==`, reset links built from `$_SERVER['HTTP_HOST']` *(pattern: the host is client-controlled)*.
- **Unverified credential change.** Core's profile handler `edit_user()` has no current-password check for a new email or
  password (the session is the proof), so a plugin that does the same for the logged-in user is following core. Only flag
  plugin endpoints that accept a **user id** or are reachable without a session.
- **Privileged option writes.** An arbitrary option update (name or value from the request) is privilege escalation in
  practice, because `default_role`, `users_can_register` and the roles option are options. Report it as `authz`/`privesc`
  with the specific option as the chain.
- **Escalation inside a role.** A user with `edit_users` or a custom role creating or editing administrators when core's
  own `edit_user`/`promote_user` checks are bypassed by calling `wp_insert_user` directly.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: role and target from the request, no capability
add_action( 'wp_ajax_nopriv_fx_register', function () {
	wp_insert_user( array( 'user_login' => $_POST['u'], 'user_pass' => $_POST['p'], 'role' => $_POST['role'] ) );
} );

// safe: fixed role, registration setting honoured
if ( ! get_option( 'users_can_register' ) ) { wp_send_json_error( null, 403 ); }
wp_insert_user( array( 'user_login' => sanitize_user( $_POST['u'] ), 'user_pass' => $_POST['p'], 'role' => 'subscriber' ) );
```

```php
// vulnerable: mass assignment
foreach ( $_POST['fields'] as $key => $value ) { update_user_meta( get_current_user_id(), $key, $value ); }
// safe: explicit field list
foreach ( array( 'nickname', 'description' ) as $key ) {
	if ( isset( $_POST[ $key ] ) ) { update_user_meta( $uid, $key, sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) ); }
}
```

```php
// safe role change, same shape as core's edit_user()
$uid = absint( $_POST['user_id'] );
if ( current_user_can( 'promote_users' ) && current_user_can( 'promote_user', $uid ) ) {
	$role = sanitize_key( $_POST['role'] );
	if ( isset( get_editable_roles()[ $role ] ) ) { ( new WP_User( $uid ) )->set_role( $role ); }
}
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. Role changes pass `promote_users`, `promote_user` for the id, and a role from `get_editable_roles()` or a fixed list that cannot exceed the caller (before the write, on every path, stopping on failure).
2. Role, user id, meta key and option name all come from server state, not the request.
3. The operation only touches the caller's own account and a fixed list of harmless fields (display name, bio).
4. Login or recovery proves a secret the attacker cannot know: core's reset key, a verified provider signature, a signed single-use token with expiry.
5. The resulting role is Subscriber, or open registration is enabled by the site owner and the plugin just follows it.
6. The caller must already be an administrator (nothing is escalated).
7. Dead code, or gated by an option the attacker cannot change.

`needs-dynamic-check` when the outcome depends on a filter such as `editable_roles`, `additional_capabilities_display`,
`allowed_redirect_hosts`, a theme, or another plugin's hook. `confirmed` needs file:line for the entry point, the
request value that carries the role / id / name / secret, and the write or login call.

## 7. Typical CVSS 3.1

`AV:N/AC:L/S:U` in all rows; computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated becomes administrator, or any account incl. admin | `PR:N/UI:N/C:H/I:H/A:H` | 9.8 |
| Unauthenticated takeover of non-admin accounts only | `PR:N/UI:N/C:H/I:H/A:N` | 9.1 |
| Subscriber becomes administrator | `PR:L/UI:N/C:H/I:H/A:H` | 8.8 |
| Takeover that needs the victim to click (reset link, forged request) | `PR:N/UI:R/C:H/I:H/A:H` | 8.8 |
| Unauthenticated becomes contributor/author, limited impact | `PR:N/UI:N/C:L/I:L/A:N` | 6.5 |
| Subscriber becomes contributor/author, limited impact | `PR:L/UI:N/C:L/I:L/A:N` | 5.4 |

Rate administrator-level escalation as C:H/I:H/A:H: an administrator can install plugins and edit files.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- Only vulnerabilities exploitable by unauthenticated users or default Subscriber/Customer roles are eligible; an escalation that needs Contributor or higher is not.
- Privilege escalation is accepted when it "must lead to contributor access or higher".
- Out of scope: "Account creation or registration with a low-privilege role (below Contributor)"; "Arbitrary user registration unless it leads to a Contributor-or-higher account"; "2FA bypass – typically Attack Complexity: High since you need the password to exploit"; "Lack of brute-force protection / rate-limiting (e.g. login)"; any report with Attack Complexity High; "Vulnerabilities where the plugin's own Permissions UI lets administrators grant a capability to a lower-priv role".
- "Arbitrary settings change" must involve "WordPress options or settings with significant impact on the site"; an option write is strongest when you can name the option (`default_role`, `users_can_register`, the roles option).
- Components with fewer than 1,000 active installs are outside the programme (except under mVDP).

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: show the exact request values that choose the role / user / name, and state the privilege gained and the
privilege needed. A reset or login bypass must name the secret that is missing or guessable.

## Sources

- [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-266](https://cwe.mitre.org/data/definitions/266.html), [CWE-915](https://cwe.mitre.org/data/definitions/915.html), [CWE-288](https://cwe.mitre.org/data/definitions/288.html), [CWE-640](https://cwe.mitre.org/data/definitions/640.html), [CWE-620](https://cwe.mitre.org/data/definitions/620.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) and [Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [Plugin Handbook: Roles and capabilities](https://developer.wordpress.org/plugins/users/roles-and-capabilities/) and [Checking user capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/)
- [`wp_insert_user()`](https://developer.wordpress.org/reference/functions/wp_insert_user/), [`wp_update_user()`](https://developer.wordpress.org/reference/functions/wp_update_user/), [`wp_create_user()`](https://developer.wordpress.org/reference/functions/wp_create_user/), [`WP_User::set_role()`](https://developer.wordpress.org/reference/classes/wp_user/set_role/), [`get_editable_roles()`](https://developer.wordpress.org/reference/functions/get_editable_roles/)
- [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/), [`wp_set_current_user()`](https://developer.wordpress.org/reference/functions/wp_set_current_user/), [`wp_set_password()`](https://developer.wordpress.org/reference/functions/wp_set_password/), [`get_password_reset_key()`](https://developer.wordpress.org/reference/functions/get_password_reset_key/), [`add_user_to_blog()`](https://developer.wordpress.org/reference/functions/add_user_to_blog/), [`grant_super_admin()`](https://developer.wordpress.org/reference/functions/grant_super_admin/)
- WordPress core `trunk`, read 2026-11-01: [`wp-includes/user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/user.php) (`wp_insert_user`, `wp_update_user`, reset keys), [`wp-admin/includes/user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/includes/user.php) (`edit_user`), [`class-wp-user.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-user.php), [`class-wp-roles.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-roles.php), [`pluggable.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/pluggable.php), [`ms-functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/ms-functions.php), [`wp-login.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-login.php)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
