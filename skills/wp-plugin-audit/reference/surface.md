# WordPress attack surface: entry points and how each is reached

Open this at step 1 (Map) and whenever a `wp_map.py` entry point needs interpreting. It answers:
*who can trigger this code, and what does WordPress itself check before calling it?*

## 1. Reachability tiers

`wp_map.py` assigns every entry point one tier. Treat it as a ranking hint; confirm it in the handler.

| Tier | Who can reach it | Typical evidence |
|---|---|---|
| `unauth` | Any visitor, no account | `wp_ajax_nopriv_*`, `admin_post_nopriv_*`, REST route with `__return_true` or no `permission_callback`, a hook that runs on front-end requests and reads `$_GET`/`$_POST`/`$_COOKIE` |
| `subscriber` | Any logged-in user, including self-registered ones when registration is open | `wp_ajax_*` or `admin_post_*` without a capability check, `read` capability |
| `author+` | Contributor, author, editor | `edit_posts`, `publish_posts`, `upload_files`; shortcode attributes and block attributes written by post authors |
| `admin` | Administrator (Super Admin on multisite for network-level actions) | `manage_options`, `install_plugins`, ... |
| `system` | WordPress itself (WP-Cron, activation); not directly attacker-driven | Scheduled events. Review only if the handler reads stored, attacker-writable data |

A bug reachable only at `admin` is still reportable when it needs no extra privilege (stored XSS from
an admin setting is usually *not* accepted by triagers; see `severity.md`).

## 2. What core does and does not check for you

- **Authentication (who are you):** core resolves the logged-in user from the cookie before most hooks.
- **Authorisation (may you):** core does **not** check capabilities for `wp_ajax_*`, `admin_post_*`,
  `init`-style hooks or your own `$_POST` handlers. The plugin must call `current_user_can()`.
- **CSRF (did you mean it):** core does **not** verify a nonce for those either. The plugin must call
  `check_ajax_referer()`, `check_admin_referer()` or `wp_verify_nonce()`.
- **A nonce is not authorisation.** Any logged-in user can obtain a valid nonce for an action the
  plugin exposes to them, so a handler with a nonce but no capability check is still open to every
  account that can load the page that prints the nonce.
- **Menu capability gates the page, not the plugin.** The capability argument of `add_menu_page()` /
  `add_submenu_page()` decides who may open that admin page. It does not protect other handlers the
  same plugin registers (AJAX, `admin_post_*`, `admin_init`) that the page's form or script calls.

## 3. Entry point types

### AJAX: `wp_ajax_{action}` / `wp_ajax_nopriv_{action}`
- Reached through `admin-ajax.php`; the action name comes from the request (`$_REQUEST['action']`),
  so both GET and POST reach the handler.
- `wp_ajax_{action}` runs for logged-in users of **any** role; `wp_ajax_nopriv_{action}` runs when
  `is_user_logged_in()` is false. Registering only the first does **not** make it admin-only.
- Registering both for the same function is common; judge the handler by the weakest caller.
- Ask: capability check? nonce? Does the handler trust a user id, post id or option name from the request?

### Admin POST: `admin_post_{action}` / `admin_post_nopriv_{action}`
- Reached through `admin-post.php`, same logged-in / logged-out split as AJAX. The generic hooks
  `admin_post` and `admin_post_nopriv` fire when no action is supplied.
- Same two checks are the plugin's job. These handlers usually redirect afterwards (see open redirect).

### REST: `register_rest_route()`
- Access is decided only by `permission_callback`. Since WordPress 5.5 a route registered without one
  triggers a `_doing_it_wrong` notice, and such a route is **public**. `'__return_true'` means public on
  purpose; check that the handler is safe for anonymous input.
- A `permission_callback` that only returns `is_user_logged_in()` is the `subscriber` tier.
- Cookie-authenticated REST requests must carry a `wp_rest` nonce (`X-WP-Nonce` header or `_wpnonce`
  parameter). With no nonce core runs the request as unauthenticated (`wp_set_current_user( 0 )`); with
  an invalid one it returns 403 `rest_cookie_invalid_nonce`. This is core's CSRF protection for cookie
  sessions, not an authorisation check: `permission_callback` still decides who may call the route.
- Read `args` (`validate_callback`, `sanitize_callback`) but do not assume they were written correctly.
- `register_rest_field()` and `register_meta()`/`register_post_meta()` with `show_in_rest` add REST
  surface through `get_callback`, `update_callback` and `auth_callback`.

### Shortcodes: `add_shortcode()`
- Executed when the post is rendered, for every visitor. Attributes and enclosed content are written by
  whoever can edit the post (contributor and above), so shortcode output is an `author+` input rendered
  to `unauth` readers: the classic stored-XSS shape.
- Core applies `do_shortcode` to `the_content` with no capability gate. KSES filtering of users without
  `unfiltered_html` (contributors, authors) restricts HTML, not shortcodes in body text; it only treats
  a shortcode in an HTML attribute-name position as requiring `unfiltered_html`.
- If the handler also reads `$_GET`/`$_POST`, it is reachable by visitors directly (`wp_map.py` upgrades the tier).

### Blocks: `register_block_type()` with `render_callback`
- Same shape as shortcodes: attributes saved by editors, output rendered to visitors. Dynamic blocks
  render server-side in PHP; static blocks are HTML saved in the post and are not a PHP surface.

### Admin pages and the Settings API
- `add_menu_page()`, `add_submenu_page()`, `add_options_page()`, ...: the capability argument gates the page.
- Settings API forms post to `wp-admin/options.php`. Core requires `manage_options` there by default
  (changeable with the `option_page_capability_{$option_page}` filter) and checks the nonce
  `{$option_page}-options` (the settings group name; a legacy path checks `update-options`). Only
  `sanitize_callback` is the plugin's job.
- Plugin pages that post to themselves, or to `admin_init`, bypass all of that: the plugin must check.

### Request-time hooks: `init`, `admin_init`, `wp_loaded`, `template_redirect`, `parse_request`, `plugins_loaded`, ...
- Run on every matching request. `wp_map.py` lists such a handler only if it reads a superglobal.
- **`admin_init` also fires for `admin-ajax.php` and `admin-post.php`**, so it runs for logged-out
  visitors who call those endpoints. `is_admin()` is true there, so `is_admin()` is **not** a
  permission check (see `wp-traps.md`).
- These handlers are the usual home of "save settings if `$_POST['x']` is set" code with no nonce or capability check.

### Cron: `wp_schedule_event()` hooks
- Triggered by WordPress, not by the visitor; arguments are fixed at scheduling time. Relevant when the
  job processes attacker-written data (queued form entries, remote feeds).

### XML-RPC: `xmlrpc_methods` filter
- Methods added to `xmlrpc.php`. The caller authenticates with a username and password in the request,
  so brute force and the capability check inside the method matter; there is no cookie or nonce.

### Widgets: `register_widget()` / `WP_Widget`
- `widget()` renders for visitors (instance values written by admins); `update()` and `form()` run for
  users who can edit widgets. Output escaping in `widget()` is the usual finding.

## 4. Surface `wp_map.py` does not list: check with Grep

| Surface | What to grep | Why it matters |
|---|---|---|
| Direct file access | PHP files without `defined( 'ABSPATH' )` (or `exit`) near the top that do work at include level | A plugin file can be requested by URL, bypassing WordPress hooks and checks (CWE-425) |
| Post and meta save | `save_post`, `add_meta_box`, `edit_attachment` | Runs for author+; needs nonce **and** `current_user_can( 'edit_post', $id )`; also fires on autosave and REST |
| User profile and registration | `personal_options_update`, `edit_user_profile_update`, `user_register`, `profile_update`, `register_form` | Fields written to user meta, including roles/capabilities |
| Comments | `preprocess_comment`, `comment_post`, `pre_comment_approved` | Unauthenticated input stored and later rendered |
| Query vars and rewrites | `query_vars`, `get_query_var`, `add_rewrite_rule`, `template_include` | Visitor-controlled routes outside the hook model |
| Heartbeat | `heartbeat_received`, `heartbeat_nopriv_received` | Data processed for logged-in (and sometimes logged-out) clients |
| Uploads | `upload_mimes`, `wp_handle_upload_prefilter`, `wp_handle_upload`, `$_FILES` | File-type and path decisions |
| Auth flow | `authenticate`, `wp_login`, `login_form`, `set_auth_cookie` | Login bypass and session issues |
| Headers and cookies | `$_SERVER['HTTP_`, `$_COOKIE`, `getallheaders` | Attacker-controlled even without a form |
| Dynamic hook names | `wp_map.py` reports `"dynamic": true` for `'wp_ajax_' . $x`; resolve the values by reading the loop | The real action list is built at run time |

## 5. Reading a `wp_map.py` entry point

- `flags`: `no-cap-check` / `no-nonce` mean the pattern was not found in the handler or one call below
  it; the check may live in a hook, a base class or a helper further away. Open the code.
- `nonce_check` / `cap_check`: `handler` (found in its body), `callee` (found one call below), `null` (not found).
  A match proves a call exists, not that it runs on every path, or that the result is acted on.
- `tier_basis` says where the tier came from. `capability-check (static hint)` means a capability string
  was found in the handler; a check inside one branch does not protect the others.
- `handler-unresolved`: the callback is dynamic or lives outside the parsed files. Find it by hand.
- Review order: `unauth` without cap/nonce, then `subscriber` without cap, then `author+`, then `admin`.
  If the plugin is large, say in the coverage section how many entry points you skipped.

## 6. Five questions for every entry point

1. Who can call it (tier), and is that what the feature intends?
2. Is there a capability check that matches the action, on every path before the first side effect?
3. Is there a nonce or other anti-CSRF control, and is it verified before the side effect?
4. Which request values reach a sink, and with which sanitiser/escaper for that sink's context?
5. Does it act on an object (post, user, order) the caller is allowed to touch?
   (Capability for the *type* of action is not capability for *this object*.)

## Sources

- [AJAX in plugins (Plugin Handbook)](https://developer.wordpress.org/plugins/javascript/ajax/)
- [`wp_ajax_nopriv_{$action}`](https://developer.wordpress.org/reference/hooks/wp_ajax_nopriv_action/) and [`wp_ajax_{$action}`](https://developer.wordpress.org/reference/hooks/wp_ajax_action/)
- [`admin_post_{$action}`](https://developer.wordpress.org/reference/hooks/admin_post_action/) and [`admin_post_nopriv_{$action}`](https://developer.wordpress.org/reference/hooks/admin_post_nopriv_action/)
- [`admin_init`](https://developer.wordpress.org/reference/hooks/admin_init/) (runs on `admin-ajax.php` and `admin-post.php`)
- [`register_rest_route()`](https://developer.wordpress.org/reference/functions/register_rest_route/) and [REST API changes in WordPress 5.5](https://make.wordpress.org/core/2020/07/22/rest-api-changes-in-wordpress-5-5/) (missing `permission_callback`)
- [REST API: Adding custom endpoints](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/)
- [REST API: Authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/) (cookie authentication and `X-WP-Nonce`)
- [Settings API](https://developer.wordpress.org/plugins/settings/settings-api/), [`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/), [`wp-admin/options.php`](https://developer.wordpress.org/reference/files/wp-admin/options.php/)
- [Shortcodes (Plugin Handbook)](https://developer.wordpress.org/plugins/shortcodes/)
- [Block registration](https://developer.wordpress.org/block-editor/reference-guides/block-api/block-registration/)
- [Administration menus](https://developer.wordpress.org/plugins/administration-menus/)
- [WP-Cron (Plugin Handbook)](https://developer.wordpress.org/plugins/cron/)
- [`xmlrpc_methods`](https://developer.wordpress.org/reference/hooks/xmlrpc_methods/)
- [Heartbeat API](https://developer.wordpress.org/plugins/javascript/heartbeat-api/)
- [Nonces (APIs handbook)](https://developer.wordpress.org/apis/security/nonces/)
- [CWE-425: Direct Request ("Forced Browsing")](https://cwe.mitre.org/data/definitions/425.html)
- WordPress core source, `trunk` as read on 2026-11-01 (behaviour may change in future releases):
  [`wp-admin/options.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/options.php) (capability filter, `{$option_page}-options` nonce),
  [`wp-includes/rest-api.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/rest-api.php) (`rest_cookie_check_errors`),
  [`wp-includes/default-filters.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/default-filters.php) (`do_shortcode` on `the_content`),
  [`wp-includes/kses.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/kses.php) (`wp_kses_hair_parse`)
