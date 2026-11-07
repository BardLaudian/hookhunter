# Worked rows

Four rows from synthetic plugins, worked the way step 2 of `SKILL.md` asks: read, judge, mark. Two are dismissals that look reasonable and are wrong;
they are the shapes behind most measured misses. Code is invented for this file; no real plugin is quoted.

## Row 1: a finding

```
{"id": "U3", "tier": "unauth", "function": "Acme_Cart::restore", "at": "includes/class-cart.php:40-58",
 "entries": ["ajax:wp_ajax_nopriv_acme_restore @ includes/class-cart.php:12 (unauth)"],
 "sinks": ["47 unserialize object-injection origin=request"]}
```

Read `includes/class-cart.php` offset=40 limit=19:

```php
44  $raw = isset( $_COOKIE['acme_cart'] ) ? wp_unslash( $_COOKIE['acme_cart'] ) : '';
47  $cart = unserialize( base64_decode( $raw ) );
```

Registration line 12 is `add_action( 'wp_ajax_nopriv_acme_restore', ... )`: anonymous. `wp_unslash` and `base64_decode` change encoding, not content.
Candidate: **unauth** reaches **wp_ajax_nopriv_acme_restore (class-cart.php:12)**, whose **cookie acme_cart** flows to **unserialize (class-cart.php:47)**
without **`allowed_classes => false` or JSON**, giving **PHP object injection**.

```
hh_ledger.py mark U3 finding --class=object-injection --lines=44-47
```

Then the variant step: Grep `unserialize(` and `acme_cart` across the plugin.

## Row 2: wrong dismissal, "admin only"

```
{"id": "U9", "tier": "admin", "function": "Acme_Admin::handle_export", "at": "admin/class-admin.php:210-260",
 "entries": ["ajax:wp_ajax_acme_export @ admin/class-admin.php:30 (admin, unconfirmed)"]}
```

The function opens with:

```php
212  if ( 'settings' === $_POST['tab'] && ! current_user_can( 'manage_options' ) ) { wp_die(); }
...
230  if ( 'csv' === $_POST['tab'] ) { $this->stream_csv( $_POST['list'] ); }
```

Wrong: `mark U9 clean --reason=cap-check --evidence=admin/class-admin.php:212`. The ledger accepts the line (it holds `current_user_can`),
but the check guards one branch only. Line 230 runs for any logged-in user (`wp_ajax_` without `nopriv` is subscriber, and the map said *unconfirmed*).
Right: read every branch that reaches a sink; this one is `finding --class=missing-authz` (or `info-disclosure` if the CSV holds personal data).
The evidence rule checks that the guard *exists*; whether it covers *this* path is your job.

## Row 3: wrong dismissal, "sanitised"

```
{"id": "U14", "tier": "unauth", "function": "acme_search_sql", "at": "includes/search.php:80-96",
 "sinks": ["91 sql-build sqli (unquoted variable $parts[0] in a numeric SQL position)"],
 "entries": ["no mapped entry reaches it: find who calls it"]}
```

```php
84  $range = filter_var( $_GET['range'], FILTER_SANITIZE_NUMBER_INT );
88  $parts = explode( ',', $range );
91  return " AND price BETWEEN {$parts[0]} AND {$parts[1]} ";
```

Tempting: `clean --reason=sanitized --evidence=includes/search.php:84`. But `FILTER_SANITIZE_NUMBER_INT` keeps `+` and `-`, so `1-1` style arithmetic and
comment sequences built from those characters survive, and here the comma that `explode` splits on was never checked either. A sanitiser is evidence
only when the characters it lets through are harmless *in this sink's context*: an unquoted SQL number needs `(int)`/`absint`, nothing less.
Grep the caller (`acme_search_sql(`): if the string reaches `$wpdb->get_results` without `prepare`, `finding --class=sqli`; if you cannot find
the caller in budget, `needs-check --class=sqli --gap=other`. Never `clean`.

## Row 4: a clean row, correctly

```
{"id": "U21", "tier": "subscriber", "function": "Acme_Rest::update_item", "at": "includes/class-rest.php:120-150",
 "entries": ["rest:/acme/v1/item @ includes/class-rest.php:20 (subscriber, unconfirmed)"],
 "sinks": ["138 option-write authz"]}
```

Line 22 registers `'permission_callback' => array( $this, 'can_edit' )`, and `can_edit` at line 60 is `return current_user_can( 'manage_options' );` with no other branch.

```
hh_ledger.py mark U21 clean --reason=cap-check --evidence=includes/class-rest.php:22,includes/class-rest.php:60
```

Two lines: where the check is attached, and what it checks. If `can_edit` had an early `return true` for some request parameter, it would not be clean.
