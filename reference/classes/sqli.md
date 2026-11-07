# SQL injection

CWE-89. A value that the requester controls changes the **structure** of a query instead of being data in it.
Open `sanitizers.md` section 4 for which function neutralises which SQL position, and `wp-traps.md` 13 and 14.

## 1. WordPress facts that decide exploitability

Read from core `trunk` on 2026-11-01.

- **Superglobals arrive pre-slashed.** `wp_magic_quotes()` runs `addslashes()` over every string in `$_GET`, `$_POST`,
  `$_COOKIE` and `$_SERVER` on each request and rebuilds `$_REQUEST` from the slashed GET and POST. A request value that
  reaches a **quoted** SQL string is usually already escaped, which is why most real WordPress SQL injection sits in other
  positions (below) or after `wp_unslash()` / `stripslashes()` / `stripslashes_deep()`.
- **Values that are not pre-slashed:** REST parameters (`$request->get_param()`), a JSON or raw body (`php://input`),
  `$_FILES` names and file contents, options and meta read from the database (second order), headers read with
  `getallheaders()`, and anything the code `wp_unslash()`es first.
- **`$wpdb` runs one statement per call.** Its query path calls `mysqli_query()`, which (PHP manual) does not execute
  stacked statements. Expect `UNION`, boolean, time-based (`SLEEP`) and error-based techniques, not `; DROP …`.
- **`$wpdb->prepare()`:**
  - supports `%d %f %s %i` (`%i`, identifiers, since 6.2), strips existing quotes around `%s` and re-adds them;
  - raises `_doing_it_wrong` when the query contains no `%`;
  - escapes stray `%` that is not a placeholder;
  - does **not** quote numbered or formatted placeholders (`%1$s`, `%5s`) and a `%s` that follows another `%`
    (as in `LIKE '%%%s%%'`): core's own comment calls these "unquoted strings for backward compatibility (dangerous)".
    The author has to supply the quotes.
  - swaps `%` in its returned query for a placeholder token that a `query` filter swaps back
    (`add_placeholder_escape`), so a second `prepare()` over an already-prepared string does not re-read `%` from values *(purpose inferred from the code)*.
- **`$wpdb->insert/update/replace`** format values but interpolate column names from the array keys (`wp-traps.md` 14).

## 2. Where it lives

- **Sinks:** `$wpdb->query|get_results|get_row|get_var|get_col|prepare` with a variable in the query text; raw
  `mysqli_*`, PDO or `$wpdb->dbh` calls; `dbDelta( $sql )`; `$wpdb->insert|update|delete` with request-chosen keys.
  `wp_sinks.py --class sqli` lists them (`wpdb-query`, `wpdb-prepare`, `raw-sql`) with `guards_in_args`.
- **API-level injection:** `WP_Query`, `get_posts`, `WP_User_Query`, `WP_Comment_Query`, `WP_Term_Query` receiving
  request-controlled **argument names or values** (`new WP_Query( $_GET )`, `orderby`, `order`, `meta_key`,
  `meta_query`, `tax_query`, `post__in` not cast to integers, `fields`). Core validates many keys but not all combinations;
  trace what reaches the arguments *(not verified in core for this skill; treat as a place to read)*.
- **Positions a placeholder cannot protect:** table and column names, `ORDER BY` / `GROUP BY` terms and direction,
  `LIMIT` and `OFFSET` (use `%d`), `LIKE` wildcards, `IN (…)` lists, `SELECT` field lists, function names.

## 3. How to hunt

1. List unguarded sqli sinks. For each, read the query construction: where does every `$variable` come from?
2. Classify the **position** of each request-derived part: quoted string, number, identifier, `LIKE`, `IN`, `ORDER BY`, `LIMIT`.
3. For the quoted-string position, find whether the value was **unslashed** or comes from an unslashed source (section 1).
   If it is still slashed, that position is usually not injectable; keep looking at the others.
4. For `prepare()`, read the **first argument**. A variable inside the query string is the bug; the arguments after it do not help.
   `prepare( $sql, … )` with a bare `$sql` is only as safe as whatever built `$sql`: trace it.
5. Find the entry point (`wp_xref.py`) and its tier. SQL injection reachable at `unauth` or `subscriber` is the reportable range.
6. For stored values (options, meta, rows) used in a query later, find who can write them (second-order).

## 4. Traps specific to this class

- **`wp_unslash()` before the query.** The standard hygiene step removes the slashes that were protecting a quoted value.
  `$wpdb->get_var( "… WHERE name = '" . wp_unslash( $_GET['n'] ) . "'" )` is injectable.
- **Numeric position.** `WHERE id = $id`, `LIMIT $n`, `IN ($ids)`: slashes do nothing without quotes. `esc_sql()` does nothing either
  (it escapes quote characters). Only a cast (`absint`, `(int)`, `array_map( 'absint', … )`) or `%d` works.
- **Placeholder defeated by interpolation, including a column name.** `prepare( "SELECT id, {$col} FROM {$table} WHERE lang = %s", $lang )` is injectable when `$col` comes from the request (`sanitize_text_field` keeps it): a whitelist is the only fix. `wp_sinks.py` marks these `prepare(format interpolates $col)`; comments between `prepare(` and the format string no longer hide the variable.
- **Placeholder defeated by interpolation.** `prepare( "… WHERE a = %s AND b = $col" )`, `prepare( "… LIKE '%$term%'" )`.
- **Unquoted numbered placeholder.** `prepare( 'SELECT … WHERE name = %1$s', $name )` leaves `$name` unquoted.
- **`esc_like()` is not a quote escaper, and `posts_search` clauses are strings.** It escapes only `% _ \\`. A `posts_search` / `posts_where` / `query` filter that writes `LIKE '{$like}'` into the clause
  leaves the quote alone, and magic-quoted input (`\\'`) gets its backslash doubled by `esc_like`, which frees the quote. `wp_sinks.py --sink sql-build` lists SQL built as text with a quoted variable.
- **`LIKE` done halfway.** Wildcards written into the query string; `esc_like()` missing, or called after `prepare()`.
- **`IN` lists.** `implode( ',', $_POST['ids'] )` or `implode( ',', array_map( 'esc_sql', … ) )` in an unquoted list.
- **`ORDER BY` from the request.** `ORDER BY $_GET['orderby'] $_GET['order']` with only `esc_sql` or `sanitize_text_field`; need an allow-list
  (`in_array( $o, array( 'date', 'title' ), true )`, then a fixed string for the direction).
- **Table or column names from the request.** `esc_sql` does not quote identifiers; use `%i` (6.2+) or an allow-list.
- **Sanitiser that keeps the payload.** `sanitize_text_field()`, `sanitize_email()`, `esc_html()` and `esc_attr()` do not make a string safe in SQL.
  `sanitize_key()` (only `a-z0-9_-`) is safe for an identifier or a quoted value because of the small alphabet.
- **Second order.** Query built from `get_option()`, `get_post_meta()`, `$row->field` written earlier by someone else.
- **Dynamic JSON/REST bodies.** `json_decode( file_get_contents( 'php://input' ), true )` values are not slashed.
- **Error disclosure.** A visible `$wpdb->last_error` / `show_errors()` / `WP_DEBUG` display turns an injection into error-based extraction.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: numeric position, slashes irrelevant
$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}fx WHERE id = " . $_GET['id'] );
// safe
$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}fx WHERE id = %d", $_GET['id'] ) );
```

```php
// vulnerable: unslashed value in quotes, and a prepare() with a variable in the template
$wpdb->get_var( "SELECT … WHERE name = '" . wp_unslash( $_POST['n'] ) . "'" );
$wpdb->get_var( $wpdb->prepare( "SELECT … WHERE name = '$name' AND kind = %s", $kind ) );
```

```php
// vulnerable: ORDER BY from the request; safe: allow-list
$wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY " . esc_sql( $_GET['by'] ) );
$by = in_array( $_GET['by'] ?? '', array( 'post_date', 'post_title' ), true ) ? $_GET['by'] : 'post_date';
$wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $by" );
```

```php
// safe LIKE and IN
$like = '%' . $wpdb->esc_like( $term ) . '%';
$wpdb->get_results( $wpdb->prepare( "… WHERE title LIKE %s", $like ) );
$ids  = array_map( 'absint', (array) $_POST['ids'] );
$wpdb->get_results( $wpdb->prepare( '… WHERE id IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', $ids ) );
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. Every request-derived part is a placeholder argument of `prepare()` (`%d`, `%f`, `%s`, `%i`), and the template contains no variable except `$wpdb->prefix`/table properties.
2. The part is an integer cast, an allow-listed identifier or keyword, or `sanitize_key()` output.
3. The part is in a **quoted string** and the value is still slashed: it comes straight from `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST` with no `wp_unslash`, `stripslashes`, `json_decode` or database round-trip in between.
4. `esc_like()` precedes `prepare()` for `LIKE`, and `IN` lists are built from per-item placeholders.
5. The entry point is unreachable at the claimed tier, or the handler is dead code (`wp_xref.py`).
6. The only caller is an administrator and nothing is escalated (still reportable only if it reads data the administrator cannot otherwise reach; usually weak).

`needs-dynamic-check` when the outcome depends on the database charset, a `query` filter, or a wrapper class that
rewrites queries. `confirmed` needs file:line for the entry point, the full query construction, the position of the
injected part, and the reason slashes or casts do not neutralise it.

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N/S:U`; computed with the FIRST formula. The database holds password hashes, options with API keys
and secrets, personal data and, through them, a path to administrator access; rate confidentiality from what the query can read.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, read data (UNION / blind) | `PR:N/C:H/I:N/A:N` | 7.5 |
| Unauthenticated, read and modify data shown | `PR:N/C:H/I:H/A:H` | 9.8 |
| Subscriber or customer, read data | `PR:L/C:H/I:N/A:N` | 6.5 |
| Subscriber or customer, read and modify | `PR:L/C:H/I:H/A:H` | 8.8 |
| Administrator only, read data | `PR:H/C:H/I:N/A:N` | 4.9 |

Use `I:H/A:H` only when the injection point allows writing (for example an `UPDATE`/`INSERT` fragment), not because the
database contains writable tables; stacked statements are not available through `$wpdb`.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- SQL injection is an accepted type with no extra condition, but only for unauthenticated and default Subscriber/Customer exploitation (rule 3.7); Contributor or higher is not eligible.
- Out of scope: any report with Attack Complexity High; reports on components with fewer than 1,000 active installs outside the mVDP programme; "Unrealistic pre-requisites or exploitation scenarios"; vendor self-submissions for bounty.
- "Multiple findings of the same vulnerability type must be consolidated into a single report": group several injectable parameters of one plugin.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: show the full query, the position of the controllable part, why slashes or casts do not stop it, and what
a query can return. Do not report a `prepare()` call that merely looks odd without a variable in its template.

## Sources

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) and [Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [Plugin Handbook: Securing input (SQL)](https://developer.wordpress.org/plugins/security/securing-input/) and [Data validation](https://developer.wordpress.org/apis/security/data-validation/)
- [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/), [`wpdb::esc_like()`](https://developer.wordpress.org/reference/classes/wpdb/esc_like/), [`esc_sql()`](https://developer.wordpress.org/reference/functions/esc_sql/), [`wp_magic_quotes()`](https://developer.wordpress.org/reference/functions/wp_magic_quotes/), [`add_magic_quotes()`](https://developer.wordpress.org/reference/functions/add_magic_quotes/), [`wp_unslash()`](https://developer.wordpress.org/reference/functions/wp_unslash/)
- [WordPress Coding Standards: Database queries](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/#database-queries)
- WordPress core `trunk`, read 2026-11-01: [`class-wpdb.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wpdb.php) (`prepare`, `mysqli_query`, placeholder escape), [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`add_magic_quotes`), [`load.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/load.php) (`wp_magic_quotes`)
- PHP manual: [`mysqli::query` and `mysqli::multi_query`](https://www.php.net/manual/en/mysqli.multi-query.php)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
