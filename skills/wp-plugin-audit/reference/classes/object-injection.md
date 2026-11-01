# PHP object injection (insecure deserialization)

CWE-502. An attacker-controlled string reaches `unserialize()` (or `maybe_unserialize()`), so the attacker chooses which
objects PHP creates and with which property values. The harm comes from what those objects do when PHP runs their magic
methods (`__wakeup`, `__unserialize`, `__destruct`, `__toString`, `__call`, `__get`, `__set`) or when autoloading loads a class.

A finding has three parts, and all three must be present:
1. **A source** the attacker controls reaches the deserializer.
2. **A gadget**: a class that can be autoloaded in that request and whose magic methods do something useful with its properties.
3. **A reachable tier** (`surface.md`).

Without part 2 the bug is a real weakness with unknown impact. Report it as such, with the gadget search you did.

Open `sanitizers.md` section 7 (the `allowed_classes` limits), `wp-traps.md` 13 (second-order data), and `file-ops.md` for `phar://` paths.

## 1. WordPress and PHP facts that decide exploitability

Core `trunk` read on 2026-11-01; PHP manual read on the same day.

- **`maybe_unserialize( $data )`** returns `@unserialize( trim( $data ) )` when `is_serialized( $data )` is true. It passes **no options**, so any
  loadable class may be instantiated. Calling it on request data is the same as calling `unserialize()` on it.
- **Core reads run it for you.** `get_option()` returns `maybe_unserialize()` of the stored value, and the metadata
  functions (`get_post_meta`, `get_user_meta`, …) do the same. Whatever is *stored raw* in `options` or a `*meta` table is deserialized on read.
- **Core writes protect strings.** `maybe_serialize()` serialises arrays and objects, and also **serialises a string that already looks
  serialized** ("double serialization"), so a string saved with `update_option` / `update_post_meta` comes back as the same string, not as an
  object. Stored object injection therefore needs a path that writes raw data: direct `$wpdb->insert|update|query` into those tables
  (see `sqli.md`), a database import or restore, a sync or migration tool, or a plugin table that the plugin itself reads with `unserialize`.
- **PHP manual** (`unserialize`): "Do not pass untrusted user input to unserialize() regardless of the options value of
  allowed_classes." `allowed_classes => false` makes PHP create `__PHP_Incomplete_Class` objects instead; omitting it, or `true`, accepts any
  class. `max_depth` defaults to 4096.
- **Phar:** since PHP 8.0, phar metadata "will no longer be automatically unserialized". On PHP below 8.0, file functions given a `phar://`
  path (`file_exists`, `is_dir`, `getimagesize`, `md5_file`, `file_get_contents`, …) can trigger deserialization of the archive's metadata.
- `wp_sinks.py` rule `unserialize` lists `unserialize` and `maybe_unserialize` and marks a call `guarded` only when `allowed_classes` is
  `false` or a list. Treat `guarded` here as "reduced", not "safe", in line with the PHP manual.

## 2. Where it lives

- **Sources of the serialized string:** a cookie (`$_COOKIE`), a form or AJAX field, a REST body parameter, an uploaded or imported file
  (settings import/export, demo content, backups), the body of an HTTP response from a remote service (`wp_remote_retrieve_body`, update
  and licence checks, API clients), a URL parameter that carries `base64_decode`/`gzuncompress`/`gzinflate` output, a value stored raw.
- **Sinks beyond the two named functions:** `unserialize()` inside helper classes or bundled libraries, `Serializable::unserialize`,
  `__unserialize`/`__wakeup` methods that themselves unserialize a property, other native decoders (`igbinary_unserialize`, YAML with PHP
  tags). These were not analysed for this skill; read them if the code uses them.
- **Gadgets:** classes with magic methods in the audited tree: the plugin's own classes, WordPress core, active themes and plugins, and
  `vendor/`. `wp_map.py` and `wp_sinks.py` **skip `vendor/` by default** and list it in `skipped`; for this class, Grep it for `__destruct`,
  `__wakeup`, `__toString`, `__call`, `__get`, `__set`, `__unserialize` and read what those methods do with their properties (file writes or
  deletes, `include`, `eval`, `call_user_func`, `exec`, HTTP requests, SQL).
- **Public gadget catalogue:** PHPGGC is a library of unserialize chains for popular PHP libraries and frameworks (its README lists, for
  example, Doctrine, Guzzle, Laravel, Monolog, Symfony, SwiftMailer, Slim and WordPress). Use it only to learn whether a bundled
  library and version has a known chain. Do not generate payloads or put them in reports or in the benchmark's `findings.json`.

## 3. How to hunt

1. List every `unserialize` / `maybe_unserialize` site (`wp_sinks.py --class object-injection`, then Grep `vendor/` and any file the script skipped).
2. For each, trace the argument to its source (section 2). A value built only from fixed data or from the plugin's own serialisation to a
   location the attacker cannot write is not a finding.
3. Check for integrity protection on the string: a signature or MAC computed with a secret the attacker does not have. A plain hash,
   checksum or CRC of the data is not protection.
4. Find the entry point and tier (`wp_map.py`, `wp_xref.py`).
5. Search for gadgets (section 2) and record the result: a chain you can describe (class, method, effect), a partial chain, or none found.
6. For stored values, find how the raw value gets written (section 1) and who can do it.

## 4. Traps specific to this class

- **`allowed_classes` is not a guarantee.** A list that includes a class with a useful magic method is still a chain; `false` stops
  instantiation of classes but the PHP manual still says not to pass untrusted input. Prefer `json_decode()`.
- **`maybe_unserialize()` on request data.** It looks like a WordPress helper; it is an unrestricted `unserialize`.
- **Encoding is not a defence.** `base64_decode`, `gzuncompress`, `urldecode`, and `hex2bin` in front of `unserialize` only hide the string.
- **Fake integrity checks.** `md5( $data ) === $hash` where the attacker supplies both, an HMAC with a key that is hard-coded, empty or
  predictable (`wp-traps.md` 17), or comparison with `==` (`wp-traps.md` 16).
- **"It comes from the database."** True only if nothing the attacker can reach writes raw data there. Core storage APIs neutralise
  serialized-looking strings, but `$wpdb` writes, imports and other plugins do not.
- **Remote data.** `unserialize( wp_remote_retrieve_body( $r ) )` trusts the remote server and anyone who can alter the response (plain HTTP,
  a controllable SSRF target, a compromised vendor endpoint).
- **Import features.** An "import settings" endpoint that unserializes an uploaded file is reachable by whoever may import; check the capability (`authz.md`).
- **`phar://` paths.** An attacker-controlled path in a file function plus an uploaded archive disguised as an image. Needs PHP below 8.0.
- **Objects made from JSON.** `json_decode()` is safe on its own. The risk returns when the result chooses a class (`new $data['class']`) or a
  callable (`call_user_func( $data['cb'] )`); see `rce.md`.
- **Property tampering without gadgets.** Unserialized values can still change types and control flow (an object where a string is expected). Note it, but do not rate it as code execution.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: cookie decoded and deserialized
$prefs = unserialize( base64_decode( $_COOKIE['fx_prefs'] ) );

// safe: data format that cannot instantiate objects
$prefs = json_decode( wp_unslash( $_COOKIE['fx_prefs'] ?? '' ), true );
```

```php
// vulnerable: WordPress helper, same effect
$data = maybe_unserialize( $_POST['payload'] );

// reduced, not safe, if unserialize cannot be avoided
$data = unserialize( $raw, array( 'allowed_classes' => false ) );
```

```php
// vulnerable: integrity check the attacker can satisfy
if ( md5( $blob ) === $_GET['sum'] ) { $o = unserialize( $blob ); }
// better: keyed MAC, still prefer JSON
if ( hash_equals( hash_hmac( 'sha256', $blob, FX_SECRET ), $_GET['sig'] ) ) { … }
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. The serialized string never comes from a source the attacker controls (fixed data, plugin-written file in a directory the attacker cannot write, value from `update_option` of a string).
2. A signature or MAC with a secret the attacker does not have is verified **before** deserialization, on every path.
3. The call is `json_decode`, or the data format is not PHP serialization.
4. The entry point is not reachable at the claimed tier, or is dead code (`wp_xref.py`).
5. Only an administrator can supply the string and nothing is escalated.

Not finding a gadget does **not** refute the bug: gadget availability depends on every other active plugin and theme. Mark it
`needs-dynamic-check` and record where you searched (plugin, `vendor/`, core).

`confirmed` needs file:line for the entry point and the deserializer, the source of the string, and either a described chain
(class, method, effect) or an explicit statement that no chain was found in the audited tree.

## 7. Typical CVSS 3.1

`AV:N/UI:N/S:U`; computed with the FIRST formula. The score depends on the best chain you can show.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, chain to code execution in the audited tree | `AC:L/PR:N/C:H/I:H/A:H` | 9.8 |
| Subscriber, chain to code execution | `AC:L/PR:L/C:H/I:H/A:H` | 8.8 |
| Unauthenticated, only a file-deletion chain | `AC:L/PR:N/C:N/I:H/A:H` | 9.1 |
| Unauthenticated, only a limited-impact chain (read or SSRF) | `AC:L/PR:N/C:L/I:N/A:N` | 5.3 |

With no chain, do not invent an impact: report the deserialization weakness, state that no chain was found, and rate the confidence low.

CVSS 3.1 says that when a specific configuration is required for an attack to succeed, the vulnerable component is scored **as if it were in that
configuration**. A chain that needs an optional library or another plugin is therefore still `AC:L`; use `AC:H` only when the attacker must overcome
extra conditions such as learning a secret or environment detail, or winning a race. Name the dependency in the text.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- "PHP Object Injection" is an accepted vulnerability type, for unauthenticated and default Subscriber/Customer exploitation only.
- "Any report involving Attack Complexity: High (AC:H)" and "Unrealistic pre-requisites or exploitation scenarios" are out of scope. Per CVSS a chain that needs an
  optional library is still `AC:L`, but it can be rejected as an unrealistic prerequisite, so point to a chain that exists in the audited tree or in a default install.
- Also out of scope: "Unrealistic pre-requisites or exploitation scenarios"; components with fewer than 1,000 active installs outside mVDP;
  "Incomplete, inaccurate, or unverifiable information, or invalid vulnerability claims".

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: name the source, the deserializer, the tier, and the gadget class and effect. If you found no gadget, say so; do not
upgrade the impact by assumption.

## Sources

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) and [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- PHP manual: [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) (warning, `allowed_classes`, `max_depth`), [migrating to PHP 8.0: backward incompatible changes](https://www.php.net/manual/en/migration80.incompatible.php) (Phar metadata), [magic methods](https://www.php.net/manual/en/language.oop5.magic.php)
- [`maybe_unserialize()`](https://developer.wordpress.org/reference/functions/maybe_unserialize/), [`maybe_serialize()`](https://developer.wordpress.org/reference/functions/maybe_serialize/), [`is_serialized()`](https://developer.wordpress.org/reference/functions/is_serialized/)
- WordPress core `trunk`, read 2026-11-01: [`functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`maybe_serialize`, `maybe_unserialize`), [`option.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/option.php) (`get_option`), [`meta.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/meta.php) (metadata reads and writes)
- [PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc) (README: libraries with known chains)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
