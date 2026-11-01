# XML external entities

CWE-611 (XML external entity reference), CWE-776 (entity expansion, "billion laughs"), and CWE-918 when the entity points at a URL
(`ssrf.md`). The XML parser resolves an entity that the document supplies, so the document can make the server read a local file, request
a URL, or spend memory and time.

Modern PHP closes most of this by default. The question is therefore not "does the plugin parse XML from a request?" but **"does it switch
entity handling on, or use a parser that resolves entities anyway?"**

Open `sanitizers.md` section 7 for the short version, `file-ops.md` and `ssrf.md` for what the entity reaches, and `xss.md` for SVG.

## 1. PHP and WordPress facts that decide exploitability

PHP manual and OWASP read on 2026-11-01; core `trunk` read on the same day.

- **Default is safe on libxml 2.9.0 and later.** The manual page for `libxml_disable_entity_loader()` says that function is deprecated as of PHP 8.0 "as external entity
  loading is disabled by default", and that "as of libxml 2.9.0 entity substitution is disabled by default". OWASP says the same for PHP.
- **Flags that re-enable the danger** (PHP manual, libxml constants):
  - `LIBXML_NOENT`: "Enabling entity substitution may facilitate XML External Entity (XXE) attacks".
  - `LIBXML_DTDLOAD` and `LIBXML_DTDATTR`: enabling them "will enable fetching of external entities"; `LIBXML_NO_XXE` can prevent that, but only with libxml 2.13.0 or later and PHP 8.4.0 or later.
  - `LIBXML_NONET` disables **network** access while loading; it does not stop reading local files.
  - `LIBXML_PARSEHUGE` raises hard-coded limits (document depth, entity recursion, text node size), which removes protection against expansion attacks.
- **OWASP's PHP guidance:** do not enable `LIBXML_NOENT`, `LIBXML_DTDLOAD` or `LIBXML_DTDVALID` for untrusted XML "without explicitly blocking external resources", and install a resolver
  callback that returns null (`libxml_set_external_entity_loader( function () { return null; } )`) for the duration of the operation; passing `null` directly "is not equivalent".
- **WordPress core's own practice:** the oEmbed XML parser calls `libxml_disable_entity_loader( true )` around the parse only when `PHP_VERSION_ID < 80000`; its comment says the call "is no longer needed
  to protect against XXE attacks" because "in libxml 2.9.0, external entity loading is disabled by default". `wp-includes/IXR/class-IXR-message.php` (XML-RPC) uses the expat parser
  (`xml_parser_create`), not libxml. Neither is a plugin finding; they show where XML enters WordPress.
- **Other parsers:** `XMLReader` (the property `XMLReader::SUBST_ENTITIES`), `XSLTProcessor` (can load documents through XSLT functions; has `setSecurityPrefs()`),
  `SoapClient` (fetches the WSDL URL), `DOMDocument::load( $url )` and `simplexml_load_file( $url )` (fetch the document itself, which is SSRF), and bundled libraries
  (PhpSpreadsheet, SAML toolkits, feed and sitemap parsers) have their own settings. They were not analysed here; read the library version and options.
- `wp_sinks.py` rule `xml-load`: `simplexml_load_string`, `simplexml_load_file` and `loadXML` calls, reported `unguarded` only when the arguments contain `LIBXML_NOENT`, `LIBXML_DTDLOAD` or
  `LIBXML_DTDATTR`, and `guarded` otherwise ("safe by default on libxml 2.9 or later"). It does **not** cover `LIBXML_DTDVALID`, `DOMDocument::load()`,
  `XMLReader`, `SimpleXMLElement` constructed with options, `xml_parse`, `XSLTProcessor` or `SoapClient`. Grep for them.

## 2. Where it lives

- Import and export: WXR and other site-content importers, product and feed importers, translation files (XLIFF), sitemap and feed readers, OPML.
- Single sign-on and payment: SAML responses and metadata, IPN or webhook receivers that accept XML bodies.
- Documents: SVG handling (sanitising, size or dimension reads), office files (docx, xlsx are zip archives of XML), PDF or e-book generators.
- Custom XML-RPC or SOAP endpoints, API clients that parse XML responses from a configurable server.
- Request value to parser: a POST body (`php://input`) or form field, an uploaded file, a URL that the plugin fetches and then parses.

## 3. How to hunt

1. List XML parse calls (`wp_sinks.py --class xxe`, then Grep for `DOMDocument`, `XMLReader`, `SimpleXMLElement`, `simplexml_`, `xml_parse`, `XSLTProcessor`, `SoapClient`).
2. For each, read the **options** (the flags passed) and any `libxml_*` calls around it. Note whether `LIBXML_NOENT`, `LIBXML_DTDLOAD`, `LIBXML_DTDATTR`, `LIBXML_DTDVALID` or `LIBXML_PARSEHUGE` appear.
3. Trace the XML string to its source. Can a request supply it (body, upload, URL content)?
4. Check the entry point and tier (`wp_map.py`, `wp_xref.py`, `authz.md`).
5. Decide what an entity could reach: local files readable by the web user (configuration, source), internal URLs, or only a denial of service.
6. State the assumed PHP and libxml versions; below libxml 2.9.0 entity loading is on by default, and the code may call `libxml_disable_entity_loader( true )`.

## 4. Traps specific to this class

- **`LIBXML_NOENT` copied from a tutorial** to "get entities replaced" in a normal document, on input that a user can influence.
- **`LIBXML_DTDLOAD | LIBXML_DTDATTR`** for "validation", or `LIBXML_DTDVALID`.
- **Slashed input breaks the document.** XML entity declarations and attribute values need quotes, and request values from `$_POST`/`$_GET`/`$_REQUEST` arrive with them backslash-escaped
  (`wp-traps.md` 19), so `simplexml_load_string( $_POST['x'], …, LIBXML_NOENT )` does not parse such documents. Exploitation needs `wp_unslash`, a decoder, or an unslashed source
  (`php://input`, an uploaded file, a REST body).
- **`LIBXML_NONET` as the only protection.** It stops network fetches, not `file://` or `php://filter` entities that read local files.
- **`libxml_disable_entity_loader( true )` as the only protection.** It is deprecated since PHP 8.0 and the manual says "relying on this function is highly discouraged". It is meaningful for code that must run on PHP below 8.0 with an old libxml; on current PHP use default flags or the resolver callback from OWASP.
- **Entity resolver callback set and unset.** A callback installed for one document and removed before parsing another.
- **Second parser path.** The primary parse is safe, but the same input also goes through `simplexml_import_dom`, XSLT, `XMLReader` with `SUBST_ENTITIES`, or a library with its own options.
- **Parsing inside the plugin's upload handler.** SVG or office documents read for size or content before sanitising.
- **Expansion attacks without external entities.** Nested internal entities or very large documents. libxml2 has hard-coded limits (depth, entity recursion, text node size); `LIBXML_PARSEHUGE` raises them, so its presence on request XML is the thing to look for.
- **XPath or XSLT injection.** Request data placed into an XPath query or a stylesheet is a different injection bug and has no reference file here; describe it as an injection finding with its own evidence.
- **Blind XXE.** No file content in the response; the entity makes an outbound request (`ssrf.md`) that carries data or confirms reachability. Needs an out-of-band channel to be shown.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: entity substitution switched on for request XML
$xml = simplexml_load_string( file_get_contents( 'php://input' ), 'SimpleXMLElement', LIBXML_NOENT );

$dom = new DOMDocument();
$dom->loadXML( $_POST['x'], LIBXML_NOENT | LIBXML_DTDLOAD );

// safe: default flags; no entity substitution, no external DTD
$xml = simplexml_load_string( $body );
$dom->loadXML( $body );

// if the flags are unavoidable, block external loading for the operation
libxml_set_external_entity_loader( function () { return null; } );
```

```php
// risky: network guard only
$xml = simplexml_load_string( $body, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET );   // local files still readable
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. The parse uses default flags (no `LIBXML_NOENT`, `LIBXML_DTDLOAD`, `LIBXML_DTDATTR`, `LIBXML_DTDVALID`), the code targets PHP 8 or libxml 2.9.0 or later, and no other parser sees the same input.
2. An external-entity resolver that returns null is active for the whole operation.
3. The XML string never comes from a source the attacker controls (plugin-generated data, a file in a directory the attacker cannot write, a trusted configuration).
4. The entry point is unreachable at the claimed tier, or is dead code (`wp_xref.py`).
5. Only an administrator can supply the XML and nothing is escalated.
6. The XML comes straight from `$_GET`/`$_POST`/`$_REQUEST` and nothing restores its quotes (`source-still-slashed`).
7. The library parser in use sets safe options (read its source or documentation for the installed version); if unknown, mark `needs-dynamic-check`.

`confirmed` needs file:line for the entry point, the parse call with its exact flags, the request value that becomes the XML, and what an entity could reach (file read, URL, denial of service).

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N`; computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, local file read (configuration, source) | `S:U/PR:N/C:H/I:N/A:N` | 7.5 |
| Unauthenticated, denial of service by entity expansion | `S:U/PR:N/C:N/I:N/A:H` | 7.5 |
| Subscriber, local file read | `S:U/PR:L/C:H/I:N/A:N` | 6.5 |
| Unauthenticated, outbound request only (blind SSRF) | `S:C/PR:N/C:L/I:N/A:N` | 5.8 |
| Administrator only, local file read | `S:U/PR:H/C:H/I:N/A:N` | 4.9 |

Rate file read only if the response or an out-of-band channel returns the content; the web user's file permissions limit what is readable.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- XXE is not one of the listed types. The closest accepted category is "Arbitrary file upload, deletion, or download – must provide full control over the path and extension", so lead with the demonstrated
  file read or request, not with "XXE".
- Out of scope: "DoS, unless it has high availability impact and is demonstrable on any environment"; "Blind SSRF – must demonstrate concrete impact"; "Any report involving Attack Complexity: High (AC:H)";
  "Unrealistic pre-requisites or exploitation scenarios".
- Only unauthenticated or default Subscriber/Customer exploitation is eligible; components with fewer than 1,000 active installs are outside the programme (except mVDP).

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: show the flag or parser setting that enables entity handling, the request path to the XML, and what is read or requested. A plugin that parses XML with default flags is not a finding.

## Sources

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) and [CWE-776: Improper Restriction of Recursive Entity References](https://cwe.mitre.org/data/definitions/776.html)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) (PHP section)
- PHP manual: [libxml constants](https://www.php.net/manual/en/libxml.constants.php), [`libxml_disable_entity_loader`](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php), [`libxml_set_external_entity_loader`](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php), [`simplexml_load_string`](https://www.php.net/manual/en/function.simplexml-load-string.php), [`DOMDocument::loadXML`](https://www.php.net/manual/en/domdocument.loadxml.php), [`XMLReader::setParserProperty`](https://www.php.net/manual/en/xmlreader.setparserproperty.php), [`XSLTProcessor::setSecurityPrefs`](https://www.php.net/manual/en/xsltprocessor.setsecurityprefs.php)
- WordPress core `trunk`, read 2026-11-01: [`class-wp-oembed.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-oembed.php) (libxml entity-loader handling), [`IXR/class-IXR-message.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/IXR/class-IXR-message.php) (expat parser)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
