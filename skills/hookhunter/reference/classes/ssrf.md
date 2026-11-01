# Server-side request forgery

CWE-918. The plugin makes an HTTP (or other protocol) request to a location that the requester chooses, so the
**server** reaches places the requester cannot: loopback services, private networks, cloud metadata endpoints.

Open `sanitizers.md` section 6 (what each WordPress URL helper checks), `file-ops.md` for `file_get_contents`/`copy`
on URLs, and `surface.md` for who can reach the handler. The same code that fetches a URL is often the upload half
of `file-ops.md` (`download_url`, `media_sideload_image`).

## 1. WordPress and PHP facts that decide exploitability

Core `trunk` read on 2026-11-01.

- **`wp_remote_get/post/request/head()`** go through `WP_Http::request()`. They always restrict the scheme to `http`, `https` and `ssl`
  (`wp_kses_bad_protocol`), follow up to **5 redirects** by default (0 for `HEAD`), and by default do **not** call
  `wp_http_validate_url()`: `reject_unsafe_urls` is `false` unless the `http_request_reject_unsafe_urls` filter changes it.
- **`wp_safe_remote_*()`** set `reject_unsafe_urls` to `true`: the URL goes through `wp_http_validate_url()` and **each redirect location** is
  validated too (`WP_Http::validate_redirects`).
- **`wp_http_validate_url()`** requires `http`/`https`; rejects URLs with userinfo (`user:pass@`) and hosts containing `:#?[]` (so IPv6 literals); resolves
  the host with `gethostbyname()` and rejects loopback (127/8), `10/8`, `172.16/12`, `192.168/16`, link-local `169.254/16` ("cloud metadata"),
  CGNAT, multicast and reserved ranges; allows only ports 80, 443 and 8080. The filters `http_request_host_is_external` and
  `http_allowed_safe_ports` can loosen it. Hosts that do not resolve to an IPv4 address are rejected.
- **Site-level blocking:** `WP_HTTP_BLOCK_EXTERNAL` limits requests to localhost and the site itself, with `WP_ACCESSIBLE_HOSTS` as an
  allow-list. Even then, requests to **localhost** remain possible.
- **Outside `WP_Http`** nothing restricts anything: `file_get_contents()`, `fopen()`, `copy()`, `get_headers()`, `getimagesize()`,
  `simplexml_load_file()`, `DOMDocument::load()` accept URLs when `allow_url_fopen` is on (default on, PHP manual) and PHP wrappers such as
  `file://`, `ftp://`, `php://`, `data://`; cURL (`curl_init`, `curl_setopt( CURLOPT_URL )`) accepts every protocol compiled in unless
  `CURLOPT_PROTOCOLS` limits it, and follows redirects only if `CURLOPT_FOLLOWLOCATION` is set. `fsockopen()` takes a host and a port.
- `esc_url_raw()` and `sanitize_url()` only clean characters and check the scheme; they say nothing about the host.
- `wp_sinks.py` rules: `http-request` (`wp_remote_*`, `get_headers`, `fsockopen`), `safe-http-request` (`wp_safe_remote_*`, marked guarded),
  `curl-url` (`curl_setopt` with `CURLOPT_URL`) and `file-read` (`file_get_contents`). `url-fetch` (`curl_init( $url )`, `download_url`, `media_sideload_image`, `fetch_feed`, `wp_oembed_get`, `wp_remote_fopen`, first argument) and `soap-client` (`new SoapClient( $wsdl )`) cover the
  helpers added later. `wp_sinks.py` does **not** cover `WP_oEmbed` internals or the `simplexml_*`/`DOMDocument` loaders given a URL: Grep for them.

## 2. Where it lives

- **Features that fetch a URL:** link preview / "fetch metadata" endpoints, image or file import "from URL", avatar or thumbnail proxies,
  RSS/feed readers, oEmbed discovery, webhook and "test connection" buttons, license, update and API clients with a configurable server,
  PDF/HTML-to-image renderers that load remote resources, URL shorteners and link checkers, "download this file to the server".
- **Request value to URL:** a full URL parameter, a host or domain parameter concatenated into a URL, a URL read from `get_option` that a lower
  role can write, a URL from user meta or a custom post field, a redirect target.
- **Tier:** an `unauth` endpoint is the strongest; an administrator-only webhook setting is weak (`wp-traps.md` 6).

## 3. How to hunt

1. List the request-fetch sinks (`wp_sinks.py --class ssrf`, then Grep for the helpers above).
2. For each, build the URL back to its source. What parts does the requester control: whole URL, host, path, query, only a path under a fixed host?
3. Read the guard against the primitive (section 4): scheme, host, resolved IP, port, redirects.
4. Decide what the attacker gets: the **response** (read SSRF), only a side effect (blind SSRF: request sent, response discarded or only a status), or
   a file saved on the server (`file-ops.md`).
5. Check the tier and the capability required (`authz.md`).

## 4. Traps specific to this class

- **`wp_remote_get( $url )` with no `wp_http_validate_url`.** The default does not block private addresses; the scheme limit is not an SSRF defence.
- **`wp_safe_remote_*` called on a different URL than the one validated,** or after the plugin follows redirects itself.
- **Validation done on a string, request made on another.** The check parses one thing, the request resolves another (`parse_url` versus the HTTP
  client; userinfo `http://allowed.example@evil.example/`; `http://evil.example#@allowed.example/`; backslashes `http://evil.example\@allowed.example/`).
  Core rejects userinfo and unusual host characters, hand-written checks often do not.
- **Substring or suffix host tests.** `strpos( $url, 'allowed.example' )`, `strstr`, `preg_match( '/allowed\.example/' )`,
  `str_ends_with( $host, 'allowed.example' )` (matches `evilallowed.example`). Compare the **parsed host** for equality with an allow-list.
- **Block-lists.** `localhost`/`127.0.0.1` only. Misses `0.0.0.0`, `[::1]`, `127.1`, decimal or hex IPv4 forms, private ranges, DNS names that
  resolve to private addresses, and `169.254.169.254` (cloud metadata).
- **Time-of-check versus time-of-use.** The host is resolved for the check and again for the request (DNS rebinding) *(reasoning, not documented)*.
  Pinning the resolved IP for the request (`CURLOPT_RESOLVE`) closes it.
- **Redirects.** A validated URL redirects to an internal address. `wp_safe_remote_*` validates each hop; `wp_remote_*` and cURL with
  `CURLOPT_FOLLOWLOCATION` do not.
- **Other protocols.** `file_get_contents`/cURL with a request-controlled scheme: `file://` (local file read), `gopher://`, `ftp://`, `php://filter`.
  `allow_url_include` being off (default) does not stop `file_get_contents`.
- **Port control.** A host parameter plus a port parameter reaches internal services on any port; core's validator restricts ports, custom code usually does not.
- **Echoing the response.** Returning the body (`wp_send_json( wp_remote_retrieve_body( $r ) )`) turns blind SSRF into read SSRF. Returning status
  codes, timing or error messages still leaks reachability.
- **Second-order URLs.** A URL saved by one role and fetched later by a cron job or an admin screen.
- **Local-only exposure.** Services reachable only on localhost (databases, admin panels, the site's own REST API) are the usual real target; `WP_HTTP_BLOCK_EXTERNAL` does not stop those.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: whole URL from the request, body returned
$r = wp_remote_get( $_POST['url'] );
wp_send_json_success( wp_remote_retrieve_body( $r ) );

// safe(r): core validates the URL and every redirect; still do not echo the body
$r = wp_safe_remote_get( esc_url_raw( wp_unslash( $_POST['url'] ) ), array( 'timeout' => 5, 'limit_response_size' => 1048576 ) );
```

```php
// vulnerable: substring host test
if ( false !== strpos( $_GET['u'], 'allowed.example' ) ) { file_get_contents( $_GET['u'] ); }
// safe: parsed host equality against an allow-list, fixed scheme, then a safe client
$p = wp_parse_url( $u );
if ( isset( $p['scheme'], $p['host'] ) && 'https' === $p['scheme'] && in_array( strtolower( $p['host'] ), array( 'api.allowed.example' ), true ) ) {
	$r = wp_safe_remote_get( $u );
}
```

```php
// vulnerable: user chooses a host, plugin builds the URL
$r = wp_remote_get( 'http://' . $_GET['host'] . '/status' );
// safe: choose from fixed endpoints
$endpoints = array( 'eu' => 'https://eu.api.example', 'us' => 'https://us.api.example' );
$r = wp_remote_get( $endpoints[ $_GET['region'] ] ?? $endpoints['eu'] );
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. The URL is fixed or chosen from a server-side allow-list; the request value is only an identifier or a path segment appended to a fixed host and cannot change the host (`?`, `#`, `@`, `\`, `..` handled).
2. The request goes through `wp_safe_remote_*` or `wp_http_validate_url()` on the **same** string used for the request, and redirects are validated.
3. The host is compared by equality with an allow-list after parsing, scheme fixed to `https`, with no redirects followed.
4. The result is never returned or used, and the request has no side effect on the target (a blind request to a target the attacker could already reach, with no sensitive effect).
5. Only an administrator can set the URL and nothing is escalated (a webhook or "test connection" feature working as designed).
6. The entry point is not reachable at the claimed tier, or is dead code (`wp_xref.py`).

`needs-dynamic-check` when the protection depends on `WP_HTTP_BLOCK_EXTERNAL`, a filter such as `http_request_host_is_external` or
`http_request_reject_unsafe_urls`, or the host's network configuration. `confirmed` needs file:line for the entry point, the
construction of the URL from the request value, the missing or bypassable validation, and what the attacker receives
(response, side effect, or only reachability).

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N`. Scope is Changed (`S:C`) when the request reaches a component other than the plugin, such as an internal service;
computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated, response returned (read internal data) | `PR:N/S:C/C:H/I:N/A:N` | 8.6 |
| Unauthenticated, limited read and request side effects | `PR:N/S:C/C:L/I:L/A:N` | 7.2 |
| Unauthenticated, blind (reachability or a harmless request) | `PR:N/S:C/C:L/I:N/A:N` | 5.8 |
| Subscriber, response returned | `PR:L/S:C/C:H/I:N/A:N` | 7.7 |
| Subscriber, limited read and side effects | `PR:L/S:C/C:L/I:L/A:N` | 6.4 |
| Administrator only (setting, webhook, test button) | `PR:H/S:C/C:L/I:L/A:N` | 5.5 |
| Request can only reach the site itself, no scope change | `S:U/PR:N/C:L/I:L/A:N` | 6.5 |

Name what you could reach and read (loopback service, cloud metadata, internal API); do not score impact on a target you have not shown.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- SSRF is **not** in the list of accepted vulnerability types; the only SSRF rule is under out-of-scope: "Blind SSRF – must demonstrate concrete impact".
  Report SSRF when the response is returned or a concrete effect (a request that changes state, access to internal data) is demonstrated.
- Only unauthenticated or default Subscriber/Customer exploitation is eligible; "Any report involving Attack Complexity: High (AC:H)",
  "Unrealistic pre-requisites or exploitation scenarios", "Vulnerabilities that only exist because a high-privilege user explicitly configured the component that way",
  and components with fewer than 1,000 active installs outside mVDP are out of scope.
- "Expected functionality is not a vulnerability": an administrator-configured webhook that calls a URL is the feature.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: show the exact request value that chooses the URL, why the validator does not stop an internal address, and
what comes back. An SSRF that cannot reach anything the attacker could not reach directly, and returns nothing, is a weak finding.

## Sources

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) and [SSRF (OWASP Top 10 A10:2021)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [HTTP API (Common APIs handbook)](https://developer.wordpress.org/plugins/http-api/)
- [`wp_remote_get()`](https://developer.wordpress.org/reference/functions/wp_remote_get/), [`wp_safe_remote_get()`](https://developer.wordpress.org/reference/functions/wp_safe_remote_get/), [`wp_http_validate_url()`](https://developer.wordpress.org/reference/functions/wp_http_validate_url/), [`http_request_reject_unsafe_urls`](https://developer.wordpress.org/reference/hooks/http_request_reject_unsafe_urls/), [`download_url()`](https://developer.wordpress.org/reference/functions/download_url/), [`WP_Http::block_request()`](https://developer.wordpress.org/reference/classes/wp_http/block_request/)
- WordPress core `trunk`, read 2026-11-01: [`class-wp-http.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wp-http.php) (`request`, defaults, `validate_redirects`, `block_request`), [`http.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/http.php) (`wp_http_validate_url`, `wp_safe_remote_*`)
- PHP manual: [Filesystem configuration](https://www.php.net/manual/en/filesystem.configuration.php) (`allow_url_fopen`, `allow_url_include`), [`curl_setopt`](https://www.php.net/manual/en/function.curl-setopt.php) (`CURLOPT_FOLLOWLOCATION`, `CURLOPT_PROTOCOLS`, `CURLOPT_RESOLVE`)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
