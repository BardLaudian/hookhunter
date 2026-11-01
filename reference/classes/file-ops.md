# File operations: upload, traversal, read, write, delete, inclusion

CWE-434 (unrestricted upload of a dangerous file type), CWE-22 (path traversal), CWE-73 (external control of a file
name or path), CWE-98 / CWE-829 (file inclusion). Stack them by what the attacker controls: the **path**, the **name or
extension**, the **content**, or all three.

Open `sanitizers.md` section 5 for the path and file-name guards, `surface.md` for who reaches the handler, and
`ssrf.md` when the path is a URL. Server-side script execution after an upload (RCE) belongs here for the upload half and in
`rce.md` for the execution half.

## 1. WordPress facts that decide exploitability

Read from core `trunk` on 2026-11-01 unless the line says otherwise.

- **`wp_handle_upload()`** (`wp-admin/includes/file.php`) is the safe path for uploads, with these defaults:
  - `test_type` is on: it calls `wp_check_filetype_and_ext()` against `get_allowed_mime_types()` and refuses other types.
    A plugin that passes `'test_type' => false`, or a wider `'mimes'` array, removes that protection.
  - `test_form` (default on) only checks that `$_POST['action']` equals the expected action. It is **not** a CSRF or authorization control.
  - It requires `is_uploaded_file()` for real uploads. `wp_handle_sideload()` instead accepts any readable local path,
    so a request-chosen path there copies an arbitrary local file into the uploads directory.
  - The final name comes from `wp_unique_filename()`, which runs `sanitize_file_name()` first, so `../` in the client name is neutralised on this path.
- **`get_allowed_mime_types()`**: starts from core's list, removes `swf` and `exe`, removes `html` and `js` for users without
  `unfiltered_html`, then applies the `upload_mimes` filter. In the list as read there are no `php` or `svg` entries;
  plugins that enable SVG, HTML or other types through `upload_mimes` widen the surface (SVG becomes stored XSS in a file).
- **`wp_check_filetype_and_ext()`** checks the extension against the allowed list, compares the detected image type
  for images, and, when PHP's `fileinfo` extension is loaded, compares the detected MIME type with the one the extension implies.
  It is not a malware scan.
- **`$_FILES`** (PHP manual): `name` is the client's original file name; `type` is whatever the browser sent and "is
  however not checked on the PHP side and therefore do not take its value for granted".
- **`unzip_file()`** skips archive entries whose name fails `validate_file()`, which is core's guard against `../` entries
  (zip-slip). Plugins that call `ZipArchive::extractTo()` or another extractor directly have no such guard unless they add one.
- **`wp_delete_file_from_directory( $file, $dir )`** deletes only when the real path of `$file` lies inside `$dir`. `unlink()` has no such limit.
- **`validate_file()`** rejects `../` and Windows drive paths, but not absolute POSIX paths such as `/etc/passwd`.
- **`allow_url_include`** defaults to off (`"0"`, PHP manual), so a remote include (RFI) needs that setting; `allow_url_fopen`
  defaults to on, so `file_get_contents`/`copy`/`fopen` accept URLs (that is SSRF, see `ssrf.md`).
- The `wp_sinks.py` rules `file-op`, `file-read` and `include` cover: `move_uploaded_file`, `copy`, `rename`, `file_put_contents`,
  `fopen`, `unlink`, `rmdir`, `mkdir`, `touch`, `readfile`, `file`, `fpassthru`, `wp_delete_file`, `wp_handle_upload`,
  `unzip_file`, `file_get_contents`, and `include`/`require`.

## 2. Where it lives

| Primitive | Look for |
|---|---|
| Upload | `$_FILES`, `wp_handle_upload`, `wp_handle_sideload`, `media_handle_upload`, `move_uploaded_file`, `download_url`, `media_sideload_image`, `file_put_contents` of request content or `base64_decode` |
| Read / download | `readfile`, `file_get_contents`, `fpassthru`, `file()`, `fopen`+`fread`, `highlight_file`, `show_source`, `header( 'Content-Disposition' )` next to a request-chosen path |
| Write | `file_put_contents`, `fwrite`, `copy`, `rename`, `unzip_file`, `ZipArchive::extractTo`, `touch`, `mkdir`, settings that write a config or template file |
| Delete | `unlink`, `wp_delete_file`, `rmdir`, `delete_option` for file-backed settings, bulk-clean routines that take a path or a glob |
| Include | `include`, `include_once`, `require`, `require_once`, `locate_template`, `load_template`, template loaders that build a path from a request value |

## 3. How to hunt

1. For each operation above, `wp_sinks.py --class file-ops,file-inclusion` and note the guards in `guards_in_args` and `sanitizers_in_function`.
2. Split the path into its parts: base directory (constant or `wp_upload_dir()`), directory segment, file name, extension. Which part comes from the request?
3. Read the guard against the **primitive**: for traversal, is the final path resolved (`realpath`) and compared to the base with a trailing separator? For upload, is the **extension** decided by an allow-list on the final name, after sanitising?
4. Check **where the file lands** and whether it is reachable and executable: the web-accessible uploads directory is, a directory protected by a web-server rule or outside the web root is not. Execution depends on server configuration, so say what you could not verify.
5. Check the entry point tier (`wp_map.py`, `wp_xref.py`), and for uploads whether `upload_files` or an equivalent capability is required.
6. For downloads and reads, check whether the target can be `wp-config.php` (database credentials and salts) or other sensitive files.

## 4. Traps specific to this class

- **`test_type => false`**, `mimes` widened, or `upload_mimes` filtered to add `php`, `phtml`, `phar`, `html`, `svg`. Check what the filter returns.
- **Client-supplied type.** `$_FILES['f']['type']` or `mime_content_type()` on an attacker-chosen name used as the allow-list. Also `getimagesize()` alone: it accepts a valid image header followed by PHP (a polyglot).
- **Extension checks that miss variants.** Blacklists (`php`, `php5`, `phtml`, `phar`, `pht`, `phps`, `inc`), case-sensitive comparisons (`.PHP`), checking `pathinfo()[extension]` of the original name while saving a different name, double extensions (`a.php.jpg` on a server that runs any `.php` segment), trailing dot or space on Windows.
- **Name sanitising missing.** `$_FILES['f']['name']` used directly in the destination path. Going through `wp_handle_upload` / `sanitize_file_name` / `wp_unique_filename` is the safe route.
- **Traversal checks that can be bypassed.** `str_replace( '../', '', $p )` (becomes `....//` -> `../`), a check for `..` before URL-decoding, `basename()` applied to a path where the *directory* is also user-controlled, `strpos( $p, $base ) === 0` with no `realpath` and no trailing separator (`/uploads` matches `/uploads-evil`), `validate_file()` used as an absolute-path guard (it is not).
- **`realpath()` on a path that does not exist** returns `false`. A containment test written as `!== false`, `==`, or a comparison of two failed `realpath()` results can pass on `false`. Test for `false` first, then do the prefix test.
- **Symlinks.** Files extracted from an archive or already in the uploads directory can be symlinks to elsewhere; `realpath` resolves them, a string prefix test does not.
- **Zip-slip.** `ZipArchive::extractTo( $dir )` or `PclZip` extraction of an uploaded archive without a per-entry `validate_file()` / `realpath` check.
- **PHP stream wrappers.** `include` / `file_get_contents` with `php://filter/…`, `data://`, `expect://`, `zip://` or a URL when the beginning of the path is request-controlled; `php://filter` can return the *source* of a local file.
- **Local file inclusion needs only the path.** An include with a controlled directory segment and a fixed suffix (`.php`) still reaches any PHP file; a fixed *prefix* with a request-controlled tail may still allow traversal.
- **Delete by pattern.** `glob( $dir . $_POST['p'] )` followed by `unlink`, `array_map( 'unlink', … )`, or cleanup jobs that take a path from an option.
- **Read of generated files.** Exports, logs, backups and invoices saved in a predictable, web-accessible path (`uploads/plugin/export-123.csv`) are information disclosure even without a vulnerable function (`info-disclosure.md`).
- **File content, not name.** Writing request content to a `.php` file in a theme/plugin directory, or to a config file the plugin later `include`s, is code execution without any upload.
- **Sideload with a request path or URL.** `wp_handle_sideload( [ 'tmp_name' => $_POST['p'] … ] )` copies a local file into the uploads directory; `download_url( $_POST['url'] )` and `media_sideload_image( $_POST['url'] )` fetch a request-chosen URL (SSRF, `ssrf.md`) and store the result. Read what extension and type checks they apply in the core version in use; they were not analysed here.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: name and type from the client, no extension control
$dest = WP_CONTENT_DIR . '/uploads/fx/' . $_FILES['f']['name'];
if ( $_FILES['f']['type'] === 'image/png' ) { move_uploaded_file( $_FILES['f']['tmp_name'], $dest ); }

// safe: let core validate name, type and destination
$r = wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'mimes' => array( 'png' => 'image/png' ) ) );
```

```php
// vulnerable: traversal in a download endpoint
readfile( FX_DIR . '/' . $_GET['file'] );
// safe
$base = realpath( FX_DIR );
$path = realpath( FX_DIR . '/' . $_GET['file'] );
if ( $path && 0 === strpos( $path, $base . DIRECTORY_SEPARATOR ) ) { readfile( $path ); }
```

```php
// vulnerable: delete anything the process can
unlink( $_POST['path'] );
// safe: core helper that checks containment
wp_delete_file_from_directory( FX_DIR . '/' . basename( $_POST['name'] ), FX_DIR );
```

```php
// vulnerable: template loader
include FX_DIR . '/views/' . $_GET['view'] . '.php';
// safe: allow-list
$views = array( 'list', 'detail' );
if ( in_array( $_GET['view'] ?? '', $views, true ) ) { include FX_DIR . '/views/' . $_GET['view'] . '.php'; }
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. The path or name is replaced by a server-chosen value (`wp_unique_filename`, a generated id plus a fixed extension) before use.
2. The path goes through `realpath()` and a prefix test with a trailing separator against a fixed base, including the false-return case, or through `wp_delete_file_from_directory`, or is checked against a strict allow-list of names.
3. For upload: the extension is validated against an allow-list **on the name that is actually written**, and the list has no executable or active-content types (`php*`, `phtml`, `phar`, `html`, `svg`, `js`).
4. The destination is not served as code or not reachable (outside the web root, or a path the web server denies). If this depends on server configuration, use `needs-dynamic-check`.
5. The operation is limited to the caller's own temporary files in a directory they cannot influence.
6. The entry point is not reachable at the claimed tier, or is dead code (`wp_xref.py`).
7. The only caller is an administrator, a role that can already edit plugin and theme files (`edit_plugins`) unless `DISALLOW_FILE_EDIT` is set (`wp-traps.md` 6).

`confirmed` needs file:line for the entry point, the request value that reaches the path or name, the missing or
bypassable guard, and the resulting capability (read, write, delete, include, execute).

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N/S:U`; computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated upload of an executable file, or arbitrary write with controlled content (RCE) | `PR:N/C:H/I:H/A:H` | 9.8 |
| Subscriber-level upload of an executable file | `PR:L/C:H/I:H/A:H` | 8.8 |
| Unauthenticated arbitrary file read (config, source) | `PR:N/C:H/I:N/A:N` | 7.5 |
| Subscriber-level arbitrary file read | `PR:L/C:H/I:N/A:N` | 6.5 |
| Unauthenticated arbitrary file deletion (for example `wp-config.php`) | `PR:N/C:N/I:H/A:H` | 9.1 |
| Subscriber-level arbitrary file deletion | `PR:L/C:N/I:H/A:H` | 8.1 |
| Read restricted to a given directory or extension | `PR:N/C:L/I:N/A:N` | 5.3 |

Rate RCE only if you showed the file can be executed (path, extension and web-server behaviour); otherwise rate the
upload as integrity/availability impact and say what is unverified.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- Accepted types and conditions: "Arbitrary file upload, deletion, or download – must provide full control over the path and extension"; "Local file inclusion or remote file inclusion – must provide full control over the path and extension"; "Remote/Arbitrary Code Execution".
- Out of scope: "Non-arbitrary LFI – only accepted with full control over the path AND extension"; "Constrained-path LFI without a working directory-traversal exploit. Windows-specific bypass techniques are excluded"; "Non-arbitrary file uploads involving legacy extensions such as .phtml".
- Only unauthenticated or default Subscriber/Customer exploitation is eligible; any report with Attack Complexity High, and components with fewer than 1,000 active installs (outside mVDP), are not.

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: state exactly what the attacker controls (path, name, extension, content), the directory and whether the
result is reachable and executable, and the sensitive file or effect. A read restricted to one directory or extension is
a weak finding; show the traversal or the unrestricted extension.

## Sources

- [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-73](https://cwe.mitre.org/data/definitions/73.html), [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) and [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Plugin Handbook: Securing input](https://developer.wordpress.org/plugins/security/securing-input/)
- [`wp_handle_upload()`](https://developer.wordpress.org/reference/functions/wp_handle_upload/), [`wp_handle_sideload()`](https://developer.wordpress.org/reference/functions/wp_handle_sideload/), [`wp_check_filetype_and_ext()`](https://developer.wordpress.org/reference/functions/wp_check_filetype_and_ext/), [`get_allowed_mime_types()`](https://developer.wordpress.org/reference/functions/get_allowed_mime_types/), [`upload_mimes`](https://developer.wordpress.org/reference/hooks/upload_mimes/), [`wp_unique_filename()`](https://developer.wordpress.org/reference/functions/wp_unique_filename/), [`unzip_file()`](https://developer.wordpress.org/reference/functions/unzip_file/), [`wp_delete_file_from_directory()`](https://developer.wordpress.org/reference/functions/wp_delete_file_from_directory/), [`validate_file()`](https://developer.wordpress.org/reference/functions/validate_file/)
- WordPress core `trunk`, read 2026-11-01: [`wp-admin/includes/file.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/includes/file.php) (`_wp_handle_upload`, `wp_handle_sideload`, `_unzip_file_ziparchive`), [`wp-includes/functions.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php) (`wp_check_filetype_and_ext`, `get_allowed_mime_types`, `wp_unique_filename`, `wp_delete_file_from_directory`, `validate_file`)
- PHP manual: [POST method uploads](https://www.php.net/manual/en/features.file-upload.post-method.php) (`$_FILES` fields), [Filesystem configuration](https://www.php.net/manual/en/filesystem.configuration.php) (`allow_url_fopen`, `allow_url_include`), [Supported protocols and wrappers](https://www.php.net/manual/en/wrappers.php)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
