# Code and command execution

CWE-94 / CWE-95 (code injection, `eval` injection), CWE-78 (OS command injection), CWE-88 (argument injection), CWE-470
(unsafe reflection: the request chooses the function, method or class), CWE-1336 (template injection).

In one request the attacker supplies something that PHP **runs**: source text, a shell command line, the name of a function
to call, or a template. Files that are written and then executed are in `file-ops.md`; objects whose magic methods run are in
`object-injection.md`.

Open `sanitizers.md` section 7 for the shell and callable guards, and `wp-traps.md` 16 and 17 for loose comparison and weak tokens
used as "protection".

## 1. Facts that decide exploitability

PHP manual and WordPress core `trunk`, read 2026-11-01.

- **`escapeshellarg()`** quotes **one argument**. **`escapeshellcmd()`** escapes shell metacharacters in a whole command string; the
  manual warns that it "still allows the attacker to pass arbitrary number of arguments" and says to use `escapeshellarg()` for a single
  argument. `wp_sinks.py` marks a command call whose arguments are wrapped in either as `guarded`; for `escapeshellcmd` read that as
  "reduced": argument injection remains.
- **`proc_open()` accepts an array command since PHP 7.4.0**: the process is opened directly, without a shell, and PHP does the argument
  escaping. This is the structural fix for command lines built from user data.
- **`mail()`'s `additional_params`** (the fifth argument) is passed through `escapeshellcmd()` internally; the manual says that stops
  command execution but "allows to add additional parameters" and recommends sanitising it.
- **`extract()`**: the manual says "Do not use extract() on untrusted data, like user input (e.g. $_GET, $_FILES)". It creates variables named by
  request keys and can overwrite variables the code relies on.
- **`assert()` with a string argument** was executed with `eval()` before PHP 8.0 (deprecated 7.2, removed 8.0). **`create_function()`** was removed in
  PHP 8.0. On PHP 7 sites these are still code-execution sinks.
- **WordPress executes whatever is registered on a name.** `do_action( $name )` / `apply_filters( $name, … )` run every callback registered on
  `$name`; `do_shortcode( $content )` runs every registered shortcode found in `$content`. With a request-chosen name or content, the attacker
  chooses *which* of the site's existing callbacks run, with the permissions of the current request *(consequence of how the hook system works;
  impact depends on what is registered)*.
- **Core's file editors** need `edit_themes` / `edit_plugins`, and `DISALLOW_FILE_EDIT` removes them for everyone (`wp-traps.md` 6). An
  administrator-only "run PHP" feature is a capability question, not a code-execution bug by itself.
- `wp_sinks.py` rules: `exec` (`eval`, `system`, `exec`, `passthru`, `shell_exec`, `proc_open`, `popen`, `pcntl_exec`, `assert`, `create_function`;
  arguments wrapped in `escapeshellarg|escapeshellcmd` count as guarded) and `dynamic-call` (`call_user_func`, `call_user_func_array`,
  `extract`; any `in_array` or `array_key_exists` call in the enclosing function counts as guarded, without checking that it is strict or that it tests the value
  that is called). **Not covered:** variable function calls (`$fn( … )`), `new $class(…)`,
  `$obj->$method()`, callable parameters (`array_map`, `usort`, `array_filter`, `preg_replace_callback`, `register_shutdown_function`),
  `do_shortcode`, `do_action`/`apply_filters` with a variable name, `parse_str`, `mail`, `putenv`, and template engines. The regex fallback backend also
  misses backtick shell execution. Grep for these.

## 2. Where it lives

- **Shell:** diagnostics ("ping", "whois", "traceroute"), image and PDF tools (`convert`, `gs`, `wkhtmltopdf`, `ffmpeg`), backup and
  import/export (`mysqldump`, `zip`, `tar`), git or WP-CLI wrappers, "test connection" buttons, anything building a command line from an option or a file name.
- **Code evaluation:** formula and condition builders (calculators, price fields, conditional logic in form plugins), "code snippet" runners,
  template or placeholder engines that `eval`, `create_function` generated code, `assert( $string )`.
- **Dynamic dispatch:** parameters named `action`, `method`, `callback`, `func`, `handler`, `class`, `type`, `module` used in
  `call_user_func`, `$this->$method()`, `$class::$method()`, `new $class`, `array_map( $_GET['f'], … )`, `usort( $a, $_POST['cmp'] )`.
- **Variable injection:** `extract( $_POST )`, `extract( $_REQUEST )`, `$$name = $value` over request keys, `parse_str( $query )` into the local scope.
- **Hook and shortcode injection:** `do_shortcode( $_POST['content'] )`, `do_action( $_REQUEST['hook'] )`, `apply_filters( $_GET['f'], … )`.
- **Template engines** (Twig, Blade, Smarty, Mustache and similar) rendering a template string that contains request data.

## 3. How to hunt

1. List `exec` and `dynamic-call` sinks (`wp_sinks.py --class rce`), then Grep for the uncovered forms in section 1.
2. For each, read the exact string or name passed. Which part is request-controlled: the whole command, one argument, the function name, the arguments to a fixed function?
3. Check the guard against the **primitive**: a command line needs `escapeshellarg()` on every user value (or an array command), plus `--` before values that could start with `-`; a callable needs a strict allow-list; evaluated text needs no user data at all.
4. Check where the value comes from (`wp_xref.py`) and the entry point's tier (`authz.md`). An unauthenticated or subscriber-level path is the reportable range.
5. For hook and shortcode injection, list what is registered on reachable names (Grep `add_action`/`add_shortcode`) and say which ones you could trigger.

## 4. Traps specific to this class

- **`escapeshellcmd()` on a whole line,** or `addslashes()`, or a blacklist of `;`, `|`, `&`, backtick, `$()`, newline. None blocks added arguments or options.
- **Argument injection with a correctly quoted value.** `escapeshellarg( $file )` prevents a second command but not a value that starts with `-` and is read as an option
  (`--output=…`, `-o`). Put `--` before user-controlled operands when the tool supports it.
- **Escaping only some values.** `exec( 'tool ' . escapeshellarg( $a ) . ' ' . $b )`, or a user value placed inside an already quoted part of the command.
- **Allow-listing by character class,** for formula evaluators: `preg_match( '/^[0-9+\-*\/() ]+$/', $f )` then `eval`. Check anchors and PHP's `$`, which matches before a final newline; check whether
  letters, `$` or quotes are allowed anywhere; prefer a parser to `eval`.
- **Callable checks that are not allow-lists.** `is_callable()`, `function_exists()`, `method_exists()`, prefixes (`'wp_' . $x`, `'fx_' . $x`), blacklists of `system`/`exec`. A `wp_` or plugin-prefixed
  function can delete users, send requests or write files; even a fixed callable with request-chosen **arguments** can be enough.
- **Callable parameters.** `array_map( $_GET['f'], $data )`, `usort( $a, $_POST['cmp'] )`, `array_filter( $a, $cb )` with a request-chosen string call any PHP function with the data as its argument.
- **`extract()` / variable variables.** Overwrite the variables that later reach `include`, `eval`, a command, or an authorisation flag (`$is_admin`, `$authenticated`).
- **Hook and shortcode injection** with request names or content (section 1). Report which callbacks are reachable and what they do, not the mechanism alone.
- **PHP version.** `assert()` and `create_function()` only matter below PHP 8.0; note the version assumption.
- **Features that run code by design.** Code-snippet plugins and developer tools are expected to execute code for an administrator. The finding is the missing or weak capability or nonce check, not the execution.
- **Template injection.** Request data concatenated into the template text (not passed as a variable) so that the engine evaluates it.
- **Second order.** The command or code string is stored by one request (an option, a post meta, a queue row) and executed later by cron or an admin screen.

## 5. Vulnerable and safe shapes (generic)

```php
// vulnerable: whole value in a shell command
echo shell_exec( 'ping -c1 ' . $_GET['host'] );
// better: one quoted argument; best: no shell
echo shell_exec( 'ping -c1 -- ' . escapeshellarg( $host ) );
$p = proc_open( array( 'ping', '-c1', '--', $host ), $descriptors, $pipes );   // PHP 7.4+
```

```php
// vulnerable: request chooses the function
call_user_func( $_POST['action_fn'], $_POST['arg'] );
// safe: strict map of allowed handlers
$handlers = array( 'resize' => 'fx_resize', 'crop' => 'fx_crop' );
$key = $_POST['op'] ?? '';
if ( isset( $handlers[ $key ] ) ) { call_user_func( $handlers[ $key ], absint( $_POST['n'] ) ); }
```

```php
// vulnerable: character-class "validation" then eval
if ( preg_match( '/^[0-9+*\/. ()-]+$/', $f ) ) { $r = eval( 'return ' . $f . ';' ); }
// safe: parse the expression yourself or use a maths library; never eval request text
```

```php
// vulnerable: request keys become local variables
extract( $_POST );
// safe: explicit, typed reads
$title = isset( $_POST['title'] ) ? sanitize_text_field( wp_unslash( $_POST['title'] ) ) : '';
```

## 6. Refutation checklist

Mark `refuted` and record which holds:
1. No request-derived data reaches the executed text, command or callable name; values appear only as separate typed arguments of a fixed call.
2. The command is built with an array (`proc_open( array(...) )`), or every user value is `escapeshellarg()`ed and cannot be read as an option (fixed `--`, validated format), and the command name is fixed.
3. The callable is chosen from a fixed map keyed by a validated string; the arguments are cast or validated.
4. The evaluated text is generated entirely by the plugin (no user data), or the evaluator is a parser, not `eval`.
5. The feature is code execution for administrators by design and has a correct capability and nonce check (`authz.md`, `csrf.md`); nothing is escalated.
6. The sink is PHP-version dependent (`assert` string, `create_function`) and the plugin declares PHP 8 or later as the minimum.
7. The entry point is unreachable at the claimed tier or is dead code (`wp_xref.py`).

`needs-dynamic-check` for hook/shortcode injection impact, tool-specific option parsing, or behaviour that depends on the PHP version
or `disable_functions`. `confirmed` needs file:line for the entry point, the full construction of the command, code or callable, the
request value that reaches it, and why the guard (if any) does not stop it.

## 7. Typical CVSS 3.1

`AV:N/AC:L/UI:N/S:U`; computed with the FIRST formula.

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated code or command execution | `PR:N/C:H/I:H/A:H` | 9.8 |
| Subscriber or author-level execution | `PR:L/C:H/I:H/A:H` | 8.8 |
| Administrator only (usually expected functionality) | `PR:H/C:H/I:H/A:H` | 7.2 |
| Argument injection with limited effect (file read and write as the web user) | `PR:N/C:H/I:H/A:N` | 9.1 |
| Execution needs a particular PHP version or optional component | `AC:H/PR:N/C:H/I:H/A:H` | 8.1 |

Rate execution as C:H/I:H/A:H only when the request really controls code or a full command; for argument injection or hook triggering, rate what you showed.

## 8. What triagers reject

Patchstack Alliance rules (read in full, 2026-11-01):
- "Remote/Arbitrary Code Execution" is an accepted type, for unauthenticated or default Subscriber/Customer exploitation only.
- Out of scope: "Any report involving Attack Complexity: High (AC:H)"; "Unrealistic pre-requisites or exploitation scenarios";
  "Vulnerabilities that only exist because a high-privilege user explicitly configured the component that way"; "Expected functionality is not a
  vulnerability"; components with fewer than 1,000 active installs outside mVDP.
- For CSRF, "RCE with a working PoC" is the bar for an accepted outcome (`csrf.md`).

Wordfence's scope could not be read (empty response to automated fetches); see `authz.md` section 7.

Practical rule: give the exact string, command or name the request controls, the guard you read and why it fails, and the tier. Do not
list "uses `eval`" or "uses `shell_exec`" alone: show the request value on the path.

## Sources

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-88](https://cwe.mitre.org/data/definitions/88.html), [CWE-470](https://cwe.mitre.org/data/definitions/470.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) and [Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- PHP manual: [`escapeshellarg`](https://www.php.net/manual/en/function.escapeshellarg.php), [`escapeshellcmd`](https://www.php.net/manual/en/function.escapeshellcmd.php), [`proc_open`](https://www.php.net/manual/en/function.proc-open.php), [`mail`](https://www.php.net/manual/en/function.mail.php), [`extract`](https://www.php.net/manual/en/function.extract.php), [`assert`](https://www.php.net/manual/en/function.assert.php), [`call_user_func`](https://www.php.net/manual/en/function.call-user-func.php), [migrating to PHP 8.0](https://www.php.net/manual/en/migration80.incompatible.php) (`create_function` removed)
- [`do_shortcode()`](https://developer.wordpress.org/reference/functions/do_shortcode/), [`do_action()`](https://developer.wordpress.org/reference/functions/do_action/), [`apply_filters()`](https://developer.wordpress.org/reference/functions/apply_filters/), [Shortcodes (Plugin Handbook)](https://developer.wordpress.org/plugins/shortcodes/)
- WordPress core `trunk`, read 2026-11-01: [`wp-includes/capabilities.php`](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/capabilities.php) (`edit_themes`, `edit_plugins`, `DISALLOW_FILE_EDIT`)
- [Patchstack Alliance: vulnerability report guidelines and rules](https://patchstack.com/articles/patchstack-alliance-vuln-report-guidelines-rules/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [calculator](https://www.first.org/cvss/calculator/3.1)
