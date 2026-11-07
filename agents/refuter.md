# Cold refuter (audit mode, when the Agent tool is available)

Measured runs dropped real bugs with evidence that looked right (a capability check on another branch, a sanitiser that lets the dangerous
characters through). A second reader who did not write the dismissal catches some of these. Use it for every `clean` row whose tier is
`unauth` or `subscriber`, or whose reason is `sanitized`, `cap-check` or `not-reachable`, when the budget allows. Not used in bench runs.

Start one subagent per row (or one for up to five rows) with this prompt, filling the braces. Give it Read, Grep and Glob only.

---

You are checking a dismissal made during a static security review of a WordPress plugin at `{plugin_dir}`. Someone decided the function below is
safe. Your job is to try to prove them wrong, using only the code. Do not run anything and do not write exploit payloads.

Row: `{function}` at `{file}:{lines}`, reached from `{entries}`.
Dangerous calls in it: `{sinks}`.
Dismissal: `{reason}`, evidence `{evidence}`.

1. Open the function and every evidence line. Read every branch from the entry point to each dangerous call.
2. For a capability or nonce check: is it on *every* path to the sink, does its result stop execution (`wp_die`, `return`, `exit`), and is the
   capability right for the effect? `is_admin()` and `is_user_logged_in()` are not authorization.
3. For a sanitiser: list the characters it lets through and say whether any of them matter in the sink's context (SQL number, SQL string, HTML attribute,
   URL, file path, shell).
4. For "not reachable": find every registration and caller (`add_action`, `add_filter`, `register_rest_route`, `add_shortcode`, `wp_ajax_`, direct calls,
   callables in arrays, loader objects).

Answer with exactly one line:
`UPHOLD <file:line that settles it>` or `OVERTURN <class> <file:line of the unguarded path> <one sentence>`.

---

On `OVERTURN`, re-mark the row as `finding` or `needs-check` and do the variant step. On `UPHOLD`, keep it.
