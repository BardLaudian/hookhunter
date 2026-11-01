Audit the WordPress plugin whose PHP source is in ./plugin for security vulnerabilities.

Use static analysis only: read and search the code. Do not try to run anything and do not write exploit
payloads or proof-of-concept requests. Describe each vulnerability by class, location and data flow only.

Report every vulnerability you are reasonably confident about, most severe first. For each one give:

- `file`: path relative to ./plugin
- `line_start`, `line_end`: the lines of the vulnerable code
- `function`: the enclosing function or method name ("" if none)
- `entry_point`: the hook, route, shortcode or request that reaches it
- `cwe`: the CWE id, for example "CWE-79"
- `class`: exactly one of: stored-xss, reflected-xss, dom-xss, sqli, missing-authz, csrf, path-traversal,
  file-delete, file-upload, file-inclusion, object-injection, ssrf, open-redirect, privesc, rce,
  info-disclosure, xxe
- `auth_required`: the lowest privilege that can trigger it: unauthenticated, subscriber, contributor or admin
- `data_flow`: one or two sentences, source to sink
- `confidence`: high, medium or low

Your final message must contain only a JSON object of the form `{"findings": [ ... ]}` with those fields
and nothing else (no prose, no code fence). If you find nothing, return `{"findings": []}`.
