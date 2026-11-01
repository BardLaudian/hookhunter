# wp-audit-bench

A benchmark that measures whether an AI agent skill actually helps find vulnerabilities in WordPress plugins. It runs Claude Code headless on old, already-patched plugin
versions with public CVEs, with and without a skill, and scores the findings against ground truth built from the vulnerable-to-patched diff.

Status: the skill (`skills/hookhunter/`, tag `skill-v1.0`) is built and frozen; the dataset tooling is in place (Phase 1). The harness, scorer and cases come next. See `docs/PLAN.md`.

## Safety

Only versions that are already patched and whose vulnerability is publicly disclosed. Static analysis only: plugin code is never executed, no WordPress is installed, no traffic is
sent to any site. The dataset stores slugs, versions, hashes and labels, never plugin source; releases are downloaded from wordpress.org at run time and checked against their SHA-256.
Labels count for metrics only when a human has signed them.

## Install and test

```bash
pip install -e ".[dev]"
pytest -q && ruff check . && mypy src skills/hookhunter/scripts
```

## Commands (Phase 1)

```bash
wpbench validate                  # check dataset/cases.toml against docs/DATASET.md
wpbench fetch --split dev         # download, hash-check and unpack into cases/<id>/{vuln,fixed}/ (git-ignored)
wpbench diff wp-0001              # PHP diff of the two releases plus the saved advisory text
wpbench split --seed 2026 --write # seeded, stratified dev/test assignment, recorded in dataset/splits.toml
```

`fetch` refuses a release whose hash is not recorded unless `--allow-unhashed` is given; it prints the hash so that you can review it and add it to the dataset.
