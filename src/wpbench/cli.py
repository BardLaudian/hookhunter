"""wpbench command line."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from wpbench import __version__
from wpbench.cases import DEFAULT_DATASET, Case, Issue, load_cases, summarise
from wpbench.diff import CHANGED_LINES_LIMIT, changed_lines, diff_trees
from wpbench.fetch import FetchError, fetch_case, http_download
from wpbench.split import SplitError, apply_to_text, assign, check_splits_file, write_splits_file

app = typer.Typer(help="Benchmark for AI agent skills that find vulnerabilities in WordPress plugins.", no_args_is_help=True, add_completion=False)
console = Console()
err = Console(stderr=True)

DatasetOpt = Annotated[Path, typer.Option("--dataset", help="Path to cases.toml.")]
CasesDirOpt = Annotated[Path, typer.Option("--cases-dir", help="Where releases are unpacked (git-ignored).")]


def _load(dataset: Path, *, fail_on_error: bool = True) -> list[Case]:
    cases, issues = load_cases(dataset)
    errors = [i for i in issues if i.level == "error"]
    if errors and fail_on_error:
        _print_issues(errors)
        err.print(f"[red]{len(errors)} error(s) in {dataset}; run `wpbench validate`.[/red]")
        raise typer.Exit(1)
    return cases


def _print_issues(issues: list[Issue]) -> None:
    for i in issues:
        colour = "red" if i.level == "error" else "yellow"
        err.print(f"[{colour}]{i.level}[/{colour}] {i.case_id} {i.field}: {i.message}", highlight=False)


def _select(cases: list[Case], split: str, ids: list[str]) -> list[Case]:
    chosen = [c for c in cases if (not ids or c.id in ids) and (split == "all" or c.split == split)]
    missing = sorted(set(ids) - {c.id for c in cases})
    if missing:
        err.print(f"[red]unknown case id(s): {', '.join(missing)}[/red]")
        raise typer.Exit(2)
    return chosen


def _version(value: bool) -> None:
    if value:
        console.print(__version__)
        raise typer.Exit()


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version and exit.")] = False) -> None:
    """wpbench."""


@app.command()
def validate(dataset: DatasetOpt = DEFAULT_DATASET, as_json: Annotated[bool, typer.Option("--json", help="Print the summary as JSON.")] = False) -> None:
    """Check cases.toml against the schema of docs/DATASET.md."""
    cases, issues = load_cases(dataset)
    issues += check_splits_file(dataset.with_name("splits.toml"), cases)
    errors = [i for i in issues if i.level == "error"]
    summary = summarise(cases)
    if as_json:
        console.print_json(json.dumps({"summary": summary, "issues": [i.__dict__ for i in issues]}))
    else:
        _print_issues(issues)
        console.print(f"{summary['cases']} case(s); splits {summary['by_split']}; {summary['signed_labels']} of {summary['labelled']} labels signed")
        console.print("[red]invalid[/red]" if errors else "[green]valid[/green]" + (f" ({len(issues)} warning(s))" if issues else ""))
    raise typer.Exit(1 if errors else 0)


@app.command()
def fetch(
    split: Annotated[str, typer.Option(help="dev, test or all.")] = "all",
    case: Annotated[list[str] | None, typer.Option("--case", help="Fetch only this case id (repeatable).")] = None,
    allow_unhashed: Annotated[bool, typer.Option(help="Download releases whose SHA-256 is not recorded yet and print the hash.")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
    cases_dir: CasesDirOpt = Path("cases"),
) -> None:
    """Download the vulnerable and fixed release of each case, verify the hash and unpack into cases/<id>/{vuln,fixed}/."""
    if split not in ("dev", "test", "all"):
        err.print("[red]--split must be dev, test or all[/red]")
        raise typer.Exit(2)
    selected = _select(_load(dataset), split, case or [])
    if not selected:
        err.print("[yellow]no cases selected[/yellow]")
        raise typer.Exit(0)
    failed = 0
    table = Table("case", "release", "status", "files", "sha256")
    for c in selected:
        try:
            for r in fetch_case(c, cases_dir, http_download, allow_unhashed):
                table.add_row(r.case_id, r.role, r.status, str(r.files), r.sha256 if not r.hashed else r.sha256[:12] + "…")
        except FetchError as exc:
            failed += 1
            err.print(f"[red]{exc}[/red]", highlight=False)
    console.print(table)
    raise typer.Exit(1 if failed else 0)


@app.command()
def diff(
    case_id: Annotated[str, typer.Argument(help="Case id, for example wp-0001.")],
    stat: Annotated[bool, typer.Option(help="Show only the per-file summary.")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
    cases_dir: CasesDirOpt = Path("cases"),
) -> None:
    """PHP diff between the vulnerable and fixed releases, plus the saved advisory text (dataset/advisories/<id>.md)."""
    cases = {c.id: c for c in _load(dataset)}
    if case_id not in cases:
        err.print(f"[red]unknown case id {case_id}[/red]")
        raise typer.Exit(2)
    c = cases[case_id]
    old, new = cases_dir / c.id / "vuln", cases_dir / c.id / "fixed"
    if not (old.is_dir() and new.is_dir()):
        err.print(f"[red]{c.id} is not fetched; run `wpbench fetch --case {c.id}`[/red]")
        raise typer.Exit(1)
    diffs = diff_trees(old, new)
    total = changed_lines(diffs)
    console.print(f"# {c.id} {c.cve} {c.slug} {c.vuln_version} -> {c.fixed_version}  ({c.source}: {c.source_url})", highlight=False)
    advisory = dataset.parent / "advisories" / f"{c.id}.md"
    console.print("## Advisory", highlight=False)
    console.print(advisory.read_text() if advisory.is_file() else f"(none saved; paste the advisory text into {advisory})", highlight=False, markup=False)
    console.print(f"## PHP changes: {len(diffs)} file(s), {total} changed line(s)", highlight=False)
    if total > CHANGED_LINES_LIMIT:
        console.print(f"[yellow]more than ~{CHANGED_LINES_LIMIT} changed lines: the fix may be too large to point at the vulnerable code (docs/DATASET.md)[/yellow]")
    for d in diffs:
        console.print(f"{d.status:9s} +{d.added} -{d.removed}  {d.path}", highlight=False, markup=False)
    if not stat:
        for d in diffs:
            console.print(d.text, end="", highlight=False, markup=False)


@app.command()
def split(
    seed: Annotated[str, typer.Option(help="Seed of the shuffle; it is recorded in dataset/splits.toml.")],
    dev: Annotated[int, typer.Option(help="Target dev size (the ratio dev:test is what counts).")] = 15,
    test: Annotated[int, typer.Option(help="Target test size.")] = 25,
    write: Annotated[bool, typer.Option(help="Write the assignment into cases.toml and splits.toml (default: dry run).")] = False,
    force: Annotated[bool, typer.Option(help="Reassign even if cases already have a split.")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
) -> None:
    """Assign cases to dev and test, stratified by class and reproducible from the seed."""
    cases = _load(dataset)
    try:
        result = assign(cases, seed, dev, test, force)
    except SplitError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    table = Table("case", "class", "split")
    for c in sorted(cases, key=lambda x: (x.cls, x.id)):
        table.add_row(c.id, c.cls, result.assignment[c.id])
    console.print(table)
    console.print(f"dev {result.dev}, test {result.test}, seed {seed!r}")
    if write:
        dataset.write_text(apply_to_text(dataset.read_text(), result.assignment))
        write_splits_file(dataset.with_name("splits.toml"), result)
        console.print(f"[green]wrote {dataset} and {dataset.with_name('splits.toml')}[/green]")
    else:
        console.print("dry run: nothing written (use --write)")
