"""wpbench command line."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from wpbench import __version__
from wpbench.cases import DEFAULT_DATASET, Case, Issue, load_cases, summarise
from wpbench.diff import CHANGED_LINES_LIMIT, changed_lines, diff_trees
from wpbench.fetch import FetchError, fetch_case, http_download
from wpbench.runplan import (
    BASE_CONTEXT_TOKENS,
    CONDITIONS,
    DEFAULT_MODEL,
    PRICES,
    SCENARIOS,
    ContainerSpec,
    build_plan,
    default_skill_dirs,
    docker_command,
    estimate_run,
    preflight,
    project,
    source_tokens,
)
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


def _money(x: float) -> str:
    return f"${x:,.2f}"


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:.1f} h" if seconds >= 5400 else f"{seconds / 60:.0f} min"


@app.command()
def run(
    split: Annotated[str, typer.Option(help="dev, test or all.")] = "all",
    case: Annotated[list[str] | None, typer.Option("--case", help="Run only this case id (repeatable).")] = None,
    conditions: Annotated[str, typer.Option(help="Comma separated: A, B, C-full, C-min, C-noscripts.")] = "A,B,C-full",
    repeats: Annotated[int, typer.Option(min=1, help="Repeats per run.")] = 1,
    model: Annotated[str, typer.Option(help="Model recorded with every run.")] = DEFAULT_MODEL,
    budget_usd: Annotated[float, typer.Option(help="Hard cap per run, passed to claude --max-budget-usd.")] = 3.0,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan, the container command and the cost estimate; start nothing.")] = False,
    allow_unsigned: Annotated[bool, typer.Option(help="Include cases whose label is not signed (never for reported metrics).")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
    cases_dir: CasesDirOpt = Path("cases"),
    prompt_file: Annotated[Path, typer.Option(help="Task prompt shared by all conditions.")] = Path("prompts/task.md"),
) -> None:
    """Plan (and, once the pilot is approved, execute) runs: condition x case version x repeat."""
    if split not in ("dev", "test", "all"):
        err.print("[red]--split must be dev, test or all[/red]")
        raise typer.Exit(2)
    names = [c.strip() for c in conditions.split(",") if c.strip()]
    unknown = [n for n in names if n not in CONDITIONS]
    if unknown or model not in PRICES:
        err.print(f"[red]unknown condition(s) {unknown or ''} or model {model!r}; conditions: {', '.join(CONDITIONS)}; models with a price: {', '.join(PRICES)}[/red]")
        raise typer.Exit(2)
    selected = _select(_load(dataset), split, case or [])
    skipped = [c.id for c in selected if not c.signed and not allow_unsigned]
    selected = [c for c in selected if c.signed or allow_unsigned]
    if skipped:
        err.print(f"[yellow]skipping unsigned labels: {', '.join(skipped)}[/yellow]")
    if not selected:
        err.print("[yellow]no cases selected[/yellow]")
        raise typer.Exit(0)
    if not dry_run:
        err.print("[red]Execution is not enabled yet: Phase 3 shows the dry run and the estimate first. Use --dry-run.[/red]")
        raise typer.Exit(2)

    plan = build_plan(selected, names, repeats)
    spec = ContainerSpec()
    skill_dirs = default_skill_dirs()
    price = PRICES[model]
    console.print(f"[bold]Plan[/bold]: {len(plan)} runs = {len(selected)} cases x 2 versions (vulnerable + fixed negative control) x {len(names)} conditions x {repeats} repeat(s); model {model}; cap ${budget_usd:g}/run")

    ct = Table("condition", "skill", "tools", "allowed tools", "what")
    for n in names:
        cond = CONDITIONS[n]
        ct.add_row(n, cond.skill or "-", ",".join(cond.tools), "; ".join(cond.allowed_tools()), cond.description)
    console.print(ct)

    sizes = {c.id: source_tokens(cases_dir / c.id / "vuln") for c in selected}
    known = [s for s in sizes.values() if s]
    mean_src = sum(known) // len(known) if known else 300_000
    console.print("\n[bold]Container command for the first run[/bold] (not executed):")
    prompt = prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else "<prompt missing>"
    first = docker_command(plan[0], CONDITIONS[plan[0].condition], spec, cases_dir, Path("runs/<id>"), model, budget_usd, "<prompts/task.md>")
    console.print(" ".join(shlex.quote(x) for x in first), soft_wrap=True, highlight=False)
    console.print(f"task prompt: {len(prompt.split())} words, identical for every condition")

    console.print("\n[bold]Preflight[/bold]")
    pf = preflight(selected, names, cases_dir, skill_dirs, spec, prompt_file)
    for ck in pf.checks:
        mark = "[green]ok[/green]" if ck.ok else ("[red]FAIL[/red]" if ck.blocking else "[yellow]warn[/yellow]")
        console.print(f"  {mark} {ck.name}: {ck.detail}", highlight=False)
    console.print("  [red]NOT READY[/red] egress: the allow-list proxy and the docker image are not built or tested (see docs/DECISIONS.md section 15)")

    console.print("\n[bold]Estimate for this plan[/bold] (a model with assumptions, not a measurement)")
    et = Table("condition", "runs", "low", "mid", "high", "mid time/run")
    totals = {s.name: 0.0 for s in SCENARIOS}
    total_s = 0.0
    for n in names:
        runs_n = sum(1 for r in plan if r.condition == n)
        per = {s.name: sum(estimate_run(sizes[r.case_id] or mean_src, CONDITIONS[n], s, price).cost for r in plan if r.condition == n) for s in SCENARIOS}
        mid_t = [estimate_run(sizes[r.case_id] or mean_src, CONDITIONS[n], SCENARIOS[1], price).seconds for r in plan if r.condition == n]
        for k, v in per.items():
            totals[k] += v
        total_s += sum(mid_t)
        et.add_row(n, str(runs_n), _money(per["low"]), _money(per["mid"]), _money(per["high"]), _hours(sum(mid_t) / runs_n))
    et.add_row("[bold]total[/bold]", str(len(plan)), _money(totals["low"]), _money(totals["mid"]), _money(totals["high"]), f"{_hours(total_s)} sequential")
    console.print(et)
    st = Table("case", "PHP tokens (no vendor)", "A mid cost / run")
    for c in selected:
        s = sizes[c.id]
        st.add_row(c.id, f"{s:,}" if s else "not fetched", _money(estimate_run(s or mean_src, CONDITIONS["A"], SCENARIOS[1], price).cost))
    console.print(st)

    console.print("\n[bold]Projection for the whole experiment[/bold] (mean plugin = " + f"{mean_src:,} tokens)")
    pt = Table("stage", "runs", "low", "mid", "high")
    stages = {
        "Phase 6 dev, one iteration: 15 cases x 2 versions x A,B,C-full x 2 repeats": {"A": 60, "B": 60, "C-full": 60},
        "Phase 7 test: 25 cases x 2 versions x 5 conditions x 2 repeats": {n: 100 for n in CONDITIONS},
    }
    for label, counts in stages.items():
        res = {s.name: project(counts, mean_src, s, model) for s in SCENARIOS}
        pt.add_row(label, str(sum(counts.values())), *(_money(res[s.name].cost) for s in SCENARIOS))
    console.print(pt)
    console.print(
        "Assumptions: low/mid/high = agent reads 15/35/70 % of the PHP, 25/45/80 model calls, 8k/20k/40k output tokens; "
        f"base context {BASE_CONTEXT_TOKENS:,} tokens + skill; prices ${price.input:g}/${price.output:g} per M, cache read ${price.cache_read:g}, "
        "write $2.5; 6 s per call + output at 60 tok/s. Prompt caching assumed to work."
    )
