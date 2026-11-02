"""wpbench command line."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from wpbench import __version__
from wpbench import env as envmod
from wpbench.cases import DEFAULT_DATASET, Case, Issue, load_cases, summarise
from wpbench.diff import CHANGED_LINES_LIMIT, changed_lines, diff_trees
from wpbench.execute import Context, execute
from wpbench.fetch import FetchError, fetch_case, http_download
from wpbench.match import FUNCTION_CAP
from wpbench.probe import build_prompt, judge
from wpbench.runplan import (
    BASE_CONTEXT_TOKENS,
    CONDITIONS,
    DEFAULT_MODEL,
    PRICES,
    SCENARIOS,
    ContainerSpec,
    Run,
    build_plan,
    default_skill_dirs,
    docker_command,
    estimate_run,
    preflight,
    project,
    source_tokens,
)
from wpbench.score import (
    LABELS,
    load_records,
    precision_breakdown,
    read_sheet,
    sample_unmatched,
    score_records,
    write_outputs,
    write_sheet,
)
from wpbench.score import (
    summarise as summarise_scores,
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
    versions: Annotated[str, typer.Option(help="vuln, fixed or vuln,fixed (fixed = negative control).")] = "vuln,fixed",
    model: Annotated[str, typer.Option(help="Model recorded with every run.")] = DEFAULT_MODEL,
    budget_usd: Annotated[float, typer.Option(help="Hard cap per run, passed to claude --max-budget-usd.")] = 3.0,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan, the container command and the cost estimate; start nothing.")] = False,
    experiment: Annotated[str | None, typer.Option(help="Name of the experiment; runs go to runs/NAME and a re-run resumes it.")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm that the runs spend money.")] = False,
    jobs: Annotated[int, typer.Option(min=1, help="Containers in parallel.")] = 1,
    max_total_usd: Annotated[float, typer.Option(help="Stop starting runs once this much has been spent.")] = 50.0,
    timeout_min: Annotated[int, typer.Option(min=1, help="Kill a run after this many minutes.")] = 40,
    retry_errors: Annotated[bool, typer.Option(help="Re-run runs that ended in error or timeout.")] = False,
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
    vers = [v.strip() for v in versions.split(",") if v.strip()]
    if not vers or any(v not in ("vuln", "fixed") for v in vers):
        err.print("[red]--versions must be vuln, fixed or vuln,fixed[/red]")
        raise typer.Exit(2)
    plan = build_plan(selected, names, repeats, vers)
    spec = ContainerSpec()
    skill_dirs = default_skill_dirs()
    price = PRICES[model]
    console.print(f"[bold]Plan[/bold]: {len(plan)} runs = {len(selected)} cases x {len(vers)} version(s) ({'+'.join(vers)}; fixed = negative control) x {len(names)} conditions x {repeats} repeat(s); model {model}; cap ${budget_usd:g}/run")

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
    first = docker_command(plan[0], CONDITIONS[plan[0].condition], spec, cases_dir, Path("runs") / (experiment or "<experiment>"), model, budget_usd, "<prompts/task.md>")
    console.print(" ".join(shlex.quote(x) for x in first), soft_wrap=True, highlight=False)
    console.print(f"task prompt: {len(prompt.split())} words, identical for every condition")

    console.print("\n[bold]Preflight[/bold]")
    pf = preflight(selected, names, cases_dir, skill_dirs, spec, prompt_file)
    for ck in pf.checks:
        mark = "[green]ok[/green]" if ck.ok else ("[red]FAIL[/red]" if ck.blocking else "[yellow]warn[/yellow]")
        console.print(f"  {mark} {ck.name}: {ck.detail}", highlight=False)
    envst = envmod.status(spec)
    console.print(f"  {'[green]ok[/green]' if envst.ready else '[red]FAIL[/red]'} docker environment: image={envst.image} internal network={envst.network_internal} proxy running={envst.proxy_running}")

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

    if dry_run:
        return

    # ---- execution -------------------------------------------------------------------------------------------
    problems = [f"{c.name}: {c.detail}" for c in pf.checks if c.blocking and not c.ok]
    if not envmod.status(spec).ready:
        problems.append("docker environment not ready (run `wpbench env build` and `wpbench env up`)")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        problems.append("ANTHROPIC_API_KEY is not set (the containers authenticate with it; the cost is billed to that key)")
    if not experiment:
        problems.append("--experiment NAME is required (it names runs/NAME and makes the run resumable)")
    if not yes:
        problems.append("pass --yes to confirm that this spends money (estimate above)")
    if problems:
        for p in problems:
            err.print(f"[red]cannot start:[/red] {p}", highlight=False)
        raise typer.Exit(2)
    schema_path = Path("schemas/findings.schema.json")
    ctx = Context(
        exp_dir=Path("runs") / str(experiment), cases_dir=cases_dir, skill_dirs=skill_dirs, spec=spec, model=model, budget_usd=budget_usd,
        prompt=prompt, schema=json.loads(schema_path.read_text(encoding="utf-8")), timeout_s=timeout_min * 60,
        prompt_sha=hashlib.sha256(prompt.encode()).hexdigest(), schema_sha=hashlib.sha256(schema_path.read_bytes()).hexdigest(),
        claude_version=subprocess.run(["claude", "--version"], capture_output=True, text=True, check=False).stdout.strip(),
    )

    def report(r: Run, rec: dict[str, Any]) -> None:
        console.print(f"{r.run_id}: {rec.get('status')} cost={_money(float(rec.get('cost_usd') or 0))} turns={rec.get('turns')} skill={rec.get('skill_invoked')} findings={len(rec.get('findings') or [])}", highlight=False)

    summary = execute(plan, ctx, jobs=jobs, max_total_usd=max_total_usd, retry_errors=retry_errors, on_done=report)
    console.print(summary)
    if summary["remaining"]:
        err.print("[yellow]stopped before finishing; re-run the same command to resume[/yellow]")
        raise typer.Exit(1)


env_app = typer.Typer(help="Docker environment for agent runs: images, internal network, egress proxy.", no_args_is_help=True)
app.add_typer(env_app, name="env")


@env_app.command("build")
def env_build() -> None:
    """Build the agent and proxy images (copies the local claude binary into the build context)."""
    try:
        for line in envmod.build(ContainerSpec()):
            console.print(line)
    except RuntimeError as exc:
        err.print(f"[red]{exc}[/red]", highlight=False)
        raise typer.Exit(1) from exc


@env_app.command("up")
def env_up() -> None:
    """Create the internal network and start the allow-list proxy."""
    try:
        for line in envmod.up(ContainerSpec()):
            console.print(line)
    except RuntimeError as exc:
        err.print(f"[red]{exc}[/red]", highlight=False)
        raise typer.Exit(1) from exc


@env_app.command("down")
def env_down() -> None:
    """Remove the proxy and the network."""
    for line in envmod.down(ContainerSpec()):
        console.print(line)


@env_app.command("check")
def env_check() -> None:
    """Report whether images, network and proxy are in place."""
    st = envmod.status(ContainerSpec())
    for name, ok in (("agent image", st.image), ("proxy image", st.proxy_image), ("internal network", st.network_internal), ("proxy running", st.proxy_running)):
        console.print(f"{'[green]ok[/green]' if ok else '[red]missing[/red]'} {name}")
    raise typer.Exit(0 if st.ready else 1)


def _pct(x: float | None) -> str:
    return "-" if x is None or x != x else f"{100 * x:.0f}%"


@app.command()
def score(
    run: Annotated[list[Path], typer.Option("--run", help="Run directory (repeatable); later ones replace the same run id.")],
    conditions: Annotated[str, typer.Option(help="Comma separated; default all found.")] = "",
    out: Annotated[Path | None, typer.Option(help="Output directory; default results/<first run name>.")] = None,
    seed: Annotated[int, typer.Option(help="Seed for the bootstrap and the sheet sample.")] = 20261101,
    boot: Annotated[int, typer.Option(min=100, help="Bootstrap resamples.")] = 10_000,
    function_cap: Annotated[int, typer.Option(help="The same-function clause only counts within this many lines of the truth (SPEC section 5).")] = FUNCTION_CAP,
    no_function_cap: Annotated[bool, typer.Option("--no-function-cap", help="Sensitivity analysis: same function matches at any distance (the old rule).")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
) -> None:
    """Score runs against the signed ground truth (local, no API calls): recall, recall@3, false alarms, cost, paired bootstrap CIs."""
    cases = _load(dataset)
    wanted = [c.strip() for c in conditions.split(",") if c.strip()]
    loaded = load_records(run, wanted or None)
    rows, unsigned = score_records(loaded.records, cases, None if no_function_cap else function_cap)
    if not rows:
        err.print("[yellow]nothing to score[/yellow]")
        raise typer.Exit(1)
    summary = summarise_scores(rows, seed, boot)
    out_dir = out or Path("results") / run[0].name
    sheet_items, sampled = sample_unmatched(rows, seed)
    previous = read_sheet(out_dir / "unmatched_sheet.csv")
    out_dir.mkdir(parents=True, exist_ok=True)
    write_sheet(out_dir / "unmatched_sheet.csv", sheet_items, previous)
    breakdown = precision_breakdown(rows, {k: v for k, v in read_sheet(out_dir / "unmatched_sheet.csv").items()})
    write_outputs(out_dir, rows, summary, {"unsigned_cases_skipped": unsigned, "excluded_runs": loaded.excluded, "precision_breakdown": breakdown, "sheet_sampled": sampled})

    t = Table("condition", "cases", "runs v/f", "recall (95% CI)", "recall@3", "false alarms", "findings/run", "cost", "$/hit", "skill loaded")
    for s in summary["conditions"]:
        lo, hi = s["recall_ci"]
        t.add_row(
            s["condition"], str(s["cases"]), f"{s['vuln_runs']}/{s['fixed_runs']}", f"{_pct(s['recall'])} ({_pct(lo)}-{_pct(hi)})", _pct(s["recall_at_3"]),
            f"{_pct(s['false_alarm_rate'])} of {s['false_alarm_cases']}" if s["false_alarm_cases"] else "no fixed runs",
            f"{s['findings_per_vuln_run']:.1f}" if s["findings_per_vuln_run"] is not None else "-", _money(s["cost_usd"]),
            _money(s["cost_per_hit"]) if s["cost_per_hit"] is not None else "-", _pct(s["skill_invoked_rate"]),
        )
    console.print(t)
    if any(s["cases"] < 10 for s in summary["conditions"]):
        console.print("[yellow]fewer than 10 cases in some condition: the confidence intervals only describe resampling a handful of cases, not the skill[/yellow]")
    for d in summary["differences"]:
        lo, hi = d["ci"]
        verdict = "interval excludes 0" if lo > 0 or hi < 0 else "interval includes 0: no difference shown"
        console.print(f"{d['condition']} minus A: recall {100 * d['recall_diff']:+.0f} points over {d['paired_cases']} paired case(s), 95% CI [{100 * lo:+.0f}, {100 * hi:+.0f}] ({verdict})", highlight=False)
    if unsigned:
        console.print(f"[yellow]excluded, label not signed: {', '.join(unsigned)}[/yellow]")
    if loaded.excluded:
        console.print(f"[yellow]{len(loaded.excluded)} run(s) excluded (infrastructure error or invalid experiment):[/yellow] " + ", ".join(sorted({e['run_id'] for e in loaded.excluded})[:8]) + (" ..." if len(loaded.excluded) > 8 else ""))
    console.print(f"labelling sheet: {out_dir / 'unmatched_sheet.csv'} ({len(sheet_items)} unmatched finding(s){', sampled' if sampled else ', all'}); fill `label` with {'/'.join(LABELS)}")
    console.print(f"written: {out_dir}/summary.csv, summary.json, per_run.jsonl")


@app.command()
def probe(
    model: Annotated[str, typer.Option(help="Model to probe (the experiment model).")] = DEFAULT_MODEL,
    out: Annotated[Path, typer.Option(help="JSONL file for the answers and verdicts.")] = Path("results/probe.jsonl"),
    yes: Annotated[bool, typer.Option("--yes", help="Confirm that this calls the API (about a cent per case).")] = False,
    dataset: DatasetOpt = DEFAULT_DATASET,
) -> None:
    """Memorisation probe: ask the model what was fixed, with no tools and no code (docs/SPEC.md section 6)."""
    cases = [c for c in _load(dataset) if c.signed]
    if not cases:
        err.print("[yellow]no signed cases[/yellow]")
        raise typer.Exit(0)
    if not yes:
        console.print(f"{len(cases)} case(s) would be probed with {model}; prompt for the first:\n{build_prompt(cases[0])}\nPass --yes to call the API.")
        raise typer.Exit(0)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        err.print("[red]ANTHROPIC_API_KEY is not set[/red]")
        raise typer.Exit(2)
    out.parent.mkdir(parents=True, exist_ok=True)
    import tempfile

    with tempfile.TemporaryDirectory() as empty, out.open("w", encoding="utf-8") as fh:
        for c in cases:
            cmd = ["claude", "-p", build_prompt(c), "--tools", "", "--model", model, "--output-format", "json", "--no-session-persistence",
                   "--setting-sources", "project", "--strict-mcp-config", "--max-budget-usd", "0.1"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=empty, stdin=subprocess.DEVNULL)
            try:
                data = json.loads(res.stdout)
            except ValueError:
                data = {"result": "", "is_error": True}
            answer = str(data.get("result") or "")
            v = judge(c, answer)
            fh.write(json.dumps({"case_id": c.id, "model": model, "answer": answer, "cost_usd": data.get("total_cost_usd"), "names_function": v.names_function,
                                 "names_file": v.names_file, "names_class": v.names_class, "admits_ignorance": v.admits_ignorance, "positive": v.positive}) + "\n")
            console.print(f"{c.id}: positive={v.positive} function={v.names_function} file={v.names_file} class={v.names_class}")
