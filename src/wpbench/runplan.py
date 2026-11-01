"""Run planning: conditions, the run matrix, the container command and a cost/time estimate.

Nothing here talks to the network or starts a process, so ``wpbench run --dry-run`` is safe to run
anywhere. The estimate is a *model with stated assumptions*, not a measurement: the pilot replaces it.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from wpbench.cases import Case

DEFAULT_MODEL = "claude-sonnet-5-5"
VERSIONS = ("vuln", "fixed")
BASE_TOOLS = ("Read", "Grep", "Glob")


@dataclass(frozen=True)
class Condition:
    name: str
    skill: str | None  # folder name under .claude/skills/
    parts: str  # what of the skill is copied: none | skill-md | skill-md+reference | full
    bash_scripts: bool  # scoped Bash for the skill's own scripts (docs/DECISIONS.md section 15)
    extra_context_tokens: int  # tokens the skill adds to the context in the mid scenario (assumption)
    description: str

    @property
    def tools(self) -> tuple[str, ...]:
        return (*BASE_TOOLS, "Bash") if self.bash_scripts else BASE_TOOLS

    def allowed_tools(self) -> list[str]:
        allowed = list(BASE_TOOLS)
        if self.bash_scripts and self.skill:
            allowed.append(f"Bash(python3 .claude/skills/{self.skill}/scripts/*)")
        return allowed


CONDITIONS: dict[str, Condition] = {
    c.name: c
    for c in (
        Condition("A", None, "none", False, 0, "no skill"),
        Condition("B", "wp-plugin-triage", "full", False, 2_500, "wp-plugin-triage v1"),
        Condition("C-full", "hookhunter", "full", True, 28_000, "hookhunter, whole skill (scripts through scoped Bash)"),
        Condition("C-min", "hookhunter", "skill-md", False, 3_000, "hookhunter: SKILL.md only"),
        Condition("C-noscripts", "hookhunter", "skill-md+reference", False, 18_000, "hookhunter: SKILL.md + reference, no scripts"),
    )
}


@dataclass(frozen=True)
class Price:
    """US dollars per million tokens."""

    input: float
    output: float
    cache_read: float
    cache_write: float


# Source: Claude API model table cached 2026-10-06 (Sonnet 5.5: $2 / $10, cache reads $0.20; 5 minute cache write = 1.25 x input).
PRICES: dict[str, Price] = {"claude-sonnet-5-5": Price(2.0, 10.0, 0.20, 2.50)}


@dataclass(frozen=True)
class Scenario:
    """How much of the code the agent reads and how long it works. All three are assumptions."""

    name: str
    read_fraction: float  # share of the PHP source (without vendor/) that ends up in the context
    turns: int  # model calls in the run
    output_tokens: int  # visible output + thinking
    seconds_per_turn: float = 6.0


SCENARIOS = (
    Scenario("low", 0.15, 25, 8_000),
    Scenario("mid", 0.35, 45, 20_000),
    Scenario("high", 0.70, 80, 40_000),
)
BASE_CONTEXT_TOKENS = 14_000  # Claude Code system prompt + tool schemas + task prompt (assumption)
OUTPUT_TOKENS_PER_SECOND = 60.0


@dataclass(frozen=True)
class Run:
    case_id: str
    version: str  # vuln | fixed
    condition: str
    repeat: int

    @property
    def run_id(self) -> str:
        return f"{self.case_id}.{self.version}.{self.condition}.r{self.repeat}"


def build_plan(cases: Iterable[Case], conditions: Iterable[str], repeats: int, versions: Iterable[str] = VERSIONS) -> list[Run]:
    plan = [
        Run(c.id, v, cond, r)
        for c in cases
        for v in versions
        for cond in conditions
        for r in range(1, repeats + 1)
    ]
    return plan


def source_tokens(tree: Path) -> int | None:
    """Rough token count of the PHP in a tree, vendor/ excluded (4 bytes per token). None if the tree is missing."""
    if not tree.is_dir():
        return None
    total = 0
    for path in tree.rglob("*.php"):
        rel = path.relative_to(tree).parts
        if "vendor" in rel:
            continue
        total += path.stat().st_size
    return total // 4


@dataclass(frozen=True)
class Estimate:
    cost: float
    seconds: float
    input_tokens: int
    output_tokens: int


def estimate_run(src_tokens: int, condition: Condition, scenario: Scenario, price: Price) -> Estimate:
    """Cost of one run under a scenario.

    The agent loop resends the whole context every turn. With prompt caching the stable prefix is read at the
    cache-read rate; each new token is written to the cache once. Context grows linearly from ``base`` to ``base + read``.
    """
    base = BASE_CONTEXT_TOKENS + condition.extra_context_tokens
    read = int(src_tokens * scenario.read_fraction)
    final = base + read
    turns = scenario.turns
    cache_read_tokens = turns * base + read * (turns + 1) // 2
    cost = (
        final * price.cache_write
        + cache_read_tokens * price.cache_read
        + scenario.output_tokens * price.output
    ) / 1_000_000
    seconds = turns * scenario.seconds_per_turn + scenario.output_tokens / OUTPUT_TOKENS_PER_SECOND
    return Estimate(cost, seconds, final + cache_read_tokens, scenario.output_tokens)


def claude_args(cond: Condition, model: str, budget_usd: float, prompt: str) -> list[str]:
    """Arguments after ``claude`` (flags confirmed against 2.1.316, docs/DECISIONS.md section 3)."""
    return [
        "-p", prompt,
        "--output-format", "json",
        "--model", model,
        "--tools", ",".join(cond.tools),
        "--allowedTools", ",".join(cond.allowed_tools()),
        "--strict-mcp-config",
        "--setting-sources", "project",
        "--no-session-persistence",
        "--max-budget-usd", f"{budget_usd:g}",
    ]


@dataclass(frozen=True)
class ContainerSpec:
    image: str = "wpbench-agent:1"
    network: str = "wpbench-egress"
    proxy: str = "http://wpbench-proxy:3128"
    memory: str = "2g"
    cpus: str = "2"


def docker_command(run: Run, cond: Condition, spec: ContainerSpec, cases_dir: Path, run_dir: Path, model: str, budget_usd: float, prompt: str) -> list[str]:
    """The ``docker run`` line for one run. Plugin and workdir are read-only; only /out is writable."""
    plugin = (cases_dir / run.case_id / run.version).resolve()
    work = (run_dir / run.run_id / "work").resolve()
    out = (run_dir / run.run_id / "out").resolve()
    cmd = [
        "docker", "run", "--rm", "--name", f"wpbench-{run.run_id}".replace(".", "-"),
        "--network", spec.network,
        "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/home/agent:uid=1000,gid=1000",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", spec.memory, "--cpus", spec.cpus, "--pids-limit", "256",
        "-e", "ANTHROPIC_API_KEY", "-e", f"HTTPS_PROXY={spec.proxy}", "-e", f"HTTP_PROXY={spec.proxy}",
        "-e", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "-e", "DISABLE_TELEMETRY=1", "-e", "HOME=/home/agent",
        "-v", f"{work}:/work:ro", "-v", f"{plugin}:/work/plugin:ro", "-v", f"{out}:/out",
        "-w", "/work",
        spec.image, "claude", *claude_args(cond, model, budget_usd, prompt),
    ]
    return cmd


def tree_hash(path: Path) -> str | None:
    """Stable SHA-256 over file names and contents, to record exactly which skill version a run used."""
    if not path.exists():
        return None
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    for p in files:
        digest.update(str(p.relative_to(path.parent if path.is_file() else path)).encode())
        digest.update(p.read_bytes())
    return digest.hexdigest()


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    blocking: bool = True


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return all(c.ok for c in self.checks if c.blocking)


def preflight(cases: list[Case], conditions: list[str], cases_dir: Path, skill_dirs: dict[str, Path], spec: ContainerSpec, prompt_file: Path) -> Preflight:
    pf = Preflight()
    unsigned = [c.id for c in cases if not c.signed]
    pf.checks.append(Check("labels signed", not unsigned, "all signed" if not unsigned else f"unsigned: {', '.join(unsigned)}", blocking=False))
    missing = [f"{c.id}/{v}" for c in cases for v in VERSIONS if not (cases_dir / c.id / f".{v}.ok").exists()]
    pf.checks.append(Check("releases fetched and hash-checked", not missing, "all present" if not missing else f"missing: {', '.join(missing)}"))
    for name in conditions:
        skill = CONDITIONS[name].skill
        if skill:
            src = skill_dirs.get(skill)
            pf.checks.append(Check(f"skill source for {name}", bool(src and src.exists()), str(src) if src else "no path configured"))
    pf.checks.append(Check("task prompt", prompt_file.exists(), str(prompt_file)))
    pf.checks.append(Check("ANTHROPIC_API_KEY set", bool(os.environ.get("ANTHROPIC_API_KEY")), "set" if os.environ.get("ANTHROPIC_API_KEY") else "not set (the pilot needs it; dry run does not)", blocking=False))
    return pf


def plan_summary(plan: list[Run]) -> dict[str, int]:
    return {"runs": len(plan), "cases": len({r.case_id for r in plan}), "conditions": len({r.condition for r in plan})}


def to_json(plan: list[Run]) -> str:
    return json.dumps([r.__dict__ | {"run_id": r.run_id} for r in plan], indent=1)


def default_skill_dirs(root: Path = Path("."), home: Path | None = None) -> dict[str, Path]:
    """Where each skill is copied from. B lives in the user scope (it is not part of this repo): the first match wins."""
    home = home or Path.home()
    found = sorted((home / ".claude" / "skills").glob("**/wp-plugin-triage/SKILL.md")) if (home / ".claude" / "skills").exists() else []
    b = found[0].parent if found else home / ".claude" / "skills" / "wp-plugin-triage"
    return {"hookhunter": root / "skills" / "hookhunter", "wp-plugin-triage": b}


def project(counts: dict[str, int], mean_src_tokens: int, scenario: Scenario, model: str = DEFAULT_MODEL) -> Estimate:
    """Total for a number of runs per condition, using the mean plugin size."""
    cost = seconds = 0.0
    tin = tout = 0
    for name, n in counts.items():
        e = estimate_run(mean_src_tokens, CONDITIONS[name], scenario, PRICES[model])
        cost += e.cost * n
        seconds += e.seconds * n
        tin += e.input_tokens * n
        tout += e.output_tokens * n
    return Estimate(cost, seconds, tin, tout)
