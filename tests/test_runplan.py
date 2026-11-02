from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from wpbench.cli import app
from wpbench.runplan import (
    CONDITIONS,
    PRICES,
    SCENARIOS,
    ContainerSpec,
    Run,
    build_plan,
    claude_args,
    default_skill_dirs,
    docker_command,
    estimate_run,
    source_tokens,
    tree_hash,
)

runner = CliRunner()


def test_plan_is_the_full_matrix() -> None:
    class C:
        def __init__(self, i: str) -> None:
            self.id = i

    plan = build_plan([C("a"), C("b")], ["A", "B"], 2)  # type: ignore[list-item]
    assert len(plan) == 2 * 2 * 2 * 2
    assert {r.version for r in plan} == {"vuln", "fixed"}
    assert len({r.run_id for r in plan}) == len(plan)


def test_a_has_no_bash_and_only_c_full_gets_scoped_bash() -> None:
    assert "Bash" not in CONDITIONS["A"].tools and "Bash" not in CONDITIONS["B"].tools
    assert "Bash" not in CONDITIONS["C-min"].tools and "Bash" not in CONDITIONS["C-noscripts"].tools
    assert "Bash" in CONDITIONS["C-full"].tools
    assert CONDITIONS["C-full"].allowed_tools()[-1] == "Bash(python3 .claude/skills/hookhunter/scripts/*)"


def test_conditions_with_a_skill_can_call_the_skill_tool() -> None:
    # pilot-1 lost conditions B and C because --tools Read,Grep,Glob removed the Skill tool
    assert "Skill" not in CONDITIONS["A"].tools
    for name in ("B", "C-full", "C-min", "C-noscripts"):
        cond = CONDITIONS[name]
        assert "Skill" in cond.tools and f"Skill({cond.skill})" in cond.allowed_tools()


def test_claude_args_isolate_the_run() -> None:
    args = claude_args(CONDITIONS["A"], "claude-sonnet-5-5", 3, "p")
    assert args[args.index("--tools") + 1] == "Read,Grep,Glob"
    for flag in ("--strict-mcp-config", "--no-session-persistence"):
        assert flag in args
    assert args[args.index("--setting-sources") + 1] == "project"
    assert "WebFetch" not in " ".join(args) and "WebSearch" not in " ".join(args)


def test_docker_command_is_locked_down(tmp_path: Path) -> None:
    run = Run("wp-0001", "vuln", "A", 1)
    cmd = docker_command(run, CONDITIONS["A"], ContainerSpec(), tmp_path / "cases", tmp_path / "runs", "m", 3, "p")
    joined = " ".join(cmd)
    assert "--network none" not in joined and "--network wpbench-egress" in joined
    assert "--read-only" in cmd and "--cap-drop" in cmd
    assert f"{tmp_path / 'cases' / 'wp-0001' / 'vuln'}:/work/plugin:ro" in joined
    assert [x for x in cmd if x.startswith("ANTHROPIC_API_KEY=")] == []  # the key is passed by name, never by value


def test_estimate_grows_with_size_and_scenario() -> None:
    price = PRICES["claude-sonnet-5-5"]
    low, mid, high = (estimate_run(300_000, CONDITIONS["A"], s, price).cost for s in SCENARIOS)
    assert 0 < low < mid < high
    assert estimate_run(600_000, CONDITIONS["A"], SCENARIOS[1], price).cost > estimate_run(100_000, CONDITIONS["A"], SCENARIOS[1], price).cost
    assert estimate_run(300_000, CONDITIONS["C-full"], SCENARIOS[1], price).cost > estimate_run(300_000, CONDITIONS["A"], SCENARIOS[1], price).cost


def test_source_tokens_skips_vendor(tmp_path: Path) -> None:
    (tmp_path / "a.php").write_text("x" * 400)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "b.php").write_text("x" * 4000)
    assert source_tokens(tmp_path) == 100
    assert source_tokens(tmp_path / "missing") is None


def test_tree_hash_changes_with_content(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("1")
    a = tree_hash(tmp_path)
    (tmp_path / "f").write_text("2")
    assert a != tree_hash(tmp_path)


def test_default_skill_dirs_finds_user_scope_copy(tmp_path: Path) -> None:
    d = tmp_path / ".claude" / "skills" / "synced" / "x" / "wp-plugin-triage"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\n---\n")
    assert default_skill_dirs(tmp_path, tmp_path)["wp-plugin-triage"] == d


def test_run_refuses_to_execute_and_dry_run_starts_nothing(tmp_path: Path) -> None:
    assert runner.invoke(app, ["run"]).exit_code == 2
    res = runner.invoke(app, ["run", "--dry-run", "--cases-dir", str(tmp_path / "none")])
    assert res.exit_code == 0 and "Plan" in res.output and "not executed" in res.output


def test_b_invoked_differs_from_b_only_by_the_prompt_line() -> None:
    b, bi = CONDITIONS["B"], CONDITIONS["B-invoked"]
    assert (b.skill, b.parts, b.tools, b.allowed_tools()) == (bi.skill, bi.parts, bi.tools, bi.allowed_tools())
    assert b.prompt_prefix == "" and "wp-plugin-triage" in bi.prompt_prefix
    assert all(c.prompt_prefix == "" for n, c in CONDITIONS.items() if n != "B-invoked")
