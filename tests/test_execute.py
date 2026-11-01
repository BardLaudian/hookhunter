from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from wpbench.execute import (
    Context,
    copy_skill,
    execute,
    existing_record,
    extract_findings,
    interpret,
    parse_stream,
    run_one,
)
from wpbench.runplan import ContainerSpec, Run

SCHEMA = json.loads((Path(__file__).parent.parent / "schemas" / "findings.schema.json").read_text())
GOOD = {
    "file": "a.php", "line_start": 1, "line_end": 2, "function": "f", "entry_point": "wp_ajax_x", "cwe": "CWE-79",
    "class": "reflected-xss", "auth_required": "unauthenticated", "data_flow": "a -> b", "confidence": "high",
}


def stream(result_text: str = '{"findings": []}', **over: Any) -> str:
    """Shape recorded from a real claude 2.1.316 stream-json run (docs/DECISIONS.md section 15)."""
    res = {
        "type": "result", "subtype": "success", "is_error": False, "result": result_text, "num_turns": 2, "duration_ms": 2768,
        "duration_api_ms": 2598, "total_cost_usd": 0.0108, "stop_reason": "end_turn", "terminal_reason": "completed", "permission_denials": [],
        "usage": {"input_tokens": 4, "output_tokens": 61, "cache_read_input_tokens": 8690, "cache_creation_input_tokens": 2340},
    } | over
    lines = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Read", "input": {}}]}},
        {"type": "rate_limit_event"},
        {"type": "user", "message": {"content": [{"type": "tool_result"}]}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {}}, {"type": "text", "text": "x"}]}},
        res,
    ]
    return "\n".join(json.dumps(x) for x in lines)


def test_parse_stream_counts_tools_and_skill() -> None:
    p = parse_stream(stream())
    assert p.tool_calls == 2 and p.tools == {"Read": 1, "Skill": 1} and p.skill_invoked
    assert p.result and p.result["num_turns"] == 2
    assert parse_stream("garbage\n[1]\n").result is None


def test_extract_findings_strict_with_fence_tolerance() -> None:
    assert extract_findings('{"findings": []}') == ({"findings": []}, None)
    obj, warn = extract_findings('```json\n{"findings": []}\n```')
    assert obj == {"findings": []} and warn
    obj, warn = extract_findings("Here you go: {}")
    assert obj is None and warn and warn.startswith("not JSON")


def test_interpret_ok_and_metrics() -> None:
    rec = interpret(stream(json.dumps({"findings": [GOOD]})), SCHEMA, 0, False)
    assert rec["status"] == "ok" and len(rec["findings"]) == 1
    assert rec["cost_usd"] == 0.0108 and rec["cache_read_tokens"] == 8690 and rec["turns"] == 2 and rec["skill_invoked"]


def test_invalid_output_is_counted_not_dropped() -> None:
    bad = dict(GOOD, cwe="79")
    assert interpret(stream(json.dumps({"findings": [bad]})), SCHEMA, 0, False)["status"] == "invalid_output"
    assert interpret(stream("prose, no json"), SCHEMA, 0, False)["status"] == "invalid_output"
    extra = json.dumps({"findings": [dict(GOOD, poc="curl ...")]})
    assert interpret(stream(extra), SCHEMA, 0, False)["status"] == "invalid_output"  # no PoC field is allowed


def test_errors_timeouts_and_budget() -> None:
    assert interpret("", SCHEMA, 1, False)["status"] == "error"
    assert interpret(stream(), SCHEMA, -1, True)["status"] == "timeout"
    assert interpret(stream(subtype="error_max_budget_usd", is_error=True), SCHEMA, 1, False)["status"] == "budget"
    assert interpret(stream(subtype="error_during_execution", is_error=True), SCHEMA, 1, False)["status"] == "error"


def make_skill(tmp: Path) -> Path:
    s = tmp / "skill"
    (s / "scripts").mkdir(parents=True)
    (s / "reference").mkdir()
    (s / "tests").mkdir()
    (s / "SKILL.md").write_text("x")
    (s / "scripts" / "a.py").write_text("x")
    (s / "reference" / "r.md").write_text("x")
    (s / "tests" / "fixture.php").write_text("vulnerable fixture")
    return s


def test_copy_skill_parts_never_ships_tests(tmp_path: Path) -> None:
    src = make_skill(tmp_path)
    for parts, expected in (("skill-md", {"SKILL.md"}), ("skill-md+reference", {"SKILL.md", "reference"}), ("full", {"SKILL.md", "reference", "scripts"})):
        dst = tmp_path / parts
        copy_skill(src, dst, parts)
        assert {p.name for p in dst.iterdir()} == expected


def ctx_for(tmp: Path, skill: Path) -> Context:
    return Context(
        exp_dir=tmp / "runs" / "e", cases_dir=tmp / "cases", skill_dirs={"hookhunter": skill, "wp-plugin-triage": skill}, spec=ContainerSpec(),
        model="claude-sonnet-5-5", budget_usd=3, prompt="p", schema=SCHEMA, prompt_sha="p", schema_sha="s", claude_version="2.1.316",
    )


def fake_runner(output: str, cost_calls: list[list[str]]):  # type: ignore[no-untyped-def]
    def runner(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        cost_calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, output, "")
    return runner


def test_run_one_writes_the_record_and_findings(tmp_path: Path) -> None:
    ctx = ctx_for(tmp_path, make_skill(tmp_path))
    calls: list[list[str]] = []
    rec = run_one(Run("wp-0001", "vuln", "C-full", 1), ctx, fake_runner(stream(json.dumps({"findings": [GOOD]})), calls))
    base = ctx.exp_dir / "wp-0001.vuln.C-full.r1"
    assert rec["status"] == "ok" and (base / "findings.json").exists() and (base / "stream.jsonl").exists()
    on_disk = json.loads((base / "record.json").read_text())
    assert on_disk["skill_hash"] and on_disk["model"] == "claude-sonnet-5-5" and on_disk["claude_version"] == "2.1.316"
    assert not (base / "work" / ".claude" / "skills" / "hookhunter" / "tests").exists()
    assert calls[0][0] == "docker"


def test_resume_skips_finished_runs_and_budget_stops(tmp_path: Path) -> None:
    ctx = ctx_for(tmp_path, make_skill(tmp_path))
    plan = [Run("wp-0001", v, "A", 1) for v in ("vuln", "fixed")] + [Run("wp-0002", "vuln", "A", 1)]
    calls: list[list[str]] = []
    out = execute(plan, ctx, max_total_usd=0.015, runner=fake_runner(stream(), calls))  # each run costs 0.0108
    assert out["ran"] == 2 and out["stopped_by_budget"] and out["remaining"] == 1
    calls.clear()
    out = execute(plan, ctx, max_total_usd=1, runner=fake_runner(stream(), calls))
    assert out["ran"] == 1 and out["skipped"] == 2 and len(calls) == 1
    assert existing_record(ctx.exp_dir, plan[0])
