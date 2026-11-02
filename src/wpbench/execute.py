"""Execute planned runs: stage the working directory, run the container, record the result.

One run = one container. Everything a run produced stays under ``runs/<experiment>/<run_id>/``:
``work/`` (what the agent saw), ``stream.jsonl`` (raw transcript), ``stderr.txt``, ``findings.json``
(extracted by the harness: the agent has no Write tool) and ``record.json`` (the metrics).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from wpbench.runplan import CONDITIONS, Condition, ContainerSpec, Run, docker_command, tree_hash

TERMINAL = {"ok", "invalid_output", "budget"}  # not repeated on resume; error and timeout are retried only on request
Sh = Callable[..., "subprocess.CompletedProcess[str]"]
SKILL_EXCLUDE = ("tests", "__pycache__", ".git")


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def copy_skill(src: Path, dst: Path, parts: str) -> None:
    """Copy a skill into ``dst`` according to the condition: SKILL.md only, plus reference, or everything (never tests/)."""
    dst.mkdir(parents=True, exist_ok=True)
    if parts == "skill-md":
        shutil.copy2(src / "SKILL.md", dst / "SKILL.md")
        return
    for item in src.iterdir():
        if item.name in SKILL_EXCLUDE:
            continue
        if parts == "skill-md+reference" and item.name not in ("SKILL.md", "reference"):
            continue
        if item.is_dir():
            shutil.copytree(item, dst / item.name, ignore=shutil.ignore_patterns(*SKILL_EXCLUDE, "*.pyc"))
        else:
            shutil.copy2(item, dst / item.name)


def stage(run: Run, cond: Condition, skill_dirs: dict[str, Path], exp_dir: Path) -> Path:
    base = exp_dir / run.run_id
    if base.exists():
        shutil.rmtree(base)
    work, out = base / "work", base / "out"
    (work / "plugin").mkdir(parents=True)  # mount point of the read-only plugin tree
    out.mkdir()
    out.chmod(0o777)  # the container user (uid 1000) must be able to write /out
    if cond.skill:
        copy_skill(skill_dirs[cond.skill], work / ".claude" / "skills" / cond.skill, cond.parts)
    if cond.bash_scripts:
        install_bash_guard(work)
    return base


def install_bash_guard(work: Path) -> None:
    """Project settings with a PreToolUse hook that restricts Bash to the skill's scripts."""
    claude = work / ".claude"
    claude.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(__file__).parent / "data" / "bash_guard.py", claude / "bash_guard.py")
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/bash_guard.py"'}]}]}}
    (claude / "settings.json").write_text(json.dumps(settings, indent=1), encoding="utf-8")


@dataclass
class Parsed:
    result: dict[str, Any] | None = None
    tool_calls: int = 0
    tools: dict[str, int] = field(default_factory=dict)
    skill_invoked: bool = False


def parse_stream(text: str) -> Parsed:
    p = Parsed()
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "result":
            p.result = ev
        elif ev.get("type") == "assistant":
            content = ev.get("message", {}).get("content")
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    name = str(block.get("name"))
                    p.tool_calls += 1
                    p.tools[name] = p.tools.get(name, 0) + 1
                    if name == "Skill":
                        p.skill_invoked = True
    return p


FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def extract_findings(text: str) -> tuple[Any, str | None]:
    """The final message must be the JSON object. A code fence is tolerated but recorded; anything else is invalid."""
    raw = text.strip()
    warning = None
    m = FENCE.match(raw)
    if m:
        raw, warning = m.group(1), "output was wrapped in a code fence"
    try:
        return json.loads(raw), warning
    except ValueError as exc:
        return None, f"not JSON: {exc}"


def validate_findings(obj: Any, schema: dict[str, Any]) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(str(x) for x in e.absolute_path) or '<root>'}: {e.message}" for e in validator.iter_errors(obj)]


def interpret(stdout: str, schema: dict[str, Any], returncode: int, timed_out: bool) -> dict[str, Any]:
    """Turn the raw stream into the metric part of a record."""
    parsed = parse_stream(stdout)
    rec: dict[str, Any] = {"tool_calls": parsed.tool_calls, "tools": parsed.tools, "skill_invoked": parsed.skill_invoked, "findings": None}
    res = parsed.result
    if res:
        usage = res.get("usage") or {}
        rec.update(
            cost_usd=res.get("total_cost_usd"), wall_ms=res.get("duration_ms"), api_ms=res.get("duration_api_ms"), turns=res.get("num_turns"),
            stop_reason=res.get("stop_reason"), terminal_reason=res.get("terminal_reason"), subtype=res.get("subtype"),
            input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"),
            cache_read_tokens=usage.get("cache_read_input_tokens"), cache_write_tokens=usage.get("cache_creation_input_tokens"),
            permission_denials=len(res.get("permission_denials") or []),
        )
    if timed_out:
        rec["status"] = "timeout"
    elif res is None:
        rec.update(status="error", detail=f"no result event (exit {returncode})")
    elif res.get("is_error") or res.get("subtype") != "success":
        status = "budget" if "budget" in str(res.get("subtype")) else "error"
        rec.update(status=status, detail=f"{res.get('subtype')}: {str(res.get('result'))[:200]}")
    else:
        obj, warn = extract_findings(str(res.get("result") or ""))
        errors = [warn] if obj is None and warn else validate_findings(obj, schema) if obj is not None else []
        if warn and obj is not None:
            rec["format_warning"] = warn
        if errors:
            rec.update(status="invalid_output", detail="; ".join(errors)[:500])
        else:
            rec.update(status="ok", findings=obj["findings"] if obj else [])
    return rec


def run_one(
    run: Run, ctx: Context, runner: Sh = subprocess.run,
) -> dict[str, Any]:
    cond = CONDITIONS[run.condition]
    base = stage(run, cond, ctx.skill_dirs, ctx.exp_dir)
    cmd = docker_command(run, cond, ctx.spec, ctx.cases_dir, ctx.exp_dir, ctx.model, ctx.budget_usd, cond.prompt_prefix + ctx.prompt)
    started = now()
    t0 = time.monotonic()
    timed_out = False
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=ctx.timeout_s, check=False, stdin=subprocess.DEVNULL)
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout) or ""
        stderr, code = "timeout", -1
        runner(["docker", "rm", "-f", f"wpbench-{run.run_id}".replace(".", "-")], capture_output=True, text=True, check=False)
    (base / "stream.jsonl").write_text(stdout, encoding="utf-8")
    (base / "stderr.txt").write_text(stderr, encoding="utf-8")
    rec = interpret(stdout, ctx.schema, code, timed_out)
    if rec.get("findings") is not None:
        (base / "findings.json").write_text(json.dumps({"findings": rec["findings"]}, indent=1), encoding="utf-8")
    rec.update(
        run_id=run.run_id, case_id=run.case_id, version=run.version, condition=run.condition, repeat=run.repeat,
        model=ctx.model, started=started, finished=now(), wall_s=round(time.monotonic() - t0, 1), exit_code=code,
        skill_hash=tree_hash(base / "work" / ".claude" / "skills" / cond.skill) if cond.skill else None,
        prompt_sha256=ctx.prompt_sha, prompt_prefix=cond.prompt_prefix, schema_sha256=ctx.schema_sha, claude_version=ctx.claude_version, budget_usd=ctx.budget_usd,
    )
    (base / "record.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


@dataclass
class Context:
    exp_dir: Path
    cases_dir: Path
    skill_dirs: dict[str, Path]
    spec: ContainerSpec
    model: str
    budget_usd: float
    prompt: str
    schema: dict[str, Any]
    timeout_s: int = 2400
    prompt_sha: str = ""
    schema_sha: str = ""
    claude_version: str = ""


def existing_record(exp_dir: Path, run: Run) -> dict[str, Any] | None:
    path = exp_dir / run.run_id / "record.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def execute(
    plan: Sequence[Run], ctx: Context, jobs: int = 1, max_total_usd: float = 50.0, retry_errors: bool = False,
    runner: Sh = subprocess.run, on_done: Callable[[Run, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run the plan with resume. Stops starting new runs once the spent total reaches ``max_total_usd``."""
    ctx.exp_dir.mkdir(parents=True, exist_ok=True)
    spent = 0.0
    lock = threading.Lock()
    skipped = ran = 0
    stopped = False
    todo: list[Run] = []
    for r in plan:
        rec = existing_record(ctx.exp_dir, r)
        if rec:
            spent += float(rec.get("cost_usd") or 0)
            if rec.get("status") in TERMINAL or not retry_errors:
                skipped += 1
                continue
        todo.append(r)

    def work(r: Run) -> None:
        nonlocal spent, ran, stopped
        with lock:
            if spent >= max_total_usd:
                stopped = True
                return
        rec = run_one(r, ctx, runner)
        with lock:
            spent += float(rec.get("cost_usd") or 0)
            ran += 1
        if on_done:
            on_done(r, rec)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        list(pool.map(work, todo))
    return {"ran": ran, "skipped": skipped, "spent_usd": round(spent, 4), "stopped_by_budget": stopped, "remaining": len(todo) - ran}
