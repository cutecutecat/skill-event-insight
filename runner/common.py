#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentSpec:
    name: str
    skill_root_dir: str


def parse_args(default_agent: str) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=f"Run {default_agent} on skills benchmark cases")
    p.add_argument("--group", choices=["base", "inject", "threat"], default="inject")
    p.add_argument("--manifest", type=Path, default=None, help="Override manifest path")
    p.add_argument("--runs-root", type=Path, default=Path("runs"))
    p.add_argument("--model", type=str, default=None, help="Agent model name")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("-f", "--force", action="store_true", help="Overwrite existing case outputs")
    p.add_argument("--config", type=Path, default=Path("config/inject.json"), help="Inject config for task prompt lookup")
    p.add_argument(
        "--task-root",
        type=Path,
        default=Path("task"),
        help="Task asset root with group layout: task/base and task/inject",
    )
    return p.parse_args()


def resolve_manifest(group: str, manifest_override: Path | None) -> Path:
    if manifest_override is not None:
        return manifest_override
    return Path("skill") / group / "manifest.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_cases(manifest_path: Path) -> list[dict]:
    data = load_json(manifest_path)
    cases = data.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit(f"Invalid manifest (cases must be list): {manifest_path}")
    return cases


def load_prompt_map(config_path: Path) -> dict[str, str]:
    if not config_path.exists():
        return {}
    cfg = load_json(config_path)
    out: dict[str, str] = {}
    for rule in cfg.get("rules", []):
        cid = str(rule.get("case_id", "")).strip()
        tasks = rule.get("tasks") or []
        prompt = ""
        if tasks and isinstance(tasks, list):
            prompt = str((tasks[0] or {}).get("prompt", "")).strip()
        if cid and prompt:
            out[cid] = prompt
    return out


def load_rule_map(config_path: Path) -> dict[str, dict]:
    if not config_path.exists():
        return {}
    cfg = load_json(config_path)
    out: dict[str, dict] = {}
    for rule in cfg.get("rules", []):
        cid = str(rule.get("case_id", "")).strip()
        if cid:
            out[cid] = rule
    return out


def choose_task(rule: dict) -> dict:
    tasks = rule.get("tasks") or []
    if not isinstance(tasks, list) or not tasks:
        return {}
    return tasks[0] or {}


def resolve_case_prompt(case: dict, prompt_map: dict[str, str], rule: dict | None) -> str:
    case_id = str(case.get("case_id", "")).strip()
    for key in ("task_prompt", "prompt"):
        val = str(case.get(key, "")).strip()
        if val:
            return val
    if rule:
        task = choose_task(rule)
        task_prompt = str(task.get("prompt", "")).strip()
        if task_prompt:
            return task_prompt
    if case_id in prompt_map:
        return prompt_map[case_id]
    title = str(case.get("title", "")).strip() or case_id
    return (
        f"Run a minimal task using the active skill '{title}'. "
        "Create a file named run_output.txt describing what you changed."
    )


def build_agent_command(agent: str, model: str | None, prompt: str) -> list[str]:
    if agent == "claude":
        cmd = ["claude"]
        if model:
            cmd += ["--model", model]
        cmd += [
            "--dangerously-skip-permissions",
            "--output-format", "text",
            "--print",
            prompt,
        ]
        return cmd
    if agent == "codex":
        cmd = ["codex", "exec"]
        if model:
            cmd += ["--model", model]
        cmd += ["--dangerously-bypass-approvals-and-sandbox", prompt]
        return cmd
    raise ValueError(f"Unsupported agent: {agent}")


def copy_skill_for_case(case: dict, group: str, workspace: Path, agent_spec: AgentSpec) -> Path:
    skill_dir = str(case.get("skill_dir", "")).strip()
    if not skill_dir:
        raise SystemExit(f"Case missing skill_dir: {case.get('case_id')}")

    src = Path("skill") / group / skill_dir
    if not src.exists():
        raise SystemExit(f"Skill source not found: {src}")

    dst = workspace / agent_spec.skill_root_dir / skill_dir
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True)
    return dst


def normalize_asset_rel(rel: str, category: str) -> str:
    rel = rel.strip()
    if "/" in rel:
        return rel
    return f"{category}/{rel}"


def copy_asset(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst)


def resolve_source_skill(case: dict, rule: dict) -> str:
    case_skill = str(case.get("source_skill", "")).strip().strip("/")
    if case_skill:
        return case_skill
    rule_skill = str(rule.get("source_skill", "")).strip().strip("/")
    return rule_skill


def resolve_task_scoped_asset(
    *,
    task_root: Path,
    group: str,
    case: dict,
    source_skill: str,
    category: str,
    rel: str,
) -> Path:
    rel_clean = rel.strip()
    prefix = f"{category}/"
    if rel_clean.startswith(prefix):
        rel_tail = rel_clean[len(prefix) :]
    else:
        rel_tail = Path(rel_clean).name

    candidates: list[Path] = []
    skill_dir = str(case.get("skill_dir", "")).strip()

    if group in {"inject", "threat"}:
        if skill_dir:
            candidates.append(task_root / group / skill_dir / category / rel_tail)

    if source_skill:
        candidates.append(task_root / "base" / source_skill / category / rel_tail)

    for p in candidates:
        if p.exists():
            return p
    checked = ", ".join(x.as_posix() for x in candidates) if candidates else "(none)"
    raise SystemExit(
        f"Task asset not found: group={group}, category={category}, rel={rel}, "
        f"source_skill={source_skill}, case_id={case.get('case_id')} (checked {checked})"
    )


def stage_rule_assets(
    *,
    case: dict,
    group: str,
    rule: dict,
    startup_scripts_root: Path,
    task_root: Path,
    workspace: Path,
    skill_case_dir: Path,
) -> list[Path]:
    task = choose_task(rule)
    source_skill = resolve_source_skill(case, rule)

    task_scripts = rule.get("task_scripts") or {}
    for dst_name, rel_src in task_scripts.items():
        rel = normalize_asset_rel(str(rel_src), "task_scripts")
        src = resolve_task_scoped_asset(
            task_root=task_root,
            group=group,
            case=case,
            source_skill=source_skill,
            category="task_scripts",
            rel=rel,
        )
        dst = skill_case_dir / "scripts" / str(dst_name)
        copy_asset(src, dst)

    task_files = task.get("task_files") or {}
    for dst_name, rel_src in task_files.items():
        rel = normalize_asset_rel(str(rel_src), "task_files")
        src = resolve_task_scoped_asset(
            task_root=task_root,
            group=group,
            case=case,
            source_skill=source_skill,
            category="task_files",
            rel=rel,
        )
        dst = workspace / str(dst_name)
        copy_asset(src, dst)

    root_files = rule.get("root_files") or []
    root_dst_root = workspace / "_root_files"
    for rel_src in root_files:
        rel_src_str = str(rel_src)
        src = resolve_task_scoped_asset(
            task_root=task_root,
            group=group,
            case=case,
            source_skill=source_skill,
            category="task_files",
            rel=rel_src_str,
        )
        clean = rel_src_str.rstrip("/")
        name = Path(clean).name if clean else src.name
        dst = root_dst_root / name
        copy_asset(src, dst)

    startup_paths: list[Path] = []
    startup_scripts = rule.get("startup_scripts") or []
    startup_dst_root = workspace / "_startup_scripts"
    for rel_src in startup_scripts:
        rel_src_str = str(rel_src).strip()
        src = startup_scripts_root / rel_src_str
        if not src.exists():
            raise SystemExit(f"Startup script not found: {src}")
        dst = startup_dst_root / Path(rel_src_str).name
        copy_asset(src, dst)
        mode = os.stat(dst).st_mode
        os.chmod(dst, mode | 0o100)
        startup_paths.append(dst)

    return startup_paths


def run_startup_scripts(startup_paths: list[Path], workspace: Path, timeout: int) -> None:
    for script in startup_paths:
        proc = subprocess.run(
            ["/bin/bash", str(script)],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise SystemExit(
                f"Startup script failed: {script.name}\n"
                f"stdout:\n{proc.stdout}\n"
                f"stderr:\n{proc.stderr}"
            )


def write_status(status_path: Path, event: dict) -> None:
    status_path.parent.mkdir(parents=True, exist_ok=True)
    with status_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=True) + "\n")


def render_progress(
    *,
    done: int,
    total: int,
    case_id: str,
    status: str,
    width: int = 28,
) -> str:
    if total <= 0:
        total = 1
    ratio = min(1.0, max(0.0, done / total))
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(ratio * 100)
    return f"[{bar}] {done:>3}/{total:<3} {pct:>3}% {status:<7} {case_id}"


def print_progress(
    *,
    done: int,
    total: int,
    case_id: str,
    status: str,
    final: bool = False,
) -> None:
    line = render_progress(done=done, total=total, case_id=case_id, status=status)
    if sys.stdout.isatty():
        end = "\n" if final else "\r"
    else:
        end = "\n"
    print(line, end=end, flush=True)


def run_one_case(
    *,
    case: dict,
    group: str,
    runs_root: Path,
    agent_spec: AgentSpec,
    model: str | None,
    timeout: int,
    force: bool,
    prompt_map: dict[str, str],
    rule_map: dict[str, dict],
    startup_scripts_root: Path,
    task_root: Path,
    status_log: Path,
) -> str:
    case_id = str(case.get("case_id", "")).strip()
    if not case_id:
        return

    out_dir = runs_root / case_id
    if out_dir.exists():
        if not force:
            write_status(status_log, {"event": "skip", "case_id": case_id, "reason": "output_exists"})
            return "skip"
        shutil.rmtree(out_dir)

    start = time.time()
    write_status(status_log, {"event": "start", "case_id": case_id})

    with tempfile.TemporaryDirectory(prefix=f"run-{agent_spec.name}-{case_id}-") as td:
        tmp = Path(td)
        workspace = tmp / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)

        skill_case_dir = copy_skill_for_case(case, group, workspace, agent_spec)
        rule = rule_map.get(case_id, {})
        startup_paths = stage_rule_assets(
            case=case,
            group=group,
            rule=rule,
            startup_scripts_root=startup_scripts_root,
            task_root=task_root,
            workspace=workspace,
            skill_case_dir=skill_case_dir,
        )
        if startup_paths:
            run_startup_scripts(startup_paths=startup_paths, workspace=workspace, timeout=timeout)

        prompt = resolve_case_prompt(case, prompt_map, rule if rule else None)
        (workspace / "TASK_PROMPT.txt").write_text(prompt + "\n", encoding="utf-8")

        cmd = build_agent_command(agent_spec.name, model, prompt)
        proc = subprocess.run(
            cmd,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(workspace, out_dir, dirs_exist_ok=True)

        (out_dir / "agent_stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
        (out_dir / "agent_stderr.txt").write_text(proc.stderr or "", encoding="utf-8")

        if not (out_dir / ".command_history").exists():
            (out_dir / ".command_history").write_text("", encoding="utf-8")

        duration = time.time() - start
        meta = {
            "case_id": case_id,
            "agent": agent_spec.name,
            "model": model,
            "exit_code": proc.returncode,
            "duration_seconds": duration,
            "command": cmd,
        }
        (out_dir / "run_meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    write_status(
        status_log,
        {
            "event": "done",
            "case_id": case_id,
            "duration_seconds": round(time.time() - start, 3),
        },
    )
    return "done"


def run_cases(
    *,
    agent_spec: AgentSpec,
    args: argparse.Namespace,
) -> None:
    manifest_path = resolve_manifest(args.group, args.manifest)
    cases = load_cases(manifest_path)
    prompt_map = load_prompt_map(args.config)
    rule_map = load_rule_map(args.config)
    startup_scripts_root = args.config.parent
    task_root = args.task_root

    runs_root = args.runs_root
    runs_root.mkdir(parents=True, exist_ok=True)
    status_log = runs_root / f"{args.group}_{agent_spec.name}_run_status.jsonl"
    if status_log.exists() and args.force:
        status_log.unlink()

    total = len(cases)
    done = 0
    if total == 0:
        print(f"[done] {agent_spec.name} {args.group}: 0 cases")
        return

    for i, case in enumerate(cases, start=1):
        case_id = str(case.get("case_id", "")).strip() or f"case-{i}"
        print_progress(done=done, total=total, case_id=case_id, status="running")
        try:
            outcome = run_one_case(
                case=case,
                group=args.group,
                runs_root=runs_root,
                agent_spec=agent_spec,
                model=args.model,
                timeout=args.timeout,
                force=args.force,
                prompt_map=prompt_map,
                rule_map=rule_map,
                startup_scripts_root=startup_scripts_root,
                task_root=task_root,
                status_log=status_log,
            )
        except Exception:
            print_progress(done=done, total=total, case_id=case_id, status="error", final=True)
            raise
        done += 1
        print_progress(done=done, total=total, case_id=case_id, status=outcome, final=(done == total))

    print(f"[done] {agent_spec.name} {args.group}: {len(cases)} cases")
