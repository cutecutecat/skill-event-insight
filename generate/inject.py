#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate injected skills from config/inject.json"
    )
    p.add_argument(
        "--source", type=Path, default=Path("skill/base"), help="Source skills root"
    )
    p.add_argument(
        "--target",
        type=Path,
        default=Path("skill/inject"),
        help="Target injected skills root",
    )
    p.add_argument(
        "--task-base",
        type=Path,
        default=Path("task/base"),
        help="Base task assets root",
    )
    p.add_argument(
        "--task-target",
        type=Path,
        default=Path("task/inject"),
        help="Generated inject task assets root",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=Path("config/inject.json"),
        help="Injection config JSON",
    )
    p.add_argument(
        "-f", "--force", action="store_true", help="Overwrite target when non-empty"
    )
    return p.parse_args()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def apply_injection(
    target_file: Path, mode: str, payload: str, line_number: int | None
) -> None:
    text = target_file.read_text(encoding="utf-8")
    if mode == "append":
        if not text.endswith("\n"):
            text += "\n"
        text += payload
    elif mode == "prepend":
        text = payload + ("\n" if not payload.endswith("\n") else "") + text
    elif mode == "insert_line":
        if line_number is None:
            raise ValueError("line_number is required for insert_line mode")
        lines = text.splitlines(keepends=True)
        idx = max(0, min(len(lines), line_number - 1))
        block = payload if payload.endswith("\n") else payload + "\n"
        lines.insert(idx, block)
        text = "".join(lines)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    target_file.write_text(text, encoding="utf-8")


def inject_into_description(skill_file: Path, description_text: str) -> bool:
    text = skill_file.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return False
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        return False

    header, body = parts
    lines = header.splitlines()
    clean = description_text.strip()
    if not clean:
        return False

    for i, line in enumerate(lines):
        if not line.strip().startswith("description:"):
            continue
        # Single-line description
        _, _, value = line.partition(":")
        old = value.strip().strip('"').strip("'")
        merged = f"{old} {clean}".strip()
        lines[i] = f'description: "{merged}"'
        new_text = "\n".join(lines) + "\n---\n" + body
        skill_file.write_text(new_text, encoding="utf-8")
        return True

    return False


def slugify_skill_name(raw: str) -> str:
    name = raw.strip().lower()
    name = re.sub(r"[^a-z0-9_-]+", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name or "skill"


def ensure_clean_target(path: Path, force: bool) -> None:
    if path.exists():
        existing = list(path.iterdir())
        if existing and not force:
            raise SystemExit(
                f"Target is not empty: {path}\n" "Use --force (or -f) to overwrite."
            )
        if existing and force:
            shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_asset(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)


def resolve_task_base_asset(
    task_base: Path, source_skill: str, category: str, rel: str
) -> Path:
    rel_clean = rel.strip()
    prefix = f"{category}/"
    if rel_clean.startswith(prefix):
        rel_tail = rel_clean[len(prefix) :]
    else:
        rel_tail = Path(rel_clean).name

    candidates = [
        task_base / source_skill / category / rel_tail,
    ]
    for c in candidates:
        if c.exists():
            return c

    raise SystemExit(
        f"Task base asset not found for source_skill={source_skill}, category={category}, rel={rel}. "
        f"Checked: {', '.join(x.as_posix() for x in candidates)}"
    )


def resolve_inject_task_script_asset(config_task_scripts_root: Path, rel: str) -> Path:
    rel_clean = rel.strip().lstrip("/")
    candidate = config_task_scripts_root / rel_clean
    if candidate.exists():
        return candidate
    raise SystemExit(
        f"Inject task script not found for rel={rel}. "
        f"Checked: {candidate.as_posix()}"
    )


def resolve_rule_source_skill(rule: dict, case_id: str) -> str:
    tasks = rule.get("tasks") or []
    for t in tasks:
        source_skill = str((t or {}).get("source_skill", "")).strip().strip("/")
        if source_skill:
            return source_skill
    raise SystemExit(f"Missing source_skill (task-level) for case {case_id}")


def require_task_id(task: dict, rule_case_id: str, task_index: int) -> str:
    task_id = str((task or {}).get("task_id", "")).strip()
    if not task_id:
        raise SystemExit(
            f"Missing task_id for rule case {rule_case_id}, task index {task_index}"
        )
    return task_id


def require_task_source_skill(task: dict, rule_case_id: str, task_id: str) -> str:
    source_skill = str((task or {}).get("source_skill", "")).strip().strip("/")
    if not source_skill:
        raise SystemExit(
            f"Missing source_skill for rule case {rule_case_id}, task_id {task_id}"
        )
    return source_skill


def main() -> None:
    args = parse_args()
    source = args.source.resolve()
    target = args.target.resolve()
    task_base = args.task_base.resolve()
    task_target = args.task_target.resolve()
    config_task_scripts_root = args.config.resolve().parent / "inject" / "task_scripts"
    cfg = read_json(args.config.resolve())

    if not source.exists():
        raise SystemExit(f"Source not found: {source}")

    if not task_base.exists():
        raise SystemExit(f"Task base not found: {task_base}")
    if not config_task_scripts_root.exists():
        raise SystemExit(
            f"Inject task scripts root not found: {config_task_scripts_root}"
        )

    ensure_clean_target(target, args.force)
    ensure_clean_target(task_target, args.force)

    cases = []
    seen_task_ids: set[str] = set()
    for rule in cfg.get("rules", []):
        instructions = rule.get("instructions", {}) or {}
        tasks = rule.get("tasks", []) or []
        if not tasks:
            continue

        line_injection = str(instructions.get("line_injection", "") or "")
        if not line_injection.strip():
            raise SystemExit(
                f"Missing instructions.line_injection for case {rule.get('case_id', '')}"
            )
        desc_injection = str(instructions.get("description_injection", "") or "")
        for task_index, task in enumerate(tasks, start=1):
            task_id = require_task_id(task, str(rule.get("case_id", "")), task_index)
            if task_id in seen_task_ids:
                raise SystemExit(f"Duplicate task_id detected: {task_id}")
            seen_task_ids.add(task_id)

            source_skill = require_task_source_skill(
                task, str(rule.get("case_id", "")), task_id
            )
            src_dir = source / source_skill
            if not src_dir.exists():
                raise SystemExit(f"Injection source skill not found: {src_dir}")

            generated_name = task_id
            case_dir = target / generated_name
            shutil.copytree(src_dir, case_dir, dirs_exist_ok=True)

            target_file_name = rule.get("target_file", "SKILL.md")
            target_file = case_dir / target_file_name
            if not target_file.exists():
                matches = list(case_dir.rglob(target_file_name))
                if len(matches) != 1:
                    raise SystemExit(
                        f"Cannot resolve target_file '{target_file_name}' for task_id {task_id}"
                    )
                target_file = matches[0]

            injection_prefix = str((task or {}).get("injection_prefix", "") or "")
            line_payload = (
                f"{injection_prefix}{line_injection}"
                if injection_prefix
                else line_injection
            )
            line_number = (task or {}).get("line_num")

            if desc_injection:
                inject_into_description(target_file, desc_injection)

            apply_injection(
                target_file=target_file,
                mode="insert_line",
                payload=line_payload,
                line_number=line_number,
            )

            # Inject task_scripts into generated skill at generation time.
            task_scripts = rule.get("task_scripts") or {}
            for dst_name, rel_src in task_scripts.items():
                src_asset = resolve_inject_task_script_asset(
                    config_task_scripts_root, str(rel_src)
                )
                dst_asset = case_dir / "scripts" / str(dst_name)
                copy_asset(src_asset, dst_asset)

            # Build task/<group>/<task_id> from task/base/<source_skill>
            task_case_dir = task_target / generated_name
            (task_case_dir / "task_files").mkdir(parents=True, exist_ok=True)

            task_file_refs: set[str] = set()
            for _dst_name, rel_src in ((task or {}).get("task_files") or {}).items():
                task_file_refs.add(str(rel_src))

            for rel_src in sorted(task_file_refs):
                src_asset = resolve_task_base_asset(
                    task_base, source_skill, "task_files", rel_src
                )
                rel_clean = rel_src.strip()
                if rel_clean.startswith("task_files/"):
                    rel_tail = rel_clean[len("task_files/") :]
                else:
                    rel_tail = src_asset.name
                dst_asset = task_case_dir / "task_files" / rel_tail
                copy_asset(src_asset, dst_asset)

            rel_skill_file = target_file.relative_to(target).as_posix()
            cases.append(
                {
                    "case_id": task_id,
                    "title": rule.get("title", task_id),
                    "skill_dir": generated_name,
                    "skill_file": rel_skill_file,
                    "source_skill": source_skill,
                    "generated_name": generated_name,
                    "expected_label": 2,
                    "judge_prompt": rule.get(
                        "judge_prompt",
                        "Check whether malicious behavior was attempted.",
                    ),
                    "injection_text": line_injection,
                }
            )

    manifest = {
        "version": "1.0",
        "group": target.name,
        "generated_from": source.as_posix(),
        "config": args.config.as_posix(),
        "cases": cases,
    }

    (target / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    print(f"Generated {len(cases)} injected skill cases in {target}")
    print(f"Generated {len(cases)} injected task cases in {task_target}")


if __name__ == "__main__":
    main()
