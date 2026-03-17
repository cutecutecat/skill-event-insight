#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Synthesize final report from attack_result and dumped events")
    p.add_argument("--group", type=str, required=True, help="Case group")
    p.add_argument(
        "--runs-root",
        type=Path,
        default=Path("runs"),
        help="Runs root; reads runs-root/<group>/attack_result.json and runs-root/<group>/*/event.full.json",
    )
    p.add_argument("--output-json", type=Path, default=None, help="Output report json path (default: runs-root/<group>/report.json)")
    p.add_argument("--output-md", type=Path, default=None, help="Output report markdown path (default: runs-root/<group>/report.md)")
    p.add_argument("-f", "--force", action="store_true", help="Overwrite outputs when they exist")
    return p.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def event_blob(case_dump: dict[str, Any]) -> str:
    if "events" in case_dump:
        try:
            return json.dumps(case_dump["events"], ensure_ascii=True).lower()
        except Exception:
            return ""
    if "events_raw" in case_dump:
        return str(case_dump["events_raw"]).lower()
    return ""


def load_case_dump_map(group_root: Path) -> tuple[dict[str, dict[str, Any]], str]:
    dump_map: dict[str, dict[str, Any]] = {}
    matched = 0
    for case_dir in sorted(group_root.iterdir(), key=lambda p: p.name):
        if not case_dir.is_dir():
            continue
        case_event_path = case_dir / "event.full.json"
        if not case_event_path.exists():
            case_event_path = case_dir / "event.json"
            if not case_event_path.exists():
                continue
        matched += 1
        case_dump_file = read_json(case_event_path)
        case_dump = case_dump_file.get("case", {}) if isinstance(case_dump_file, dict) else {}
        if not isinstance(case_dump, dict):
            continue
        case_id = str(case_dump.get("case_id", "")).strip() or case_dir.name
        dump_map[case_id] = case_dump

    if matched == 0:
        raise SystemExit(
            f"Missing events dump files: {group_root.as_posix()}/*/event.full.json "
            f"(or legacy event.json)"
        )
    return dump_map, f"{group_root.as_posix()}/*/event.full.json"


def main() -> None:
    args = parse_args()
    group_root = args.runs_root / args.group
    attack_result_path = group_root / "attack_result.json"
    if not attack_result_path.exists():
        raise SystemExit(f"Missing attack_result file: {attack_result_path}")

    inter = read_json(attack_result_path)
    dump_map, events_dump_source = load_case_dump_map(group_root)

    merged_results = []
    for row in inter.get("results", []):
        case_id = str(row.get("case_id", ""))
        case_dump = dump_map.get(case_id, {})

        merged = dict(row)
        merged["watchu_event"] = {
            "source": case_dump.get("event_source"),
            "count": case_dump.get("event_count", 0),
            "status": case_dump.get("status", "ok"),
            "has_events": bool(event_blob(case_dump)),
        }
        merged_results.append(merged)

    total = len(merged_results)
    c0 = sum(1 for r in merged_results if r.get("label") == 0)
    c1 = sum(1 for r in merged_results if r.get("label") == 1)
    c2 = sum(1 for r in merged_results if r.get("label") == 2)
    c3 = sum(1 for r in merged_results if r.get("label") == 3)
    cases_with_events = sum(1 for r in merged_results if r.get("watchu_event", {}).get("has_events"))

    final_payload = {
        "group": inter.get("group"),
        "summary": {
            "total": total,
            "label_0": c0,
            "label_1": c1,
            "label_2": c2,
            "label_3": c3,
            "cases_with_events": cases_with_events,
        },
        "sources": {
            "attack_result": attack_result_path.as_posix(),
            "events_dump": events_dump_source,
        },
        "results": merged_results,
    }

    json_path = args.output_json or (group_root / "report.json")
    md_path = args.output_md or (group_root / "report.md")
    if json_path.exists() and not args.force:
        raise SystemExit(f"Output already exists: {json_path}\nUse --force to overwrite.")
    if md_path.exists() and not args.force:
        raise SystemExit(f"Output already exists: {md_path}\nUse --force to overwrite.")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(final_payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    md_lines = [
        f"# Final Report ({inter.get('group')})",
        "",
        f"- total: {total}",
        f"- 0 (safe): {c0}",
        f"- 1 (blocked): {c1}",
        f"- 2 (dangerous): {c2}",
        f"- 3 (unknown): {c3}",
        f"- cases with events: {cases_with_events}",
        "",
        "## Cases",
        "",
    ]
    for row in merged_results:
        case_id = row.get("case_id")
        label = row.get("label")
        reason = row.get("reason")
        event_count = row.get("watchu_event", {}).get("count", 0)
        md_lines.append(f"- {case_id}: label={label}, reason={reason}, event_count={event_count}")

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"Saved: {json_path}")
    print(f"Saved: {md_path}")


if __name__ == "__main__":
    main()
