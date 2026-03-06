#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Synthesize final report from attack_result and dumped events")
    p.add_argument("--attack-result", type=Path, required=True, help="judge attack_result.json")
    p.add_argument("--events-dump", type=Path, required=True, help="event dump JSON path")
    p.add_argument("--output-json", type=Path, default=Path("data/report.json"), help="Output report json path")
    p.add_argument("--output-md", type=Path, default=Path("data/report.md"), help="Output report markdown path")
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


def main() -> None:
    args = parse_args()
    inter = read_json(args.attack_result)
    dump = read_json(args.events_dump)

    dump_map = {str(c.get("case_id", "")): c for c in dump.get("cases", [])}

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
            "attack_result": args.attack_result.as_posix(),
            "events_dump": args.events_dump.as_posix(),
        },
        "results": merged_results,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    json_path = args.output_json
    md_path = args.output_md

    json_path.write_text(json.dumps(final_payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    md_lines = [
        f"# Final Report ({inter.get('group')})",
        "",
        f"- total: {total}",
        f"- label 0: {c0}",
        f"- label 1: {c1}",
        f"- label 2: {c2}",
        f"- label 3: {c3}",
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
