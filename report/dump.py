#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dump WatchU exported events for evaluated cases")
    p.add_argument("--events-root", type=Path, required=True, help="Directory containing <case_id>.json or <case_id>.jsonl")
    p.add_argument("--attack-result", type=Path, required=True, help="judge attack_result.json path")
    p.add_argument("--output", type=Path, default=Path("data/events.json"), help="Output dump path")
    p.add_argument("--include-events", action="store_true", help="Embed raw events in output (may be large)")
    return p.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def load_attack_result(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_case(events_root: Path, case_id: str, include_events: bool) -> dict[str, Any]:
    json_path = events_root / f"{case_id}.json"
    jsonl_path = events_root / f"{case_id}.jsonl"

    out: dict[str, Any] = {
        "case_id": case_id,
        "event_source": None,
        "event_count": 0,
    }

    if json_path.exists():
        raw = read_text(json_path)
        out["event_source"] = json_path.as_posix()
        try:
            obj = json.loads(raw)
            if isinstance(obj, list):
                out["event_count"] = len(obj)
            elif isinstance(obj, dict):
                out["event_count"] = sum(len(v) for v in obj.values() if isinstance(v, list))
            if include_events:
                out["events"] = obj
        except json.JSONDecodeError:
            if include_events:
                out["events_raw"] = raw
        return out

    if jsonl_path.exists():
        lines = [ln for ln in read_text(jsonl_path).splitlines() if ln.strip()]
        out["event_source"] = jsonl_path.as_posix()
        out["event_count"] = len(lines)
        if include_events:
            payload = []
            for ln in lines:
                try:
                    payload.append(json.loads(ln))
                except json.JSONDecodeError:
                    payload.append({"raw": ln})
            out["events"] = payload
        return out

    out["status"] = "missing"
    return out


def main() -> None:
    args = parse_args()
    inter = load_attack_result(args.attack_result)

    cases = [str(r.get("case_id", "")) for r in inter.get("results", [])]
    dump = {
        "group": inter.get("group"),
        "attack_result": args.attack_result.as_posix(),
        "events_root": args.events_root.as_posix(),
        "cases": [dump_case(args.events_root, case_id, args.include_events) for case_id in cases],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dump, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
