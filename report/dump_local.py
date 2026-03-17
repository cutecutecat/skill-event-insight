#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dump import _parse_http_body, render_exec_txt, render_http_txt


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build event.http.txt and event.exec.txt from local event.full.json")
    p.add_argument("--group", type=str, default=None, help="Scan runs/<group>/*/event.full.json")
    p.add_argument("--runs-root", type=Path, default=Path("runs"))
    p.add_argument("--input", type=Path, default=None, help="Single event.full.json path")
    p.add_argument("-f", "--force", action="store_true", help="Overwrite output txt files when they exist")
    return p.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_http_txt_from_full(case_payload: dict[str, Any]) -> str:
    case = case_payload.get("case", {}) if isinstance(case_payload, dict) else {}
    events = case.get("events", {}) if isinstance(case, dict) else {}
    phe = events.get("process_http_events", []) if isinstance(events, dict) else []

    parsed: list[dict[str, Any]] = []
    for ev in phe if isinstance(phe, list) else []:
        if not isinstance(ev, dict):
            parsed.append({"body_parsed": None})
            continue
        parsed_body, _ = _parse_http_body(ev)
        ev2 = dict(ev)
        ev2["body_parsed"] = parsed_body
        parsed.append(ev2)
    return render_http_txt(parsed)


def build_exec_txt_from_full(case_payload: dict[str, Any]) -> str:
    case = case_payload.get("case", {}) if isinstance(case_payload, dict) else {}
    events = case.get("events", {}) if isinstance(case, dict) else {}
    pe = events.get("process_events", []) if isinstance(events, dict) else []
    return render_exec_txt(pe if isinstance(pe, list) else [])


def process_one(full_path: Path, force: bool) -> None:
    if full_path.name != "event.full.json":
        raise SystemExit(f"Input file must be event.full.json: {full_path}")
    payload = read_json(full_path)
    out_http = full_path.with_name("event.http.txt")
    out_exec = full_path.with_name("event.exec.txt")
    for out in (out_http, out_exec):
        if out.exists() and not force:
            raise SystemExit(f"Output already exists: {out}\nUse --force to overwrite.")
    out_http.write_text(build_http_txt_from_full(payload), encoding="utf-8")
    out_exec.write_text(build_exec_txt_from_full(payload), encoding="utf-8")
    print(f"Saved: {out_http}")
    print(f"Saved: {out_exec}")


def main() -> None:
    args = parse_args()
    if args.input is not None:
        process_one(args.input, args.force)
        return

    if not args.group:
        raise SystemExit("Either --input or --group is required.")
    group_dir = args.runs_root / args.group
    if not group_dir.is_dir():
        raise SystemExit(f"Group run directory not found: {group_dir}")

    count = 0
    for case_dir in sorted(group_dir.iterdir(), key=lambda p: p.name):
        if not case_dir.is_dir():
            continue
        full_path = case_dir / "event.full.json"
        if not full_path.exists():
            continue
        process_one(full_path, args.force)
        count += 1
    print(f"Processed {count} event.full.json files under: {group_dir}")


if __name__ == "__main__":
    main()
