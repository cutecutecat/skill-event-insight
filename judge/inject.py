#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from common import evaluate_group, load_manifest, load_rules_map, parse_args, write_attack_result


def main() -> None:
    args = parse_args(default_group="inject")
    manifest_path = args.manifest or Path("skill/inject/manifest.json")
    manifest = load_manifest(manifest_path)
    rules_map = load_rules_map(args.inject_config)
    results = evaluate_group(
        manifest=manifest,
        group="inject",
        runs_root=args.runs_root,
        rules_map=rules_map,
        judge_agent=args.judge_agent,
        judge_model=args.judge_model,
        judge_timeout=args.judge_timeout,
    )
    json_path, md_path = write_attack_result(results, args.report_dir, manifest, group="inject")
    print(f"Saved: {json_path}")
    print(f"Saved: {md_path}")


if __name__ == "__main__":
    main()
