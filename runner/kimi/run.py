#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner.common import AgentSpec, parse_args, run_cases


def build_command(model: str | None, prompt: str) -> list[str]:
    cmd = ["kimi", "--print"]
    if model:
        cmd += ["--model", model]
    cmd += ["--prompt", prompt]
    return cmd


def main() -> None:
    args = parse_args(default_agent="kimi")
    run_cases(
        agent_spec=AgentSpec(name="kimi", skill_root_dir=".kimi/skills", build_command=build_command),
        args=args,
    )


if __name__ == "__main__":
    main()
