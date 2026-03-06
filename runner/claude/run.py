#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner.common import AgentSpec, parse_args, run_cases


def main() -> None:
    args = parse_args(default_agent="claude")
    run_cases(
        agent_spec=AgentSpec(name="claude", skill_root_dir=".claude/skills"),
        args=args,
    )


if __name__ == "__main__":
    main()
