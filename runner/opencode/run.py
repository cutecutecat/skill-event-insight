#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner.common import AgentSpec, parse_args, run_cases

OPENCODE_ALLOW_ALL_CONFIG = """{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "*": {
      "*": "allow"
    }
  }
}
"""


@contextmanager
def opencode_allow_all_permissions() -> Iterator[None]:
    # Avoid interactive authorization prompts during experiment runs
    original_config = os.environ.get("OPENCODE_CONFIG")
    config_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix="opencode-",
            suffix=".json",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write(OPENCODE_ALLOW_ALL_CONFIG)
            config_path = Path(handle.name)

        os.environ["OPENCODE_CONFIG"] = str(config_path)
        yield
    finally:
        if original_config is None:
            os.environ.pop("OPENCODE_CONFIG", None)
        else:
            os.environ["OPENCODE_CONFIG"] = original_config

        if config_path is not None:
            config_path.unlink(missing_ok=True)


def build_command(model: str | None, prompt: str) -> list[str]:
    cmd = ["opencode", "run"]
    if model:
        cmd += ["--model", model]
    cmd += [prompt]
    return cmd


def main() -> None:
    args = parse_args(default_agent="opencode")
    with opencode_allow_all_permissions():
        run_cases(
            agent_spec=AgentSpec(name="opencode", skill_root_dir=".opencode/skills", build_command=build_command),
            args=args,
        )


if __name__ == "__main__":
    main()

