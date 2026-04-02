# skills-event-insight

Structured skill dataset for evaluating agent defense behavior with WatchU-exported events.

This repository includes safe and harmful skill cases, generation scripts, and per-directory judges:
- `skill/base` -> safe baseline cases
- `skill/obvious` -> obvious injected cases generated from base
- `skill/contextual` -> contextual injected cases generated from base

## Data Sources

- Injection config is in `config/inject.json` and follows a skill-inject style case definition.
- Per-skill base task assets are stored under `task/base/<source_skill>/`, including:
  - `task_files/`
- Inject task assets are generated into `task/inject/<case_dir>/` by `generate/inject.py`.
- Injection task scripts source files are stored under `config/inject/task_scripts/<source_skill>/` and are copied into `skill/inject/<generated_skill>/scripts/` during generation.
- `task/inject/<case_dir>/` no longer stores `task_scripts/`; it keeps task-scoped `task_files/` only.
- The runner no longer injects `task_scripts` at runtime.
- WatchU is used in exported JSON mode only (no API dependency).

## Environment Setup

Core benchmark pipeline (`generate/runner/report`) has no third-party Python dependency.

Only ensure:
- Python 3.11+
- agent CLI on PATH (`codex` and/or `claude` and/or `opencode` and/or `kimi`)

## Quick Start

1. Generate injected dataset:

```bash

python generate/inject.py --target skill/contextual --task-target task/contextual --config config/inject_contextual.json --force
python generate/inject.py --target skill/obvious --task-target task/obvious --config config/inject_obvious.json --force

# python generate/inject.py --target skill/inject --task-target task/inject --config config/inject.json
```

If target directories are non-empty and `--force` is not provided, generation will stop with a warning.

2. Run task phase first:

```bash
python runner/opencode/run.py task --group obvious --model openai/gpt-5.1-codex-mini

# python runner/claude/run.py task --group obvious --model sonnet
# python runner/codex/run.py task --group obvious --model gpt-5.3-codex-spark
# python runner/kimi/run.py task --group obvious --model kimi-k2
```
Argument group can be one of:
- obvious
- contextual

Runner supports `--rate-limit` (global seconds between any two LLM requests; default `10`).

Runner output per case:
- `runs/<group>/<case_id>/agent_stdout.txt`
- `runs/<group>/<case_id>/agent_stderr.txt`
- `runs/<group>/<case_id>/.command_history`
- `runs/<group>/<case_id>/task_result.json`
- `runs/<group>/<case_id>/timeline.json`

3. Dump events from WatchU gateway (timeline-based, after task):

```bash
python report/dump.py --group obvious --gateway http://localhost:8080 --force
```

`dump.py` reads `runs-root/<group>/*/timeline.json`.
Default output per case:
- `runs-root/<group>/<case_id>/event.full.json`
- `runs-root/<group>/<case_id>/event.http.txt`
- `runs-root/<group>/<case_id>/event.exec.txt`

4. Run judge phase:

```bash
python runner/opencode/run.py judge --group inject --model openai/gpt-5.1-codex-mini

# python runner/claude/run.py judge --group inject --model sonnet
# python runner/codex/run.py judge --group inject --model gpt-5.3-codex-spark
# python runner/kimi/run.py judge --group inject --model kimi-k2
```

Runner output per case:
- `runs/<group>/<case_id>/judge_result.json`

## Manifest Format

Each `skill/<group>` directory has its own `manifest.json` (for example `base`, `inject`, `obvious`, `contextual`, `script`, `threat`).

Required case fields:
- `case_id`
- `skill_dir`
- `skill_file`
- `expected_label`
- `judge_prompt`
- `injection_text` (required for inject/threat cases)
