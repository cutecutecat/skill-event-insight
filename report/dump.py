#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dump WatchU events from gateway by case timeline")
    p.add_argument("--group", type=str, default="inject")
    p.add_argument("--runs-root", type=Path, default=Path("runs"), help="Root output dir; data is read from runs-root/<group>/")
    p.add_argument("--gateway", type=str, default="http://localhost:8080", help="WatchU gateway base URL")
    p.add_argument("--host", type=str, default=None, help="Optional host override; by default query from gateway /analysis/hosts")
    p.add_argument("--limit", type=int, default=1000, help="Per-endpoint max records (gateway-side cap)")
    p.add_argument("-f", "--force", action="store_true", help="Overwrite per-case output when it exists")
    return p.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_timeline_source(group_dir: Path, group: str) -> dict[str, Any]:
    if not group_dir.is_dir():
        raise SystemExit(f"Group run directory not found: {group_dir}")
    cases: list[dict[str, Any]] = []
    for child in sorted(group_dir.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        case_timeline_path = child / "timeline.json"
        if not case_timeline_path.exists():
            continue
        try:
            row = load_json(case_timeline_path)
        except Exception:
            continue
        if isinstance(row, dict):
            row["__case_dir"] = child.as_posix()
            cases.append(row)
    return {
        "group": group,
        "runs_root": group_dir.as_posix(),
        "cases": cases,
    }


def to_rfc3339_utc(ms: int) -> str:
    ts = dt.datetime.fromtimestamp(ms / 1000.0, tz=dt.timezone.utc)
    return ts.isoformat().replace("+00:00", "Z")


def normalize_api_base(gateway: str) -> str:
    g = gateway.rstrip("/")
    if g.endswith("/api/v1"):
        return g
    return g + "/api/v1"


def host_from_gateway(gateway: str) -> str:
    parsed = urllib.parse.urlparse(gateway)
    host = parsed.hostname
    if not host:
        raise SystemExit(f"Invalid --gateway URL: {gateway}")
    return host


def http_get_json(base_url: str, path: str, params: dict[str, Any]) -> Any:
    clean = {k: v for k, v in params.items() if v is not None}
    qs = urllib.parse.urlencode(clean)
    url = f"{base_url}{path}"
    if qs:
        url = f"{url}?{qs}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw.strip() else []


def resolve_host(base_url: str, gateway: str, manual_host: str | None, limit: int) -> str:
    if manual_host:
        return manual_host
    try:
        rows = http_get_json(base_url, "/analysis/hosts", {"limit": max(1, min(limit, 1000))})
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, str) and row.strip():
                    return row.strip()
    except Exception:
        pass
    return host_from_gateway(gateway)


WATCHU_INTERNAL_ARG_MARKER = "pg_isready -U watchu -d watchu"


def _normalize_pid(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return str(value)
    s = str(value).strip()
    if not s or s.lower() == "none":
        return None
    return s


def _normalize_exec_id(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() == "none":
        return None
    return s


def _is_watchu_internal_process_event(event: dict[str, Any]) -> bool:
    args = str(event.get("args", "")).strip()
    return WATCHU_INTERNAL_ARG_MARKER in args


def _filter_watchu_internal_events(
    process_events: list[Any],
    process_http_events: list[Any],
) -> tuple[list[Any], list[Any], list[str], list[str]]:
    # Build a PID -> PPID map. For one PID with multiple samples, prefer
    # the smallest depth (closest to the root) and ignore self-loops.
    pid_parent: dict[str, str] = {}
    pid_depth: dict[str, int] = {}
    for ev in process_events:
        if not isinstance(ev, dict):
            continue
        pid = _normalize_pid(ev.get("pid"))
        ppid = _normalize_pid(ev.get("ppid"))
        if pid is None or ppid is None or pid == ppid:
            continue
        raw_depth = ev.get("depth")
        try:
            depth = int(raw_depth)
        except Exception:
            depth = 10**9
        prev_depth = pid_depth.get(pid, 10**9)
        if depth <= prev_depth:
            pid_parent[pid] = ppid
            pid_depth[pid] = depth

    def top_ancestor_pid(pid: str) -> str:
        cur = pid
        seen: set[str] = set()
        while True:
            if cur in seen:
                return cur
            seen.add(cur)
            parent = pid_parent.get(cur)
            if parent is None:
                return cur
            cur = parent

    # Seeds: process events with the internal marker.
    seed_pids: list[str] = []
    for ev in process_events:
        if not isinstance(ev, dict):
            continue
        if not _is_watchu_internal_process_event(ev):
            continue
        pid = _normalize_pid(ev.get("pid"))
        if pid is not None:
            seed_pids.append(pid)

    blocked_root_pids: set[str] = {top_ancestor_pid(pid) for pid in seed_pids}

    # Expand descendants from blocked roots using PID tree.
    children: dict[str, list[str]] = {}
    for pid, ppid in pid_parent.items():
        children.setdefault(ppid, []).append(pid)

    blocked_pids: set[str] = set()
    stack = list(blocked_root_pids)
    while stack:
        cur = stack.pop()
        if cur in blocked_pids:
            continue
        blocked_pids.add(cur)
        stack.extend(children.get(cur, []))

    # Keep root exec IDs for visibility if roots exist in current window.
    blocked_root_exec_ids: set[str] = set()
    for ev in process_events:
        if not isinstance(ev, dict):
            continue
        pid = _normalize_pid(ev.get("pid"))
        if pid is None or pid not in blocked_root_pids:
            continue
        exec_id = _normalize_exec_id(ev.get("exec_id"))
        if exec_id is not None:
            blocked_root_exec_ids.add(exec_id)

    def keep_process_event(ev: Any) -> bool:
        if not isinstance(ev, dict):
            return True
        if _is_watchu_internal_process_event(ev):
            return False
        pid = _normalize_pid(ev.get("pid"))
        if pid and pid in blocked_pids:
            return False
        root_pid = _normalize_pid(ev.get("root_pid"))
        if root_pid and root_pid in blocked_pids:
            return False
        return True

    def keep_http_event(ev: Any) -> bool:
        if not isinstance(ev, dict):
            return True
        pid = _normalize_pid(ev.get("pid"))
        if pid and pid in blocked_pids:
            return False
        root_pid = _normalize_pid(ev.get("root_pid"))
        if root_pid and root_pid in blocked_pids:
            return False
        return True

    filtered_pe = [ev for ev in process_events if keep_process_event(ev)]
    filtered_phe = [ev for ev in process_http_events if keep_http_event(ev)]
    return filtered_pe, filtered_phe, sorted(blocked_root_pids), sorted(blocked_root_exec_ids)


def _parse_http_body(event: dict[str, Any]) -> tuple[str | None, str | None]:
    body = event.get("body")
    if body is None:
        return None, None
    if not isinstance(body, str):
        return None, f"unsupported body type: {type(body).__name__}; expected str"

    s = body.strip()
    if not s:
        return body, None
    try:
        decoded = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None, "body is not valid base64"
    try:
        return decoded.decode("utf-8", errors="backslashreplace"), None
    except UnicodeDecodeError:
        return None, "base64-decoded bytes are not valid UTF-8"


def dump_case(
    *,
    base_url: str,
    host: str,
    case: dict[str, Any],
    limit: int,
) -> dict[str, Any]:
    case_id = str(case.get("case_id", "")).strip()
    start_raw = case.get("started_at_unix_ms")
    end_raw = case.get("ended_at_unix_ms")
    status = str(case.get("status", "")).strip()

    out: dict[str, Any] = {
        "case_id": case_id,
        "event_source": f"{base_url} (host={host})",
        "event_count": 0,
    }

    if not case_id:
        out["status"] = "invalid_case_id"
        return out
    if status == "skip":
        out["status"] = "skipped_case"
        return out
    if start_raw is None or end_raw is None:
        out["status"] = "missing_window"
        return out

    try:
        start_ms = int(start_raw)
        end_ms = int(end_raw)
    except Exception:
        out["status"] = "invalid_window"
        return out
    if end_ms < start_ms:
        out["status"] = "invalid_window"
        return out

    since = to_rfc3339_utc(start_ms)
    until = to_rfc3339_utc(end_ms)
    query_limit = max(1, min(limit, 1000))
    params = {"host": host, "since": since, "until": until, "limit": query_limit}

    try:
        process_events = http_get_json(base_url, "/analysis/process_events", params)
        process_http_events = http_get_json(base_url, "/analysis/process_http_events", params)
    except Exception as e:  # noqa: BLE001
        out["status"] = "gateway_error"
        out["error"] = str(e)
        return out

    pe = process_events if isinstance(process_events, list) else []
    phe = process_http_events if isinstance(process_http_events, list) else []
    pe, phe, blocked_root_pids, blocked_root_exec_ids = _filter_watchu_internal_events(pe, phe)
    parsed_phe: list[dict[str, Any]] = []
    full_phe: list[dict[str, Any]] = []
    body_parse_warnings: list[str] = []
    for idx, ev in enumerate(phe):
        if not isinstance(ev, dict):
            parsed_phe.append(
                {
                    "raw": ev,
                    "body_parsed": None,
                    "body_parse_warning": "non-object event; cannot parse body",
                }
            )
            full_phe.append({"raw": ev, "body_parse_warning": "non-object event; cannot parse body"})
            body_parse_warnings.append(f"process_http_events[{idx}]: non-object event; cannot parse body")
            continue
        ev2 = dict(ev)
        parsed_body, parse_warning = _parse_http_body(ev2)
        ev2["body_parsed"] = parsed_body
        if parse_warning:
            ev2["body_parse_warning"] = parse_warning
            body_parse_warnings.append(f"process_http_events[{idx}]: {parse_warning}")
        parsed_phe.append(ev2)
        ev_full = dict(ev2)
        ev_full.pop("body_parsed", None)
        full_phe.append(ev_full)
    table_counts = {
        "process_events": len(pe),
        "process_http_events": len(parsed_phe),
    }
    total = table_counts["process_events"] + table_counts["process_http_events"]

    out["event_count"] = total
    out["table_counts"] = table_counts
    if len(pe) >= query_limit or len(phe) >= query_limit:
        out["integrity_warnings"] = [
            "At least one table hit request limit; result may be incomplete. Increase --limit if gateway allows, or split time windows.",
        ]
    if body_parse_warnings:
        out["body_parse_warnings"] = body_parse_warnings
    out["time_window"] = {
        "started_at_unix_ms": int(start_raw),
        "ended_at_unix_ms": int(end_raw),
        "window_start_unix_ms": start_ms,
        "window_end_unix_ms": end_ms,
        "since": since,
        "until": until,
    }
    out["status"] = "ok"
    if blocked_root_pids:
        out["filtered_root_pids"] = blocked_root_pids
    if blocked_root_exec_ids:
        out["filtered_root_exec_ids"] = blocked_root_exec_ids
    out["events"] = {
        "process_events": pe,
        "process_http_events": full_phe,
    }
    out["_process_http_events_parsed"] = parsed_phe
    return out


def _http_event_kind(ev: dict[str, Any]) -> str:
    for key in ("direction", "message_type", "event_type", "kind", "type"):
        raw = ev.get(key)
        if raw is None:
            continue
        s = str(raw).strip().lower()
        if "request" in s:
            return "REQUEST"
        if "response" in s:
            return "RESPONSE"

    # Heuristic fallback when explicit direction is not present.
    if ev.get("request") is not None and ev.get("response") is None:
        return "REQUEST"
    if ev.get("response") is not None and ev.get("request") is None:
        return "RESPONSE"
    if ev.get("method") is not None and ev.get("status_code") is None:
        return "REQUEST"
    if ev.get("status_code") is not None:
        return "RESPONSE"
    return "HTTP"


def _materialize_newlines(text: str) -> str:
    # Preserve raw separator intent from payloads that encode newlines as "\n".
    return text.replace("\\r\\n", "\n").replace("\\n", "\n")


def render_http_txt(process_http_events_parsed: list[Any]) -> str:
    lines: list[str] = []
    for idx, ev in enumerate(process_http_events_parsed, start=1):
        kind = "HTTP"
        if isinstance(ev, dict):
            kind = _http_event_kind(ev)
        begin = f"<<<<__WATCHU_{kind}_EVENT_{idx:05d}_BEGIN__>>>>"
        end = f"<<<<__WATCHU_{kind}_EVENT_{idx:05d}_END__>>>>"
        lines.append(begin)
        if isinstance(ev, dict):
            body = ev.get("body_parsed")
            if body is not None:
                lines.append(_materialize_newlines(str(body)))
        lines.append(end)
        lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def render_exec_txt(process_events: list[Any]) -> str:
    lines: list[str] = []
    for idx, ev in enumerate(process_events, start=1):
        begin = f"<<<<__WATCHU_EXEC_EVENT_{idx:05d}_BEGIN__>>>>"
        end = f"<<<<__WATCHU_EXEC_EVENT_{idx:05d}_END__>>>>"
        line = ""
        if isinstance(ev, dict):
            comm = str(ev.get("comm", "")).strip()
            args = str(ev.get("args", "")).strip()
            line = f"{comm} {args}".strip()
        lines.extend([begin, line, end, ""])
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def main() -> None:
    args = parse_args()
    group_dir = args.runs_root / args.group
    timeline = load_timeline_source(group_dir, args.group)
    cases = timeline.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit(f"Invalid timeline format under: {group_dir}")

    base_url = normalize_api_base(args.gateway)
    host = resolve_host(base_url, args.gateway, args.host, args.limit)

    saved_count = 0
    for case in cases:
        case_obj = case if isinstance(case, dict) else {}
        row = dump_case(
            base_url=base_url,
            host=host,
            case=case_obj,
            limit=args.limit,
        )

        case_dir_raw = case_obj.get("__case_dir")
        case_dir = Path(case_dir_raw) if isinstance(case_dir_raw, str) and case_dir_raw else None
        if case_dir is None:
            case_id = str(case_obj.get("case_id", "")).strip()
            if not case_id:
                continue
            case_dir = group_dir / case_id

        output_full = case_dir / "event.full.json"
        output_http = case_dir / "event.http.txt"
        output_exec = case_dir / "event.exec.txt"
        for output in (output_full, output_http, output_exec):
            if output.exists() and not args.force:
                raise SystemExit(f"Output already exists: {output}\nUse --force to overwrite.")
        case_dir.mkdir(parents=True, exist_ok=True)

        parsed_http = row.pop("_process_http_events_parsed", [])
        events = row.get("events", {}) if isinstance(row, dict) else {}
        process_events = events.get("process_events", []) if isinstance(events, dict) else []
        http_txt = render_http_txt(parsed_http if isinstance(parsed_http, list) else [])
        exec_txt = render_exec_txt(process_events if isinstance(process_events, list) else [])

        payload: dict[str, Any] = {
            "group": args.group,
            "source": "dump_gateway",
            "generated_at_unix": int(time.time()),
            "runs_root": args.runs_root.as_posix(),
            "group_dir": group_dir.as_posix(),
            "gateway": args.gateway,
            "host": host,
            "case": row,
        }
        output_full.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        output_http.write_text(http_txt, encoding="utf-8")
        output_exec.write_text(exec_txt, encoding="utf-8")
        saved_count += 1

    print(f"Saved {saved_count} case event.full.json + event.http.txt + event.exec.txt under: {group_dir}")


if __name__ == "__main__":
    main()
