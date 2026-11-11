#!/usr/bin/env python3
"""Collect a submission's literal public-game chronology and freeze horizons.

The Kaggle episodes endpoint returns newest games first and may include a
validation episode.  This collector filters to completed public episodes,
sorts by hosted creation time, enforces append-only chronology, and freezes the
first 24, 48, and 96 games once each horizon is complete.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.public_episode_quality_report import archetype, deck_hash, load_leaderboard, public_layer


HORIZONS = (24, 48, 96)
SHORT_LOSS_MAX_STEPS = 50


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def run_kaggle_csv(args: list[str]) -> list[dict[str, str]]:
    result = subprocess.run(
        ["uv", "run", "kaggle", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    lines = result.stdout.splitlines()
    header = next((i for i, line in enumerate(lines) if line.startswith("id,")), None)
    if header is None:
        raise RuntimeError("Kaggle episodes output did not contain a CSV header")
    return list(csv.DictReader(io.StringIO("\n".join(lines[header:]))))


def completed_public_episodes(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    public: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        episode_id = (row.get("id") or "").strip()
        state = (row.get("state") or "").upper()
        episode_type = (row.get("type") or "").upper()
        if not episode_id or "COMPLETED" not in state or "PUBLIC" not in episode_type:
            continue
        if episode_id in seen:
            raise RuntimeError(f"duplicate public episode id: {episode_id}")
        seen.add(episode_id)
        public.append(
            {
                "id": episode_id,
                "createTime": (row.get("createTime") or "").strip(),
                "endTime": (row.get("endTime") or "").strip(),
                "state": (row.get("state") or "").strip(),
                "type": (row.get("type") or "").strip(),
            }
        )
    public.sort(key=lambda row: (parse_time(row["createTime"]), parse_time(row["endTime"]), int(row["id"])))
    return public


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv_atomic(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def enforce_append_only(existing: list[dict[str, str]], current: list[dict[str, str]]) -> None:
    if len(existing) > len(current):
        raise RuntimeError("hosted chronology shrank")
    fields = ("id", "createTime", "endTime", "state", "type")
    for index, old in enumerate(existing):
        new = current[index]
        if any(old.get(field, "") != new.get(field, "") for field in fields):
            raise RuntimeError(f"hosted chronology changed at index {index + 1}: {old.get('id')} -> {new.get('id')}")


def download_replay(episode_id: str, replay_dir: Path) -> Path:
    target = replay_dir / f"episode-{episode_id}-replay.json"
    if target.exists():
        return target
    replay_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "uv",
            "run",
            "kaggle",
            "competitions",
            "replay",
            "-q",
            "-p",
            str(replay_dir),
            episode_id,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not target.exists():
        detail = result.stderr.strip() or result.stdout.strip() or "replay file missing"
        raise RuntimeError(detail)
    return target


def replay_status(data: dict[str, Any], slot: int) -> str:
    statuses = data.get("statuses") or []
    if slot < len(statuses):
        return str(statuses[slot])
    steps = data.get("steps") or []
    if steps and slot < len(steps[-1]):
        return str(steps[-1][slot].get("status") or "")
    return ""


def analyze_episode(
    episode: dict[str, str],
    chronology_index: int,
    replay_path: Path,
    team: str,
    leaderboard: dict[str, tuple[int, float]],
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "chronology_index": chronology_index,
        "episode_id": episode["id"],
        "create_time_utc": episode["createTime"],
        "end_time_utc": episode["endTime"],
        "analysis_status": "ok",
        "result": "",
        "our_seat": "",
        "opponent_team": "",
        "opponent_rank": "",
        "opponent_score": "",
        "opponent_layer": "unranked",
        "opponent_archetype": "",
        "opponent_deck_hash": "",
        "steps": "",
        "short_loss": False,
        "agent_status": "",
        "runtime_or_package_failure": False,
    }
    try:
        data = json.loads(replay_path.read_text(encoding="utf-8"))
        teams = data["info"]["TeamNames"]
        if team not in teams or len(teams) != 2:
            raise ValueError(f"team list does not contain exactly one {team}: {teams}")
        slot = teams.index(team)
        opponent_slot = 1 - slot
        rewards = data.get("rewards") or []
        if slot >= len(rewards) or rewards[slot] is None:
            raise ValueError("our reward is missing")
        reward = rewards[slot]
        result = "W" if reward == 1 else "L" if reward == -1 else "D"
        decks = data["steps"][0][0]["visualize"][0]["action"]
        opponent_deck = decks[opponent_slot]
        opponent_team = teams[opponent_slot]
        opponent_rank, opponent_score = leaderboard.get(opponent_team, ("", ""))
        status = replay_status(data, slot)
        step_count = len(data.get("steps") or [])
        base.update(
            {
                "result": result,
                "our_seat": f"p{slot}",
                "opponent_team": opponent_team,
                "opponent_rank": opponent_rank,
                "opponent_score": opponent_score,
                "opponent_layer": public_layer(opponent_rank, opponent_score),
                "opponent_archetype": archetype(opponent_deck),
                "opponent_deck_hash": deck_hash(opponent_deck),
                "steps": step_count,
                "short_loss": result == "L" and step_count <= SHORT_LOSS_MAX_STEPS,
                "agent_status": status,
                "runtime_or_package_failure": status.upper() != "DONE",
            }
        )
    except Exception as exc:
        base["analysis_status"] = f"error:{type(exc).__name__}:{exc}"
        base["runtime_or_package_failure"] = True
    return base


def wld(rows: list[dict[str, Any]]) -> str:
    counts = Counter(row["result"] for row in rows)
    return f"{counts['W']}-{counts['L']}-{counts['D']}"


def grouped_wld(rows: list[dict[str, Any]], field: str) -> dict[str, str]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row[field])].append(row)
    return {key: wld(groups[key]) for key in sorted(groups)}


def horizon_summary(rows: list[dict[str, Any]], size: int) -> dict[str, Any]:
    selected = rows[:size]
    complete = len(selected) == size and all(row["analysis_status"] == "ok" for row in selected)
    valid = [row for row in selected if row["analysis_status"] == "ok"]
    wins = sum(row["result"] == "W" for row in valid)
    return {
        "horizon": size,
        "complete": complete,
        "listed_games": len(selected),
        "valid_games": len(valid),
        "episode_ids": [row["episode_id"] for row in selected],
        "wld": wld(valid),
        "win_rate": wins / len(valid) if valid else None,
        "by_opponent_layer": grouped_wld(valid, "opponent_layer"),
        "by_archetype": grouped_wld(valid, "opponent_archetype"),
        "by_seat": grouped_wld(valid, "our_seat"),
        "short_losses": sum(bool(row["short_loss"]) for row in valid),
        "runtime_or_package_failures": sum(bool(row["runtime_or_package_failure"]) for row in selected),
    }


def render_summary(summary: dict[str, Any], title: str) -> str:
    win_rate = summary["win_rate"]
    rate_text = f"{win_rate:.3f}" if win_rate is not None else "-"
    lines = [
        f"# {title}",
        "",
        f"- Horizon: {summary['horizon']}",
        f"- Complete: {str(summary['complete']).lower()}",
        f"- Listed / valid games: {summary['listed_games']} / {summary['valid_games']}",
        f"- W-L-D: {summary['wld']}",
        f"- Win rate: {rate_text}",
        f"- Short losses (steps <= {SHORT_LOSS_MAX_STEPS}): {summary['short_losses']}",
        f"- Runtime/package failures: {summary['runtime_or_package_failures']}",
        "",
    ]
    for heading, key in (
        ("Opponent Rating Layer", "by_opponent_layer"),
        ("Opponent Archetype", "by_archetype"),
        ("Seat", "by_seat"),
    ):
        lines.extend([f"## {heading}", "", "| bucket | W-L-D |", "| --- | ---: |"])
        for bucket, value in summary[key].items():
            lines.append(f"| `{bucket}` | {value} |")
        if not summary[key]:
            lines.append("| `none` | 0-0-0 |")
        lines.append("")
    return "\n".join(lines)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def freeze_horizon(freeze_dir: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    if not summary["complete"]:
        return
    size = int(summary["horizon"])
    json_path = freeze_dir / f"horizon_{size:03d}.json"
    md_path = freeze_dir / f"horizon_{size:03d}.md"
    payload = {"frozen_at_utc": utc_now(), "summary": summary, "games": rows[:size]}
    if json_path.exists():
        existing = json.loads(json_path.read_text(encoding="utf-8"))
        existing_ids = existing.get("summary", {}).get("episode_ids")
        if existing_ids != summary["episode_ids"]:
            raise RuntimeError(f"frozen horizon {size} episode identities changed")
        return
    write_json_atomic(json_path, payload)
    md_path.write_text(render_summary(summary, f"Frozen Public Calibration Horizon {size}"), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--replay-dir", required=True, type=Path)
    parser.add_argument("--chronology-csv", required=True, type=Path)
    parser.add_argument("--games-csv", required=True, type=Path)
    parser.add_argument("--report-json", required=True, type=Path)
    parser.add_argument("--report-md", required=True, type=Path)
    parser.add_argument("--freeze-dir", required=True, type=Path)
    parser.add_argument("--leaderboard", type=Path)
    parser.add_argument("--max-games", type=int, default=max(HORIZONS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw = run_kaggle_csv(["competitions", "episodes", "-v", args.ref])
    episodes = completed_public_episodes(raw)[: args.max_games]
    existing = read_csv(args.chronology_csv)
    enforce_append_only(existing, episodes)
    write_csv_atomic(args.chronology_csv, episodes)

    leaderboard = load_leaderboard(args.leaderboard) if args.leaderboard else {}
    rows: list[dict[str, Any]] = []
    for index, episode in enumerate(episodes, start=1):
        try:
            replay_path = download_replay(episode["id"], args.replay_dir)
        except Exception as exc:
            row = {
                "chronology_index": index,
                "episode_id": episode["id"],
                "create_time_utc": episode["createTime"],
                "end_time_utc": episode["endTime"],
                "analysis_status": f"download_error:{type(exc).__name__}:{exc}",
                "result": "",
                "our_seat": "",
                "opponent_team": "",
                "opponent_rank": "",
                "opponent_score": "",
                "opponent_layer": "unranked",
                "opponent_archetype": "",
                "opponent_deck_hash": "",
                "steps": "",
                "short_loss": False,
                "agent_status": "",
                "runtime_or_package_failure": True,
            }
        else:
            row = analyze_episode(episode, index, replay_path, args.team, leaderboard)
        rows.append(row)
    write_csv_atomic(args.games_csv, rows)

    current = horizon_summary(rows, len(rows))
    horizon_summaries = [horizon_summary(rows, size) for size in HORIZONS]
    payload = {
        "generated_at_utc": utc_now(),
        "submission_ref": str(args.ref),
        "team": args.team,
        "leaderboard": str(args.leaderboard) if args.leaderboard else None,
        "chronology_count": len(episodes),
        "current_prefix": current,
        "horizons": horizon_summaries,
        "games": rows,
    }
    write_json_atomic(args.report_json, payload)
    lines = [
        "# Public Calibration Chronology",
        "",
        f"- Submission ref: `{args.ref}`",
        f"- Generated: {payload['generated_at_utc']}",
        f"- Completed public games listed: {len(episodes)}",
        f"- Leaderboard snapshot: `{payload['leaderboard'] or 'none'}`",
        "- Ordering: hosted `createTime`, then `endTime`, then episode ID",
        "- Validation episodes are excluded",
        "",
        render_summary(current, f"Current Literal Prefix ({len(rows)} games)"),
        "## Preregistered Horizons",
        "",
        "| horizon | complete | listed | valid | W-L-D | win rate | short losses | runtime/package failures |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for summary in horizon_summaries:
        rate = summary["win_rate"]
        rate_text = f"{rate:.3f}" if rate is not None else "-"
        lines.append(
            f"| {summary['horizon']} | {str(summary['complete']).lower()} | {summary['listed_games']} | "
            f"{summary['valid_games']} | {summary['wld']} | {rate_text} | {summary['short_losses']} | "
            f"{summary['runtime_or_package_failures']} |"
        )
    lines.append("")
    args.report_md.parent.mkdir(parents=True, exist_ok=True)
    args.report_md.write_text("\n".join(lines), encoding="utf-8")
    for summary in horizon_summaries:
        freeze_horizon(args.freeze_dir, summary, rows)

    print(f"completed_public_games={len(episodes)}")
    print(f"current_wld={current['wld']}")
    print(f"current_win_rate={current['win_rate']}")
    print(f"report={args.report_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
