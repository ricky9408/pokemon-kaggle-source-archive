#!/usr/bin/env python3
"""Build target-slot ML rows from an immutable evaluation_v2 cohort.

The legacy replay builder emits both players from every replay.  That is useful
for broad EDA, but it contaminates exact-deck teacher training when both players
appear in the selected team set.  This wrapper binds every emitted decision to
the target slot recorded in the frozen cohort manifest.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from evaluation_v2.cohort import load_manifest, verify_manifest  # noqa: E402
from evaluation_v2.schemas import EpisodeRecord  # noqa: E402
from build_ml_replay_dataset import iter_decisions, load_names, write_jsonl  # noqa: E402


def target_rows(rows: Iterable[dict[str, Any]], episode: EpisodeRecord, cohort_id: str) -> list[dict[str, Any]]:
    """Return only rows controlled by the manifest's declared target slot."""
    selected: list[dict[str, Any]] = []
    for row in rows:
        if int(row.get("episode_id", -1)) != episode.episode_id:
            continue
        if int(row.get("player_index", -1)) != episode.target_slot:
            continue
        copy = dict(row)
        copy.update(
            {
                "cohort_id": cohort_id,
                "cohort_role": episode.role,
                "teacher_team": episode.target_team,
                "teacher_reward": episode.target_reward,
                "frozen_replay_sha256": episode.replay_sha256,
            }
        )
        selected.append(copy)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--role", choices=("development", "holdout"), required=True)
    parser.add_argument("--cards", type=Path, default=REPO / "data" / "EN_Card_Data.csv")
    parser.add_argument("--decisions-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    errors = verify_manifest(manifest, REPO)
    if errors:
        raise SystemExit("frozen cohort verification failed: " + "; ".join(errors))

    names = load_names(args.cards)
    decisions: list[dict[str, Any]] = []
    per_team: Counter[str] = Counter()
    per_context: Counter[str] = Counter()
    episode_count = 0
    for episode in manifest.episodes:
        if episode.role != args.role:
            continue
        replay_path = manifest.resolve_replay(REPO, episode)
        replay = json.loads(replay_path.read_text())
        rows, _ = iter_decisions(replay_path, replay, names, include_deck_choices=False)
        selected = target_rows(rows, episode, manifest.cohort_id)
        for row in selected:
            row["observation"] = replay["steps"][int(row["step_index"])][episode.target_slot]["observation"]
        decisions.extend(selected)
        per_team[episode.target_team] += len(selected)
        per_context.update(str(row.get("context")) for row in selected)
        episode_count += 1

    write_jsonl(args.decisions_out, decisions)
    lines = [
        "# Frozen Cohort ML Dataset",
        "",
        f"- Cohort: `{manifest.cohort_id}`",
        f"- Role: `{args.role}`",
        f"- Episodes: {episode_count}",
        f"- Decisions: {len(decisions)}",
        f"- Teacher teams: {len(per_team)}",
        "",
        "## Teacher Coverage",
        "",
        "| Team | Decisions |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {team} | {count} |" for team, count in sorted(per_team.items()))
    lines.extend(["", "## Context Coverage", "", "| Context | Decisions |", "| --- | ---: |"])
    lines.extend(f"| `{context}` | {count} |" for context, count in per_context.most_common())
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"cohort={manifest.cohort_id} role={args.role} episodes={episode_count} decisions={len(decisions)} teams={len(per_team)}")
    print(f"decisions={args.decisions_out}")
    print(f"report={args.report_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
