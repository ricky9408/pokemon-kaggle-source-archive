#!/usr/bin/env python3
"""Build fresh development rows without opening any frozen-cohort episode."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from build_ml_replay_dataset import iter_decisions, load_names, write_jsonl  # noqa: E402
from evaluation_v2.augmentation import build_augmentation, write_augmentation  # noqa: E402
from evaluation_v2.cohort import load_manifest  # noqa: E402
from tools.build_cohort_ml_dataset import target_rows  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--replay-root", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--decisions-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--cards", type=Path, default=REPO / "data" / "EN_Card_Data.csv")
    args = parser.parse_args()

    base = load_manifest(args.base_manifest)
    if not base.episodes or not base.target_deck_sha256:
        raise SystemExit("base manifest is incomplete")
    augmentation = build_augmentation(
        repo_root=REPO,
        replay_root=args.replay_root,
        base_manifest=base,
    )
    write_augmentation(augmentation, args.manifest_out)

    names = load_names(args.cards)
    decisions: list[dict] = []
    per_team: Counter[str] = Counter()
    per_context: Counter[str] = Counter()
    for episode in augmentation.records:
        replay_path = Path(episode.replay_path)
        if not replay_path.is_absolute():
            replay_path = REPO / replay_path
        replay = json.loads(replay_path.read_text())
        rows, _ = iter_decisions(replay_path, replay, names, include_deck_choices=False)
        selected = target_rows(rows, episode, augmentation.augmentation_id)
        for row in selected:
            row["observation"] = replay["steps"][int(row["step_index"])][episode.target_slot]["observation"]
            row["parent_cohort_id"] = base.cohort_id
            row["augmentation_id"] = augmentation.augmentation_id
        decisions.extend(selected)
        per_team[episode.target_team] += len(selected)
        per_context.update(str(row.get("context")) for row in selected)
    write_jsonl(args.decisions_out, decisions)

    lines = [
        "# Leakage-safe Development Augmentation",
        "",
        f"- Parent cohort: `{base.cohort_id}`",
        f"- Augmentation: `{augmentation.augmentation_id}`",
        f"- Fresh replay files scanned: {augmentation.scanned_files}",
        f"- Frozen replay files skipped before open: {augmentation.skipped_frozen_files}",
        f"- Exact-deck records: {len(augmentation.records)}",
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
    print("\n".join(lines))
    print(f"manifest={args.manifest_out}")
    print(f"decisions={args.decisions_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
