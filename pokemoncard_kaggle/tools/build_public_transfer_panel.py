#!/usr/bin/env python3
"""Build and audit the post-shift exact-agent public outcome panel."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evaluation_v2.public_transfer import build_panel, panel_inventory, write_panel  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument(
        "--submissions",
        type=Path,
        default=Path("strategy/kaggle_submissions_latest.csv"),
    )
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--cutoff-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    cutoff = datetime.fromisoformat(args.cutoff_utc.replace("Z", "+00:00"))
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    panel = build_panel(
        repo_root=REPO,
        sources_path=args.sources,
        submissions_path=args.submissions,
        team=args.team,
        cutoff_utc=cutoff.astimezone(timezone.utc),
    )
    write_panel(panel, args.output)
    inventory = panel_inventory(panel)
    by_agent = Counter(game.agent_label for game in panel.games)
    by_axis = Counter(game.opponent_axis for game in panel.games)
    by_block = Counter(game.time_block for game in panel.games)
    by_module = Counter(game.module_version for game in panel.games)
    win_by_agent: Counter[str] = Counter()
    for game in panel.games:
        win_by_agent[game.agent_label] += game.outcome

    lines = [
        "# Exact-agent Public Transfer Panel",
        "",
        f"- Panel: `{panel.panel_id}`",
        f"- Cutoff: `{panel.cutoff_utc}`",
        f"- Games: {inventory['games']}",
        f"- Exact policy lineages: {inventory['policy_lineages']}",
        f"- Submission refs: {inventory['submission_refs']}",
        f"- Time blocks: {inventory['time_blocks']}",
        f"- Opponent axes: {inventory['opponent_axes']}",
        f"- Sol inventory minimums met: **{inventory['inventory_ready']}**",
        "- Evaluator certified: **False** (agent features and blocked transfer validation not run)",
        "",
        "## Agent Coverage",
        "",
        "| Agent | Games | Raw outcome mean |",
        "| --- | ---: | ---: |",
    ]
    for label, count in sorted(by_agent.items()):
        lines.append(f"| `{label}` | {count} | {win_by_agent[label] / count:.3f} |")
    lines.extend(["", "## Opponent Axes", "", "| Axis | Games |", "| --- | ---: |"])
    lines.extend(f"| `{axis}` | {count} |" for axis, count in by_axis.most_common())
    lines.extend(["", "## Time Blocks", "", "| UTC day | Games |", "| --- | ---: |"])
    lines.extend(f"| `{block}` | {count} |" for block, count in sorted(by_block.items()))
    lines.extend(["", "## Engine Versions", "", "| Module | Games |", "| --- | ---: |"])
    lines.extend(f"| `{module}` | {count} |" for module, count in sorted(by_module.items()))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
