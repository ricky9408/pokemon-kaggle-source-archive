#!/usr/bin/env python3
"""Where does OUR submission bleed rating? Win-rate by opponent archetype.

Both search probes converged family-neutral publicly despite large controlled
local decision-quality gains — so rating is matchup-coverage-bound. This tool
measures the coverage directly from OUR OWN public episodes:

  1. `kaggle competitions episodes -v <submission_id>` -> episode list
  2. download each public replay
  3. per game: our slot, reward, opponent deck -> archetype
  4. report win-rate by opponent archetype, worst-first — the targeting data
     for the next agent iteration.

Usage:
  uv run python tools/matchup_bleed_report.py --ref 54303407 --label v151 \
      --max-episodes 40 --out-dir strategy/our_episodes_v151
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
from analyze_replays import archetype, deck_hash  # noqa: E402

OUR_TEAM = "GarlicToday"
COMPLETED_STATE = "EpisodeState.COMPLETED"
PUBLIC_TYPE = "EpisodeType.EPISODE_TYPE_PUBLIC"


@dataclass(frozen=True)
class MatchupResult:
    """Validated result data extracted from one completed replay."""

    opponent_archetype: str
    opponent_deck_hash: str
    result: str


def public_completed_episodes(rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Keep valid public episode rows in the hosted order they were returned."""

    selected: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        episode_id = row.get("id")
        if (
            row.get("state") != COMPLETED_STATE
            or row.get("type") != PUBLIC_TYPE
            or not isinstance(episode_id, str)
            or not episode_id.strip()
        ):
            continue
        episode_id = episode_id.strip()
        if episode_id in seen_ids:
            raise ValueError(f"duplicate public episode id: {episode_id}")
        seen_ids.add(episode_id)
        selected.append(dict(row))
    return selected


def parse_replay(
    data: object,
    *,
    episode_id: str | None = None,
    our_team: str = OUR_TEAM,
) -> MatchupResult | None:
    """Return matchup data only when the replay has a complete valid shape."""

    if not isinstance(data, Mapping):
        return None
    info = data.get("info")
    if not isinstance(info, Mapping):
        return None
    if episode_id is not None and str(info.get("EpisodeId") or "").strip() != episode_id:
        return None

    teams = info.get("TeamNames")
    if (
        not isinstance(teams, list)
        or len(teams) != 2
        or any(type(team) is not str or not team.strip() for team in teams)
        or len(set(teams)) != 2
        or teams.count(our_team) != 1
    ):
        return None
    slot = teams.index(our_team)

    rewards = data.get("rewards")
    if (
        not isinstance(rewards, list)
        or len(rewards) != 2
        or any(type(reward) not in (int, float) or reward not in (-1, 0, 1) for reward in rewards)
        or rewards[0] != -rewards[1]
    ):
        return None

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps or not isinstance(steps[0], list) or not steps[0]:
        return None
    first_record = steps[0][0]
    if not isinstance(first_record, Mapping):
        return None
    visualize = first_record.get("visualize")
    if not isinstance(visualize, list) or not visualize or not isinstance(visualize[0], Mapping):
        return None
    decks = visualize[0].get("action")
    if (
        not isinstance(decks, list)
        or len(decks) != 2
        or any(
            not isinstance(deck, list)
            or len(deck) != 60
            or any(type(card_id) is not int for card_id in deck)
            for deck in decks
        )
    ):
        return None

    opponent_deck = decks[1 - slot]
    reward = rewards[slot]
    result = "W" if reward == 1 else "L" if reward == -1 else "D"
    return MatchupResult(archetype(opponent_deck), deck_hash(opponent_deck), result)


def run_csv(args: list[str]) -> list[dict]:
    out = subprocess.run(["uv", "run", "kaggle"] + args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or out.stdout.strip() or "Kaggle CLI failed")
    lines = out.stdout.splitlines()
    start = next((i for i, l in enumerate(lines) if "," in l and ("id" in l.split(",")[0].lower())), None)
    if start is None:
        raise RuntimeError("Kaggle episodes output did not contain a CSV header")
    return list(csv.DictReader(io.StringIO("\n".join(lines[start:]))))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", required=True, help="submission id")
    ap.add_argument("--label", default="probe")
    ap.add_argument("--max-episodes", type=int, default=48)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    episodes = run_csv(["competitions", "episodes", "-v", args.ref])
    pub = public_completed_episodes(episodes)
    print(f"episodes listed: {len(episodes)} (usable {len(pub)})")

    by_arch = defaultdict(lambda: {"W": 0, "L": 0, "D": 0})
    details = []
    for e in pub[:args.max_episodes]:
        eid = str(e.get("id") or "").strip()
        if not eid:
            continue
        target = args.out_dir / f"episode-{eid}-replay.json"
        if not target.exists():
            downloaded = subprocess.run(
                ["uv", "run", "kaggle", "competitions", "replay", "-q",
                 "-p", str(args.out_dir), eid],
                capture_output=True,
                text=True,
            )
            if downloaded.returncode != 0:
                raise RuntimeError(
                    f"replay download failed for episode {eid}: "
                    f"{downloaded.stderr.strip() or downloaded.stdout.strip()}"
                )
        if not target.exists():
            raise RuntimeError(f"replay download produced no file for episode {eid}")
        try:
            data = json.loads(target.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid replay JSON for episode {eid}: {exc}") from exc
        matchup = parse_replay(data, episode_id=eid)
        if matchup is None:
            raise RuntimeError(f"replay shape is invalid for episode {eid}")
        by_arch[matchup.opponent_archetype][matchup.result] += 1
        details.append((eid, matchup.opponent_archetype, matchup.opponent_deck_hash, matchup.result))

    lines = [f"# Matchup Bleed — {args.label} (ref {args.ref})", "",
             f"- games analyzed: {sum(sum(v.values()) for v in by_arch.values())}", "",
             "| opponent archetype | W-L-D | win% |", "| --- | --- | ---: |"]
    total_w = sum(v["W"] for v in by_arch.values())
    total_l = sum(v["L"] for v in by_arch.values())
    total_d = sum(v["D"] for v in by_arch.values())
    for arch, counts in sorted(by_arch.items(), key=lambda kv: kv[1]["W"] / max(sum(kv[1].values()), 1)):
        games = sum(counts.values())
        lines.append(f"| {arch} | {counts['W']}-{counts['L']}-{counts['D']} | {100 * counts['W'] / games:.0f} |")
    total_g = total_w + total_l + total_d
    lines += ["", f"**overall: {total_w}-{total_l}-{total_d} ({100 * total_w / max(total_g, 1):.0f}%)**", "",
              "## Game log", ""]
    for eid, arch, h, r in details:
        lines.append(f"- {r} vs {arch} ({h}) ep {eid}")
    report = "\n".join(lines) + "\n"
    print(report)
    if args.report:
        args.report.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
