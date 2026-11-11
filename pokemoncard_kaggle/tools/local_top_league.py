#!/usr/bin/env python3
"""Run a local round-robin league from a public scout plus local candidates.

The public scout gives us decks, not other teams' private agents. Top teams are
therefore represented by the replay-observed deck plus the local archetype
policy template used by `replay_pool_gauntlet.py`.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import pstdev

sys.path.insert(0, str(Path(__file__).resolve().parent))
import replay_pool_gauntlet as pool_tool  # noqa: E402
from run_local_battle import load_agent, read_deck, run_games  # noqa: E402


@dataclass(frozen=True)
class Participant:
    label: str
    kind: str
    rank: int | None
    public_score: float | None
    source_team: str
    source_replay: Path | None
    archetype: str
    deck_hash: str
    policy: Path
    deck: tuple[int, ...]


@dataclass
class Standing:
    participant: Participant
    match_wins: int = 0
    match_losses: int = 0
    match_draws: int = 0
    game_wins: int = 0
    game_losses: int = 0
    game_draws: int = 0
    unfinished: int = 0

    @property
    def points(self) -> int:
        return self.match_wins * 3 + self.match_draws

    @property
    def game_diff(self) -> int:
        return self.game_wins - self.game_losses

    @property
    def total_games(self) -> int:
        return self.game_wins + self.game_losses + self.game_draws

    @property
    def win_pct(self) -> float:
        if self.total_games <= 0:
            return 0.0
        return (self.game_wins + 0.5 * self.game_draws) / self.total_games


@dataclass(frozen=True)
class RobustnessRow:
    entry: str
    top_games: int
    top_win_pct: float
    maximin_archetype_win_pct: float
    max_regret: float
    avg_regret: float
    archetype_stddev: float
    worst_archetype: str
    worst_opponent: str
    robustness_score: float


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_label(text: str) -> str:
    return "_".join("".join(ch if ch.isalnum() else "_" for ch in text).split("_")) or "entry"


def deck_hash(deck: list[int] | tuple[int, ...]) -> str:
    return hashlib.sha1(",".join(map(str, sorted(deck))).encode()).hexdigest()[:10]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def engine_provenance_lines() -> list[str]:
    """Describe which native cg engine this league actually imported."""

    lines: list[str] = []
    runtime_sim = sys.modules.get("cg.sim")
    runtime_package = sys.modules.get("cg")
    runtime_lib_value = getattr(runtime_sim, "lib_path", "") if runtime_sim else ""
    runtime_lib = Path(runtime_lib_value) if runtime_lib_value else None
    runtime_hash = sha256_file(runtime_lib) if runtime_lib and runtime_lib.is_file() else ""

    if runtime_lib:
        lines.append(f"- Runtime `cg.sim` library: `{runtime_lib}`")
        lines.append(f"- Runtime `libcg` sha256: `{runtime_hash or 'missing'}`")
    else:
        lines.append("- Runtime `cg.sim` library: not imported before report render")
    if runtime_package is not None and getattr(runtime_package, "__file__", None):
        lines.append(f"- Runtime `cg` package: `{runtime_package.__file__}`")

    reference_paths = [
        ("workspace submission template", Path("submission/cg/libcg.so")),
        ("Kaggle sample 2026-07-01", Path("references/sample_submission_20260701/libcg.so")),
        (
            "Kaggle/kaggle-environments cabt",
            Path("references/kaggle-environments-source/kaggle_environments/envs/cabt/cg/libcg.so"),
        ),
    ]
    reference_hashes: dict[str, str] = {}
    for label, path in reference_paths:
        if path.exists():
            digest = sha256_file(path)
            reference_hashes[label] = digest
            lines.append(f"- Reference `{label}` sha256: `{digest}`")

    fresh_hash = reference_hashes.get("Kaggle sample 2026-07-01")
    github_hash = reference_hashes.get("Kaggle/kaggle-environments cabt")
    if runtime_hash and fresh_hash and runtime_hash != fresh_hash:
        lines.append(
            "- Engine warning: runtime `libcg` does not match the freshly published "
            "Kaggle sample engine; treat this league as engine-mismatch diagnostic evidence."
        )
    if runtime_hash and github_hash and runtime_hash != github_hash:
        lines.append(
            "- Engine warning: runtime `libcg` does not match the current "
            "Kaggle/kaggle-environments cabt engine either."
        )
    if fresh_hash and github_hash and fresh_hash != github_hash:
        lines.append(
            "- Engine warning: the Kaggle sample engine and GitHub cabt engine are "
            "not byte-identical, so reports must name the exact engine source."
        )
    return lines


def rel_for_container(path: Path, workspace: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(path)


def docker_reinvoke(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    command = [
        "docker",
        "run",
        "-i",
        "--rm",
        "--platform",
        args.docker_platform,
        "-v",
        f"{workspace}:/work",
        "-w",
        "/work",
        args.docker_image,
        args.python,
        "tools/local_top_league.py",
        "--no-docker",
        "--scout-dir",
        rel_for_container(args.scout_dir, workspace),
        "--top-limit",
        str(args.top_limit),
        "--selection-mode",
        args.selection_mode,
        "--scan-limit",
        str(args.scan_limit),
        "--min-archetypes",
        str(args.min_archetypes),
        "--min-decks",
        str(args.min_decks),
        "--games-per-seat",
        str(args.games_per_seat),
        "--max-steps",
        str(args.max_steps),
        "--output-prefix",
        rel_for_container(args.output_prefix, workspace),
    ]
    for candidate in args.candidate:
        command.extend(["--candidate", candidate])
    if args.allow_partial_top:
        command.append("--allow-partial-top")
    if args.quiet:
        command.append("--quiet")
    print("docker_command=" + " ".join(shlex.quote(part) for part in command))
    return subprocess.run(command, cwd=workspace, check=False).returncode


def load_replay_deck_for_team(path: Path, team: str) -> tuple[list[int], str]:
    data = json.loads(path.read_text())
    teams = data.get("info", {}).get("TeamNames", [])
    decks = data["steps"][0][0]["visualize"][0]["action"]
    for slot, team_name in enumerate(teams):
        if team_name == team:
            return list(decks[slot]), team_name
    raise ValueError(f"{team!r} not found in {path}")


def load_valid_top_pool(scout_dir: Path, scan_limit: int) -> list[Participant]:
    summary = scout_dir / "download_summary.csv"
    if not summary.exists():
        raise FileNotFoundError(summary)
    participants: list[Participant] = []
    seen: set[str] = set()
    with summary.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            rank = int(row["rank"])
            if scan_limit > 0 and rank > scan_limit:
                continue
            team = row["team"]
            if team in seen:
                continue
            replay_path = Path(row["path"])
            try:
                deck, team_name = load_replay_deck_for_team(replay_path, team)
            except Exception:
                continue
            archetype = pool_tool.archetype(deck)
            policy = pool_tool.policy_for(archetype, deck)
            if policy is None:
                continue
            label = f"{rank:02d}_{safe_label(team_name)}"
            participants.append(
                Participant(
                    label=label,
                    kind="top_team",
                    rank=rank,
                    public_score=float(row["score"]),
                    source_team=team_name,
                    source_replay=replay_path,
                    archetype=archetype.replace("_", "-"),
                    deck_hash=deck_hash(deck),
                    policy=policy,
                    deck=tuple(deck),
                )
            )
            seen.add(team)
    return participants


def select_diverse_participants(
    pool: list[Participant],
    top_limit: int,
    *,
    min_archetypes: int,
    min_decks: int,
) -> list[Participant]:
    selected: list[Participant] = []
    selected_labels: set[str] = set()

    def add(participant: Participant) -> None:
        selected.append(participant)
        selected_labels.add(participant.label)

    def coverage() -> tuple[set[str], set[str]]:
        return {p.archetype for p in selected}, {p.deck_hash for p in selected}

    if not pool or top_limit <= 0:
        return selected
    add(pool[0])

    while len(selected) < top_limit:
        archetypes, decks = coverage()
        if len(archetypes) >= min_archetypes and len(decks) >= min_decks:
            break
        best: Participant | None = None
        best_score: tuple[int, int, int] | None = None
        for participant in pool:
            if participant.label in selected_labels:
                continue
            new_arch = int(participant.archetype not in archetypes)
            new_deck = int(participant.deck_hash not in decks)
            score = (new_arch, new_deck, -(participant.rank or 999999))
            if best_score is None or score > best_score:
                best = participant
                best_score = score
        if best is None:
            break
        add(best)

    for participant in pool:
        if len(selected) >= top_limit:
            break
        if participant.label not in selected_labels:
            add(participant)
    selected.sort(key=lambda participant: (participant.rank or 999999, participant.label))
    return selected


def load_top_team_participants(
    scout_dir: Path,
    top_limit: int,
    allow_partial: bool = False,
    selection_mode: str = "rank",
    scan_limit: int = 0,
    min_archetypes: int = 3,
    min_decks: int = 3,
) -> list[Participant]:
    if scan_limit <= 0:
        scan_limit = top_limit
    pool = load_valid_top_pool(scout_dir, scan_limit)
    if selection_mode == "diverse":
        participants = select_diverse_participants(
            pool,
            top_limit,
            min_archetypes=min_archetypes,
            min_decks=min_decks,
        )
    else:
        participants = pool[:top_limit]
    if len(participants) < top_limit and not allow_partial:
        summary = scout_dir / "download_summary.csv"
        raise ValueError(f"Only loaded {len(participants)} top-team participants from {summary}")
    return participants


def load_candidate_participants(candidate_specs: list[str]) -> list[Participant]:
    participants: list[Participant] = []
    for spec in candidate_specs:
        if "=" not in spec:
            raise ValueError("--candidate must be LABEL=PATH")
        label, path_text = spec.split("=", 1)
        path = Path(path_text)
        deck = read_deck(path)
        arch = pool_tool.archetype(deck)
        participants.append(
            Participant(
                label=safe_label(label),
                kind="ours",
                rank=None,
                public_score=None,
                source_team=label,
                source_replay=None,
                archetype=arch.replace("_", "-"),
                deck_hash=deck_hash(deck),
                policy=path,
                deck=tuple(deck),
            )
        )
    return participants


def summarize(results: list[dict], left_is_p0: bool) -> tuple[int, int, int, int]:
    counts = Counter(result["result"] for result in results)
    left_wins = counts[0] if left_is_p0 else counts[1]
    right_wins = counts[1] if left_is_p0 else counts[0]
    return left_wins, right_wins, counts[2], counts[-1]


def play_pair(left, right, games_per_seat: int, max_steps: int, quiet: bool) -> tuple[int, int, int, int]:
    left_agent, left_deck = left
    right_agent, right_deck = right
    forward = run_games(left_agent, left_deck, right_agent, right_deck, games_per_seat, max_steps, False, True, "forward")
    f_left, f_right, f_draw, f_unfinished = summarize(forward, True)
    swapped = run_games(right_agent, right_deck, left_agent, left_deck, games_per_seat, max_steps, False, True, "swapped")
    s_left, s_right, s_draw, s_unfinished = summarize(swapped, False)
    return f_left + s_left, f_right + s_right, f_draw + s_draw, f_unfinished + s_unfinished


def score_from_games(wins: int, losses: int, draws: int) -> float:
    total = wins + losses + draws
    if total <= 0:
        return 0.0
    return (wins + 0.5 * draws) / total


def candidate_robustness(participants: list[Participant], matches: list[dict]) -> list[RobustnessRow]:
    """Compute robustness diagnostics for every candidate-like participant.

    This intentionally scores only games against replay-observed top-team decks.
    Candidate-vs-candidate games are useful for adversarial testing, but they can
    make local mimicry look better than actual public-field coverage.
    """
    by_label = {participant.label: participant for participant in participants}
    candidate_labels = [participant.label for participant in participants if participant.kind == "ours"]
    top_labels = {participant.label for participant in participants if participant.kind == "top_team"}

    # First pass: candidate/opponent win rates for regret calculation.
    per_candidate_opponent: dict[str, dict[str, tuple[int, int, int]]] = {
        label: {} for label in candidate_labels
    }
    for match in matches:
        left = match["left"]
        right = match["right"]
        if left in candidate_labels and right in top_labels:
            per_candidate_opponent[left][right] = (match["left_games"], match["right_games"], match["draws"])
        elif right in candidate_labels and left in top_labels:
            per_candidate_opponent[right][left] = (match["right_games"], match["left_games"], match["draws"])

    best_by_opponent: dict[str, float] = {}
    for opponent in top_labels:
        scores = [
            score_from_games(*opponents[opponent])
            for opponents in per_candidate_opponent.values()
            if opponent in opponents
        ]
        if scores:
            best_by_opponent[opponent] = max(scores)

    rows: list[RobustnessRow] = []
    for candidate in candidate_labels:
        by_opponent = per_candidate_opponent[candidate]
        total_wins = total_losses = total_draws = 0
        by_archetype: dict[str, list[float]] = {}
        regrets: list[float] = []
        worst_opponent = "-"
        worst_opponent_score = 2.0

        for opponent, games in by_opponent.items():
            wins, losses, draws = games
            total_wins += wins
            total_losses += losses
            total_draws += draws
            opponent_score = score_from_games(wins, losses, draws)
            opponent_info = by_label[opponent]
            by_archetype.setdefault(opponent_info.archetype, []).append(opponent_score)
            if opponent in best_by_opponent:
                regrets.append(best_by_opponent[opponent] - opponent_score)
            if opponent_score < worst_opponent_score:
                worst_opponent_score = opponent_score
                worst_opponent = opponent

        top_games = total_wins + total_losses + total_draws
        top_win_pct = score_from_games(total_wins, total_losses, total_draws)
        archetype_scores = {
            archetype: sum(values) / len(values)
            for archetype, values in by_archetype.items()
            if values
        }
        if archetype_scores:
            worst_archetype, maximin = min(archetype_scores.items(), key=lambda item: (item[1], item[0]))
            archetype_stddev = pstdev(archetype_scores.values()) if len(archetype_scores) > 1 else 0.0
        else:
            worst_archetype = "-"
            maximin = 0.0
            archetype_stddev = 0.0
        max_regret = max(regrets) if regrets else 0.0
        avg_regret = sum(regrets) / len(regrets) if regrets else 0.0
        robustness_score = maximin - max_regret - 0.25 * archetype_stddev
        rows.append(
            RobustnessRow(
                entry=candidate,
                top_games=top_games,
                top_win_pct=top_win_pct,
                maximin_archetype_win_pct=maximin,
                max_regret=max_regret,
                avg_regret=avg_regret,
                archetype_stddev=archetype_stddev,
                worst_archetype=worst_archetype,
                worst_opponent=worst_opponent,
                robustness_score=robustness_score,
            )
        )

    rows.sort(
        key=lambda row: (
            -row.robustness_score,
            -row.maximin_archetype_win_pct,
            row.max_regret,
            -row.top_win_pct,
            row.entry,
        )
    )
    return rows


def render_report(
    participants: list[Participant],
    standings: list[Standing],
    matches: list[dict],
    robustness_rows: list[RobustnessRow],
    args: argparse.Namespace,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Local Top-10 Plus GarlicToday League",
        "",
        f"Generated: {now}",
        "",
        "## Configuration",
        "",
        f"- Scout: `{args.scout_dir}`",
        f"- Top teams: {args.top_limit}",
        f"- Selection mode: `{args.selection_mode}`",
        f"- Scout scan limit: {args.scan_limit}",
        f"- Diversity targets: archetypes>={args.min_archetypes}, deck hashes>={args.min_decks}",
        f"- GarlicToday candidates: {', '.join(p.label for p in participants if p.kind == 'ours')}",
        f"- Games per seat per pairing: {args.games_per_seat}",
        f"- Total games per pairing: {args.games_per_seat * 2}",
        f"- Max steps: {args.max_steps}",
        f"- Host: {socket.gethostname()}",
        "",
        "## Engine Provenance",
        "",
        *engine_provenance_lines(),
        "",
        "## Trust Status",
        "",
        "**Diagnostic only. Do not use this league by itself as a submit signal.**",
        "",
        "Top teams are represented by their replay-observed deck and the local archetype policy template; this is not their private Kaggle agent code.",
        "",
        "A local league winner is submit-eligible only after the predictive-validity, public-anchor, and pre-submit gates open. If those gates are closed, this table is a stress-test and hypothesis source, not a public-score forecast.",
        "",
        "Before promoting a local winner, run `tools/audit_local_league_public_gap.py` against mature public submissions and check that the league ranking is not contradicted by public anchors.",
        "",
        "## Candidate Robustness Diagnostics",
        "",
        "These rows score only candidate games against replay-observed top-team decks. `Maximin` is the candidate's worst average win rate by opponent archetype; `max regret` is the largest gap to the best candidate against any one top-team opponent.",
        "",
        "| Robust rank | Candidate | Top games | Top win % | Maximin | Max regret | Avg regret | Archetype stddev | Worst archetype | Worst opponent | Robustness score |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: |",
    ]
    for rank, row in enumerate(robustness_rows, 1):
        lines.append(
            f"| {rank} | `{row.entry}` | {row.top_games} | {row.top_win_pct:.3f} | "
            f"{row.maximin_archetype_win_pct:.3f} | {row.max_regret:.3f} | "
            f"{row.avg_regret:.3f} | {row.archetype_stddev:.3f} | "
            f"`{row.worst_archetype}` | `{row.worst_opponent}` | {row.robustness_score:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Standings",
            "",
            "| Rank | Entry | Match record | Points | Game record | Game diff | Archetype | Deck hash | Source |",
            "| ---: | --- | --- | ---: | --- | ---: | --- | --- | --- |",
        ]
    )
    for rank, standing in enumerate(standings, 1):
        p = standing.participant
        source = "GarlicToday" if p.kind == "ours" else f"public rank {p.rank}, score {p.public_score:.1f}"
        match_record = f"win-{standing.match_wins} lose-{standing.match_losses} draw-{standing.match_draws}"
        game_record = f"{standing.game_wins}-{standing.game_losses}-{standing.game_draws}"
        lines.append(
            f"| {rank} | `{p.label}` | {match_record} | {standing.points} | "
            f"{game_record} | {standing.game_diff} | `{p.archetype}` | `{p.deck_hash}` | {source} |"
        )
    lines.extend(
        [
            "",
            "## Participants",
            "",
            "| Entry | Kind | Policy | Replay |",
            "| --- | --- | --- | --- |",
        ]
    )
    for p in participants:
        replay = "-" if p.source_replay is None else f"`{p.source_replay}`"
        lines.append(f"| `{p.label}` | {p.kind} | `{p.policy}` | {replay} |")
    lines.extend(
        [
            "",
            "## Match Results",
            "",
            "| Left | Right | Left games | Right games | Draws | Unfinished | Match winner |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for match in matches:
        lines.append(
            f"| `{match['left']}` | `{match['right']}` | {match['left_games']} | {match['right_games']} | "
            f"{match['draws']} | {match['unfinished']} | `{match['winner']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scout-dir", type=Path, required=True)
    parser.add_argument("--top-limit", type=int, default=10)
    parser.add_argument("--selection-mode", choices=("rank", "diverse"), default="rank")
    parser.add_argument(
        "--scan-limit",
        type=int,
        default=0,
        help="Highest public rank to scan for selectable local-policy opponents; 0 means top-limit.",
    )
    parser.add_argument("--min-archetypes", type=int, default=3)
    parser.add_argument("--min-decks", type=int, default=3)
    parser.add_argument(
        "--allow-partial-top",
        action="store_true",
        help="Run with all locally mapped top-window decks instead of failing when some top decks have no policy template.",
    )
    parser.add_argument("--candidate", action="append", default=[], help="LABEL=AGENT_DIR")
    parser.add_argument("--games-per-seat", type=int, default=3)
    parser.add_argument("--max-steps", type=int, default=2000)
    parser.add_argument("--output-prefix", type=Path, default=None)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--docker", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--docker-image", default="python:3.11-slim")
    parser.add_argument("--docker-platform", default="linux/amd64")
    parser.add_argument("--python", default="python")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.docker:
        return docker_reinvoke(args)

    if not args.candidate:
        raise ValueError("At least one --candidate LABEL=PATH is required")
    output_prefix = args.output_prefix or Path("strategy") / f"local_league_{timestamp()}"
    output_prefix.parent.mkdir(parents=True, exist_ok=True)

    participants = load_top_team_participants(
        args.scout_dir,
        args.top_limit,
        args.allow_partial_top,
        args.selection_mode,
        args.scan_limit,
        args.min_archetypes,
        args.min_decks,
    )
    participants.extend(load_candidate_participants(args.candidate))

    loaded = {}
    for participant in participants:
        agent, deck_from_agent = load_agent(participant.policy, participant.label)
        deck = list(participant.deck)
        loaded[participant.label] = (agent, deck)
        if participant.kind == "ours" and tuple(deck_from_agent) != participant.deck:
            raise ValueError(f"Candidate deck mismatch for {participant.label}")

    standing_by_label = {participant.label: Standing(participant) for participant in participants}
    matches: list[dict] = []
    for left_index, left in enumerate(participants):
        for right in participants[left_index + 1 :]:
            left_games, right_games, draws, unfinished = play_pair(
                loaded[left.label], loaded[right.label], args.games_per_seat, args.max_steps, args.quiet
            )
            left_standing = standing_by_label[left.label]
            right_standing = standing_by_label[right.label]
            left_standing.game_wins += left_games
            left_standing.game_losses += right_games
            left_standing.game_draws += draws
            left_standing.unfinished += unfinished
            right_standing.game_wins += right_games
            right_standing.game_losses += left_games
            right_standing.game_draws += draws
            right_standing.unfinished += unfinished
            if left_games > right_games:
                left_standing.match_wins += 1
                right_standing.match_losses += 1
                winner = left.label
            elif right_games > left_games:
                right_standing.match_wins += 1
                left_standing.match_losses += 1
                winner = right.label
            else:
                left_standing.match_draws += 1
                right_standing.match_draws += 1
                winner = "draw"
            matches.append(
                {
                    "left": left.label,
                    "right": right.label,
                    "left_games": left_games,
                    "right_games": right_games,
                    "draws": draws,
                    "unfinished": unfinished,
                    "winner": winner,
                }
            )
            if not args.quiet:
                print(
                    f"{left.label} vs {right.label}: {left_games}-{right_games}"
                    f"-{draws} unfinished={unfinished} winner={winner}"
                )

    standings = sorted(
        standing_by_label.values(),
        key=lambda item: (
            -item.points,
            -item.match_wins,
            -item.game_diff,
            -item.game_wins,
            item.participant.rank if item.participant.rank is not None else 999,
            item.participant.label,
        ),
    )

    md_path = output_prefix.with_suffix(".md")
    csv_path = output_prefix.with_suffix(".csv")
    match_path = output_prefix.with_name(output_prefix.name + "_matches.csv")
    robustness_path = output_prefix.with_name(output_prefix.name + "_robustness.csv")
    robustness_rows = candidate_robustness(participants, matches)
    report = render_report(participants, standings, matches, robustness_rows, args)
    md_path.write_text(report, encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "rank",
                "entry",
                "win_pct",
                "match_wins",
                "match_losses",
                "match_draws",
                "points",
                "game_wins",
                "game_losses",
                "game_draws",
                "unfinished",
                "game_diff",
                "archetype",
                "deck_hash",
                "kind",
                "source_team",
                "public_rank",
                "public_score",
                "policy",
                "source_replay",
            ]
        )
        for rank, standing in enumerate(standings, 1):
            p = standing.participant
            writer.writerow(
                [
                    rank,
                    p.label,
                    f"{standing.win_pct:.6f}",
                    standing.match_wins,
                    standing.match_losses,
                    standing.match_draws,
                    standing.points,
                    standing.game_wins,
                    standing.game_losses,
                    standing.game_draws,
                    standing.unfinished,
                    standing.game_diff,
                    p.archetype,
                    p.deck_hash,
                    p.kind,
                    p.source_team,
                    p.rank or "",
                    "" if p.public_score is None else p.public_score,
                    p.policy,
                    "" if p.source_replay is None else p.source_replay,
                ]
            )
    with match_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["left", "right", "left_games", "right_games", "draws", "unfinished", "winner"])
        writer.writeheader()
        writer.writerows(matches)
    with robustness_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "rank",
                "entry",
                "top_games",
                "top_win_pct",
                "maximin_archetype_win_pct",
                "max_regret",
                "avg_regret",
                "archetype_stddev",
                "worst_archetype",
                "worst_opponent",
                "robustness_score",
            ]
        )
        for rank, row in enumerate(robustness_rows, 1):
            writer.writerow(
                [
                    rank,
                    row.entry,
                    row.top_games,
                    f"{row.top_win_pct:.6f}",
                    f"{row.maximin_archetype_win_pct:.6f}",
                    f"{row.max_regret:.6f}",
                    f"{row.avg_regret:.6f}",
                    f"{row.archetype_stddev:.6f}",
                    row.worst_archetype,
                    row.worst_opponent,
                    f"{row.robustness_score:.6f}",
                ]
            )
    print(f"wrote {md_path}")
    print(f"wrote {csv_path}")
    print(f"wrote {match_path}")
    print(f"wrote {robustness_path}")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
