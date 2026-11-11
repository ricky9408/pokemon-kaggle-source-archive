#!/usr/bin/env python3
"""Report public-anchor support for candidate strategy families.

Local full-game simulation is currently fenced because it cannot inject Kaggle
public replay seeds. This report makes the replacement evidence explicit:
candidate families need real GarlicToday public submissions and/or exact-hash
top-window public replays before they can become submit-facing hypotheses.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import tarfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backtest_local_vs_public import ArchiveRecord, load_submission_history  # noqa: E402
from strategy_research import archetype, deck_hash, load_replay_observations  # noqa: E402


@dataclass
class Candidate:
    name: str
    archive: str
    path: Path
    family: str
    kind: str
    replay_win_rate: float | None
    public_current: float | None
    public_best: float | None
    public_floor: float | None
    notes: str
    deck_hash: str | None = None
    inferred_archetype: str | None = None


@dataclass
class ReplayAnchor:
    archetype: str
    deck_hash: str
    seen: int = 0
    wins: int = 0
    weighted_seen: float = 0.0
    weighted_wins: float = 0.0
    teams: Counter[str] = field(default_factory=Counter)
    ranks: list[int] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.archetype}:{self.deck_hash}"

    @property
    def win_rate(self) -> float:
        return self.wins / self.seen if self.seen else 0.0


@dataclass
class CandidateAnchorStatus:
    candidate: Candidate
    submission_runs: int
    latest_public: float | None
    best_public: float | None
    min_public: float | None
    top_replay_seen: int
    top_replay_wins: int
    top_replay_teams: str
    anchor_state: str
    submit_eligible: bool
    reasons: list[str]


def parse_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def fmt_float(value: float | None, digits: int = 1) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def archive_name(path_text: str) -> str:
    return Path(path_text).name if path_text else ""


def read_deck_from_archive(path: Path) -> tuple[int, ...] | None:
    if not path.exists():
        return None
    if path.is_dir():
        deck_path = path / "deck.csv"
        if not deck_path.exists():
            return None
        return tuple(int(line.strip()) for line in deck_path.read_text().splitlines() if line.strip())
    if path.suffixes[-2:] != [".tar", ".gz"]:
        return None
    try:
        with tarfile.open(path, "r:gz") as archive:
            member = next((item for item in archive.getmembers() if Path(item.name).name == "deck.csv"), None)
            if member is None:
                return None
            extracted = archive.extractfile(member)
            if extracted is None:
                return None
            text = extracted.read().decode("utf-8")
    except (tarfile.TarError, OSError, UnicodeDecodeError):
        return None
    return tuple(int(line.strip()) for line in text.splitlines() if line.strip())


def load_candidates(path: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            candidate_path = Path(row.get("path") or row.get("candidate") or "")
            candidate = Candidate(
                name=row.get("candidate", "") or candidate_path.stem,
                archive=archive_name(row.get("path") or row.get("candidate") or ""),
                path=candidate_path,
                family=row.get("family", ""),
                kind=row.get("kind", ""),
                replay_win_rate=parse_float(row.get("replay_win_rate")),
                public_current=parse_float(row.get("public_current")),
                public_best=parse_float(row.get("public_best")),
                public_floor=parse_float(row.get("public_floor")),
                notes=row.get("notes", ""),
            )
            deck = read_deck_from_archive(candidate_path)
            if deck:
                candidate.deck_hash = deck_hash(deck)
                candidate.inferred_archetype = archetype(deck)
            candidates.append(candidate)
    return candidates


def rank_factor(rank: int | None) -> float:
    if rank is None or rank <= 0:
        return 1.0
    return 1.0 + 0.75 / (rank**0.5)


def load_replay_anchors(replays: list[Path]) -> dict[str, ReplayAnchor]:
    observations, _duplicates = load_replay_observations(replays, dedupe=True, rank_weighting=True)
    anchors: dict[str, ReplayAnchor] = {}
    for obs in observations:
        key = f"{obs.archetype}:{obs.deck_hash}"
        anchor = anchors.setdefault(key, ReplayAnchor(archetype=obs.archetype, deck_hash=obs.deck_hash))
        weight = rank_factor(obs.rank)
        anchor.seen += 1
        anchor.weighted_seen += weight
        anchor.teams[obs.team] += 1
        if obs.rank is not None:
            anchor.ranks.append(obs.rank)
        if obs.reward == 1:
            anchor.wins += 1
            anchor.weighted_wins += weight
        if obs.path is not None and len(anchor.examples) < 3:
            anchor.examples.append(str(obs.path))
    return anchors


def family_submission_counts(candidates: list[Candidate], records: dict[str, ArchiveRecord]) -> dict[str, list[float]]:
    archive_to_family = {candidate.archive: candidate.family for candidate in candidates if candidate.archive}
    scores: dict[str, list[float]] = defaultdict(list)
    for archive, record in records.items():
        family = archive_to_family.get(archive)
        if not family:
            continue
        for submission in record.submissions:
            if submission.status.endswith(".COMPLETE"):
                scores[family].append(submission.public_score)
    return scores


def candidate_scores(candidate: Candidate, records: dict[str, ArchiveRecord]) -> tuple[int, float | None, float | None, float | None]:
    record = records.get(candidate.archive)
    scores: list[float] = []
    if record:
        scores = [submission.public_score for submission in record.submissions if submission.status.endswith(".COMPLETE")]
    if not scores:
        fallback_scores = [candidate.public_current, candidate.public_best, candidate.public_floor]
        scores = [score for score in fallback_scores if score is not None]
    if not scores:
        return 0, None, None, None
    latest = scores[0] if record else candidate.public_current
    return len(scores), latest, max(scores), min(scores)


def classify_anchor(
    candidate: Candidate,
    records: dict[str, ArchiveRecord],
    replay_anchor: ReplayAnchor | None,
    family_scores: dict[str, list[float]],
    args: argparse.Namespace,
) -> CandidateAnchorStatus:
    runs, latest, best, minimum = candidate_scores(candidate, records)
    family_public_scores = family_scores.get(candidate.family, [])
    family_runs = len(family_public_scores)
    family_min = min(family_public_scores) if family_public_scores else None
    top_seen = replay_anchor.seen if replay_anchor else 0
    top_wins = replay_anchor.wins if replay_anchor else 0
    teams = ", ".join(f"{team}x{count}" for team, count in (replay_anchor.teams.most_common(4) if replay_anchor else [])) or "-"

    reasons: list[str] = []
    submit_eligible = False
    anchor_state = "unanchored"

    if family_runs >= args.min_family_submissions:
        anchor_state = "family-public-anchored"
        reasons.append(f"family has {family_runs} completed GarlicToday public submissions")
        submit_eligible = True
    elif runs >= args.min_family_submissions:
        anchor_state = "candidate-public-anchored"
        reasons.append(f"candidate has {runs} completed public submissions")
        submit_eligible = True
    elif runs >= 1 and top_seen >= args.min_top_replays:
        anchor_state = "hybrid-public-plus-exact-hash"
        reasons.append(f"{runs} GarlicToday public run plus {top_seen} exact-hash top-window replay decks")
        submit_eligible = True
    elif top_seen >= args.min_top_replays:
        anchor_state = "exact-hash-observed-only"
        reasons.append(f"{top_seen} exact-hash top-window replay decks but no GarlicToday public run")
    elif runs >= 1:
        anchor_state = "single-public-run"
        reasons.append(f"{runs} GarlicToday public run but only {top_seen} exact-hash top-window replay decks")
    else:
        reasons.append("no completed GarlicToday public run and insufficient exact-hash top-window replay evidence")

    low_scores = [score for score in (latest, minimum, family_min) if score is not None and score < args.low_public_floor]
    if low_scores:
        submit_eligible = False
        reasons.append(f"contradictory low public anchor below {args.low_public_floor:.0f}: {min(low_scores):.1f}")
    if candidate.kind in {"local-variant", "exact-ranker-mimic"} and not submit_eligible:
        reasons.append("keep as policy research only until public-anchor rule is met")

    return CandidateAnchorStatus(
        candidate=candidate,
        submission_runs=runs,
        latest_public=latest,
        best_public=best,
        min_public=minimum,
        top_replay_seen=top_seen,
        top_replay_wins=top_wins,
        top_replay_teams=teams,
        anchor_state=anchor_state,
        submit_eligible=submit_eligible,
        reasons=reasons,
    )


def summarize_live_anchors(anchors: dict[str, ReplayAnchor], limit: int) -> list[ReplayAnchor]:
    return sorted(anchors.values(), key=lambda item: (-item.weighted_wins, -item.wins, item.key))[:limit]


def write_csv(path: Path, statuses: list[CandidateAnchorStatus]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "candidate",
        "archive",
        "family",
        "kind",
        "deck_hash",
        "inferred_archetype",
        "submission_runs",
        "latest_public",
        "best_public",
        "min_public",
        "top_replay_seen",
        "top_replay_wins",
        "top_replay_teams",
        "anchor_state",
        "submit_eligible",
        "reasons",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for status in statuses:
            candidate = status.candidate
            writer.writerow(
                {
                    "candidate": candidate.name,
                    "archive": candidate.archive,
                    "family": candidate.family,
                    "kind": candidate.kind,
                    "deck_hash": candidate.deck_hash or "",
                    "inferred_archetype": candidate.inferred_archetype or "",
                    "submission_runs": status.submission_runs,
                    "latest_public": "" if status.latest_public is None else f"{status.latest_public:.1f}",
                    "best_public": "" if status.best_public is None else f"{status.best_public:.1f}",
                    "min_public": "" if status.min_public is None else f"{status.min_public:.1f}",
                    "top_replay_seen": status.top_replay_seen,
                    "top_replay_wins": status.top_replay_wins,
                    "top_replay_teams": status.top_replay_teams,
                    "anchor_state": status.anchor_state,
                    "submit_eligible": "1" if status.submit_eligible else "0",
                    "reasons": "; ".join(status.reasons),
                }
            )


def build_report(
    args: argparse.Namespace,
    candidates: list[Candidate],
    statuses: list[CandidateAnchorStatus],
    anchors: dict[str, ReplayAnchor],
    csv_path: Path,
) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    eligible = [status for status in statuses if status.submit_eligible]
    anchored = [status for status in statuses if status.anchor_state != "unanchored"]
    lines: list[str] = []
    lines.append("# Public Anchor Strategy Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategic premise: public-anchor evidence outranks local replay-pool win rate until the simulator fidelity gap is resolved.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Candidate CSV: `{args.candidates}`")
    lines.append(f"- Submissions history: `{args.submissions}`")
    lines.append(f"- Replay files: {len(args.replays)} requested")
    lines.append(f"- Candidate anchor CSV: `{csv_path}`")
    lines.append(f"- Anchor rule: >= {args.min_family_submissions} family public submissions, or one public submission plus >= {args.min_top_replays} exact-hash top-window replay decks, with no public score below {args.low_public_floor:.0f}.")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    if eligible:
        names = ", ".join(f"`{status.candidate.name}`" for status in eligible)
        lines.append(f"- Submit-eligible anchored candidates under this public-anchor rule: {names}.")
    else:
        lines.append("- No candidate clears the submit-facing public-anchor rule. Continue strategy research and public-anchor collection before any upload.")
    lines.append(f"- Anchored or partially anchored candidates: {len(anchored)}/{len(candidates)}.")
    lines.append("- Local gauntlet scores are intentionally omitted from the verdict; use them only to choose policy probes.")
    lines.append("")
    lines.append("## Candidate Anchor Status")
    lines.append("")
    lines.append("| Candidate | Family | Kind | Deck Hash | Public Runs | Latest | Best | Min | Top Replay Seen/Wins | Top Teams | Anchor State | Eligible | Reasons |")
    lines.append("| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |")
    for status in statuses:
        candidate = status.candidate
        lines.append(
            f"| `{candidate.name}` | {candidate.family} | {candidate.kind} | `{candidate.deck_hash or '-'}` | "
            f"{status.submission_runs} | {fmt_float(status.latest_public)} | {fmt_float(status.best_public)} | {fmt_float(status.min_public)} | "
            f"{status.top_replay_seen}/{status.top_replay_wins} | {status.top_replay_teams} | {status.anchor_state} | "
            f"{'yes' if status.submit_eligible else 'no'} | {'; '.join(status.reasons)} |"
        )
    lines.append("")
    lines.append("## Strongest Current Top-Window Exact Hashes")
    lines.append("")
    lines.append("| Rank | Public Archetype:Hash | Seen | Wins | Weighted Wins | Teams | Example Replay |")
    lines.append("| ---: | --- | ---: | ---: | ---: | --- | --- |")
    for index, anchor in enumerate(summarize_live_anchors(anchors, args.live_limit), 1):
        teams = ", ".join(f"{team}x{count}" for team, count in anchor.teams.most_common(4)) or "-"
        example = anchor.examples[0] if anchor.examples else "-"
        lines.append(
            f"| {index} | `{anchor.key}` | {anchor.seen} | {anchor.wins} | {anchor.weighted_wins:.2f} | {teams} | `{example}` |"
        )
    lines.append("")
    lines.append("## Strategy Implications")
    lines.append("")
    lines.append("- Candidate-family promotion should be public-evidence-first: if a family has a low recent GarlicToday score, a local policy tweak in the same family is not submit-safe without new exact-hash public support.")
    lines.append("- Exact top-window hashes are still useful as strategy research targets even when they are not submit anchors; use them for ML/RL imitation and policy-gap mining.")
    lines.append("- Recovery families with real GarlicToday public scores are better calibration anchors than unsubmitted local variants, even when their local replay-pool scores look worse.")
    lines.append("- Next tooling step: feed this CSV into the pair selector/pre-submit gate so anchor status becomes a hard eligibility column.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--submissions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--min-family-submissions", type=int, default=2)
    parser.add_argument("--min-top-replays", type=int, default=5)
    parser.add_argument("--low-public-floor", type=float, default=800.0)
    parser.add_argument("--live-limit", type=int, default=12)
    args = parser.parse_args()

    candidates = load_candidates(args.candidates)
    records = load_submission_history(args.submissions)
    anchors = load_replay_anchors(args.replays)
    family_scores = family_submission_counts(candidates, records)
    statuses = [
        classify_anchor(
            candidate,
            records,
            anchors.get(f"{candidate.inferred_archetype}:{candidate.deck_hash}") if candidate.deck_hash and candidate.inferred_archetype else None,
            family_scores,
            args,
        )
        for candidate in candidates
    ]
    statuses.sort(
        key=lambda status: (
            not status.submit_eligible,
            status.anchor_state,
            -(status.best_public or -1.0),
            status.candidate.family,
            status.candidate.name,
        )
    )
    csv_path = args.csv_output or args.output.with_suffix(".csv")
    write_csv(csv_path, statuses)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(args, candidates, statuses, anchors, csv_path), encoding="utf-8")
    print(f"report={args.output}")
    print(f"csv={csv_path}")
    print(f"candidates={len(candidates)}")
    print(f"eligible={sum(1 for status in statuses if status.submit_eligible)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
