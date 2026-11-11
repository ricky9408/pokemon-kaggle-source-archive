"""Freeze public replays into an immutable, leakage-resistant cohort."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .schemas import CohortManifest, EpisodeRecord, SCHEMA_VERSION


SUBMISSION_RE = re.compile(r"submission_(\d+)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deck_sha256(cards: Iterable[int]) -> str:
    canonical = ",".join(str(card) for card in sorted(int(card) for card in cards))
    return sha256_bytes(canonical.encode("ascii"))


def read_deck(path: Path) -> tuple[int, ...]:
    cards = tuple(int(line.strip()) for line in path.read_text().splitlines() if line.strip())
    if len(cards) != 60:
        raise ValueError(f"expected 60 cards in {path}, found {len(cards)}")
    return cards


def initial_decks(replay: dict[str, Any]) -> list[list[int]]:
    """Return the two submitted decks from the replay's setup frame."""
    for step in replay.get("steps", []):
        for record in step:
            for frame in record.get("visualize") or []:
                action = frame.get("action") if isinstance(frame, dict) else None
                if (
                    isinstance(action, list)
                    and len(action) == 2
                    and all(isinstance(deck, list) and len(deck) == 60 for deck in action)
                ):
                    return [[int(card) for card in deck] for deck in action]
    raise ValueError("replay has no two-deck visualization frame")


# Backward-compatible alias for older local callers.
_initial_decks = initial_decks


def _submission_id(path: Path) -> int | None:
    match = SUBMISSION_RE.search(str(path))
    return int(match.group(1)) if match else None


def _role(episode_id: int, *, seed: int, holdout_fraction: float, inspected: set[int]) -> str:
    if episode_id in inspected:
        return "development"
    token = sha256_bytes(f"{seed}:{episode_id}".encode("ascii"))
    bucket = int(token[:16], 16) / float(16**16 - 1)
    return "holdout" if bucket < holdout_fraction else "development"


def _source_digest(records: list[EpisodeRecord], *, version: int) -> str:
    if version == 1:
        payload = "\n".join(
            f"{record.episode_id},{record.replay_sha256},{record.role}" for record in records
        )
    elif version == 2:
        payload = "\n".join(
            f"{record.episode_id},{record.target_slot},{record.target_team},{record.replay_sha256},{record.role}"
            for record in records
        )
    else:
        raise ValueError(f"unsupported source digest version: {version}")
    return sha256_bytes(payload.encode("ascii"))


def freeze_cohort(
    *,
    repo_root: Path,
    replay_root: Path,
    target_team: str | None,
    target_teams: set[str] | None = None,
    target_deck: tuple[int, ...],
    cohort_name: str,
    split_seed: int,
    holdout_fraction: float,
    preinspected_episode_ids: set[int],
    leaderboard_path: Path | None,
) -> CohortManifest:
    if not 0.1 <= holdout_fraction <= 0.9:
        raise ValueError("holdout_fraction must be between 0.1 and 0.9")
    target_hash = deck_sha256(target_deck)
    selected_teams = set(target_teams or ())
    if target_team:
        selected_teams.add(target_team)
    if not selected_teams:
        raise ValueError("at least one target team is required")
    records: list[EpisodeRecord] = []
    seen: set[tuple[int, int]] = set()
    for replay_path in sorted(replay_root.rglob("episode-*-replay.json")):
        replay = json.loads(replay_path.read_text())
        info = replay.get("info") or {}
        teams = info.get("TeamNames") or []
        decks = initial_decks(replay)
        target_slots = [
            slot
            for slot, team in enumerate(teams)
            if team in selected_teams and deck_sha256(decks[slot]) == target_hash
        ]
        if not target_slots:
            continue
        episode_id = int(info.get("EpisodeId") or replay.get("id"))
        rewards = replay.get("rewards") or [0, 0]
        config = replay.get("configuration") or {}
        try:
            relative_path = replay_path.resolve().relative_to(repo_root.resolve())
        except ValueError:
            relative_path = replay_path.resolve()
        for target_slot in target_slots:
            record_key = (episode_id, target_slot)
            if record_key in seen:
                continue
            seen.add(record_key)
            records.append(
                EpisodeRecord(
                    episode_id=episode_id,
                    replay_path=str(relative_path),
                    replay_sha256=sha256_file(replay_path),
                    target_team=str(teams[target_slot]),
                    opponent_team=str(teams[1 - target_slot]),
                    target_slot=target_slot,
                    target_reward=float(rewards[target_slot]),
                    target_deck_sha256=target_hash,
                    submission_id=_submission_id(replay_path),
                    module_version=str(replay.get("module_version") or "unknown"),
                    public_seed=int(config["seed"]) if config.get("seed") is not None else None,
                    role=_role(
                        episode_id,
                        seed=split_seed,
                        holdout_fraction=holdout_fraction,
                        inspected=preinspected_episode_ids,
                    ),
                )
            )
    records.sort(key=lambda record: (record.episode_id, record.target_slot))
    if len(records) < 12:
        raise ValueError(f"only {len(records)} exact-deck episodes; need at least 12")
    missing_inspected = preinspected_episode_ids - {record.episode_id for record in records}
    if missing_inspected:
        raise ValueError(f"preinspected episodes absent from exact-deck cohort: {sorted(missing_inspected)}")
    source_digest_version = 2
    source_hash = _source_digest(records, version=source_digest_version)
    canonical = {
        "schema_version": SCHEMA_VERSION,
        "cohort_name": cohort_name,
        "source_root_sha256": source_hash,
        "source_digest_version": source_digest_version,
        "target_teams": sorted(selected_teams),
        "target_deck_sha256": target_hash,
        "split_seed": split_seed,
        "holdout_fraction": holdout_fraction,
        "episodes": [record.to_dict() for record in records],
    }
    cohort_id = sha256_bytes(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )[:20]
    leaderboard = leaderboard_path.resolve() if leaderboard_path else None
    leaderboard_record: str | None = None
    if leaderboard is not None:
        try:
            leaderboard_record = str(leaderboard.relative_to(repo_root.resolve()))
        except ValueError:
            leaderboard_record = str(leaderboard)
    return CohortManifest(
        cohort_id=cohort_id,
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        cohort_name=cohort_name,
        source_root=str(replay_root.resolve()),
        source_root_sha256=source_hash,
        target_team=sorted(selected_teams)[0],
        target_deck_sha256=target_hash,
        target_deck_cards=tuple(target_deck),
        split_seed=split_seed,
        holdout_fraction=holdout_fraction,
        preinspected_episode_ids=tuple(sorted(preinspected_episode_ids)),
        leaderboard_path=leaderboard_record,
        leaderboard_sha256=sha256_file(leaderboard) if leaderboard else None,
        episodes=tuple(records),
        target_teams=tuple(sorted(selected_teams)),
        source_digest_version=source_digest_version,
    )


def write_manifest(manifest: CohortManifest, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n")


def write_split_csv(manifest: CohortManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(manifest.episodes[0].to_dict()))
        writer.writeheader()
        writer.writerows(record.to_dict() for record in manifest.episodes)


def load_manifest(path: Path) -> CohortManifest:
    data = json.loads(path.read_text())
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported cohort schema: {data.get('schema_version')}")
    episodes = tuple(EpisodeRecord(**record) for record in data.pop("episodes"))
    data["target_deck_cards"] = tuple(data["target_deck_cards"])
    data["preinspected_episode_ids"] = tuple(data["preinspected_episode_ids"])
    data["target_teams"] = tuple(data.get("target_teams") or (data["target_team"],))
    return CohortManifest(episodes=episodes, **data)


def verify_manifest(manifest: CohortManifest, repo_root: Path) -> list[str]:
    errors: list[str] = []
    records: list[EpisodeRecord] = []
    for episode in manifest.episodes:
        path = manifest.resolve_replay(repo_root, episode)
        if not path.exists():
            errors.append(f"missing replay: {path}")
            continue
        digest = sha256_file(path)
        if digest != episode.replay_sha256:
            errors.append(f"replay changed: {path}")
        records.append(replace(episode, replay_sha256=digest))
    if not errors and _source_digest(records, version=manifest.source_digest_version) != manifest.source_root_sha256:
        errors.append("source root digest mismatch")
    if manifest.leaderboard_path and manifest.leaderboard_sha256:
        leaderboard = Path(manifest.leaderboard_path)
        if not leaderboard.is_absolute():
            leaderboard = repo_root / leaderboard
        if not leaderboard.exists() or sha256_file(leaderboard) != manifest.leaderboard_sha256:
            errors.append("leaderboard changed or missing")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--replay-root", type=Path, required=True)
    parser.add_argument("--target-team", action="append", required=True)
    parser.add_argument("--deck", type=Path, required=True)
    parser.add_argument("--cohort-name", required=True)
    parser.add_argument("--split-seed", type=int, default=20260710)
    parser.add_argument("--holdout-fraction", type=float, default=0.5)
    parser.add_argument("--preinspected", type=int, nargs="*", default=[])
    parser.add_argument("--leaderboard", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split-csv", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = freeze_cohort(
        repo_root=args.repo_root.resolve(),
        replay_root=args.replay_root.resolve(),
        target_team=None,
        target_teams=set(args.target_team),
        target_deck=read_deck(args.deck),
        cohort_name=args.cohort_name,
        split_seed=args.split_seed,
        holdout_fraction=args.holdout_fraction,
        preinspected_episode_ids=set(args.preinspected),
        leaderboard_path=args.leaderboard,
    )
    write_manifest(manifest, args.output)
    if args.split_csv:
        write_split_csv(manifest, args.split_csv)
    counts = {role: sum(record.role == role for record in manifest.episodes) for role in ("development", "holdout")}
    print(json.dumps({"cohort_id": manifest.cohort_id, "episodes": len(manifest.episodes), **counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
