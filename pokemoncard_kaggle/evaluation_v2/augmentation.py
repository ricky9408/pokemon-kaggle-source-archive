"""Leakage-safe development augmentation from fresh public replay scouts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .cohort import deck_sha256, initial_decks, sha256_file
from .schemas import CohortManifest, EpisodeRecord


EPISODE_RE = re.compile(r"episode-(\d+)-replay\.json$")
SUBMISSION_RE = re.compile(r"submission_(\d+)")


@dataclass(frozen=True)
class Augmentation:
    augmentation_id: str
    created_at_utc: str
    parent_cohort_id: str
    source_root: str
    source_sha256: str
    target_deck_sha256: str
    frozen_episode_ids: tuple[int, ...]
    skipped_frozen_files: int
    scanned_files: int
    records: tuple[EpisodeRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "cohort_development_augmentation_v1",
            "augmentation_id": self.augmentation_id,
            "created_at_utc": self.created_at_utc,
            "parent_cohort_id": self.parent_cohort_id,
            "source_root": self.source_root,
            "source_sha256": self.source_sha256,
            "target_deck_sha256": self.target_deck_sha256,
            "frozen_episode_ids": list(self.frozen_episode_ids),
            "skipped_frozen_files": self.skipped_frozen_files,
            "scanned_files": self.scanned_files,
            "records": [record.to_dict() for record in self.records],
        }


def episode_id_from_path(path: Path) -> int | None:
    match = EPISODE_RE.search(path.name)
    return int(match.group(1)) if match else None


def eligible_replay_paths(
    replay_root: Path,
    *,
    frozen_episode_ids: set[int],
) -> tuple[list[Path], int]:
    """Filter frozen IDs by filename before any replay content is opened."""
    eligible: list[Path] = []
    skipped = 0
    for path in sorted(replay_root.rglob("episode-*-replay.json")):
        episode_id = episode_id_from_path(path)
        if episode_id is None:
            continue
        if episode_id in frozen_episode_ids:
            skipped += 1
            continue
        eligible.append(path)
    return eligible, skipped


def _submission_id(path: Path) -> int | None:
    match = SUBMISSION_RE.search(str(path))
    return int(match.group(1)) if match else None


def _relative_path(repo_root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path.resolve())


def _source_hash(records: Iterable[EpisodeRecord]) -> str:
    payload = "\n".join(
        f"{record.episode_id},{record.target_slot},{record.target_team},"
        f"{record.replay_sha256}"
        for record in records
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_augmentation(
    *,
    repo_root: Path,
    replay_root: Path,
    base_manifest: CohortManifest,
) -> Augmentation:
    """Collect fresh exact-deck records while preserving the frozen split."""
    frozen_ids = {record.episode_id for record in base_manifest.episodes}
    paths, skipped_frozen = eligible_replay_paths(
        replay_root,
        frozen_episode_ids=frozen_ids,
    )
    records: list[EpisodeRecord] = []
    seen: set[tuple[int, int]] = set()
    for replay_path in paths:
        replay = json.loads(replay_path.read_text())
        info = replay.get("info") or {}
        episode_id = int(info.get("EpisodeId") or replay.get("id"))
        filename_id = episode_id_from_path(replay_path)
        if filename_id != episode_id:
            raise ValueError(
                f"episode id mismatch for {replay_path}: filename={filename_id} payload={episode_id}"
            )
        teams = info.get("TeamNames") or []
        decks = initial_decks(replay)
        if len(teams) != 2 or len(decks) != 2:
            raise ValueError(f"expected two teams and decks in {replay_path}")
        rewards = replay.get("rewards") or [0.0, 0.0]
        config = replay.get("configuration") or {}
        replay_hash = sha256_file(replay_path)
        for target_slot, cards in enumerate(decks):
            if deck_sha256(cards) != base_manifest.target_deck_sha256:
                continue
            key = (episode_id, target_slot)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                EpisodeRecord(
                    episode_id=episode_id,
                    replay_path=_relative_path(repo_root, replay_path),
                    replay_sha256=replay_hash,
                    target_team=str(teams[target_slot]),
                    opponent_team=str(teams[1 - target_slot]),
                    target_slot=target_slot,
                    target_reward=float(rewards[target_slot]),
                    target_deck_sha256=base_manifest.target_deck_sha256,
                    submission_id=_submission_id(replay_path),
                    module_version=str(replay.get("module_version") or "unknown"),
                    public_seed=(
                        int(config["seed"])
                        if config.get("seed") is not None
                        else None
                    ),
                    role="development",
                )
            )
    records.sort(key=lambda record: (record.episode_id, record.target_slot))
    source_hash = _source_hash(records)
    identity = {
        "schema": "cohort_development_augmentation_v1",
        "parent_cohort_id": base_manifest.cohort_id,
        "source_sha256": source_hash,
        "target_deck_sha256": base_manifest.target_deck_sha256,
        "records": [record.to_dict() for record in records],
    }
    augmentation_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return Augmentation(
        augmentation_id=augmentation_id,
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        parent_cohort_id=base_manifest.cohort_id,
        source_root=str(replay_root.resolve()),
        source_sha256=source_hash,
        target_deck_sha256=base_manifest.target_deck_sha256,
        frozen_episode_ids=tuple(sorted(frozen_ids)),
        skipped_frozen_files=skipped_frozen,
        scanned_files=len(paths),
        records=tuple(records),
    )


def write_augmentation(augmentation: Augmentation, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(augmentation.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "Augmentation",
    "build_augmentation",
    "eligible_replay_paths",
    "episode_id_from_path",
    "write_augmentation",
]
