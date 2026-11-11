"""Exact-agent, game-level public outcome panel for transfer calibration."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tarfile
from typing import Any, Iterable
import uuid

from .cohort import deck_sha256, initial_decks, sha256_file


UUID_EPOCH_OFFSET = 0x01B21DD213814000


@dataclass(frozen=True)
class ArchivePolicyIdentity:
    archive_sha256: str
    policy_content_sha256: str
    main_sha256: str
    deck_sha256: str


@dataclass(frozen=True)
class PublicPanelSource:
    label: str
    submission_ref: int
    archive_path: str
    replay_dir: str
    max_games: int = 48
    window_quality: str = "retrieved_chronological"


@dataclass(frozen=True)
class PublicGame:
    episode_id: int
    replay_uuid: str
    replay_sha256: str
    replay_path: str
    replay_started_at_utc: str
    time_block: str
    submission_ref: int
    submitted_at_utc: str
    agent_label: str
    policy_lineage_id: str
    archive_sha256: str
    agent_deck_sha256: str
    player_slot: int
    opponent_team: str
    opponent_axis: str
    opponent_deck_sha256: str
    outcome: float
    module_version: str
    source_window_index: int
    source_window_quality: str


@dataclass(frozen=True)
class PublicTransferPanel:
    panel_id: str
    created_at_utc: str
    cutoff_utc: str
    team: str
    source_config_sha256: str
    games: tuple[PublicGame, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "public_transfer_panel_v1",
            "panel_id": self.panel_id,
            "created_at_utc": self.created_at_utc,
            "cutoff_utc": self.cutoff_utc,
            "team": self.team,
            "source_config_sha256": self.source_config_sha256,
            "games": [asdict(game) for game in self.games],
        }


def replay_started_at(replay_uuid: str) -> datetime:
    value = uuid.UUID(replay_uuid)
    if value.version != 1:
        raise ValueError(f"replay UUID is not version 1: {replay_uuid}")
    unix_seconds = (value.time - UUID_EPOCH_OFFSET) / 10_000_000
    return datetime.fromtimestamp(unix_seconds, timezone.utc)


def _member_name(member: tarfile.TarInfo) -> str:
    name = member.name
    while name.startswith("./"):
        name = name[2:]
    return name


def _canonical_policy_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        if not member.isfile():
            continue
        normalized = _member_name(member)
        parts = Path(normalized).parts
        if not parts or parts[0] == "cg":
            continue
        if "__pycache__" in parts or normalized.endswith((".pyc", ".pyo")):
            continue
        members.append(member)
    return sorted(members, key=_member_name)


def archive_policy_identity(path: Path) -> ArchivePolicyIdentity:
    digest = hashlib.sha256()
    main_bytes: bytes | None = None
    deck_bytes: bytes | None = None
    with tarfile.open(path, "r:gz") as archive:
        for member in _canonical_policy_members(archive):
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read archive member {member.name}")
            data = extracted.read()
            normalized = _member_name(member)
            name = normalized.encode("utf-8")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
            if normalized == "main.py":
                main_bytes = data
            elif normalized == "deck.csv":
                deck_bytes = data
    if main_bytes is None or deck_bytes is None:
        raise ValueError(f"archive lacks main.py or deck.csv: {path}")
    cards = tuple(int(line.strip()) for line in deck_bytes.decode("utf-8-sig").splitlines() if line.strip())
    if len(cards) != 60:
        raise ValueError(f"archive deck has {len(cards)} cards: {path}")
    return ArchivePolicyIdentity(
        archive_sha256=sha256_file(path),
        policy_content_sha256=digest.hexdigest(),
        main_sha256=hashlib.sha256(main_bytes).hexdigest(),
        deck_sha256=deck_sha256(cards),
    )


def materialize_historical_archive(path: Path, destination: Path) -> None:
    """Safely materialize legacy ``./``-prefixed archives for offline evaluation."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            normalized = _member_name(member)
            parts = Path(normalized).parts
            if not parts or normalized.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe archive member: {member.name}")
            if "__pycache__" in parts or normalized.endswith((".pyc", ".pyo")):
                continue
            target = (destination / normalized).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError(f"archive member escapes destination: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())


def load_sources(path: Path) -> tuple[PublicPanelSource, ...]:
    payload = json.loads(path.read_text())
    if payload.get("schema") != "public_transfer_sources_v1":
        raise ValueError("unsupported public transfer source schema")
    return tuple(PublicPanelSource(**row) for row in payload.get("sources") or ())


def load_submission_times(path: Path) -> dict[int, datetime]:
    import csv

    values: dict[int, datetime] = {}
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                timestamp = datetime.fromisoformat(str(row["date"]))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                values[int(row["ref"])] = timestamp.astimezone(timezone.utc)
            except (KeyError, TypeError, ValueError):
                continue
    return values


def _axis(deck: list[int]) -> str:
    # Reuse the established public, deck-only classifier. It has no outcome or
    # future-state inputs and is therefore safe as a nuisance covariate.
    from tools.public_episode_quality_report import archetype

    return archetype(deck)


def _relative(repo_root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path.resolve())


def _source_games(
    *,
    repo_root: Path,
    source: PublicPanelSource,
    submitted_at: datetime,
    team: str,
) -> list[PublicGame]:
    archive_path = repo_root / source.archive_path
    replay_dir = repo_root / source.replay_dir
    identity = archive_policy_identity(archive_path)
    candidates: list[tuple[datetime, Path, dict[str, Any]]] = []
    for replay_path in sorted(replay_dir.glob("episode-*-replay.json")):
        replay = json.loads(replay_path.read_text())
        started_at = replay_started_at(str(replay["id"]))
        if started_at < submitted_at:
            continue
        candidates.append((started_at, replay_path, replay))
    candidates.sort(key=lambda value: (value[0], value[1].name))
    if source.max_games > 0:
        candidates = candidates[: source.max_games]

    games: list[PublicGame] = []
    for window_index, (started_at, replay_path, replay) in enumerate(candidates):
        info = replay.get("info") or {}
        teams = info.get("TeamNames") or []
        if team not in teams or len(teams) != 2:
            continue
        slot = teams.index(team)
        decks = initial_decks(replay)
        observed_deck_hash = deck_sha256(decks[slot])
        if observed_deck_hash != identity.deck_sha256:
            raise ValueError(
                f"archive/replay deck mismatch ref={source.submission_ref} "
                f"episode={info.get('EpisodeId')} archive={identity.deck_sha256} "
                f"replay={observed_deck_hash}"
            )
        rewards = replay.get("rewards") or [0.0, 0.0]
        reward = float(rewards[slot])
        outcome = 1.0 if reward > 0 else 0.0 if reward < 0 else 0.5
        opponent_deck = decks[1 - slot]
        games.append(
            PublicGame(
                episode_id=int(info.get("EpisodeId")),
                replay_uuid=str(replay["id"]),
                replay_sha256=sha256_file(replay_path),
                replay_path=_relative(repo_root, replay_path),
                replay_started_at_utc=started_at.isoformat(),
                time_block=started_at.date().isoformat(),
                submission_ref=source.submission_ref,
                submitted_at_utc=submitted_at.isoformat(),
                agent_label=source.label,
                policy_lineage_id=identity.policy_content_sha256,
                archive_sha256=identity.archive_sha256,
                agent_deck_sha256=identity.deck_sha256,
                player_slot=slot,
                opponent_team=str(teams[1 - slot]),
                opponent_axis=_axis(opponent_deck),
                opponent_deck_sha256=deck_sha256(opponent_deck),
                outcome=outcome,
                module_version=str(replay.get("module_version") or "unknown"),
                source_window_index=window_index,
                source_window_quality=source.window_quality,
            )
        )
    return games


def build_panel(
    *,
    repo_root: Path,
    sources_path: Path,
    submissions_path: Path,
    team: str,
    cutoff_utc: datetime,
) -> PublicTransferPanel:
    sources = load_sources(sources_path)
    submission_times = load_submission_times(submissions_path)
    games: list[PublicGame] = []
    seen: set[tuple[int, int]] = set()
    for source in sources:
        submitted_at = submission_times.get(source.submission_ref)
        if submitted_at is None:
            raise ValueError(f"submission ref missing from ledger: {source.submission_ref}")
        for game in _source_games(
            repo_root=repo_root,
            source=source,
            submitted_at=submitted_at,
            team=team,
        ):
            if datetime.fromisoformat(game.replay_started_at_utc) > cutoff_utc:
                continue
            key = (game.submission_ref, game.episode_id)
            if key in seen:
                continue
            seen.add(key)
            games.append(game)
    games.sort(key=lambda game: (game.replay_started_at_utc, game.submission_ref, game.episode_id))
    source_config_hash = sha256_file(sources_path)
    canonical = {
        "schema": "public_transfer_panel_v1",
        "cutoff_utc": cutoff_utc.isoformat(),
        "team": team,
        "source_config_sha256": source_config_hash,
        "games": [asdict(game) for game in games],
    }
    panel_id = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return PublicTransferPanel(
        panel_id=panel_id,
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        cutoff_utc=cutoff_utc.isoformat(),
        team=team,
        source_config_sha256=source_config_hash,
        games=tuple(games),
    )


def panel_inventory(panel: PublicTransferPanel) -> dict[str, Any]:
    lineages = {game.policy_lineage_id for game in panel.games}
    blocks = {game.time_block for game in panel.games}
    axes = {game.opponent_axis for game in panel.games}
    refs = {game.submission_ref for game in panel.games}
    return {
        "games": len(panel.games),
        "submission_refs": len(refs),
        "policy_lineages": len(lineages),
        "time_blocks": len(blocks),
        "opponent_axes": len(axes),
        "inventory_ready": (
            len(lineages) >= 8
            and len(panel.games) >= 200
            and len(blocks) >= 3
            and len(axes) >= 4
        ),
    }


def write_panel(panel: PublicTransferPanel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(panel.to_dict(), indent=2, sort_keys=True) + "\n")


def filter_panel_by_label(
    panel: dict[str, Any],
    *,
    excluded_labels: Iterable[str],
    exclusion_reason: str,
) -> dict[str, Any]:
    """Create a content-addressed child panel from explicit label exclusions.

    The caller supplies labels; this function never examines outcomes to choose
    them. The parent ID and reason remain in the artifact for auditability.
    """

    if panel.get("schema") != "public_transfer_panel_v1":
        raise ValueError("unsupported public transfer panel schema")
    excluded = tuple(sorted(set(excluded_labels)))
    if not excluded or not exclusion_reason:
        raise ValueError("excluded labels and an exclusion reason are required")
    available = {str(game["agent_label"]) for game in panel.get("games") or []}
    missing = set(excluded) - available
    if missing:
        raise ValueError("excluded labels absent from panel: " + ", ".join(sorted(missing)))
    games = [game for game in panel.get("games") or [] if str(game["agent_label"]) not in excluded]
    canonical = {
        "schema": "public_transfer_panel_v1",
        "parent_panel_id": panel.get("panel_id"),
        "excluded_labels": excluded,
        "exclusion_reason": exclusion_reason,
        "games": games,
    }
    panel_id = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:20]
    return {
        **panel,
        "panel_id": panel_id,
        "parent_panel_id": panel.get("panel_id"),
        "excluded_labels": list(excluded),
        "exclusion_reason": exclusion_reason,
        "games": games,
    }


__all__ = [
    "ArchivePolicyIdentity",
    "PublicGame",
    "PublicPanelSource",
    "PublicTransferPanel",
    "archive_policy_identity",
    "build_panel",
    "filter_panel_by_label",
    "load_sources",
    "materialize_historical_archive",
    "panel_inventory",
    "replay_started_at",
    "write_panel",
]
