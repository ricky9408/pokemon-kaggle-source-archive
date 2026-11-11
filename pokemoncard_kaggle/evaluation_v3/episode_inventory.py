"""Build deterministic, outcome-blind inventories from scout episode CSVs.

This module deliberately opens only files named ``episodes.csv`` under the
provided source root. It never follows replay references or inspects replay,
deck, action, or outcome artifacts.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


INVENTORY_SCHEMA = "postretirement_episode_inventory_v1"
COMPLETED_STATE = "EpisodeState.COMPLETED"
PUBLIC_TYPE = "EpisodeType.EPISODE_TYPE_PUBLIC"
REQUIRED_COLUMNS = ("id", "createTime", "endTime", "state", "type")


def canonical_json(value: Any) -> str:
    """Return the canonical ASCII JSON representation used for content ids."""

    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object, *, label: str, require_timezone: bool) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {text!r}") from exc
    if parsed.tzinfo is None:
        if require_timezone:
            raise ValueError(f"{label} must include a UTC offset")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_input_utc(value: str, *, label: str) -> str:
    """Normalize an explicit CLI timestamp and reject timezone-less values."""

    return _format_utc(_parse_utc(value, label=label, require_timezone=True))


def _is_kaggle_footer(row: Mapping[str, str | None]) -> bool:
    """Recognize the informational row emitted by older Kaggle CLI exports."""

    identifier = str(row.get("id") or "").strip()
    return (
        identifier.startswith("Use ")
        and not str(row.get("state") or "").strip()
        and not str(row.get("type") or "").strip()
    )


def _submission_id(source_path: Path) -> str | None:
    for parent in source_path.parents:
        if parent.name.startswith("submission_"):
            value = parent.name.removeprefix("submission_")
            return value or None
    return None


@dataclass(frozen=True)
class _EpisodeMetadata:
    episode_id: str
    create_time_utc: str
    end_time_utc: str | None
    state: str
    episode_type: str

    @classmethod
    def from_row(cls, row: Mapping[str, str | None], *, source: Path, row_number: int) -> "_EpisodeMetadata":
        def field(name: str) -> str:
            value = str(row.get(name) or "").strip()
            if not value:
                raise ValueError(f"{source}:{row_number}: {name} is required")
            return value

        episode_id = field("id")
        if not episode_id.isdecimal():
            raise ValueError(f"{source}:{row_number}: id must be a decimal episode id")
        create = _format_utc(
            _parse_utc(field("createTime"), label=f"{source}:{row_number}: createTime", require_timezone=False)
        )
        end_raw = str(row.get("endTime") or "").strip()
        end = (
            _format_utc(_parse_utc(end_raw, label=f"{source}:{row_number}: endTime", require_timezone=False))
            if end_raw
            else None
        )
        if end is not None and _parse_utc(end, label="normalized endTime", require_timezone=True) < _parse_utc(
            create, label="normalized createTime", require_timezone=True
        ):
            raise ValueError(f"{source}:{row_number}: endTime precedes createTime")
        return cls(
            episode_id=episode_id,
            create_time_utc=create,
            end_time_utc=end,
            state=field("state"),
            episode_type=field("type"),
        )

    @property
    def completed_public(self) -> bool:
        return self.state == COMPLETED_STATE and self.episode_type == PUBLIC_TYPE

    def as_inventory_row(self) -> dict[str, str | None]:
        return {
            "create_time_utc": self.create_time_utc,
            "end_time_utc": self.end_time_utc,
            "episode_id": self.episode_id,
            "state": self.state,
            "type": self.episode_type,
        }


def _read_episode_csv(path: Path, *, source_root: Path) -> tuple[list[tuple[_EpisodeMetadata, dict[str, Any]]], str]:
    source_hash = sha256_file(path)
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames
            if not headers:
                raise ValueError(f"{path}: episodes.csv has no header")
            normalized_headers = [header.strip() if header is not None else "" for header in headers]
            missing = sorted(set(REQUIRED_COLUMNS) - set(normalized_headers))
            duplicate = sorted({name for name in normalized_headers if normalized_headers.count(name) > 1})
            if missing or duplicate:
                details = []
                if missing:
                    details.append(f"missing columns: {', '.join(missing)}")
                if duplicate:
                    details.append(f"duplicate columns: {', '.join(duplicate)}")
                raise ValueError(f"{path}: invalid episodes.csv schema ({'; '.join(details)})")

            records: list[tuple[_EpisodeMetadata, dict[str, Any]]] = []
            relative_path = path.relative_to(source_root).as_posix()
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ValueError(f"{path}:{row_number}: row has more fields than the header")
                if not any(str(value or "").strip() for value in row.values()):
                    continue
                if _is_kaggle_footer(row):
                    continue
                metadata = _EpisodeMetadata.from_row(row, source=path, row_number=row_number)
                provenance = {
                    "row_number": row_number,
                    "source_file_sha256": source_hash,
                    "source_path": relative_path,
                    "submission_id": _submission_id(path),
                }
                records.append((metadata, provenance))
    except csv.Error as exc:
        raise ValueError(f"{path}: malformed CSV") from exc
    return records, source_hash


def _source_files(source_root: Path) -> Iterable[Path]:
    if not source_root.is_dir():
        raise ValueError(f"source root is not a directory: {source_root}")
    return sorted((path for path in source_root.rglob("episodes.csv") if path.is_file()), key=lambda path: path.as_posix())


def build_episode_inventory(
    *,
    source_root: str | Path,
    strict_utc_cutoff: str,
    source_leaderboard: str | Path,
    collection_timestamp_utc: str,
) -> dict[str, Any]:
    """Build a content-addressed inventory from completed public episode metadata.

    Naive ``episodes.csv`` timestamps are interpreted as UTC because Kaggle CLI
    exports use that form. CLI-supplied cutoff and collection timestamps must
    carry an explicit offset so no wall-clock or host-timezone behavior leaks in.
    """

    root = Path(source_root).resolve()
    leaderboard = Path(source_leaderboard).resolve()
    if not leaderboard.is_file():
        raise ValueError(f"source leaderboard is not a file: {leaderboard}")
    cutoff = normalize_input_utc(strict_utc_cutoff, label="strict UTC cutoff")
    collected = normalize_input_utc(collection_timestamp_utc, label="collection timestamp")
    cutoff_time = _parse_utc(cutoff, label="strict UTC cutoff", require_timezone=True)
    collected_time = _parse_utc(collected, label="collection timestamp", require_timezone=True)
    if collected_time < cutoff_time:
        raise ValueError("collection timestamp precedes strict UTC cutoff")

    by_episode: dict[str, tuple[_EpisodeMetadata, list[dict[str, Any]]]] = {}
    source_files: list[dict[str, str]] = []
    discovered_sources = list(_source_files(root))
    if not discovered_sources:
        raise ValueError(f"source root contains no episodes.csv files: {root}")
    for source_path in discovered_sources:
        records, source_hash = _read_episode_csv(source_path, source_root=root)
        source_files.append(
            {"path": source_path.relative_to(root).as_posix(), "sha256": source_hash}
        )
        for metadata, provenance in records:
            created_time = _parse_utc(
                metadata.create_time_utc, label="normalized createTime", require_timezone=True
            )
            if created_time > collected_time:
                raise ValueError(
                    f"episode {metadata.episode_id} was created after the collection timestamp"
                )
            if metadata.end_time_utc is not None:
                end_time = _parse_utc(
                    metadata.end_time_utc, label="normalized endTime", require_timezone=True
                )
                if end_time > collected_time:
                    raise ValueError(
                        f"episode {metadata.episode_id} ended after the collection timestamp"
                    )
            if metadata.completed_public and metadata.end_time_utc is None:
                raise ValueError(
                    f"completed public episode {metadata.episode_id} requires endTime"
                )
            existing = by_episode.get(metadata.episode_id)
            if existing is None:
                by_episode[metadata.episode_id] = (metadata, [provenance])
            elif existing[0] != metadata:
                raise ValueError(f"conflicting metadata for episode id {metadata.episode_id}")
            else:
                existing[1].append(provenance)

    episodes: list[dict[str, Any]] = []
    for metadata, provenance in by_episode.values():
        created = _parse_utc(metadata.create_time_utc, label="normalized createTime", require_timezone=True)
        if metadata.completed_public and created > cutoff_time:
            row: dict[str, Any] = metadata.as_inventory_row()
            row["sources"] = sorted(
                provenance,
                key=lambda item: (str(item["source_path"]), int(item["row_number"])),
            )
            episodes.append(row)
    episodes.sort(key=lambda item: (str(item["create_time_utc"]), str(item["episode_id"])))

    payload: dict[str, Any] = {
        "collection_timestamp_utc": collected,
        "episodes": episodes,
        "leaderboard": {
            "path": leaderboard.as_posix(),
            "sha256": sha256_file(leaderboard),
        },
        "schema": INVENTORY_SCHEMA,
        "source_files": sorted(source_files, key=lambda item: item["path"]),
        "strict_utc_cutoff": cutoff,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()
    return payload


def write_episode_inventory(path: str | Path, inventory: Mapping[str, Any]) -> None:
    """Create an inventory once; never overwrite a previous collection."""

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(canonical_json(dict(inventory)))
        handle.write("\n")


__all__ = [
    "COMPLETED_STATE",
    "INVENTORY_SCHEMA",
    "PUBLIC_TYPE",
    "build_episode_inventory",
    "canonical_json",
    "normalize_input_utc",
    "sha256_file",
    "write_episode_inventory",
]
