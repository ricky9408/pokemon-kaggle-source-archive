"""Deterministic archive-derived lineage evidence for selector v4.

The registry is intentionally an archive fact, not a claim made by an agent:
``archive_sha256`` is read from the archive bytes, ``deck_sha256`` is the
SHA-256 of the exact ``deck.csv`` member bytes, and
``policy_content_sha256`` is a hash of the safely inspected regular members.
The policy framing is, for each sorted UTF-8 path, a four-byte big-endian path
length, the path, an eight-byte big-endian content length, and the content.

Input records contain only ``archive_path``, ``family_id``,
``parent_archive_sha256``, and ``first_seen_utc``.  Hash fields supplied by a
caller are rejected rather than trusted.  Parent declarations are validated
as a DAG and ancestry ids are derived from reachable root archive hashes.
Undeclared parents cannot be detected from local archive evidence; this
module therefore does not claim near-clone independence or complete ancestry.
That limitation is also exposed as ``UNDECLARED_PARENT_LIMITATION`` for
callers that render registry status output.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, Iterable, Mapping


REGISTRY_SCHEMA = "archive_lineage_registry_v1"
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
UNDECLARED_PARENT_LIMITATION = (
    "Undeclared parents are not detectable from local archive evidence; "
    "ancestry is only the declared-parent DAG and is not a near-clone claim."
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_INPUT_FIELDS = frozenset(
    {"archive_path", "family_id", "parent_archive_sha256", "first_seen_utc"}
)
_RECORD_FIELDS = frozenset(
    {
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "lineage_id",
        "ancestry_id",
        "family_id",
        "first_seen_utc",
    }
)
_REGISTRY_FIELDS = frozenset({"schema", "records", "content_sha256"})
_EXCLUDED_METADATA_NAMES = {".DS_Store"}


def canonical_json_bytes(value: object) -> bytes:
    """Return the only JSON byte encoding used by this module."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    """Hash a value using canonical sorted-key JSON."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _canonical_utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.isoformat(timespec="microseconds") + "Z" != value:
        raise ValueError(f"{label} must be canonical UTC")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_member_path(name: object) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError(f"invalid archive member path: {name!r}")
    if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", name):
        raise ValueError(f"absolute archive member path: {name!r}")
    if "\\" in name:
        raise ValueError(f"ambiguous archive member path: {name!r}")

    # Tar producers commonly emit a harmless leading './'.  Strip it while
    # treating all other dot components as a single canonical path namespace.
    parts = name.split("/")
    while parts and parts[0] == ".":
        parts.pop(0)
    if not parts or any(part == ".." for part in parts):
        raise ValueError(f"traversal archive member path: {name!r}")
    normalized_parts = [part for part in parts if part not in {"", "."}]
    if not normalized_parts:
        raise ValueError(f"empty archive member path: {name!r}")
    return PurePosixPath(*normalized_parts).as_posix()


def _is_excluded_metadata(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in _EXCLUDED_METADATA_NAMES or name.startswith("._")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"cannot read regular archive member {member.name!r}")
    with stream:
        data = stream.read(member.size + 1)
    if len(data) != member.size:
        raise ValueError(f"archive member size changed while reading: {member.name!r}")
    return data


def inspect_archive(
    path: str | Path,
    *,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES,
) -> dict[str, str]:
    """Safely inspect an archive and return hashes derived from its contents.

    Only regular tar members are accepted.  The returned mapping contains
    exactly the three hashes used by the v4 protocol.  ``main.py`` and
    ``deck.csv`` are identified by basename and each must occur exactly once.
    """

    if isinstance(max_uncompressed_bytes, bool) or not isinstance(max_uncompressed_bytes, int):
        raise ValueError("max_uncompressed_bytes must be a positive integer")
    if max_uncompressed_bytes <= 0:
        raise ValueError("max_uncompressed_bytes must be a positive integer")
    archive_path = Path(path)
    try:
        archive_stat = archive_path.lstat()
    except OSError as exc:
        raise ValueError(f"archive cannot be stat'ed: {archive_path}") from exc
    if not stat.S_ISREG(archive_stat.st_mode):
        raise ValueError(f"archive path is not a regular file: {archive_path}")

    archive_sha256 = _sha256_file(archive_path)
    policy_digest = hashlib.sha256()
    seen_paths: set[str] = set()
    content_members: list[tuple[str, bytes]] = []
    deck_data: bytes | None = None
    total_size = 0
    entrypoint_paths: list[str] = []
    deck_paths: list[str] = []

    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.isdir() and member.name in {".", "./"}:
                    continue
                normalized = _canonical_member_path(member.name)
                if normalized in seen_paths:
                    raise ValueError(f"duplicate archive member path: {normalized!r}")
                seen_paths.add(normalized)

                member_path = PurePosixPath(normalized)
                if "__pycache__" in member_path.parts:
                    raise ValueError(f"__pycache__ archive member: {member.name!r}")
                if member_path.suffix.lower() in {".pyc", ".pyo"}:
                    raise ValueError(f"pyc archive member: {member.name!r}")

                if member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError(
                        f"archive member is not a regular file: {member.name!r}"
                    )
                if member.size < 0:
                    raise ValueError(f"negative archive member size: {member.name!r}")
                total_size += member.size
                if total_size > max_uncompressed_bytes:
                    raise ValueError(
                        "archive exceeds maximum uncompressed size "
                        f"({max_uncompressed_bytes} bytes)"
                    )

                data = _read_member(archive, member)
                basename = PurePosixPath(normalized).name
                if basename == "main.py":
                    entrypoint_paths.append(normalized)
                if basename == "deck.csv":
                    deck_paths.append(normalized)
                    deck_data = data
                if basename != "deck.csv" and not _is_excluded_metadata(normalized):
                    content_members.append((normalized, data))
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"archive cannot be read: {archive_path}") from exc

    if len(entrypoint_paths) != 1:
        raise ValueError(
            f"archive must contain exactly one main.py; found {len(entrypoint_paths)}"
        )
    if len(deck_paths) != 1:
        raise ValueError(
            f"archive must contain exactly one deck.csv; found {len(deck_paths)}"
        )

    for normalized, data in sorted(content_members, key=lambda item: item[0]):
        name = normalized.encode("utf-8")
        policy_digest.update(len(name).to_bytes(4, "big"))
        policy_digest.update(name)
        policy_digest.update(len(data).to_bytes(8, "big"))
        policy_digest.update(data)

    assert deck_data is not None
    return {
        "archive_sha256": archive_sha256,
        "policy_content_sha256": policy_digest.hexdigest(),
        "deck_sha256": hashlib.sha256(deck_data).hexdigest(),
    }


# Explicit aliases make the archive-derived operation discoverable to callers
# that use identity rather than inspection terminology.
archive_identity = inspect_archive
compute_archive_identity = inspect_archive
archive_policy_identity = inspect_archive


def lineage_id_for_archive(archive_sha256: str) -> str:
    """Return the transparent, deterministic lineage id for an archive hash."""

    return "archive-" + _sha256(archive_sha256, label="archive_sha256")


def ancestry_id_for_roots(root_archive_hashes: Iterable[str]) -> str:
    """Hash sorted reachable root hashes using canonical JSON."""

    roots = [_sha256(value, label="root archive hash") for value in root_archive_hashes]
    if not roots:
        raise ValueError("ancestry requires at least one root archive hash")
    if len(roots) != len(set(roots)):
        raise ValueError("ancestry root archive hashes must be unique")
    return canonical_sha256(sorted(roots))


def _normalize_input_record(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _INPUT_FIELDS:
        raise ValueError(f"lineage input fields must exactly be {sorted(_INPUT_FIELDS)}")
    archive_path = value["archive_path"]
    if not isinstance(archive_path, (str, Path)) or not str(archive_path).strip():
        raise ValueError("archive_path must be a non-empty path")
    parents = value["parent_archive_sha256"]
    if not isinstance(parents, list):
        raise ValueError("parent_archive_sha256 must be a list")
    normalized_parents = [_sha256(item, label="parent_archive_sha256 item") for item in parents]
    if len(normalized_parents) != len(set(normalized_parents)):
        raise ValueError("parent_archive_sha256 must not contain duplicates")
    return {
        "archive_path": Path(archive_path),
        "family_id": _identifier(value["family_id"], label="family_id"),
        "parent_archive_sha256": sorted(normalized_parents),
        "first_seen_utc": _canonical_utc(value["first_seen_utc"], label="first_seen_utc"),
    }


def _validate_record(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _RECORD_FIELDS:
        raise ValueError(f"lineage record fields must exactly be {sorted(_RECORD_FIELDS)}")
    return {
        "archive_sha256": _sha256(value["archive_sha256"], label="archive_sha256"),
        "policy_content_sha256": _sha256(
            value["policy_content_sha256"], label="policy_content_sha256"
        ),
        "deck_sha256": _sha256(value["deck_sha256"], label="deck_sha256"),
        "lineage_id": _identifier(value["lineage_id"], label="lineage_id"),
        "ancestry_id": _sha256(value["ancestry_id"], label="ancestry_id"),
        "family_id": _identifier(value["family_id"], label="family_id"),
        "first_seen_utc": _canonical_utc(value["first_seen_utc"], label="first_seen_utc"),
    }


def validate_registry(value: object) -> dict[str, Any]:
    """Validate a canonical registry and its content digest."""

    if not isinstance(value, Mapping) or set(value) != _REGISTRY_FIELDS:
        raise ValueError(f"registry fields must exactly be {sorted(_REGISTRY_FIELDS)}")
    if value["schema"] != REGISTRY_SCHEMA:
        raise ValueError(f"registry schema must be {REGISTRY_SCHEMA!r}")
    if not isinstance(value["records"], list) or not value["records"]:
        raise ValueError("registry records must be a non-empty list")
    records = [_validate_record(record) for record in value["records"]]
    if records != sorted(records, key=lambda item: (item["ancestry_id"], item["lineage_id"])):
        raise ValueError("registry records must be sorted by ancestry_id and lineage_id")

    seen_archives: set[str] = set()
    policy_bindings: dict[str, set[tuple[str, str]]] = {}
    ancestry_families: dict[str, str] = {}
    for record in records:
        if record["lineage_id"] != lineage_id_for_archive(record["archive_sha256"]):
            raise ValueError("lineage_id is not derived from archive_sha256")
        if record["archive_sha256"] in seen_archives:
            raise ValueError("duplicate archive_sha256 in registry")
        seen_archives.add(record["archive_sha256"])
        ancestry = record["ancestry_id"]
        family = record["family_id"]
        if ancestry in ancestry_families and ancestry_families[ancestry] != family:
            raise ValueError(f"ancestry_id {ancestry!r} has conflicting families")
        ancestry_families[ancestry] = family
        policy_bindings.setdefault(record["policy_content_sha256"], set()).add(
            (record["lineage_id"], record["ancestry_id"])
        )
    duplicate_policy = sorted(
        digest for digest, bindings in policy_bindings.items() if len(bindings) > 1
    )
    if duplicate_policy:
        raise ValueError(
            "policy content is assigned to multiple ancestry components or lineages: "
            + ", ".join(duplicate_policy)
        )

    content = {"schema": REGISTRY_SCHEMA, "records": records}
    if value["content_sha256"] != canonical_sha256(content):
        raise ValueError("registry content_sha256 mismatch")
    return {**content, "content_sha256": value["content_sha256"]}


def build_registry(input_records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build deterministic protocol-compatible records from archive paths."""

    try:
        inputs = [_normalize_input_record(value) for value in input_records]
    except TypeError as exc:
        raise ValueError("lineage inputs must be iterable") from exc
    if not inputs:
        raise ValueError("at least one lineage input is required")

    inspected: list[dict[str, Any]] = []
    by_archive: dict[str, dict[str, Any]] = {}
    for item in inputs:
        identity = inspect_archive(item["archive_path"])
        archive_hash = identity["archive_sha256"]
        if archive_hash in by_archive:
            raise ValueError(f"duplicate archive bytes: {archive_hash}")
        entry = {**item, **identity}
        by_archive[archive_hash] = entry
        inspected.append(entry)

    for entry in inspected:
        archive_hash = entry["archive_sha256"]
        for parent in entry["parent_archive_sha256"]:
            if parent == archive_hash:
                raise ValueError(f"archive {archive_hash} cannot parent itself")
            if parent not in by_archive:
                raise ValueError(f"missing parent archive: {parent}")
            if by_archive[parent]["family_id"] != entry["family_id"]:
                raise ValueError("parent and child must have the same family_id")

    state: dict[str, int] = {}
    root_cache: dict[str, tuple[str, ...]] = {}

    def roots_for(archive_hash: str) -> tuple[str, ...]:
        current_state = state.get(archive_hash, 0)
        if current_state == 1:
            raise ValueError(f"parent archive DAG contains a cycle at {archive_hash}")
        if current_state == 2:
            return root_cache[archive_hash]
        state[archive_hash] = 1
        parents = by_archive[archive_hash]["parent_archive_sha256"]
        if not parents:
            roots = (archive_hash,)
        else:
            roots = tuple(sorted({root for parent in parents for root in roots_for(parent)}))
        state[archive_hash] = 2
        root_cache[archive_hash] = roots
        return roots

    output_records: list[dict[str, str]] = []
    for entry in sorted(inspected, key=lambda item: item["archive_sha256"]):
        roots = roots_for(entry["archive_sha256"])
        output_records.append(
            {
                "archive_sha256": entry["archive_sha256"],
                "policy_content_sha256": entry["policy_content_sha256"],
                "deck_sha256": entry["deck_sha256"],
                "lineage_id": lineage_id_for_archive(entry["archive_sha256"]),
                "ancestry_id": ancestry_id_for_roots(roots),
                "family_id": entry["family_id"],
                "first_seen_utc": entry["first_seen_utc"],
            }
        )

    output_records.sort(key=lambda item: (item["ancestry_id"], item["lineage_id"]))
    policy_bindings: dict[str, set[tuple[str, str]]] = {}
    for record in output_records:
        policy_bindings.setdefault(record["policy_content_sha256"], set()).add(
            (record["lineage_id"], record["ancestry_id"])
        )
    duplicate_policy = sorted(
        digest for digest, bindings in policy_bindings.items() if len(bindings) > 1
    )
    if duplicate_policy:
        raise ValueError(
            "policy content is assigned to multiple ancestry components or lineages: "
            + ", ".join(duplicate_policy)
        )

    content = {"schema": REGISTRY_SCHEMA, "records": output_records}
    registry = {**content, "content_sha256": canonical_sha256(content)}
    return validate_registry(registry)


build_lineage_registry = build_registry


def write_registry_once(path: str | Path, registry: Mapping[str, Any]) -> Path:
    """Create a registry exactly once, flushing both file and directory."""

    target = Path(path)
    clean = validate_registry(registry)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(clean) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(target, flags, 0o644)
    except FileExistsError:
        raise FileExistsError(f"registry already exists: {target}") from None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # The exclusive create remains deliberately non-reusable after a
        # failed write; callers must treat the evidence path as contaminated.
        raise

    try:
        directory_descriptor = os.open(target.parent, os.O_RDONLY)
    except OSError:
        directory_descriptor = None
    if directory_descriptor is not None:
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    return target


write_lineage_registry_once = write_registry_once


def read_registry(path: str | Path) -> dict[str, Any]:
    """Read and validate a previously written registry."""

    target = Path(path)
    try:
        value = json.loads(target.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read registry: {target}") from exc
    return validate_registry(value)


canonical_json = canonical_json_bytes


__all__ = [
    "MAX_UNCOMPRESSED_BYTES",
    "REGISTRY_SCHEMA",
    "UNDECLARED_PARENT_LIMITATION",
    "archive_identity",
    "archive_policy_identity",
    "ancestry_id_for_roots",
    "build_lineage_registry",
    "build_registry",
    "canonical_json",
    "canonical_json_bytes",
    "canonical_sha256",
    "compute_archive_identity",
    "inspect_archive",
    "lineage_id_for_archive",
    "read_registry",
    "validate_registry",
    "write_registry_once",
    "write_lineage_registry_once",
]
