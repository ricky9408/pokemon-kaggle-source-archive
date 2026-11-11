from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.host_census import (
    CENSUS_SCHEMA,
    CLOSE_OFFSETS_SECONDS,
    PAGE_RESPONSE_SCHEMA,
    UPLOAD_RESPONSE_SCHEMA,
    HostCensusError,
    audit_host_census,
    audit_collector_timeline,
    build_census_bundle,
    build_collector_timeline,
    build_query_identity,
    build_signed_raw_upload_response,
    build_submission_identity,
    close_host_census,
    census_signing_payload,
    derive_maturity_cutoff,
    reconcile_collectors,
)


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _identity() -> dict[str, object]:
    return build_submission_identity(
        competition="pokemon-tcg-ai-battle",
        submission_id="submission-1",
        account_id="account-1",
        team_id="team-1",
        archive_sha256="a" * 64,
        package_sha256="b" * 64,
        archive_name="submission.tar.gz",
        created_at_utc="2026-07-14T00:00:00.000000Z",
    )


def _episode(index: int, *, status: str = "COMPLETE", created_hour: int = 1, created_minute: int | None = None) -> dict[str, object]:
    minute = index if created_minute is None else created_minute
    common: dict[str, object] = {
        "sequence": index + 1,
        "game_id": f"game-{index:03d}",
        "submission_id": "submission-1",
        "archive_sha256": "a" * 64,
        "created_at_utc": f"2026-07-14T{created_hour:02d}:{minute:02d}:00.000000Z",
        "server_started_at_utc": f"2026-07-14T{created_hour:02d}:{minute:02d}:05.000000Z",
        "completed_at_utc": f"2026-07-14T{created_hour:02d}:{minute:02d}:30.000000Z",
        "status": status,
        "validation_status": "PASS",
        "runtime_status": "PASS",
        "failure": None,
        "outcome": "win" if index % 2 == 0 else "loss",
        "seat": index % 2,
        "opponent_rating": 1500 + index,
        "replay_content_sha256": f"{index + 1:064x}",
        "window_exclusion_code": "before_maturity_window" if created_hour < 2 else None,
    }
    if status == "VALIDATION_FAILED":
        common.update(
            validation_status="FAIL",
            runtime_status="UNKNOWN",
            failure="invalid action",
            outcome="validation_failure",
            seat=None,
            opponent_rating=None,
            replay_content_sha256=None,
        )
    return common


def _fixture(
    tmp_path: Path,
    count: int = 48,
    *,
    created_hour: int = 2,
    first_status: str = "COMPLETE",
):
    root = tmp_path / "evidence"
    (root / "raw").mkdir(parents=True)
    identity = _identity()
    upload_raw = {
        **identity,
        "status": "COMPLETE",
    }
    upload_bytes = json.dumps(upload_raw, separators=(",", ":"), sort_keys=True).encode()
    (root / "upload.json").write_bytes(upload_bytes)
    completion_raw = {
        "schema": "evaluation_v5_1_completion_poll_v1",
        "submission_id": "submission-1",
        "archive_sha256": "a" * 64,
        "status": "COMPLETE",
        "observed_at_utc": "2026-07-14T01:00:00.000000Z",
        "source": "observer-kaggle-cli",
    }
    completion_bytes = json.dumps(completion_raw, separators=(",", ":"), sort_keys=True).encode()
    (root / "completion.json").write_bytes(completion_bytes)
    private, public = _keypair()
    upload = build_signed_raw_upload_response(
        identity=identity,
        raw_response_path="upload.json",
        raw_response_sha256=_hash(upload_bytes),
        first_observed_complete_at_utc=completion_raw["observed_at_utc"],
        completion_poll_path="completion.json",
        completion_poll_sha256=_hash(completion_bytes),
        completion_poll_source=completion_raw["source"],
        signer_public_key_bytes=public,
        signer_private_key_bytes=_private_bytes(private),
    )
    query = build_query_identity(
        identity=identity,
        endpoint="episodes",
        page_size=24,
        started_at_utc="2026-07-14T00:00:01.000000Z",
    )
    episodes = [
        _episode(index, created_hour=created_hour, status=first_status if index == 0 else "COMPLETE")
        for index in range(count)
    ]
    pages = []
    page_entries = []
    previous_watermark = 0
    for page_index in range((count + 23) // 24):
        page_episodes = episodes[page_index * 24 : (page_index + 1) * 24]
        next_cursor = f"cursor-{page_index + 1}" if page_index + 1 < (count + 23) // 24 else None
        raw_page = {
            "schema": PAGE_RESPONSE_SCHEMA,
            "request_cursor": None if page_index == 0 else f"cursor-{page_index}",
            "next_cursor": next_cursor,
            "sequence_watermark": page_episodes[-1]["sequence"] if page_episodes else previous_watermark,
            "episodes": page_episodes,
        }
        page_bytes = json.dumps(raw_page, separators=(",", ":"), sort_keys=True).encode()
        page_path = f"raw/page-{page_index}.json"
        (root / page_path).write_bytes(page_bytes)
        after = int(raw_page["sequence_watermark"])
        page_entries.append(
            {
                "page_index": page_index,
                "request_cursor": raw_page["request_cursor"],
                "response_next_cursor": next_cursor,
                "fetched_at_utc": f"2026-07-14T02:0{page_index}:00.000000Z",
                "raw_response_path": page_path,
                "raw_response_sha256": _hash(page_bytes),
                "sequence_watermark_before": previous_watermark,
                "sequence_watermark_after": after,
            }
        )
        pages.append(raw_page)
        previous_watermark = after
    census = build_census_bundle(
        identity=identity,
        query_identity=query,
        pages=page_entries,
        episodes=episodes,
        sequence_watermarks=[entry["sequence_watermark_after"] for entry in page_entries],
        observer_public_key_bytes=public,
        observer_private_key_bytes=_private_bytes(private),
        census_observed_at_utc="2026-07-14T03:00:00.000000Z",
        traversal_id="traversal-0",
    )
    return root, identity, upload, census, public, private


def _snapshot_series(
    census: dict[str, object], public: bytes, private: bytes, *, traversal_prefix: str = "traversal"
):
    anchor = datetime.fromisoformat("2026-07-14T03:00:00+00:00")
    snapshots = []
    for offset in CLOSE_OFFSETS_SECONDS:
        observed = anchor + timedelta(seconds=offset)
        pages = _pages_for_observed(census["pages"], observed)
        snapshots.append(
        build_census_bundle(
            identity=census["submission_identity"],
            query_identity=census["query_identity"],
            pages=pages,
            episodes=census["episodes"],
            sequence_watermarks=census["sequence_watermarks"],
            close_offset_seconds=offset,
            census_observed_at_utc=observed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            traversal_id=f"{traversal_prefix}-{offset}",
            observer_public_key_bytes=public,
            observer_private_key_bytes=private,
        )
        )
    return snapshots


def _snapshot_with_episodes(
    *,
    root: Path,
    census: dict[str, object],
    episodes: list[dict[str, object]],
    observed: datetime,
    offset: int,
    traversal_id: str,
    public: bytes,
    private: bytes,
) -> dict[str, object]:
    page_entries: list[dict[str, object]] = []
    previous_watermark = 0
    page_count = (len(episodes) + 23) // 24
    for page_index in range(page_count):
        page_episodes = episodes[page_index * 24 : (page_index + 1) * 24]
        next_cursor = f"{traversal_id}-cursor-{page_index + 1}" if page_index + 1 < page_count else None
        request_cursor = None if page_index == 0 else f"{traversal_id}-cursor-{page_index}"
        raw_page = {
            "schema": PAGE_RESPONSE_SCHEMA,
            "request_cursor": request_cursor,
            "next_cursor": next_cursor,
            "sequence_watermark": page_episodes[-1]["sequence"],
            "episodes": page_episodes,
        }
        page_bytes = json.dumps(raw_page, separators=(",", ":"), sort_keys=True).encode()
        page_path = f"raw/{traversal_id}-page-{page_index}.json"
        (root / page_path).write_bytes(page_bytes)
        fetched = observed - timedelta(seconds=60 - page_index)
        after = int(raw_page["sequence_watermark"])
        page_entries.append(
            {
                "page_index": page_index,
                "request_cursor": request_cursor,
                "response_next_cursor": next_cursor,
                "fetched_at_utc": fetched.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "raw_response_path": page_path,
                "raw_response_sha256": _hash(page_bytes),
                "sequence_watermark_before": previous_watermark,
                "sequence_watermark_after": after,
            }
        )
        previous_watermark = after
    return build_census_bundle(
        identity=census["submission_identity"],
        query_identity=census["query_identity"],
        pages=page_entries,
        episodes=episodes,
        sequence_watermarks=[entry["sequence_watermark_after"] for entry in page_entries],
        close_offset_seconds=offset,
        census_observed_at_utc=observed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        traversal_id=traversal_id,
        observer_public_key_bytes=public,
        observer_private_key_bytes=private,
    )


def _pages_for_observed(pages: list[object], observed: datetime):
    copied = deepcopy(pages)
    for index, page in enumerate(copied):
        page["fetched_at_utc"] = (
            observed - timedelta(seconds=60 - index)
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return copied


def _second_signed_upload(
    identity: dict[str, object], upload: dict[str, object], public: bytes, private: bytes
) -> dict[str, object]:
    return build_signed_raw_upload_response(
        identity=identity,
        raw_response_path=upload["raw_response_path"],
        raw_response_sha256=upload["raw_response_sha256"],
        first_observed_complete_at_utc=upload["first_observed_complete_at_utc"],
        completion_poll_path=upload["completion_poll_path"],
        completion_poll_sha256=upload["completion_poll_sha256"],
        completion_poll_source=upload["completion_poll_source"],
        signer_public_key_bytes=public,
        signer_private_key_bytes=private,
    )


def _platform_signed_upload(
    identity: dict[str, object], upload: dict[str, object], public: bytes, private: bytes
) -> dict[str, object]:
    return build_signed_raw_upload_response(
        identity=identity,
        raw_response_path=upload["raw_response_path"],
        raw_response_sha256=upload["raw_response_sha256"],
        first_observed_complete_at_utc=upload["first_observed_complete_at_utc"],
        completion_poll_path=upload["completion_poll_path"],
        completion_poll_sha256=upload["completion_poll_sha256"],
        completion_poll_source=upload["completion_poll_source"],
        signer_public_key_bytes=public,
        signer_private_key_bytes=private,
        signature_authority="kaggle",
    )


def test_valid_census_is_complete_but_never_authoritative(tmp_path: Path) -> None:
    root, identity, upload, census, public, _ = _fixture(tmp_path)
    audit = audit_host_census(upload, census, root, pinned_public_key_bytes=public)
    assert audit["evidence_complete"] is True
    assert audit["completeness_basis"] == "witness_custody"
    assert audit["witness_custody"] is True
    assert audit["platform_attestation"] is False
    assert audit["authority"] is False
    assert audit["submission_authorized"] is False
    assert derive_maturity_cutoff(upload) == "2026-07-14T02:00:00.000000Z"

    closure = close_host_census(
        upload,
        census,
        root,
        as_of_utc="2026-07-14T03:00:00.000000Z",
        pinned_public_key_bytes=public,
    )
    assert len(closure["first48"]) == 48
    assert closure["first48"][0]["game_id"] == "game-000"


def test_two_collectors_have_stable_close_plus_6h_plus_24h_censuses(tmp_path: Path) -> None:
    root, identity, upload_a, census, public_a, private_a = _fixture(tmp_path)
    private_b_obj, public_b = _keypair()
    private_b = _private_bytes(private_b_obj)
    upload_b = _second_signed_upload(identity, upload_a, public_b, private_b)
    timeline_a = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=upload_a,
        censuses=_snapshot_series(census, public_a, _private_bytes(private_a)),
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b",
        signed_upload_response=upload_b,
        censuses=_snapshot_series(census, public_b, private_b, traversal_prefix="b-traversal"),
    )
    result = reconcile_collectors(
        timeline_a,
        root,
        timeline_b,
        root,
        pinned_a_upload_key=public_a,
        pinned_a_observer_key=public_a,
        pinned_b_upload_key=public_b,
        pinned_b_observer_key=public_b,
    )
    assert result["evidence_complete"] is True
    assert result["completeness_basis"] == "witness_custody"
    assert len(result["first48_ids"]) == 48
    assert result["authority"] is False


def test_later_censuses_may_append_games_without_changing_first48(tmp_path: Path) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    anchor = datetime.fromisoformat("2026-07-14T03:00:00+00:00")
    initial = deepcopy(census["episodes"])
    game_49 = _episode(48, created_hour=4)
    game_50 = _episode(49, created_hour=10)
    snapshots = [
        _snapshot_with_episodes(
            root=root,
            census=census,
            episodes=initial,
            observed=anchor,
            offset=0,
            traversal_id="append-0",
            public=public,
            private=_private_bytes(private),
        ),
        _snapshot_with_episodes(
            root=root,
            census=census,
            episodes=[*initial, game_49],
            observed=anchor + timedelta(hours=6),
            offset=21600,
            traversal_id="append-21600",
            public=public,
            private=_private_bytes(private),
        ),
        _snapshot_with_episodes(
            root=root,
            census=census,
            episodes=[*initial, game_49, game_50],
            observed=anchor + timedelta(hours=24),
            offset=86400,
            traversal_id="append-86400",
            public=public,
            private=_private_bytes(private),
        ),
    ]
    timeline = build_collector_timeline(
        collector_id="collector-a", signed_upload_response=upload, censuses=snapshots
    )
    result = audit_collector_timeline(
        timeline,
        root,
        upload_pinned_public_key_bytes=public,
        observer_pinned_public_key_bytes=public,
    )
    assert len(result["episode_ids"]) == 50
    assert result["first48_ids"] == [f"game-{index:03d}" for index in range(48)]


def test_later_census_cannot_mutate_an_existing_episode(tmp_path: Path) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    anchor = datetime.fromisoformat("2026-07-14T03:00:00+00:00")
    initial = deepcopy(census["episodes"])
    mutated = deepcopy(initial)
    mutated[47]["outcome"] = "win" if mutated[47]["outcome"] == "loss" else "loss"
    snapshots = [
        _snapshot_with_episodes(
            root=root, census=census, episodes=initial, observed=anchor,
            offset=0, traversal_id="mutate-0", public=public,
            private=_private_bytes(private),
        ),
        _snapshot_with_episodes(
            root=root, census=census, episodes=mutated,
            observed=anchor + timedelta(hours=6), offset=21600,
            traversal_id="mutate-21600", public=public,
            private=_private_bytes(private),
        ),
        _snapshot_with_episodes(
            root=root, census=census, episodes=mutated,
            observed=anchor + timedelta(hours=24), offset=86400,
            traversal_id="mutate-86400", public=public,
            private=_private_bytes(private),
        ),
    ]
    timeline = build_collector_timeline(
        collector_id="collector-a", signed_upload_response=upload, censuses=snapshots
    )
    with pytest.raises(HostCensusError, match="append-only semantic extensions"):
        audit_collector_timeline(
            timeline,
            root,
            upload_pinned_public_key_bytes=public,
            observer_pinned_public_key_bytes=public,
        )


def test_collectors_must_agree_at_each_close_not_only_at_plus_24h(tmp_path: Path) -> None:
    root, identity, upload_a, census, public_a, private_a = _fixture(tmp_path)
    private_b_obj, public_b = _keypair()
    private_b = _private_bytes(private_b_obj)
    upload_b = _second_signed_upload(identity, upload_a, public_b, private_b)
    anchor = datetime.fromisoformat("2026-07-14T03:00:00+00:00")
    initial = deepcopy(census["episodes"])
    game_49 = _episode(48, created_hour=4)
    game_50 = _episode(49, created_hour=4)

    def snapshots(public: bytes, private: bytes, prefix: str, counts: tuple[int, int, int]):
        inventory = [*initial, game_49, game_50]
        return [
            _snapshot_with_episodes(
                root=root,
                census=census,
                episodes=inventory[:count],
                observed=anchor + timedelta(seconds=offset),
                offset=offset,
                traversal_id=f"{prefix}-{offset}",
                public=public,
                private=private,
            )
            for count, offset in zip(counts, CLOSE_OFFSETS_SECONDS)
        ]

    timeline_a = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=upload_a,
        censuses=snapshots(public_a, _private_bytes(private_a), "per-close-a", (48, 49, 50)),
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b",
        signed_upload_response=upload_b,
        censuses=snapshots(public_b, private_b, "per-close-b", (48, 50, 50)),
    )
    with pytest.raises(HostCensusError, match="close offset 21600"):
        reconcile_collectors(
            timeline_a,
            root,
            timeline_b,
            root,
            pinned_a_upload_key=public_a,
            pinned_a_observer_key=public_a,
            pinned_b_upload_key=public_b,
            pinned_b_observer_key=public_b,
        )


def test_collectors_may_share_one_platform_signed_upload_receipt(tmp_path: Path) -> None:
    root, identity, upload, census, public_a, private_a = _fixture(tmp_path)
    platform_upload = _platform_signed_upload(
        identity, upload, public_a, _private_bytes(private_a)
    )
    private_b_obj, public_b = _keypair()
    private_b = _private_bytes(private_b_obj)
    timeline_a = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=platform_upload,
        censuses=_snapshot_series(census, public_a, _private_bytes(private_a), traversal_prefix="a-traversal"),
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b",
        signed_upload_response=platform_upload,
        censuses=_snapshot_series(census, public_b, private_b, traversal_prefix="b-traversal"),
    )
    result = reconcile_collectors(
        timeline_a,
        root,
        timeline_b,
        root,
        pinned_a_upload_key=public_a,
        pinned_a_observer_key=public_a,
        pinned_b_upload_key=public_a,
        pinned_b_observer_key=public_b,
    )
    assert result["evidence_complete"] is True
    assert result["authority"] is False


def test_collectors_with_one_census_observer_key_are_rejected(tmp_path: Path) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    timeline_a = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=upload,
        censuses=_snapshot_series(census, public, _private_bytes(private), traversal_prefix="a-traversal"),
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b",
        signed_upload_response=upload,
        censuses=_snapshot_series(census, public, _private_bytes(private), traversal_prefix="b-traversal"),
    )
    with pytest.raises(HostCensusError, match="observers are not independent"):
        reconcile_collectors(
            timeline_a,
            root,
            timeline_b,
            root,
            pinned_a_upload_key=public,
            pinned_a_observer_key=public,
            pinned_b_upload_key=public,
            pinned_b_observer_key=public,
        )


def test_collectors_with_reused_census_traversals_are_rejected(tmp_path: Path) -> None:
    root, _, upload, census, public_a, private_a = _fixture(tmp_path)
    private_b_obj, public_b = _keypair()
    private_b = _private_bytes(private_b_obj)
    timeline_a = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=upload,
        censuses=_snapshot_series(census, public_a, _private_bytes(private_a)),
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b",
        signed_upload_response=upload,
        censuses=_snapshot_series(census, public_b, private_b),
    )
    with pytest.raises(HostCensusError, match="traversals are not independent"):
        reconcile_collectors(
            timeline_a,
            root,
            timeline_b,
            root,
            pinned_a_upload_key=public_a,
            pinned_a_observer_key=public_a,
            pinned_b_upload_key=public_a,
            pinned_b_observer_key=public_b,
        )


def test_two_collector_disagreement_is_rejected(tmp_path: Path) -> None:
    root_a, identity, upload_a, census, public_a, private_a = _fixture(tmp_path / "a")
    root_b = tmp_path / "b" / "evidence"
    shutil.copytree(root_a, root_b)
    page_path = root_b / census["pages"][0]["raw_response_path"]
    raw_page = json.loads(page_path.read_text())
    raw_page["episodes"][0]["outcome"] = "loss"
    changed_page = json.dumps(raw_page, separators=(",", ":"), sort_keys=True).encode()
    page_path.write_bytes(changed_page)
    changed_pages = deepcopy(census["pages"])
    changed_pages[0]["raw_response_sha256"] = _hash(changed_page)
    changed_episodes = deepcopy(census["episodes"])
    changed_episodes[0]["outcome"] = "loss"
    private_b_obj, public_b = _keypair()
    private_b = _private_bytes(private_b_obj)
    upload_b = _second_signed_upload(identity, upload_a, public_b, private_b)
    snapshots_b = [
        build_census_bundle(
            identity=census["submission_identity"],
            query_identity=census["query_identity"],
            pages=_pages_for_observed(
                changed_pages,
                datetime.fromisoformat("2026-07-14T03:00:00+00:00")
                + timedelta(seconds=offset),
            ),
            episodes=changed_episodes,
            sequence_watermarks=census["sequence_watermarks"],
            close_offset_seconds=offset,
            census_observed_at_utc=(
                datetime.fromisoformat("2026-07-14T03:00:00+00:00")
                + timedelta(seconds=offset)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            traversal_id=f"b-traversal-{offset}",
            observer_public_key_bytes=public_b,
            observer_private_key_bytes=private_b,
        )
        for offset in CLOSE_OFFSETS_SECONDS
    ]
    timeline_a = build_collector_timeline(
        collector_id="collector-a", signed_upload_response=upload_a, censuses=_snapshot_series(census, public_a, _private_bytes(private_a))
    )
    timeline_b = build_collector_timeline(
        collector_id="collector-b", signed_upload_response=upload_b, censuses=snapshots_b
    )
    with pytest.raises(HostCensusError, match="disagreement"):
        reconcile_collectors(
            timeline_a,
            root_a,
            timeline_b,
            root_b,
            pinned_a_upload_key=public_a,
            pinned_a_observer_key=public_a,
            pinned_b_upload_key=public_b,
            pinned_b_observer_key=public_b,
        )


def test_maturity_uses_first_complete_poll_not_submission_creation(tmp_path: Path) -> None:
    _, identity, upload, _, _, _ = _fixture(tmp_path)
    assert identity["created_at_utc"] == "2026-07-14T00:00:00.000000Z"
    assert upload["first_observed_complete_at_utc"] == "2026-07-14T01:00:00.000000Z"
    assert derive_maturity_cutoff(upload) == "2026-07-14T02:00:00.000000Z"


def test_unsigned_or_unverifiable_page_bundle_cannot_report_completeness(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    unsigned = deepcopy(census)
    unsigned.pop("observer_signature_ed25519_base64")
    assert audit_host_census(upload, unsigned, root, pinned_public_key_bytes=public)["evidence_complete"] is False
    assert audit_host_census(upload, census, root)["evidence_complete"] is False


def test_pre_cutoff_rows_are_excluded_from_the_preregistered_horizon(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path, created_hour=1)
    audit = audit_host_census(upload, census, root, pinned_public_key_bytes=public)
    assert audit["evidence_complete"] is True
    with pytest.raises(HostCensusError, match="fewer than 48"):
        close_host_census(
            upload,
            census,
            root,
            as_of_utc="2026-07-14T03:00:00.000000Z",
            pinned_public_key_bytes=public,
        )


def test_duplicate_json_key_is_rejected_before_semantic_parsing(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    raw = b'{"schema":"evaluation_v5_1_host_submission_identity_v1","schema":"x"}'
    (root / "upload.json").write_bytes(raw)
    changed = deepcopy(upload)
    changed["raw_response_sha256"] = _hash(raw)
    failed = audit_host_census(changed, census, root, pinned_public_key_bytes=public)
    assert failed["evidence_complete"] is False


def test_exhaustive_claim_without_terminal_raw_page_fails_closed(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    changed = deepcopy(census)
    changed["terminal_next_cursor"] = "cursor-never-fetched"
    changed["exhaustive"] = True
    assert audit_host_census(upload, changed, root, pinned_public_key_bytes=public)["evidence_complete"] is False

    page_path = root / changed["pages"][-1]["raw_response_path"]
    page = json.loads(page_path.read_text())
    page["next_cursor"] = "cursor-omitted"
    page_path.write_text(json.dumps(page, separators=(",", ":"), sort_keys=True))
    assert audit_host_census(upload, census, root, pinned_public_key_bytes=public)["evidence_complete"] is False


@pytest.mark.parametrize("mutation", ["cursor", "watermark", "duplicate_game", "archive"])
def test_page_chain_and_identity_mismatches_are_rejected(tmp_path: Path, mutation: str) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    changed = deepcopy(census)
    if mutation == "cursor":
        changed["pages"][1]["request_cursor"] = "skipped-cursor"
    elif mutation == "watermark":
        changed["pages"][1]["sequence_watermark_before"] = 1
    elif mutation == "duplicate_game":
        changed["episodes"][24]["game_id"] = changed["episodes"][0]["game_id"]
    else:
        changed["episodes"][0]["archive_sha256"] = "c" * 64
    assert audit_host_census(upload, changed, root, pinned_public_key_bytes=public)["evidence_complete"] is False


def test_first48_is_recomputed_and_maturity_is_derived(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    changed = deepcopy(census)
    changed["episodes"] = list(reversed(changed["episodes"]))
    assert audit_host_census(upload, changed, root, pinned_public_key_bytes=public)["evidence_complete"] is False
    with pytest.raises(HostCensusError, match="signed census_observed_at_utc"):
        close_host_census(
            upload,
            census,
            root,
            as_of_utc="2026-07-14T01:59:59.000000Z",
            pinned_public_key_bytes=public,
        )


def test_validation_failure_is_not_dropped_from_raw_census(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path, first_status="VALIDATION_FAILED")
    audit = audit_host_census(upload, census, root, pinned_public_key_bytes=public)
    assert audit["evidence_complete"] is True
    assert audit["episodes"][0]["status"] == "VALIDATION_FAILED"


def test_symlinked_raw_page_is_not_accepted(tmp_path: Path) -> None:
    root, _, upload, census, public, _ = _fixture(tmp_path)
    page = root / census["pages"][0]["raw_response_path"]
    replacement = root / "replacement.json"
    replacement.write_bytes(page.read_bytes())
    page.unlink()
    page.symlink_to(replacement)
    assert audit_host_census(upload, census, root, pinned_public_key_bytes=public)["evidence_complete"] is False


def test_bundle_extra_selected_rows_are_rejected_as_non_exact() -> None:
    with pytest.raises(HostCensusError, match="exactly"):
        # The exact-field validator prevents callers from smuggling a chosen
        # first48 into the evidence object.
        from evaluation_v5_1.host_census import validate_census_bundle

        value = {
            "schema": CENSUS_SCHEMA,
            "submission_identity": {},
            "query_identity": {},
            "pages": [],
            "episodes": [],
            "sequence_watermarks": [],
            "terminal_next_cursor": None,
            "exhaustive": True,
            "selected_rows": [],
        }
        validate_census_bundle(value)


@pytest.mark.parametrize("relabelled_offset", [21600, 86400])
def test_one_signed_census_cannot_be_relabelled_as_a_later_close(
    tmp_path: Path, relabelled_offset: int
) -> None:
    _, _, upload, census, public, private = _fixture(tmp_path)
    snapshots = _snapshot_series(census, public, _private_bytes(private))
    relabelled = deepcopy(snapshots[0])
    relabelled["close_offset_seconds"] = relabelled_offset
    snapshots[1 if relabelled_offset == 21600 else 2] = relabelled
    with pytest.raises(HostCensusError, match="close offset|anchor-relative|bound to the close anchor"):
        build_collector_timeline(
            collector_id="collector-a",
            signed_upload_response=upload,
            censuses=snapshots,
        )


def test_episode_completed_after_snapshot_observation_is_rejected(tmp_path: Path) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    observed = datetime.fromisoformat("2026-07-14T02:00:00+00:00")
    earlier = build_census_bundle(
        identity=census["submission_identity"],
        query_identity=census["query_identity"],
        pages=_pages_for_observed(census["pages"], observed),
        episodes=census["episodes"],
        sequence_watermarks=census["sequence_watermarks"],
        census_observed_at_utc="2026-07-14T02:00:00.000000Z",
        traversal_id="traversal-earlier",
        observer_public_key_bytes=public,
        observer_private_key_bytes=_private_bytes(private),
    )
    audit = audit_host_census(upload, earlier, root, pinned_public_key_bytes=public)
    assert audit["evidence_complete"] is False
    assert "after census observation" in audit["reason"]


def test_stable_snapshots_cannot_be_timed_from_complete(tmp_path: Path) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    complete_anchor = datetime.fromisoformat("2026-07-14T01:00:00+00:00")
    snapshots = []
    for offset in CLOSE_OFFSETS_SECONDS:
        observed = complete_anchor + timedelta(seconds=offset)
        snapshots.append(
            build_census_bundle(
                identity=census["submission_identity"],
                query_identity=census["query_identity"],
                pages=_pages_for_observed(census["pages"], observed),
                episodes=census["episodes"],
                sequence_watermarks=census["sequence_watermarks"],
                close_offset_seconds=offset,
                census_observed_at_utc=observed.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                traversal_id=f"complete-timed-{offset}",
                observer_public_key_bytes=public,
                observer_private_key_bytes=_private_bytes(private),
            )
        )
    with pytest.raises(HostCensusError, match="maturity boundary"):
        build_collector_timeline(
            collector_id="collector-a",
            signed_upload_response=upload,
            censuses=snapshots,
        )


def test_identical_snapshot_bytes_cannot_supply_three_signed_traversals(
    tmp_path: Path,
) -> None:
    root, _, upload, census, public, private = _fixture(tmp_path)
    snapshots = _snapshot_series(census, public, _private_bytes(private))
    timeline = build_collector_timeline(
        collector_id="collector-a",
        signed_upload_response=upload,
        censuses=snapshots,
    )
    cloned = deepcopy(timeline)
    cloned["snapshots"][1]["census"] = cloned["snapshots"][0]["census"]
    with pytest.raises(HostCensusError, match="offset|anchor-relative"):
        audit_collector_timeline(cloned, root, pinned_public_key_bytes=public)
