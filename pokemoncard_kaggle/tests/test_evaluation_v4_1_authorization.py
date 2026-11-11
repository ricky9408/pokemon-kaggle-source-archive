from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v4_1.authorization import (
    AUTHORIZATION_SCHEMA,
    PERMIT_SCHEMA,
    USAGE_LEDGER_SCHEMA,
    AuthorizationError,
    build_authorization,
    guard_research_submission,
    validate_authorization,
    validate_research_permit,
    validate_usage_ledger,
    write_authorization_create_once,
)
from evaluation_v4_1.protocol import canonical_sha256
from evaluation_v4_1.runtime import build_kaggle_runtime_binding
from tests.test_evaluation_v4_1_prediction import _bundle


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fixture(
    usage_ledger_path: str | Path = "/tmp/voi-p5-test-unused.jsonl",
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    bundle, values = _bundle()
    protocol, population, assignment, model, _ = values
    artifacts = {
        "protocol": protocol,
        "population_manifest": population,
        "pair_assignment": assignment,
        "prediction_bundle": bundle,
        "predictor_model": model,
        "kaggle_runtime_binding": build_kaggle_runtime_binding(
            Path(__file__).resolve().parents[1]
        ),
    }
    names = {
        lineage_uuid: f"submission-codex-voi-{index:02d}.tar.gz"
        for index, lineage_uuid in enumerate(assignment["selected_lineage_uuids"], start=1)
    }
    authorization = build_authorization(
        **artifacts,
        usage_ledger_path=usage_ledger_path,
        archive_names_by_lineage_uuid=names,
        authorization_id="voi-p5-test-001",
        explicit_user_override_text_sha256=_digest("explicit current user authorization"),
        created_at_utc="2026-07-11T09:01:00.000000Z",
        expires_at_utc="2026-07-12T09:01:00.000000Z",
    )
    return authorization, artifacts, bundle


def _request(authorization: dict[str, object], index: int) -> dict[str, object]:
    return dict(authorization["archive_assignments"][index])  # type: ignore[index]


def _permit(
    authorization: dict[str, object],
    artifacts: dict[str, object],
    ledger: Path,
    index: int,
    *,
    prior_pair_capture: object | None = None,
) -> dict[str, object]:
    return guard_research_submission(
        authorization,
        ledger,
        artifacts=artifacts,
        **_request(authorization, index),
        now="2026-07-11T10:00:00.000000Z",
        prior_pair_capture=prior_pair_capture,
    )


def _fake_barrier(pair_index: int) -> dict[str, object]:
    return {
        "pair_id": f"pair-{pair_index:02d}",
        "horizon_completed_at_utc": "2026-07-11T09:30:00.000000Z",
        "content_sha256": hashlib.sha256(f"pair-{pair_index:02d}".encode("ascii")).hexdigest(),
    }


def _fake_capture(pair_index: int) -> dict[str, object]:
    return {
        "pair_id": f"pair-{pair_index:02d}",
        "pair_completion_barrier": _fake_barrier(pair_index),
    }


def test_authorization_is_derived_from_exact_artifacts_and_create_once(tmp_path: Path) -> None:
    authorization, artifacts, _ = _fixture()
    assert authorization["schema"] == AUTHORIZATION_SCHEMA
    assert authorization["research_only"] is True
    assert authorization["production_submission_authorized"] is False
    assert [row["pair_id"] for row in authorization["archive_assignments"]] == [
        "pair-01",
        "pair-01",
        "pair-02",
        "pair-02",
        "pair-03",
        "pair-03",
        "pair-04",
        "pair-04",
        "pair-05",
        "pair-05",
    ]
    path = tmp_path / "authorization.json"
    assert write_authorization_create_once(path, authorization, artifacts=artifacts) == path
    assert json.loads(path.read_text(encoding="ascii")) == authorization
    with pytest.raises(FileExistsError):
        write_authorization_create_once(path, authorization, artifacts=artifacts)


def test_pair_wave_slot_and_archive_bindings_cannot_be_invented() -> None:
    authorization, artifacts, _ = _fixture()
    for field, value in (
        ("pair_id", "pair-05"),
        ("wave_id", "wave-3"),
        ("slot", 2),
        ("archive_sha256", "9" * 64),
        ("lineage_uuid", "00000000-0000-0000-0000-000000000099"),
    ):
        changed = copy.deepcopy(authorization)
        changed["archive_assignments"][0][field] = value
        with pytest.raises(AuthorizationError, match="exact"):
            validate_authorization(changed, **artifacts)


def test_prediction_or_assignment_hash_mutation_is_rejected() -> None:
    authorization, artifacts, _ = _fixture()
    for field in (
        "protocol_sha256",
        "population_content_sha256",
        "pair_assignment_content_sha256",
        "prediction_bundle_content_sha256",
    ):
        changed = copy.deepcopy(authorization)
        changed[field] = "9" * 64
        with pytest.raises(AuthorizationError, match="exact artifact-derived"):
            validate_authorization(changed, **artifacts)


def test_archive_names_are_unique_basenames_without_final() -> None:
    _, artifacts, _ = _fixture()
    assignment = artifacts["pair_assignment"]
    names = {
        lineage_uuid: f"submission-codex-voi-{index:02d}.tar.gz"
        for index, lineage_uuid in enumerate(assignment["selected_lineage_uuids"], start=1)  # type: ignore[index]
    }
    for bad in ("nested/archive.tar.gz", "submission-codex-final-v1.tar.gz"):
        changed = dict(names)
        changed[next(iter(changed))] = bad
        with pytest.raises(AuthorizationError):
            build_authorization(
                **artifacts,
                usage_ledger_path="/tmp/voi-p5-test-unused.jsonl",
                archive_names_by_lineage_uuid=changed,
                authorization_id="voi-p5-test-001",
                explicit_user_override_text_sha256=_digest("override"),
                created_at_utc="2026-07-11T09:01:00.000000Z",
                expires_at_utc="2026-07-12T09:01:00.000000Z",
            )


def test_guard_requires_exact_sequential_pair_slots(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    with pytest.raises(AuthorizationError, match="next exact"):
        _permit(authorization, artifacts, ledger, 2)
    first = _permit(authorization, artifacts, ledger, 0)
    assert first["schema"] == PERMIT_SCHEMA
    assert first["pair_id"] == "pair-01"
    assert first["slot"] == 1
    assert first["production_submission_authorized"] is False
    with pytest.raises(AuthorizationError, match="next exact"):
        _permit(authorization, artifacts, ledger, 2)
    second = _permit(authorization, artifacts, ledger, 1)
    assert second["pair_id"] == "pair-01"
    assert second["slot"] == 2


def test_all_ten_research_permits_remain_nonproduction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)

    def validate_fake_capture(value: object, **_: object) -> object:
        return value

    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.reverify_authenticated_pair_capture_online",
        validate_fake_capture,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    permits = []
    for index in range(10):
        pair_index = index // 2
        kwargs = {}
        if pair_index:
            kwargs = {
                "prior_pair_capture": _fake_capture(pair_index),
            }
        permits.append(_permit(authorization, artifacts, ledger, index, **kwargs))
    assert [permit["remaining_cap"] for permit in permits] == list(range(9, -1, -1))
    assert all(permit["research_only"] is True for permit in permits)
    assert all(permit["production_submission_authorized"] is False for permit in permits)
    with pytest.raises(AuthorizationError, match="exhausted"):
        _permit(authorization, artifacts, ledger, 0)
    assert len(validate_usage_ledger(ledger, authorization, artifacts=artifacts)) == 10


def test_usage_ledger_mutation_and_wrong_artifact_fail_closed(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    _permit(authorization, artifacts, ledger, 0)
    event = json.loads(ledger.read_text(encoding="ascii"))
    event["archive_name"] = "tampered.tar.gz"
    ledger.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    with pytest.raises(AuthorizationError):
        validate_usage_ledger(ledger, authorization, artifacts=artifacts)

    wrong = dict(artifacts)
    wrong["prediction_bundle"] = {"schema": "forged"}
    with pytest.raises(Exception):
        validate_usage_ledger(ledger, authorization, artifacts=wrong)


def test_permit_must_exist_in_exact_frozen_usage_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    _permit(authorization, artifacts, ledger, 0)
    row = authorization["archive_assignments"][1]
    content = {
        "schema": PERMIT_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "protocol_sha256": authorization["protocol_sha256"],
        "population_content_sha256": authorization["population_content_sha256"],
        "pair_assignment_content_sha256": authorization["pair_assignment_content_sha256"],
        "prediction_bundle_content_sha256": authorization["prediction_bundle_content_sha256"],
        **row,
        "prior_pair_barrier_content_sha256": None,
        "usage_sequence": 2,
        "usage_event_sha256": "9" * 64,
        "horizon": "literal_first24",
        "scope": "RESEARCH_ONLY_CALIBRATION",
        "remaining_cap": 8,
        "research_only": True,
        "production_submission_authorized": False,
    }
    forged = {**content, "content_sha256": canonical_sha256(content)}
    with pytest.raises(AuthorizationError, match="usage event"):
        validate_research_permit(
            forged,
            authorization,
            ledger_path=ledger,
            artifacts=artifacts,
        )


def test_authorization_cannot_be_replayed_on_alternate_ledger_path(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    _permit(authorization, artifacts, ledger, 0)
    with pytest.raises(AuthorizationError, match="frozen authorization"):
        guard_research_submission(
            authorization,
            tmp_path / "replacement-usage.jsonl",
            artifacts=artifacts,
            **_request(authorization, 0),
            now="2026-07-11T10:00:00.000000Z",
        )


def test_expiry_and_exact_artifact_argument_surface() -> None:
    ledger = "/tmp/voi-p5-expired.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    with pytest.raises(AuthorizationError, match="outside"):
        guard_research_submission(
            authorization,
            ledger,
            artifacts=artifacts,
            **_request(authorization, 0),
            now="2026-07-12T09:01:00.000000Z",
        )
    with pytest.raises(AuthorizationError, match="artifacts fields"):
        validate_usage_ledger(
            "/tmp/unused-voi-p5.jsonl",
            authorization,
            artifacts={"protocol": artifacts["protocol"]},
        )


def test_backdated_caller_time_cannot_bypass_wall_clock_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "usage.jsonl"
    authorization, artifacts, _ = _fixture(ledger)
    monkeypatch.setattr(
        "evaluation_v4_1.authorization._wall_now",
        lambda: datetime(2026, 7, 12, 9, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(AuthorizationError, match="outside"):
        guard_research_submission(
            authorization,
            ledger,
            artifacts=artifacts,
            **_request(authorization, 0),
            now="2026-07-11T10:00:00.000000Z",
        )


def test_schema_versions_make_legacy_five_wave_receipts_unusable() -> None:
    assert AUTHORIZATION_SCHEMA == "voi_p5_authorization_v4"
    assert USAGE_LEDGER_SCHEMA == "voi_p5_usage_ledger_v4"
    legacy = {
        "schema": "voi_p5_authorization_v3",
        "archive_assignments": [],
    }
    _, artifacts, _ = _fixture()
    with pytest.raises(AuthorizationError):
        validate_authorization(legacy, **artifacts)
