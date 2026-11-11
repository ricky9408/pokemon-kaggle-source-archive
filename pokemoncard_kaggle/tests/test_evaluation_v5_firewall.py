from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from evaluation_v5.firewall import (
    DEV_BURNED,
    EXTERNAL_CONFIRMATORY,
    PROSPECTIVE_SHADOW,
    SEALED_50,
    ArchiveRecord,
    Firewall,
    FirewallError,
    build_firewall,
)


def _record(index: int, partition: str = DEV_BURNED, **changes: object) -> ArchiveRecord:
    value: dict[str, object] = {
        "archive_id": f"archive-{index}",
        "partition": partition,
        "archive_sha256": f"{index:064x}",
        "deck_sha256": f"{index + 100:064x}",
        "policy_sha256": f"{index + 200:064x}",
        "family_provenance_sha256": f"{index + 300:064x}",
        "model_input_sha256": f"{index + 400:064x}",
        "registered_at_utc": (
            "2026-07-14T00:00:00.000000Z"
            if partition == EXTERNAL_CONFIRMATORY
            else "2026-07-01T00:00:00.000000Z"
        ),
    }
    value.update(changes)
    return ArchiveRecord(**value)  # type: ignore[arg-type]


def test_confirmatory_requires_outcome_free_pre_registration() -> None:
    valid = _record(1, EXTERNAL_CONFIRMATORY)
    assert build_firewall([valid]).authority is False
    with pytest.raises(FirewallError, match="post-freeze"):
        _record(
            2,
            EXTERNAL_CONFIRMATORY,
            registered_at_utc="2026-07-13T17:54:27.000000Z",
        )
    with pytest.raises(FirewallError, match="post-freeze"):
        _record(
            3,
            EXTERNAL_CONFIRMATORY,
            registered_at_utc="2026-07-13T17:54:26.999999Z",
        )
    assert build_firewall(
        [_record(4, EXTERNAL_CONFIRMATORY, registered_at_utc="2026-07-13T17:54:27.000001Z")]
    ).authority is False
    with pytest.raises(FirewallError, match="observed outcomes"):
        _record(
            5,
            EXTERNAL_CONFIRMATORY,
            outcomes_observed=True,
        )
    with pytest.raises(FirewallError, match="hosted chronology"):
        _record(
            6,
            EXTERNAL_CONFIRMATORY,
            first_hosted_game_at_utc="2026-07-01T00:00:01.000000Z",
        )


def test_contamination_boundaries_fail_closed_but_decks_and_families_may_repeat() -> None:
    shared_policy = "e" * 64
    for development_partition in (DEV_BURNED, PROSPECTIVE_SHADOW):
        with pytest.raises(FirewallError, match="policy_sha256 overlap"):
            build_firewall(
                [
                    _record(10, development_partition, policy_sha256=shared_policy),
                    _record(11, EXTERNAL_CONFIRMATORY, policy_sha256=shared_policy),
                ]
            )

    shared_deck = "d" * 64
    shared_family = "f" * 64
    assert build_firewall(
        [
            _record(12, EXTERNAL_CONFIRMATORY, deck_sha256=shared_deck, family_provenance_sha256=shared_family),
            _record(13, EXTERNAL_CONFIRMATORY, deck_sha256=shared_deck, family_provenance_sha256=shared_family),
        ]
    ).authority is False

    with pytest.raises(FirewallError, match="model_input_sha256 overlap"):
        build_firewall(
            [
                _record(14, EXTERNAL_CONFIRMATORY, model_input_sha256="a" * 64),
                _record(15, EXTERNAL_CONFIRMATORY, model_input_sha256="a" * 64),
            ]
        )


@pytest.mark.parametrize("sealed_first", [True, False])
@pytest.mark.parametrize("nonsealed_partition", [DEV_BURNED, PROSPECTIVE_SHADOW, EXTERNAL_CONFIRMATORY])
@pytest.mark.parametrize("field", ["policy_sha256", "model_input_sha256"])
def test_sealed_sensitive_hashes_cannot_overlap_nonsealed_records(
    sealed_first: bool, nonsealed_partition: str, field: str
) -> None:
    shared_hash = "a" * 64
    sealed = _record(16, SEALED_50, **{field: shared_hash})
    nonsealed = _record(17, nonsealed_partition, **{field: shared_hash})
    records = [sealed, nonsealed] if sealed_first else [nonsealed, sealed]
    with pytest.raises(FirewallError, match=field):
        build_firewall(records)


def test_confirmatory_identical_policies_must_have_one_family() -> None:
    with pytest.raises(FirewallError, match="family_provenance_sha256 mismatch"):
        build_firewall(
            [
                _record(18, EXTERNAL_CONFIRMATORY, policy_sha256="b" * 64, family_provenance_sha256="c" * 64),
                _record(19, EXTERNAL_CONFIRMATORY, policy_sha256="b" * 64, family_provenance_sha256="d" * 64),
            ]
        )

    assert build_firewall(
        [
            _record(20, EXTERNAL_CONFIRMATORY, policy_sha256="e" * 64, family_provenance_sha256="f" * 64),
            _record(21, EXTERNAL_CONFIRMATORY, policy_sha256="e" * 64, family_provenance_sha256="f" * 64),
            _record(22, EXTERNAL_CONFIRMATORY, policy_sha256="1" * 64, family_provenance_sha256="f" * 64),
        ]
    ).authority is False


def test_unknown_partition_and_archive_overlap_fail_closed() -> None:
    with pytest.raises(FirewallError, match="unrecognized partition"):
        _record(1, "NOT_A_PARTITION")
    with pytest.raises(FirewallError, match="overlap"):
        build_firewall([_record(1), _record(1)])
    with pytest.raises(FirewallError, match="archive_sha256"):
        build_firewall([_record(1), _record(2, archive_sha256=f"{1:064x}")])


def test_sealed_projection_has_identifiers_and_hashes_only() -> None:
    sealed = _record(1, SEALED_50)
    view = build_firewall([sealed]).sealed_records()[0]
    assert view.archive_id == sealed.archive_id
    assert view.archive_sha256 == sealed.archive_sha256
    assert not hasattr(view, "payload_path")
    assert not hasattr(view, "outcomes_observed")
    assert not hasattr(view, "registered_at_utc")
    assert not hasattr(view, "first_hosted_game_at_utc")
    assert "payload_path" not in view.as_dict()
    assert "registered_at_utc" not in view.as_dict()
    assert "first_hosted_game_at_utc" not in view.as_dict()
    assert "outcomes_observed" not in view.as_dict()
    assert "payload_path" not in sealed.as_dict()
    with pytest.raises(FirewallError, match="payload path"):
        _record(2, SEALED_50, payload_path="sealed/payload.json")


def test_records_are_immutable_and_hash_tampering_changes_identity() -> None:
    record = _record(1)
    with pytest.raises(FrozenInstanceError):
        record.archive_sha256 = "f" * 64  # type: ignore[misc]
    tampered = replace(record, archive_sha256="f" * 64)
    assert tampered.archive_sha256 != record.archive_sha256
    with pytest.raises(FirewallError, match="overlap"):
        build_firewall([record, tampered])


def test_type_and_tamper_checks_fail_closed() -> None:
    with pytest.raises(FirewallError, match="lowercase SHA-256"):
        _record(20, policy_sha256="A" * 64)
    with pytest.raises(FirewallError, match="canonical UTC"):
        _record(21, registered_at_utc="2026-07-14T00:00:00Z")
    with pytest.raises(FirewallError, match="outcomes_observed"):
        _record(22, outcomes_observed=1)
    with pytest.raises(FirewallError, match="payload_path"):
        _record(23, payload_path=object())
    with pytest.raises(FirewallError, match="authority"):
        Firewall(records=(), authority=True)
