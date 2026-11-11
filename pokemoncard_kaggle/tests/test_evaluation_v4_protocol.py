from __future__ import annotations

import copy

import pytest

from evaluation_v4.protocol import (
    BURNED_PANEL_ID,
    ProtocolError,
    assign_ancestry_split,
    build_manifest,
    canonical_sha256,
    validate_lineage_records,
    validate_manifest,
    validate_protocol,
    write_manifest_once,
)


def _protocol() -> dict[str, object]:
    return {
        "schema": "whole_policy_selector_protocol_v1",
        "protocol_id": "selector-v4-prospective-001",
        "frozen_at_utc": "2026-07-11T07:03:00.000000Z",
        "selector_code_sha256": "a" * 64,
        "split_salt_sha256": "b" * 64,
        "burned_panel_ids": [BURNED_PANEL_ID],
        "sealed_holdout_id": "sealed-v4-50",
        "estimand": "next24_win_plus_half_draw",
        "setup_games": 8,
        "horizon_games": 24,
        "minimums": {"min_lineages": 16, "min_families": 4, "min_blocks": 3},
        "thresholds": {
            "macro_lineage_logloss_lift_min": 0.015,
            "lineage_bootstrap_positive_probability_min": 0.95,
            "lineage_bootstrap_q10_lift_min": 0,
            "residual_pairwise_concordance_min": 0.65,
            "positive_unit_fraction_min": 0.8,
            "family_lift_floor": -0.01,
            "calibration_slope_lower_bound_min": 0,
            "max_candidate_visited_ood_mass": 0.10,
            "candidate_posterior_mean_lift_min": 0.03,
            "candidate_posterior_positive_probability_min": 0.95,
            "candidate_posterior_q10_lift_min": 0,
            "worst_family_q10_lift_min": -0.02,
            "engine_variant_mean_lift_min": 0,
        },
        "bootstrap_samples": 1000,
        "seed": 20260711,
        "state": "FROZEN",
    }


def _record(index: int, ancestry: str | None = None) -> dict[str, str]:
    return {
        "archive_sha256": f"{index:064x}",
        "policy_content_sha256": f"{index + 100:064x}",
        "deck_sha256": f"{index + 200:064x}",
        "lineage_id": f"lineage-{index}",
        "ancestry_id": ancestry or f"ancestry-{index}",
        "family_id": "family-shared" if ancestry else f"family-{index % 4}",
        "first_seen_utc": f"2026-07-01T00:00:{index:02d}.000000Z",
    }


def test_assignment_is_deterministic() -> None:
    first = assign_ancestry_split("b" * 64, "ancestry-123")
    assert first == assign_ancestry_split("b" * 64, "ancestry-123")
    assert first in {"train", "tune", "local_test"}


def test_related_lineages_stay_in_one_split() -> None:
    records = [_record(1, "shared"), _record(2, "shared"), _record(3)]
    manifest = build_manifest(_protocol(), records)
    shared_splits = {row["split"] for row in manifest["records"] if row["ancestry_id"] == "shared"}
    assert len(shared_splits) == 1


def test_manifest_is_input_order_invariant() -> None:
    records = [_record(1), _record(2), _record(3)]
    assert build_manifest(_protocol(), records) == build_manifest(_protocol(), list(reversed(records)))


def test_conflicting_lineage_or_ancestry_is_rejected() -> None:
    changed_hash = _record(1)
    changed_hash["archive_sha256"] = "f" * 64
    with pytest.raises(ProtocolError, match="lineage_id"):
        validate_lineage_records([_record(1), changed_hash])

    other_family = _record(2, "shared")
    other_family["family_id"] = "other-family"
    with pytest.raises(ProtocolError, match="ancestry_id"):
        validate_lineage_records([_record(1, "shared"), other_family])


@pytest.mark.parametrize("field", ["archive_sha256", "policy_content_sha256"])
def test_duplicate_executable_content_cannot_cross_ancestry_splits(field: str) -> None:
    duplicate = _record(2, "other-ancestry")
    duplicate[field] = _record(1, "source-ancestry")[field]
    with pytest.raises(ProtocolError, match=field):
        build_manifest(_protocol(), [_record(1, "source-ancestry"), duplicate])


def test_deck_hash_can_repeat_across_lineages() -> None:
    second = _record(2, "other-ancestry")
    second["deck_sha256"] = _record(1, "source-ancestry")["deck_sha256"]
    assert build_manifest(_protocol(), [_record(1, "source-ancestry"), second])["counts"]["lineages"] == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.__setitem__("state", "OPEN"),
        lambda value: value.__setitem__("estimand", "win_rate"),
        lambda value: value.__setitem__("setup_games", 7),
        lambda value: value["thresholds"].__setitem__("macro_lineage_logloss_lift_min", 0.014),
        lambda value: value.__setitem__("burned_panel_ids", ["other-panel"]),
        lambda value: value.__setitem__("unknown", True),
    ],
)
def test_bad_protocol_fields_thresholds_and_denylist_are_rejected(mutate: object) -> None:
    protocol = copy.deepcopy(_protocol())
    mutate(protocol)  # type: ignore[operator]
    with pytest.raises(ProtocolError):
        validate_protocol(protocol)


def _rehash_manifest(manifest: dict[str, object]) -> None:
    content = {key: value for key, value in manifest.items() if key != "content_sha256"}
    manifest["content_sha256"] = canonical_sha256(content)


def test_tampered_split_is_rejected_after_rehash() -> None:
    protocol = _protocol()
    manifest = build_manifest(protocol, [_record(1)])
    row = manifest["records"][0]
    wrong_split = next(split for split in ("train", "tune", "local_test") if split != row["split"])
    row["split"] = wrong_split
    manifest["counts"] = {
        "lineages": 1,
        "ancestries": 1,
        "families": 1,
        "train_lineages": int(wrong_split == "train"),
        "tune_lineages": int(wrong_split == "tune"),
        "local_test_lineages": int(wrong_split == "local_test"),
    }
    _rehash_manifest(manifest)
    with pytest.raises(ProtocolError, match="split mismatch"):
        validate_manifest(manifest, protocol)


def test_wrong_protocol_is_rejected() -> None:
    protocol = _protocol()
    manifest = build_manifest(protocol, [_record(1)])
    wrong_protocol = copy.deepcopy(protocol)
    wrong_protocol["split_salt_sha256"] = "c" * 64
    with pytest.raises(ProtocolError, match="protocol_sha256 mismatch"):
        validate_manifest(manifest, wrong_protocol)


def test_create_once_writer_creates_parent_directories(tmp_path: object) -> None:
    protocol = _protocol()
    manifest = build_manifest(protocol, [_record(1)])
    path = tmp_path / "nested" / "manifest.json"  # type: ignore[operator]
    assert write_manifest_once(path, manifest, protocol) == path
    with pytest.raises(FileExistsError):
        write_manifest_once(path, manifest, protocol)


def test_outcome_field_is_not_accepted_in_lineage_records() -> None:
    record = _record(1)
    record["outcome"] = "win"
    with pytest.raises(ProtocolError, match="fields"):
        validate_lineage_records([record])
