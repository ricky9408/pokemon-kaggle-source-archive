from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.engine_capabilities import (
    CAPABILITY_NAMES,
    ENGINE_CAPABILITY_MANIFEST_SCHEMA,
    FEATURE_SCENARIOS,
    HASH_NAMES,
    REQUIRED_BACKENDS,
    EngineCapabilityError,
    audit_engine_capabilities,
    build_engine_capability_manifest,
    engine_capability_manifest_sha256,
    validate_engine_capability_manifest,
)


def _backend(*, enabled: bool = True, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {name: f"{index + 1:064x}" for index, name in enumerate(HASH_NAMES)}
    value.update({name: enabled for name in CAPABILITY_NAMES})
    value.update(overrides)
    if "capability_evidence_sha256" not in overrides:
        value["capability_evidence_sha256"] = {
            name: f"{index + 11:064x}"
            for index, name in enumerate(CAPABILITY_NAMES)
            if value[name] is True
        }
    return value


def _manifest(
    *, opened_source: dict[str, object] | None = None, official_wrapper: dict[str, object] | None = None
) -> dict[str, object]:
    return {
        "schema": ENGINE_CAPABILITY_MANIFEST_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "backends": {
            "opened_source": opened_source or _backend(),
            "official_wrapper": official_wrapper or _backend(),
        },
    }


def test_complete_pair_is_canonical_and_all_features_are_feasible() -> None:
    wire = _manifest()
    manifest = validate_engine_capability_manifest(wire)
    assert manifest.as_dict() == wire
    assert manifest.manifest_sha256 == canonical_sha256(wire)
    assert engine_capability_manifest_sha256(wire) == manifest.manifest_sha256

    result = audit_engine_capabilities(manifest)
    assert result["decision"] == "LOCAL_FEATURE_EXTRACTION_FEASIBLE"
    assert result["missing_features"] == []
    assert result["local_feature_extraction"] is True
    assert result["submission_authorized"] is False
    assert result["holdout_access_authorized"] is False
    assert all(item["feasible"] for item in result["feature_feasibility"].values())
    assert result == audit_engine_capabilities(_manifest())


def test_current_reality_official_wrapper_capability_gap_closes_gate() -> None:
    # Current reality: the opened-source derivative supports seeded openings
    # and audited search/world research, but not full state/RNG restore or
    # replayable legal intervention. The official wrapper lacks all controls.
    source = _backend(
        seeded_start=True,
        snapshot_restore_rng=False,
        legal_interventions=False,
        search_world_interface=True,
        repeatability_audited=True,
    )
    wrapper = _backend(
        enabled=False,
    )
    result = audit_engine_capabilities(
        _manifest(opened_source=source, official_wrapper=wrapper)
    )

    assert result["decision"] == "NO_LOCAL_FEATURE_EXTRACTION"
    assert result["local_feature_extraction"] is False
    assert set(result["missing_features"]) == set(FEATURE_SCENARIOS)
    assert result["missing_capabilities"]
    assert result["missing_capabilities"]["observation_invariance"]["official_wrapper"] == [
        "search_world_interface",
        "repeatability_audited",
    ]
    assert result["scenario_feasibility"]["active_ko"]["missing_capabilities"][
        "opened_source"
    ] == ["snapshot_restore_rng", "legal_interventions"]
    assert result["scenario_feasibility"]["observation_invariance"]["missing_capabilities"][
        "opened_source"
    ] == []
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    assert result["holdout_access_authorized"] is False


def test_both_backends_are_required_for_each_feature_and_crn() -> None:
    source = _backend(snapshot_restore_rng=False)
    result = audit_engine_capabilities(_manifest(opened_source=source))

    assert result["feature_feasibility"]["attack_availability_t2_t4"]["feasible"] is True
    assert result["feature_feasibility"]["post_active_ko_attack_recovery"]["feasible"] is False
    assert result["feature_feasibility"]["post_active_ko_attack_recovery"]["missing_capabilities"][
        "opened_source"
    ] == ["snapshot_restore_rng"]
    assert result["scenario_feasibility"]["crn"]["feasible"] is False
    assert result["scenario_feasibility"]["crn"]["missing_capabilities"]["opened_source"] == [
        "snapshot_restore_rng"
    ]


@pytest.mark.parametrize("field", ["schema", "protocol_id"])
def test_manifest_identity_tampering_fails_closed(field: str) -> None:
    wire = _manifest()
    wire[field] = "tampered"
    with pytest.raises(EngineCapabilityError):
        validate_engine_capability_manifest(wire)


@pytest.mark.parametrize("field", [*HASH_NAMES])
def test_hash_binding_tampering_fails_closed(field: str) -> None:
    wire = _manifest()
    wire["backends"]["official_wrapper"][field] = "0" * 63 + "G"  # type: ignore[index]
    with pytest.raises(EngineCapabilityError):
        validate_engine_capability_manifest(wire)


@pytest.mark.parametrize("field", [*CAPABILITY_NAMES])
def test_capability_type_tampering_fails_closed(field: str) -> None:
    wire = _manifest()
    wire["backends"]["opened_source"][field] = 1  # type: ignore[index]
    with pytest.raises(EngineCapabilityError):
        validate_engine_capability_manifest(wire)


def test_true_capability_without_matching_bound_evidence_fails_closed() -> None:
    wire = _manifest()
    del wire["backends"]["opened_source"]["capability_evidence_sha256"]["seeded_start"]  # type: ignore[index]
    with pytest.raises(EngineCapabilityError, match="exactly the true capabilities"):
        validate_engine_capability_manifest(wire)

    wire = _manifest(
        opened_source=_backend(
            snapshot_restore_rng=False,
            legal_interventions=False,
        )
    )
    wire["backends"]["opened_source"]["snapshot_restore_rng"] = True  # type: ignore[index]
    with pytest.raises(EngineCapabilityError, match="exactly the true capabilities"):
        validate_engine_capability_manifest(wire)


def test_false_capability_cannot_carry_evidence_and_evidence_hashes_are_typed() -> None:
    wire = _manifest(opened_source=_backend(snapshot_restore_rng=False))
    wire["backends"]["opened_source"]["capability_evidence_sha256"][  # type: ignore[index]
        "snapshot_restore_rng"
    ] = "1" * 64
    with pytest.raises(EngineCapabilityError, match="exactly the true capabilities"):
        validate_engine_capability_manifest(wire)

    wire = _manifest()
    wire["backends"]["official_wrapper"]["capability_evidence_sha256"]["seeded_start"] = 1  # type: ignore[index]
    with pytest.raises(EngineCapabilityError, match="keys and values must be strings"):
        validate_engine_capability_manifest(wire)


def test_extra_or_missing_backend_and_backend_fields_fail_closed() -> None:
    wire = _manifest()
    del wire["backends"]["official_wrapper"]  # type: ignore[index]
    with pytest.raises(EngineCapabilityError):
        validate_engine_capability_manifest(wire)

    wire = _manifest()
    wire["backends"]["opened_source"]["unexpected"] = True  # type: ignore[index]
    with pytest.raises(EngineCapabilityError):
        validate_engine_capability_manifest(wire)


def test_manifest_and_audit_do_not_mutate_input_and_tamper_changes_hash() -> None:
    wire = _manifest()
    before = deepcopy(wire)
    manifest = build_engine_capability_manifest(wire)
    assert wire == before
    changed = deepcopy(wire)
    changed["backends"]["opened_source"]["seeded_start"] = False  # type: ignore[index]
    del changed["backends"]["opened_source"]["capability_evidence_sha256"]["seeded_start"]  # type: ignore[index]
    assert engine_capability_manifest_sha256(changed) != manifest.manifest_sha256
    with pytest.raises(FrozenInstanceError):
        manifest.schema = "tampered"  # type: ignore[misc]
    with pytest.raises(TypeError):
        manifest.backends["opened_source"] = manifest.backends["official_wrapper"]  # type: ignore[index]


def test_typed_manifest_rejects_non_backend_objects() -> None:
    with pytest.raises(EngineCapabilityError, match="must be a mapping"):
        build_engine_capability_manifest(
            {
                "schema": ENGINE_CAPABILITY_MANIFEST_SCHEMA,
                "protocol_id": "MCI_TRANSFER_V1",
                "backends": {"opened_source": object(), "official_wrapper": object()},
            }
        )
