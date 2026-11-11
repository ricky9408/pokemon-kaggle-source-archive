from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from typing import Callable

import pytest

import evaluation_v6_3_1.local_panel as local_panel
from evaluation_v6_3_1.local_panel import (
    CONTROL_ENTRY_SCHEMA,
    CONTROL_LABELS,
    CONTROL_REGISTRY_SCHEMA,
    EXPECTED_GAME_COUNT,
    FEATURE_CANDIDATE_SCHEMA,
    FEATURE_NAMES,
    FEATURE_SPEC,
    FEATURE_SPEC_STATE,
    GAME_TRANSCRIPT_SCHEMA,
    LocalPanelError,
    OfflineLocalFeatureCandidate,
    OfflineLocalPanelCandidate,
    PANEL_TRANSCRIPT_SCHEMA,
    RAW_SUFFICIENT_STATISTIC_FIELDS,
    SEATS,
    SEED_INDEXES,
    VerifiedControlRegistry,
    canonical_json_bytes,
    canonical_panel_merkle_root,
    derive_game_trace_root,
    derive_local_feature_candidate,
    derive_rng_seed,
    derive_seat_robustness,
    parse_canonical_transcript,
    revalidate_control_registry,
    revalidate_local_feature_derivation,
    revalidate_offline_local_feature_candidate,
    revalidate_offline_local_panel_candidate,
    verify_control_registry,
    verify_local_panel,
    zero_authority_report,
)


CANDIDATE = {
    "candidate_archive_sha256": "a" * 64,
    "candidate_source_root_sha256": "b" * 64,
    "candidate_deck_sha256": "c" * 64,
    "candidate_policy_sha256": "d" * 64,
    "runtime_engine_root_sha256": "e" * 64,
}


def _hash(index: int) -> str:
    return f"{index + 1:064x}"


def _registry_object() -> dict[str, object]:
    return {
        "schema": CONTROL_REGISTRY_SCHEMA,
        "entries": [
            {
                "schema": CONTROL_ENTRY_SCHEMA,
                "label": label,
                "archive_sha256": _hash(index * 5),
                "source_root_sha256": _hash(index * 5 + 1),
                "deck_sha256": _hash(index * 5 + 2),
                "policy_sha256": _hash(index * 5 + 3),
                "runtime_sha256": _hash(index * 5 + 4),
            }
            for index, label in enumerate(CONTROL_LABELS)
        ],
    }


def _registry() -> VerifiedControlRegistry:
    return verify_control_registry(canonical_json_bytes(_registry_object()))


def _raw_statistics() -> dict[str, int]:
    values = {field: 0 for field in RAW_SUFFICIENT_STATISTIC_FIELDS}
    values.update(
        {
            "candidate_recovery_opportunities": 1,
            "control_recovery_opportunities": 1,
            "candidate_resource_checkpoint_count": 1,
            "control_resource_checkpoint_count": 1,
        }
    )
    return values


def _game(
    registry: VerifiedControlRegistry,
    control_label: str,
    seat: str,
    seed_index: int,
    winner: str,
) -> dict[str, object]:
    entry = next(item for item in registry.entries if item["label"] == control_label)
    core: dict[str, object] = {
        "schema": GAME_TRANSCRIPT_SCHEMA,
        **CANDIDATE,
        "control_label": control_label,
        "control_entry_sha256": entry["entry_sha256"],
        "seat": seat,
        "seed_index": seed_index,
        "rng_seed_sha256": derive_rng_seed(
            CANDIDATE["candidate_archive_sha256"],
            entry["archive_sha256"],
            seat,
            seed_index,
            CANDIDATE["runtime_engine_root_sha256"],
        ),
        "status": "COMPLETE",
        "error": None,
        "events": [
            {
                "sequence": 0,
                "event_type": "GAME_END",
                "actor": "system",
                "facts": {"terminal_category": "completed", "winner": winner},
            }
        ],
        "raw_sufficient_statistics": _raw_statistics(),
    }
    return {**core, "trace_root_sha256": derive_game_trace_root(core)}


Winner = Callable[[str, str, int], str]


def _panel_object(
    registry: VerifiedControlRegistry,
    winner: Winner | None = None,
) -> dict[str, object]:
    choose = winner or (lambda _control, _seat, _seed: "candidate")
    return {
        "schema": PANEL_TRANSCRIPT_SCHEMA,
        "games": [
            _game(registry, control, seat, seed_index, choose(control, seat, seed_index))
            for control in CONTROL_LABELS
            for seat in SEATS
            for seed_index in SEED_INDEXES
        ],
    }


def _verify(
    panel: dict[str, object] | None = None,
    registry: VerifiedControlRegistry | None = None,
) -> OfflineLocalPanelCandidate:
    checked_registry = registry or _registry()
    raw_panel = panel or _panel_object(checked_registry)
    return verify_local_panel(
        canonical_json_bytes(raw_panel),
        checked_registry,
        **CANDIDATE,
    )


def _assert_zero_authority(value: object) -> None:
    assert value.authority is False
    assert value.calibration_upload_authorized is False
    assert value.production_upload_authorized is False
    assert value.sealed_holdout_access_authorized is False
    assert value.agent_modification_authorized is False
    assert value.permits == ()


def _recompute_panel_content(
    candidate: OfflineLocalPanelCandidate,
) -> OfflineLocalPanelCandidate:
    return replace(
        candidate,
        content_sha256=local_panel._domain_hash(
            local_panel._DOMAIN_PANEL_CANDIDATE,
            local_panel._panel_core(candidate),
        ),
    )


def test_exact_panel_derives_points_seed_trace_merkle_and_one_archive_r() -> None:
    registry = _registry()
    candidate = _verify(registry=registry)
    assert isinstance(candidate, OfflineLocalPanelCandidate)
    assert candidate.game_count == EXPECTED_GAME_COUNT == 4 * 2 * 300
    assert candidate.archive_point_rate == "1"
    assert candidate.archive_r == "1"
    assert candidate.control_registry_root_sha256 == registry.content_sha256
    assert candidate.control_registry is registry
    assert candidate.canonical_transcript_bytes
    trace_roots = tuple(game["trace_root_sha256"] for game in candidate.games)
    assert candidate.panel_merkle_root_sha256 == canonical_panel_merkle_root(trace_roots)
    assert not hasattr(candidate, "control_diagnostics")
    assert not hasattr(candidate, "select_control")
    assert "archive_game_points" not in candidate.games[0]
    assert "feature_values" not in candidate.games[0]
    assert candidate.games[0]["derived_game_points"] == "1"
    _assert_zero_authority(candidate)
    assert revalidate_offline_local_panel_candidate(candidate) is candidate


def test_feature_stage_emits_spec_incomplete_and_no_feature_candidate() -> None:
    candidate = _verify()
    result = derive_local_feature_candidate(candidate)
    assert result.state == FEATURE_SPEC_STATE == "LEGACY_SUMMARY_PANEL_RETIRED"
    assert result.feature_candidate is None
    assert result.report["incomplete_features"] == tuple(FEATURE_NAMES[:5])
    assert result.report["selectable_stratum_diagnostics"] is False
    assert all(FEATURE_SPEC[name]["complete"] is False for name in FEATURE_NAMES[:5])
    assert FEATURE_SPEC["seat_robustness"]["complete"] is True
    _assert_zero_authority(result)
    assert revalidate_local_feature_derivation(result) is result
    with pytest.raises(LocalPanelError):
        revalidate_local_feature_derivation(replace(result, content_sha256="f" * 64))


@pytest.mark.parametrize("injected_field", ["archive_game_points", "feature_values"])
def test_caller_injected_outcomes_and_normalized_features_are_rejected(
    injected_field: str,
) -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"][0][injected_field] = "1" if injected_field == "archive_game_points" else {
        name: "1" for name in FEATURE_NAMES
    }
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "CALLER_DERIVED_VALUE_FORBIDDEN"


def test_derived_values_are_rejected_even_when_nested_in_event_facts() -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"][0]["events"].insert(
        0,
        {
            "sequence": 0,
            "event_type": "CHECKPOINT",
            "actor": "system",
            "facts": {"feature_values": {"early_prize_tempo": "1"}},
        },
    )
    panel["games"][0]["events"][1]["sequence"] = 1
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "CALLER_DERIVED_VALUE_FORBIDDEN"


def test_control_registry_is_exact_typed_and_relabeling_fails() -> None:
    registry = _registry()
    assert isinstance(registry, VerifiedControlRegistry)
    assert tuple(entry["label"] for entry in registry.entries) == CONTROL_LABELS
    assert all(
        set(entry)
        == {
            "schema",
            "label",
            "archive_sha256",
            "source_root_sha256",
            "deck_sha256",
            "policy_sha256",
            "runtime_sha256",
            "entry_sha256",
        }
        for entry in registry.entries
    )
    assert revalidate_control_registry(registry) is registry

    raw = _registry_object()
    raw["entries"][0]["label"] = CONTROL_LABELS[1]
    with pytest.raises(LocalPanelError) as caught:
        verify_control_registry(canonical_json_bytes(raw))
    assert caught.value.code == "CONTROL_REGISTRY_INVALID"


def test_game_control_relabeling_cannot_rebind_a_favorable_entry() -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"][0]["control_label"] = CONTROL_LABELS[1]
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "CONTROL_BINDING_INVALID"


def test_rng_seed_substitution_fails_even_when_the_replacement_is_well_formed() -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"][0]["rng_seed_sha256"] = "f" * 64
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "RNG_SEED_INVALID"


def test_favorable_control_selection_and_duplicate_cells_fail_closed() -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"] = [
        game for game in panel["games"] if game["control_label"] == CONTROL_LABELS[0]
    ]
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "PANEL_COVERAGE_INVALID"

    panel = _panel_object(registry)
    panel["games"][1] = copy.deepcopy(panel["games"][0])
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "PANEL_DUPLICATE_GAME"


def test_archive_r_uses_equal_control_seat_and_seed_weights() -> None:
    registry = _registry()
    favorable_control = _panel_object(
        registry,
        lambda control, _seat, _seed: (
            "candidate" if control == CONTROL_LABELS[0] else "control"
        ),
    )
    candidate = _verify(favorable_control, registry)
    assert candidate.archive_point_rate == "1/4"
    assert candidate.archive_r == "-1/2"

    asymmetric_seats = _panel_object(
        registry,
        lambda _control, seat, _seed: (
            "candidate" if seat == SEATS[0] else "control"
        ),
    )
    candidate = _verify(asymmetric_seats, registry)
    assert candidate.archive_point_rate == "1/2"
    assert candidate.archive_r == "0"


def test_seat_robustness_is_post_seat_formula_and_clipped() -> None:
    assert derive_seat_robustness("0.4", "0.4") == "0"
    assert derive_seat_robustness("0.75", "-0.25") == "-0.5"
    assert derive_seat_robustness("1", "-1") == "-1"
    with pytest.raises(LocalPanelError):
        derive_seat_robustness("1.1", "0")


def test_trace_mutation_is_rejected() -> None:
    registry = _registry()
    panel = _panel_object(registry)
    panel["games"][0]["raw_sufficient_statistics"][
        "candidate_prizes_taken_through_turn_2"
    ] = 1
    with pytest.raises(LocalPanelError) as caught:
        _verify(panel, registry)
    assert caught.value.code == "TRACE_ROOT_INVALID"


def test_dataclass_replace_cannot_bypass_panel_or_registry_content_roots() -> None:
    registry = _registry()
    with pytest.raises(LocalPanelError) as caught:
        revalidate_control_registry(replace(registry, content_sha256="f" * 64))
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"

    candidate = _verify(registry=registry)
    for forged in (
        replace(candidate, archive_r="-1"),
        replace(candidate, panel_merkle_root_sha256="f" * 64),
        replace(candidate, content_sha256="f" * 64),
    ):
        with pytest.raises(LocalPanelError) as caught:
            revalidate_offline_local_panel_candidate(forged)
        assert caught.value.code == "VERIFIER_IDENTITY_INVALID"


def test_recomputed_raw_trace_merkle_and_content_roots_do_not_forge_identity() -> None:
    candidate = _verify()
    raw = parse_canonical_transcript(candidate.canonical_transcript_bytes)
    raw_game = raw["games"][0]
    raw_game["raw_sufficient_statistics"][
        "candidate_prizes_taken_through_turn_2"
    ] = 1
    trace_core = {
        key: value for key, value in raw_game.items() if key != "trace_root_sha256"
    }
    raw_game["trace_root_sha256"] = derive_game_trace_root(trace_core)
    forged_bytes = canonical_json_bytes(raw)
    bindings = {
        "candidate_archive_sha256": candidate.candidate_archive_sha256,
        "candidate_source_root_sha256": candidate.candidate_source_root_sha256,
        "candidate_deck_sha256": candidate.candidate_deck_sha256,
        "candidate_policy_sha256": candidate.candidate_policy_sha256,
    }
    games, merkle, point_rate, diagnostics = local_panel._replay_panel_transcript(
        forged_bytes,
        candidate.control_registry,
        bindings,
        candidate.runtime_engine_root_sha256,
    )
    draft = replace(
        candidate,
        canonical_transcript_bytes=forged_bytes,
        transcript_payload_sha256=hashlib.sha256(forged_bytes).hexdigest(),
        games=games,
        panel_merkle_root_sha256=merkle,
        diagnostics_root_sha256=diagnostics,
        archive_point_rate=local_panel._fraction_text(point_rate),
        content_sha256="",
    )
    forged = _recompute_panel_content(draft)
    with pytest.raises(LocalPanelError) as caught:
        derive_local_feature_candidate(forged)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"


def test_recomputed_candidate_and_control_root_swaps_do_not_forge_identity() -> None:
    candidate = _verify()
    changed_candidate = replace(
        candidate,
        candidate_archive_sha256="f" * 64,
        content_sha256="",
    )
    changed_candidate = _recompute_panel_content(changed_candidate)
    with pytest.raises(LocalPanelError) as caught:
        revalidate_offline_local_panel_candidate(changed_candidate)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"

    alternate_raw = _registry_object()
    alternate_raw["entries"][0]["archive_sha256"] = "f" * 64
    alternate_registry = verify_control_registry(canonical_json_bytes(alternate_raw))
    changed_control = replace(
        candidate,
        control_registry=alternate_registry,
        control_registry_root_sha256=alternate_registry.content_sha256,
        content_sha256="",
    )
    changed_control = _recompute_panel_content(changed_control)
    with pytest.raises(LocalPanelError) as caught:
        derive_local_feature_candidate(changed_control)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"


def test_object_setattr_mutations_fail_at_registry_panel_and_derivation_consumers() -> None:
    registry = _registry()
    object.__setattr__(registry, "content_sha256", "f" * 64)
    with pytest.raises(LocalPanelError) as caught:
        revalidate_control_registry(registry)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"

    panel = _verify()
    object.__setattr__(panel, "authority", True)
    with pytest.raises(LocalPanelError) as caught:
        derive_local_feature_candidate(panel)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"

    derivation = derive_local_feature_candidate(_verify())
    object.__setattr__(derivation, "state", "FORGED")
    with pytest.raises(LocalPanelError) as caught:
        revalidate_local_feature_derivation(derivation)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"


def test_copied_sentinel_and_recomputed_derivation_root_are_not_issuance() -> None:
    panel = _verify()
    derivation = derive_local_feature_candidate(panel)
    forged_report = local_panel._thaw(derivation.report)
    forged_report["reason"] = "attacker-selected reason"
    report_bytes = canonical_json_bytes(forged_report)
    draft = replace(
        derivation,
        report=local_panel._freeze(forged_report),
        canonical_report_bytes=report_bytes,
        content_sha256="",
    )
    forged = replace(
        draft,
        content_sha256=local_panel._domain_hash(
            local_panel._DOMAIN_FEATURE_DERIVATION,
            local_panel._derivation_core(draft),
        ),
    )
    with pytest.raises(LocalPanelError) as caught:
        revalidate_local_feature_derivation(forged)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"

    feature_payload = {
        "schema": FEATURE_CANDIDATE_SCHEMA,
        "panel_content_sha256": panel.content_sha256,
        "mechanics_vector": ["0", "0", "0", "0", "0", "0"],
        "mechanics_x": "0",
        "archive_r": panel.archive_r,
    }
    feature_bytes = canonical_json_bytes(feature_payload)
    feature_draft = OfflineLocalFeatureCandidate(
        schema=FEATURE_CANDIDATE_SCHEMA,
        panel_candidate=panel,
        panel_content_sha256=panel.content_sha256,
        mechanics_vector=("0", "0", "0", "0", "0", "0"),
        mechanics_x="0",
        archive_r=panel.archive_r,
        canonical_feature_bytes=feature_bytes,
        authority=False,
        calibration_upload_authorized=False,
        production_upload_authorized=False,
        sealed_holdout_access_authorized=False,
        agent_modification_authorized=False,
        permits=(),
        content_sha256="",
        _construction_token=local_panel._FEATURE_TOKEN,
    )
    forged_feature = replace(
        feature_draft,
        content_sha256=local_panel._domain_hash(
            local_panel._DOMAIN_FEATURE_CANDIDATE,
            local_panel._feature_candidate_core(feature_draft),
        ),
    )
    with pytest.raises(LocalPanelError) as caught:
        revalidate_offline_local_feature_candidate(forged_feature)
    assert caught.value.code == "VERIFIER_IDENTITY_INVALID"


def test_plain_maps_cannot_be_typed_feature_or_panel_candidates() -> None:
    with pytest.raises(LocalPanelError):
        revalidate_offline_local_panel_candidate({})
    with pytest.raises(LocalPanelError):
        revalidate_offline_local_feature_candidate({})
    panel = _verify()
    with pytest.raises(ValueError, match="construction token"):
        OfflineLocalFeatureCandidate(
            "x",
            panel,
            "a" * 64,
            ("0", "0", "0", "0", "0", "0"),
            "0",
            "0",
            canonical_json_bytes({}),
            False,
            False,
            False,
            False,
            False,
            (),
            "b" * 64,
            object(),
        )


def test_canonical_byte_parser_rejects_maps_duplicate_keys_floats_and_whitespace() -> None:
    with pytest.raises(LocalPanelError, match="bytes"):
        parse_canonical_transcript({})  # type: ignore[arg-type]
    with pytest.raises(LocalPanelError, match="duplicate"):
        parse_canonical_transcript(b'{"a":1,"a":2}')
    with pytest.raises(LocalPanelError, match="floating"):
        parse_canonical_transcript(b'{"a":1.0}')
    with pytest.raises(LocalPanelError, match="canonical"):
        parse_canonical_transcript(b"{}\n")
    assert parse_canonical_transcript(canonical_json_bytes({})) == {}


def test_zero_authority_surface_is_explicit() -> None:
    assert zero_authority_report() == {
        "schema": "eval.v6.3.1.local-panel-zero-authority",
        "state": "LEGACY_SUMMARY_PANEL_RETIRED",
        "authority": False,
        "local_panel_execution_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }
