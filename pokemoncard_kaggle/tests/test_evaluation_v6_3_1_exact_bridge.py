from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType

import pytest

import evaluation_v6_3_1.trace_bootstrap as bootstrap
import evaluation_v6_3_1.trace_features as trace_features
from evaluation_v6_3_1.assignment import ExactRational as AssignmentExactRational
from evaluation_v6_3_1.exact_bridge import (
    ExactBridgeError,
    OfflineExactLocalMetadata,
    bridge_offline_trace_to_exact_local_unit,
)
from evaluation_v6_3_1.exact_statistics import (
    CANDIDATE_EXACT_MODEL_ROOT_SHA256,
    ExactHostedEndpoint,
    ExactLocalUnit,
    ExactRational,
    HostedPollReceipt,
    RETIRED_LEGACY_MODEL_ROOT_SHA256,
)
from evaluation_v6_3_1.trace_features import (
    FEATURE_KEYS,
    FEATURE_RESULT_SCHEMA,
    GameSufficientStatistics,
    OfflineTraceFeatureResult,
    SeedPairSufficientStatistics,
)


def _hash(value: int) -> str:
    return f"{value:064x}"


def _game(orientation: int, seed: int) -> GameSufficientStatistics:
    variant = int(seed == 1)
    if orientation == 0:
        return GameSufficientStatistics(
            0,
            1 + variant,
            0,
            6,
            (1, 0),
            (1, 1),
            (2 + variant, 0),
            (1, 1),
            (1, 0),
            (1, 1),
            (1, 0),
            (1, 1),
            2,
        )
    return GameSufficientStatistics(
        1,
        0,
        1 + variant,
        6,
        (0, 1),
        (1, 1),
        (0, 2 + variant),
        (1, 1),
        (0, 1),
        (1, 1),
        (0, 1),
        (1, 1),
        0,
    )


def _rows() -> tuple[SeedPairSufficientStatistics, ...]:
    return tuple(
        SeedPairSufficientStatistics(
            _hash(control + 1),
            f"seed-{seed:03d}",
            _game(0, seed),
            _game(1, seed),
        )
        for control in range(4)
        for seed in range(300)
    )


def _result() -> OfflineTraceFeatureResult:
    rows = _rows()
    controls = tuple(f"{control + 1:064x}" for control in range(4))
    by_control = {control: tuple(row for row in rows if row.control_archive_sha256 == control) for control in controls}
    point = bootstrap._endpoint_for_selection(  # type: ignore[attr-defined]
        bootstrap._prepare_controls(by_control),  # type: ignore[attr-defined]
        {control: tuple(range(300)) for control in controls},
    )
    exact = {name: value for name, value in zip(FEATURE_KEYS, point.features, strict=True)}
    exact.update({"x": point.x, "R": point.r})
    return OfflineTraceFeatureResult(
        FEATURE_RESULT_SCHEMA,
        MappingProxyType(exact),
        point,
        MappingProxyType(dict(zip(FEATURE_KEYS, point.display_features, strict=True))),
        point.display_x,
        point.display_r,
        MappingProxyType(
            {
                name: trace_features._exact_mpfr_text(exact[name].as_fraction())  # type: ignore[attr-defined]
                for name in (*FEATURE_KEYS, "x", "R")
            }
        ),
        point.mpfr256_projection_sha256,
        rows,
        4,
        300,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        (),
        MappingProxyType(
            {
                "calibration_upload_authorized": False,
                "production_upload_authorized": False,
                "sealed_holdout_access_authorized": False,
                "agent_modification_authorized": False,
                "offline_conformance_only": True,
                "trace_authenticity_verified": False,
                "official_wrapper_parity_verified": False,
            }
        ),
    )


def _metadata(*, phase: str = "CONFIRM", model_root: str = CANDIDATE_EXACT_MODEL_ROOT_SHA256) -> OfflineExactLocalMetadata:
    return OfflineExactLocalMetadata(
        "C01",
        _hash(1),
        "source-claim",
        "lineage-claim",
        "development-control-claim",
        "intervention-claim",
        _hash(2),
        _hash(3),
        _hash(4),
        _hash(5),
        model_root,
        phase,  # type: ignore[arg-type]
    )


def _endpoint() -> ExactHostedEndpoint:
    polls = tuple(
        HostedPollReceipt(f"poll-{index}", ExactRational.from_integers(1000), ExactRational.from_integers(999), _hash(20 + index), _hash(30 + index))
        for index in range(4)
    )
    return ExactHostedEndpoint("C01", polls)  # type: ignore[arg-type]


def test_bridge_returns_only_exact_unit_and_derives_rate_from_R() -> None:
    result = _result()
    unit = bridge_offline_trace_to_exact_local_unit(result, _metadata())
    assert type(unit) is ExactLocalUnit
    assert unit.point.exact_canonical() == result.feature_point.exact_canonical()
    expected = ExactRational.from_fraction((unit.point.r.as_fraction() + 1) / 2)
    assert unit.local_game_point_rate == expected
    assert unit.archive_sha256 == _hash(1)
    assert unit.source_component_id == "source-claim"
    assert not hasattr(unit, "authority")


def test_bridge_rejects_mutated_result_and_rounded_mapping() -> None:
    result = _result()
    mutated_point = replace(result.feature_point, x=AssignmentExactRational("0", "1"))
    with pytest.raises(ExactBridgeError):
        bridge_offline_trace_to_exact_local_unit(replace(result, feature_point=mutated_point), _metadata())

    rounded = dict(result.exact_rationals)
    rounded["F1"] = "0.5"  # type: ignore[assignment]
    with pytest.raises(ExactBridgeError):
        bridge_offline_trace_to_exact_local_unit(replace(result, exact_rationals=MappingProxyType(rounded)), _metadata())

    with pytest.raises(ExactBridgeError):
        bridge_offline_trace_to_exact_local_unit(replace(result, x="mutated-display"), _metadata())


def test_bridge_rejects_root_substitution_and_positive_F6() -> None:
    result = _result()
    with pytest.raises(ExactBridgeError) as root_error:
        bridge_offline_trace_to_exact_local_unit(result, _metadata(model_root=_hash(99)))
    assert root_error.value.code == "BRIDGE_MODEL_ROOT_MISMATCH"
    with pytest.raises(ExactBridgeError) as retired_error:
        bridge_offline_trace_to_exact_local_unit(result, _metadata(model_root=RETIRED_LEGACY_MODEL_ROOT_SHA256))
    assert retired_error.value.code == "BRIDGE_MODEL_ROOT_RETIRED"

    values = list(result.feature_point.features)
    values[5] = AssignmentExactRational("1", "10")
    invalid_point = replace(result.feature_point, features=tuple(values))
    invalid_map = dict(result.exact_rationals)
    invalid_map["F6"] = values[5]
    with pytest.raises(ExactBridgeError):
        bridge_offline_trace_to_exact_local_unit(
            replace(result, feature_point=invalid_point, exact_rationals=MappingProxyType(invalid_map)),
            _metadata(),
        )


def test_endpoint_requires_explicit_DEV_and_is_typed() -> None:
    result = _result()
    with pytest.raises(ExactBridgeError) as phase_error:
        bridge_offline_trace_to_exact_local_unit(result, _metadata(), endpoint=_endpoint())
    assert phase_error.value.code == "BRIDGE_ENDPOINT_PHASE_INVALID"
    unit = bridge_offline_trace_to_exact_local_unit(result, _metadata(phase="DEV"), endpoint=_endpoint())
    assert unit.endpoint is not None


def test_rate_is_not_a_caller_input() -> None:
    with pytest.raises(TypeError):
        bridge_offline_trace_to_exact_local_unit(_result(), _metadata(), local_game_point_rate=0.5)  # type: ignore[call-arg]
