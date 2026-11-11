from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType

import pytest

import evaluation_v6_3_1.trace_bootstrap as bootstrap
from evaluation_v6_3_1.assignment import BootstrapIndexMatrix, ExactRational, FeaturePoint
from evaluation_v6_3_1.trace_features import (
    FEATURE_KEYS,
    FEATURE_RESULT_SCHEMA,
    GameSufficientStatistics,
    OfflineTraceFeatureResult,
    SeedPairSufficientStatistics,
    TraceFeatureError,
)


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
            f"{control + 1:064x}",
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
    point = bootstrap._endpoint_for_selection(bootstrap._prepare_controls(by_control), {control: tuple(range(300)) for control in controls})
    exact = {name: value for name, value in zip(FEATURE_KEYS, point.features, strict=True)}
    exact.update({"x": point.x, "R": point.r})
    return OfflineTraceFeatureResult(
        FEATURE_RESULT_SCHEMA,
        MappingProxyType(exact),
        point,
        MappingProxyType({name: "display-only" for name in FEATURE_KEYS}),
        "display-only",
        "display-only",
        MappingProxyType({name: "mpfr-display-only" for name in (*FEATURE_KEYS, "x", "R")}),
        "a" * 64,
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
            }
        ),
    )


def _matrix(*, first_control_indices: tuple[int, ...] | None = None) -> BootstrapIndexMatrix:
    packed = bytearray(10_000 * 4 * 300 * 2)
    if first_control_indices is not None:
        if len(first_control_indices) != 300:
            raise AssertionError("fixture needs 300 indices")
        base = 300 * 2
        for position, index in enumerate(first_control_indices):
            packed[base + 2 * position : base + 2 * position + 2] = index.to_bytes(2, "big")
    return BootstrapIndexMatrix(bytes(packed), ((0, 0, 0, 0),) * 10_000, "b" * 64)


@pytest.fixture(scope="module")
def result() -> OfflineTraceFeatureResult:
    return _result()


@pytest.fixture(scope="module")
def baseline(result: OfflineTraceFeatureResult) -> bootstrap.OfflineBootstrapResult:
    return bootstrap.recompute_offline_bootstrap(result, _matrix())


def test_endpoints_are_deterministic_exact_and_zero_authority(
    result: OfflineTraceFeatureResult,
    baseline: bootstrap.OfflineBootstrapResult,
) -> None:
    repeated = bootstrap.recompute_offline_bootstrap(result, _matrix())
    assert baseline.endpoints == repeated.endpoints
    assert len(baseline) == 10_000
    assert all(isinstance(endpoint, FeaturePoint) for endpoint in baseline)
    assert baseline.endpoints[0].features[:5] == (ExactRational("0", "1"),) * 5
    assert baseline.endpoints[0].features[5] == ExactRational("-23", "30")
    assert baseline.endpoints[0].x == ExactRational("-23", "180")
    assert baseline.endpoints[0].r == ExactRational("0", "1")
    assert baseline.mode == "TEST_ONLY/OFFLINE"
    assert baseline.authority is False
    assert baseline.calibration_upload_authorized is False
    assert baseline.production_upload_authorized is False
    assert baseline.sealed_holdout_access_authorized is False
    assert baseline.agent_modification_authorized is False
    assert baseline.permits == ()


def test_sampling_rows_changes_only_the_recomputed_endpoint(result: OfflineTraceFeatureResult, baseline: bootstrap.OfflineBootstrapResult) -> None:
    sampled = bootstrap.recompute_bootstrap_endpoints(result, _matrix(first_control_indices=(1,) * 300))
    assert sampled[0] != baseline.endpoints[0]
    assert sampled[1:] == baseline.endpoints[1:]
    assert sampled[0].features[0] == ExactRational("0", "1")


def test_seed_pair_rates_are_averaged_instead_of_pooled() -> None:
    high = SeedPairSufficientStatistics(
        "1" * 64,
        "high",
        replace(_game(0, 0), f2_success=(1, 0), f2_count=(1, 1)),
        replace(_game(1, 0), f2_success=(0, 0), f2_count=(0, 0)),
    )
    low = SeedPairSufficientStatistics(
        "1" * 64,
        "low",
        replace(_game(0, 0), f2_success=(0, 0), f2_count=(2, 2)),
        replace(_game(1, 0), f2_success=(0, 0), f2_count=(2, 2)),
    )
    rows = (high,) * 150 + (low,) * 150
    prepared = bootstrap._prepare_controls({"1" * 64: rows})
    values, *_ = bootstrap._aggregate_control(
        prepared,
        prepared.rows["1" * 64],
        tuple(range(300)),
    )
    assert values[1] == __import__("fractions").Fraction(1, 2)
    assert values[1] != __import__("fractions").Fraction(1, 5)


@pytest.mark.parametrize(
    "mutator",
    (
        lambda matrix: replace(matrix, packed=b""),
        lambda matrix: replace(matrix, key_sha256="0" * 64),
        lambda matrix: replace(matrix, rejection_counts=((0, 0, 0),) * 10_000),
    ),
)
def test_malformed_matrix_rejected(result: OfflineTraceFeatureResult, mutator) -> None:
    with pytest.raises(TraceFeatureError):
        bootstrap.recompute_bootstrap_endpoints(result, mutator(_matrix()))


def test_malformed_result_and_mutated_exact_rows_rejected(result: OfflineTraceFeatureResult) -> None:
    with pytest.raises(TraceFeatureError):
        bootstrap.recompute_bootstrap_endpoints(replace(result, control_count=3), _matrix())
    rows = list(result.seed_pair_sufficient_statistics)
    rows[0] = replace(rows[0], common_seed_id="seed-999")
    with pytest.raises(TraceFeatureError):
        bootstrap.recompute_bootstrap_endpoints(replace(result, seed_pair_sufficient_statistics=tuple(rows)), _matrix())
    with pytest.raises(TraceFeatureError):
        bootstrap.recompute_bootstrap_endpoints(replace(result, production_upload_authorized=True), _matrix())
