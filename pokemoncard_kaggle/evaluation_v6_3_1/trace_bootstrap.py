"""TEST_ONLY/OFFLINE exact bootstrap recomputation for v6.3.1 trace features.

This module consumes only the integer sufficient statistics retained by
``OfflineTraceFeatureResult`` and the already-generated index matrix.  It does
not read display strings, run a game engine, access hosted data, or create any
kind of campaign authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import math
from types import MappingProxyType
from typing import Any

from .assignment import (
    BOOTSTRAP_REPLICATES,
    CONTROL_COUNT,
    SEEDS_PER_CONTROL,
    BootstrapIndexMatrix,
    ExactRational,
    FeaturePoint,
)
from .trace_features import (
    FEATURE_KEYS,
    FEATURE_RESULT_SCHEMA,
    GameSufficientStatistics,
    OfflineTraceFeatureResult,
    SeedPairSufficientStatistics,
    TraceFeatureError,
)


OFFLINE_BOOTSTRAP_SCHEMA = "eval.v6.3.1.test-only-offline.trace-bootstrap.v1"
OFFLINE_BOOTSTRAP_MODE = "TEST_ONLY/OFFLINE"
_SHA = frozenset("0123456789abcdef")
_EXPECTED_MATRIX_BYTES = BOOTSTRAP_REPLICATES * CONTROL_COUNT * SEEDS_PER_CONTROL * 2


def _fail(message: str) -> TraceFeatureError:
    return TraceFeatureError("LOCAL_FEATURE_BOOTSTRAP_INVALID", message)


def _is_sha256(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA


def _int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        raise _fail(f"{label} must be an integer >= {minimum}")
    return value


def _pair(value: Any, label: str) -> tuple[int, int]:
    if type(value) is not tuple or len(value) != 2:
        raise _fail(f"{label} must be a two-element integer tuple")
    return (_int(value[0], f"{label}[0]"), _int(value[1], f"{label}[1]"))


def _validate_game(value: Any, *, expected_orientation: int, label: str) -> None:
    if type(value) is not GameSufficientStatistics:
        raise _fail(f"{label} must be GameSufficientStatistics")
    if value.orientation != expected_orientation:
        raise _fail(f"{label} has the wrong orientation")
    initial = _int(value.initial_prize_count, f"{label}.initial_prize_count", minimum=1)
    prizes = _pair((value.candidate_prizes_taken, value.control_prizes_taken), f"{label}.prizes_taken")
    if any(item > initial for item in prizes):
        raise _fail(f"{label}.prizes_taken exceeds initial prizes")
    f2_success, f2_count = _pair(value.f2_success, f"{label}.f2_success"), _pair(value.f2_count, f"{label}.f2_count")
    f3_damage, f3_energy = _pair(value.f3_damage, f"{label}.f3_damage"), _pair(value.f3_energy, f"{label}.f3_energy")
    f4_success, f4_opportunity = _pair(value.f4_success, f"{label}.f4_success"), _pair(value.f4_opportunity, f"{label}.f4_opportunity")
    f5_success, f5_count = _pair(value.f5_success, f"{label}.f5_success"), _pair(value.f5_count, f"{label}.f5_count")
    for success, count, name in (
        (f2_success, f2_count, "f2"),
        (f4_success, f4_opportunity, "f4"),
        (f5_success, f5_count, "f5"),
    ):
        if any(left > right for left, right in zip(success, count, strict=True)):
            raise _fail(f"{label}.{name} success exceeds opportunity count")
    if any(count > 2 for count in f2_count):
        raise _fail(f"{label}.f2_count exceeds turns 2 and 4")
    if any(count > 4 for count in (*f4_opportunity, *f5_count)):
        raise _fail(f"{label} recovery/resource count exceeds the first four turns")
    _int(value.game_point_numerator, f"{label}.game_point_numerator")
    if value.game_point_numerator > 2:
        raise _fail(f"{label}.game_point_numerator must be at most 2")


def _validate_result(result: Any) -> tuple[tuple[SeedPairSufficientStatistics, ...], tuple[str, ...]]:
    if type(result) is not OfflineTraceFeatureResult:
        raise _fail("result must be OfflineTraceFeatureResult")
    if result.schema_id != FEATURE_RESULT_SCHEMA:
        raise _fail("result schema is not v6.3.1")
    if result.control_count != CONTROL_COUNT or result.seeds_per_control != SEEDS_PER_CONTROL:
        raise _fail("result must contain four controls and 300 seeds per control")
    if result.offline_conformance_only is not True or any(
        flag is not False
        for flag in (
            result.trace_authenticity_verified,
            result.official_wrapper_parity_verified,
            result.authority,
            result.calibration_upload_authorized,
            result.production_upload_authorized,
            result.sealed_holdout_access_authorized,
            result.agent_modification_authorized,
        )
    ):
        raise _fail("result is not explicitly TEST_ONLY/OFFLINE and zero-authority")
    if type(result.permits) is not tuple or result.permits:
        raise _fail("offline bootstrap result must contain no permits")
    if type(result.seed_pair_sufficient_statistics) is not tuple or len(result.seed_pair_sufficient_statistics) != CONTROL_COUNT * SEEDS_PER_CONTROL:
        raise _fail("result must contain exactly 1,200 seed-pair rows")

    expected_exact_keys = frozenset((*FEATURE_KEYS, "x", "R"))
    if not isinstance(result.exact_rationals, Mapping) or set(result.exact_rationals) != expected_exact_keys:
        raise _fail("result exact rational map is malformed")
    if type(result.feature_point) is not FeaturePoint:
        raise _fail("result feature point is malformed")
    for name in expected_exact_keys:
        if type(result.exact_rationals[name]) is not ExactRational:
            raise _fail(f"result exact rational {name} is malformed")
    for field, expected_keys in (
        (result.features, frozenset(FEATURE_KEYS)),
        (result.pre_serialization_mpfr256, expected_exact_keys),
    ):
        if not isinstance(field, Mapping) or set(field) != expected_keys or any(type(item) is not str for item in field.values()):
            raise _fail("result display/conformance map is malformed")
    if type(result.x) is not str or type(result.r) is not str or not _is_sha256(result.mpfr256_projection_sha256):
        raise _fail("result display or projection digest is malformed")
    if not isinstance(result.report, Mapping):
        raise _fail("result authority report is malformed")
    for name in (
        "calibration_upload_authorized",
        "production_upload_authorized",
        "sealed_holdout_access_authorized",
        "agent_modification_authorized",
    ):
        if result.report.get(name) is not False:
            raise _fail("result authority report is not zero-authority")
    if result.report.get("authority", False) is not False or result.report.get("sealed_holdout_accessed", False) is not False:
        raise _fail("result authority report contains a positive authority claim")
    if "permits" in result.report and result.report["permits"] not in ((), []):
        raise _fail("result authority report contains permits")

    rows = result.seed_pair_sufficient_statistics
    previous: tuple[str, str] | None = None
    controls: list[str] = []
    seeds_by_control: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    initial_prize_counts: set[int] = set()
    for index, row in enumerate(rows):
        if type(row) is not SeedPairSufficientStatistics or not _is_sha256(row.control_archive_sha256) or type(row.common_seed_id) is not str or not row.common_seed_id:
            raise _fail(f"seed-pair row {index} is malformed")
        key = (row.control_archive_sha256, row.common_seed_id)
        if previous is not None and key <= previous:
            raise _fail("seed-pair rows must be frozen in sorted control/seed order")
        previous = key
        if key in seen:
            raise _fail("seed-pair rows contain a duplicate")
        seen.add(key)
        if row.control_archive_sha256 not in seeds_by_control:
            controls.append(row.control_archive_sha256)
            seeds_by_control[row.control_archive_sha256] = []
        seeds_by_control[row.control_archive_sha256].append(row.common_seed_id)
        _validate_game(row.orientation_zero, expected_orientation=0, label=f"row {index}.orientation_zero")
        _validate_game(row.orientation_one, expected_orientation=1, label=f"row {index}.orientation_one")
        if row.orientation_zero.initial_prize_count != row.orientation_one.initial_prize_count:
            raise _fail(f"row {index} has inconsistent initial prizes")
        initial_prize_counts.add(row.orientation_zero.initial_prize_count)
    if len(controls) != CONTROL_COUNT or controls != sorted(controls):
        raise _fail("result controls are not exactly four sorted controls")
    seed_sets = [tuple(values) for values in seeds_by_control.values()]
    if any(len(values) != SEEDS_PER_CONTROL for values in seed_sets) or len(set(seed_sets)) != 1:
        raise _fail("controls do not each contain the same 300 sorted seed rows")
    if len(initial_prize_counts) != 1:
        raise _fail("seed-pair rows do not share one frozen initial-prize count")
    return rows, tuple(controls)


def validate_bootstrap_index_matrix(matrix: Any) -> BootstrapIndexMatrix:
    """Validate matrix shape, key encoding, rejection receipt, and indices."""
    if type(matrix) is not BootstrapIndexMatrix:
        raise _fail("matrix must be BootstrapIndexMatrix")
    if type(matrix.packed) is not bytes or len(matrix.packed) != _EXPECTED_MATRIX_BYTES:
        raise _fail("matrix packed dimensions are invalid")
    if not _is_sha256(matrix.key_sha256) or matrix.key_sha256 == "0" * 64:
        raise _fail("matrix key must be lowercase SHA-256 hex")
    if type(matrix.rejection_counts) is not tuple or len(matrix.rejection_counts) != BOOTSTRAP_REPLICATES:
        raise _fail("matrix rejection receipt dimensions are invalid")
    for replicate, counts in enumerate(matrix.rejection_counts):
        if type(counts) is not tuple or len(counts) != CONTROL_COUNT:
            raise _fail(f"matrix rejection receipt {replicate} is malformed")
        for count in counts:
            _int(count, "matrix rejection count")
    for offset in range(0, len(matrix.packed), 2):
        index = int.from_bytes(matrix.packed[offset : offset + 2], "big")
        if index >= SEEDS_PER_CONTROL:
            raise _fail("matrix contains a seed index outside 0..299")
    return matrix


def _rate(success: int, count: int) -> Fraction:
    return Fraction(success, count) if count else Fraction(1, 2)


def _efficiency(damage: int, energy: int) -> Fraction:
    return Fraction(0) if damage == energy == 0 else Fraction(damage, damage + energy)


@lru_cache(maxsize=None)
def _single_feature_sum(game: GameSufficientStatistics) -> Fraction:
    """Sum one orientation's F1-F5 values for the independent F6 aggregate."""
    initial = game.initial_prize_count
    f1 = Fraction(game.candidate_prizes_taken - game.control_prizes_taken, initial)
    f2 = _rate(game.f2_success[0], game.f2_count[0]) - _rate(game.f2_success[1], game.f2_count[1])
    f3 = _efficiency(game.f3_damage[0], game.f3_energy[0]) - _efficiency(game.f3_damage[1], game.f3_energy[1])
    f4 = _rate(game.f4_success[0], game.f4_opportunity[0]) - _rate(game.f4_success[1], game.f4_opportunity[1])
    f5 = _rate(game.f5_success[0], game.f5_count[0]) - _rate(game.f5_success[1], game.f5_count[1])
    return (f1 + f2 + f3 + f4 + f5) / 5


@dataclass(frozen=True, slots=True)
class _RawSeedPair:
    features: tuple[Fraction, Fraction, Fraction, Fraction, Fraction]
    seat_sums: tuple[Fraction, Fraction]
    game_points: int


def _prepare_row(row: SeedPairSufficientStatistics) -> _RawSeedPair:
    left, right = row.orientation_zero, row.orientation_one
    f1 = Fraction(
        (left.candidate_prizes_taken - left.control_prizes_taken)
        + (right.candidate_prizes_taken - right.control_prizes_taken),
        left.initial_prize_count * 2,
    )
    features = [f1]
    for success_name, count_name, efficiency in (
        ("f2_success", "f2_count", False),
        ("f3_damage", "f3_energy", True),
        ("f4_success", "f4_opportunity", False),
        ("f5_success", "f5_count", False),
    ):
        successes = tuple(
            getattr(left, success_name)[seat] + getattr(right, success_name)[seat]
            for seat in (0, 1)
        )
        counts = tuple(
            getattr(left, count_name)[seat] + getattr(right, count_name)[seat]
            for seat in (0, 1)
        )
        if efficiency:
            candidate, control = _efficiency(successes[0], counts[0]), _efficiency(successes[1], counts[1])
        else:
            candidate, control = _rate(successes[0], counts[0]), _rate(successes[1], counts[1])
        features.append(candidate - control)
    return _RawSeedPair(
        tuple(features),  # type: ignore[arg-type]
        (_single_feature_sum(left), _single_feature_sum(right)),
        left.game_point_numerator + right.game_point_numerator,
    )


@dataclass(frozen=True, slots=True)
class _PreparedSeedPair:
    feature_numerators: tuple[int, int, int, int, int]
    seat_numerators: tuple[int, int]
    game_points: int


@dataclass(frozen=True, slots=True)
class _PreparedControls:
    rows: Mapping[str, tuple[_PreparedSeedPair, ...]]
    feature_denominators: tuple[int, int, int, int, int]
    seat_denominator: int


def _prepare_controls(by_control: Mapping[str, tuple[SeedPairSufficientStatistics, ...]]) -> _PreparedControls:
    raw = {control: tuple(_prepare_row(row) for row in rows) for control, rows in by_control.items()}
    feature_denominators = tuple(
        math.lcm(*(row.features[index].denominator for rows in raw.values() for row in rows))
        for index in range(5)
    )
    seat_denominator = math.lcm(*(seat.denominator for rows in raw.values() for row in rows for seat in row.seat_sums))
    prepared = {
        control: tuple(
            _PreparedSeedPair(
                tuple(
                    value.numerator * (feature_denominators[index] // value.denominator)
                    for index, value in enumerate(row.features)
                ),  # type: ignore[arg-type]
                tuple(seat.numerator * (seat_denominator // seat.denominator) for seat in row.seat_sums),
                row.game_points,
            )
            for row in rows
        )
        for control, rows in raw.items()
    }
    return _PreparedControls(prepared, feature_denominators, seat_denominator)


def _aggregate_control(prepared: _PreparedControls, rows: Sequence[_PreparedSeedPair], indices: Sequence[int]) -> tuple[tuple[Fraction, Fraction, Fraction, Fraction, Fraction], int, int, int]:
    if len(rows) != SEEDS_PER_CONTROL:
        raise _fail("each bootstrap control must use exactly 300 rows")
    if len(indices) != SEEDS_PER_CONTROL:
        raise _fail("each bootstrap control selection must contain exactly 300 indices")
    feature_totals = [0] * 5
    seat_zero, seat_one, game_points = 0, 0, 0
    for index in indices:
        if type(index) is not int or not 0 <= index < SEEDS_PER_CONTROL:
            raise _fail("bootstrap selection contains an invalid seed index")
        row = rows[index]
        for feature_index, numerator in enumerate(row.feature_numerators):
            feature_totals[feature_index] += numerator
        seat_zero += row.seat_numerators[0]
        seat_one += row.seat_numerators[1]
        game_points += row.game_points
    values = [
        Fraction(total, prepared.feature_denominators[index] * SEEDS_PER_CONTROL)
        for index, total in enumerate(feature_totals)
    ]
    return tuple(values), seat_zero, seat_one, game_points  # type: ignore[return-value]


def _endpoint_for_selection(prepared: _PreparedControls, selections: Mapping[str, tuple[int, ...]]) -> FeaturePoint:
    aggregates = [_aggregate_control(prepared, prepared.rows[control], selections[control]) for control in prepared.rows]
    control_values = [aggregate[0] for aggregate in aggregates]
    f1_to_f5 = tuple(sum((values[index] for values in control_values), Fraction(0)) / CONTROL_COUNT for index in range(5))
    seat_sums = [sum(aggregate[1] for aggregate in aggregates), sum(aggregate[2] for aggregate in aggregates)]
    game_points = sum(aggregate[3] for aggregate in aggregates)
    f6 = -Fraction(abs(seat_sums[0] - seat_sums[1]), prepared.seat_denominator * 2 * CONTROL_COUNT * SEEDS_PER_CONTROL)
    values = (*f1_to_f5, f6)
    r = Fraction(game_points, 2 * CONTROL_COUNT * SEEDS_PER_CONTROL) - 1
    if any(value < -1 or value > 1 for value in (*values, r)):
        raise _fail("bootstrap endpoint is outside [-1, 1]")
    return FeaturePoint.make(tuple(ExactRational.from_fraction(value, label=name) for name, value in zip(FEATURE_KEYS, values, strict=True)), ExactRational.from_fraction(r, label="R"))


def _validate_point_estimate(result: OfflineTraceFeatureResult, prepared: _PreparedControls) -> None:
    selections = {control: tuple(range(SEEDS_PER_CONTROL)) for control in prepared.rows}
    point = _endpoint_for_selection(prepared, selections)
    expected = tuple(result.exact_rationals[name] for name in FEATURE_KEYS)
    if point.features != expected or point.x != result.exact_rationals["x"] or point.r != result.exact_rationals["R"] or point != result.feature_point:
        raise _fail("result exact point estimate does not match sufficient statistics")


@dataclass(frozen=True, slots=True)
class OfflineBootstrapResult(Sequence[FeaturePoint]):
    """Exactly 10,000 endpoints with explicit TEST_ONLY/OFFLINE zero authority."""

    endpoints: tuple[FeaturePoint, ...]
    schema_id: str = OFFLINE_BOOTSTRAP_SCHEMA
    mode: str = OFFLINE_BOOTSTRAP_MODE
    offline_conformance_only: bool = True
    authority: bool = False
    calibration_upload_authorized: bool = False
    production_upload_authorized: bool = False
    sealed_holdout_access_authorized: bool = False
    agent_modification_authorized: bool = False
    permits: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if type(self.endpoints) is not tuple or len(self.endpoints) != BOOTSTRAP_REPLICATES or any(type(item) is not FeaturePoint for item in self.endpoints):
            raise _fail("offline bootstrap output must contain exactly 10,000 FeaturePoints")
        if (
            self.schema_id != OFFLINE_BOOTSTRAP_SCHEMA
            or self.mode != OFFLINE_BOOTSTRAP_MODE
            or self.offline_conformance_only is not True
            or any(
                flag is not False
                for flag in (
                    self.authority,
                    self.calibration_upload_authorized,
                    self.production_upload_authorized,
                    self.sealed_holdout_access_authorized,
                    self.agent_modification_authorized,
                )
            )
            or self.permits
        ):
            raise _fail("offline bootstrap output authority metadata is invalid")

    @property
    def report(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "schema": OFFLINE_BOOTSTRAP_SCHEMA,
                "mode": OFFLINE_BOOTSTRAP_MODE,
                "offline_conformance_only": True,
                "authority": False,
                "calibration_upload_authorized": False,
                "production_upload_authorized": False,
                "sealed_holdout_access_authorized": False,
                "agent_modification_authorized": False,
                "permits": (),
            }
        )

    def __len__(self) -> int:
        return len(self.endpoints)

    def __getitem__(self, index: int | slice) -> FeaturePoint | tuple[FeaturePoint, ...]:
        return self.endpoints[index]


def recompute_offline_bootstrap(result: OfflineTraceFeatureResult, matrix: BootstrapIndexMatrix) -> OfflineBootstrapResult:
    """Recompute 10,000 exact endpoints from paired seed-block resamples."""
    rows, controls = _validate_result(result)
    matrix = validate_bootstrap_index_matrix(matrix)
    raw_by_control: dict[str, tuple[SeedPairSufficientStatistics, ...]] = {
        control: tuple(row for row in rows if row.control_archive_sha256 == control) for control in controls
    }
    prepared = _prepare_controls(raw_by_control)
    _validate_point_estimate(result, prepared)
    endpoints: list[FeaturePoint] = []
    for replicate in range(BOOTSTRAP_REPLICATES):
        selections = {control: matrix.indices(replicate, control_index) for control_index, control in enumerate(controls)}
        endpoints.append(_endpoint_for_selection(prepared, selections))
    return OfflineBootstrapResult(tuple(endpoints))


def recompute_bootstrap_endpoints(result: OfflineTraceFeatureResult, matrix: BootstrapIndexMatrix) -> tuple[FeaturePoint, ...]:
    """Convenience API returning the endpoint tuple and no authority metadata."""
    return recompute_offline_bootstrap(result, matrix).endpoints


__all__ = [
    "OFFLINE_BOOTSTRAP_MODE",
    "OFFLINE_BOOTSTRAP_SCHEMA",
    "OfflineBootstrapResult",
    "recompute_bootstrap_endpoints",
    "recompute_offline_bootstrap",
    "validate_bootstrap_index_matrix",
]
