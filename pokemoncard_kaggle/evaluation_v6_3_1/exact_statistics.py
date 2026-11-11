"""Candidate exact-rational Evaluation v6.3.1 statistics core.

This is a zero-authority conformance implementation of the 2026-07-17 exact
statistics migration.  It intentionally does not import ``statistics.py``:
that module's decimal feature boundary and model root are explicitly retired.
Nothing in this module can issue a permit, read a holdout, modify an agent, or
authorize a calibration or production upload.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Literal

import gmpy2

from .common import CALIBRATION_BUDGET, PRODUCTION_BUDGET, canonical_json_bytes, canonical_sha256, freeze, zero_authority


MPFR_PRECISION_BITS = 256
MPFR_ROUNDING = "MPFR_RNDN"
RETIRED_LEGACY_MODEL_ROOT_SHA256 = "8c2ea348904e9914c946eedc263ee68ae5dfacd24d87a36d703d19e72ab22e98"
FEATURE_KEYS = ("F1", "F2", "F3", "F4", "F5", "F6")
DEV_PRIMARY_SLOTS = ("D01", "D02", "D03", "D04", "D05", "D06")
DEV_RESERVE_SLOT = "DR01"
DEV_SLOTS = DEV_PRIMARY_SLOTS + (DEV_RESERVE_SLOT,)
CONFIRM_PRIMARY_SLOTS = ("C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08")
CONFIRM_RESERVE_SLOT = "CR01"
CONFIRM_SLOTS = CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_SIGNED_INTEGER_RE = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")
_CANONICAL_POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
_C99_HEX_RE = re.compile(r"^-?0x[0-9a-f]+\.[0-9a-f]{64}p[+-][0-9]+$")
_MPFR_TYPE = type(gmpy2.mpfr(0))
_ARTIFACT_SNAPSHOTS: dict[int, tuple[str, bytes]] = {}


class ExactStatisticsError(ValueError):
    """A candidate exact-statistics validation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> ExactStatisticsError:
    return ExactStatisticsError(code, message)


def _sha256(value: Any, label: str, *, reject_retired: bool = False) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", f"{label} must be a lowercase SHA-256 digest")
    if reject_retired and value == RETIRED_LEGACY_MODEL_ROOT_SHA256:
        raise _fail("STATISTICS_MODEL_ROOT_RETIRED", f"{label} is the retired legacy statistics model root")
    return value


def _component(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 255:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", f"{label} must be a nonempty bounded string")
    return value


def _ctx() -> Any:
    context = gmpy2.get_context().copy()
    context.precision = MPFR_PRECISION_BITS
    context.round = gmpy2.RoundToNearest
    return context


def _require_runtime() -> None:
    context = _ctx()
    if context.precision != MPFR_PRECISION_BITS or context.round != gmpy2.RoundToNearest:
        raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "MPFR context is not frozen MPFR256 RNDN")
    if gmpy2.version() != "2.3.1":
        raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "gmpy2 runtime must be exactly 2.3.1")


@dataclass(frozen=True, slots=True)
class ExactRational:
    """The only authoritative scalar input representation.

    The strings are intentionally decimal *integers*, never a decimal-valued
    statistic.  All finite values, including hosted score values, use this
    schema before their single MPQ-to-MPFR projection.
    """

    numerator: str
    denominator: str

    def __post_init__(self) -> None:
        if (
            type(self.numerator) is not str
            or type(self.denominator) is not str
            or _CANONICAL_SIGNED_INTEGER_RE.fullmatch(self.numerator) is None
            or _CANONICAL_POSITIVE_INTEGER_RE.fullmatch(self.denominator) is None
        ):
            raise _fail("STATISTICS_RATIONAL_NONCANONICAL", "exact rationals require canonical signed/positive integer strings")
        numerator, denominator = int(self.numerator), int(self.denominator)
        if math.gcd(abs(numerator), denominator) != 1 or numerator == 0 and denominator != 1:
            raise _fail("STATISTICS_RATIONAL_NONCANONICAL", "exact rationals must be reduced and encode zero as 0/1")

    @classmethod
    def make(cls, value: Any, *, label: str = "value") -> "ExactRational":
        if type(value) is cls:
            return value
        if isinstance(value, Mapping):
            keys = set(value)
            if keys == {"numerator", "denominator"}:
                try:
                    return cls(value["numerator"], value["denominator"])
                except ExactStatisticsError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive shape guard
                    raise _fail("STATISTICS_RATIONAL_NONCANONICAL", f"{label} rational object is malformed") from exc
            if any("display" in str(key).lower() or "decimal" in str(key).lower() for key in keys):
                raise _fail("STATISTICS_ROUNDED_INPUT_USED", f"{label} contains a display or decimal sibling")
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"{label} must contain exactly numerator and denominator")
        if type(value) is str or isinstance(value, (float, Decimal, _MPFR_TYPE)):
            raise _fail("STATISTICS_ROUNDED_INPUT_USED", f"{label} cannot be a decimal, float, Decimal, MPFR, or display string")
        raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"{label} must be an ExactRational or canonical numerator/denominator object")

    @classmethod
    def from_fraction(cls, value: Fraction, *, label: str = "value") -> "ExactRational":
        if type(value) is not Fraction:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"{label} must be an exact Fraction")
        return cls(str(value.numerator), str(value.denominator))

    @classmethod
    def from_integers(cls, numerator: int, denominator: int = 1) -> "ExactRational":
        if type(numerator) is not int or isinstance(numerator, bool) or type(denominator) is not int or isinstance(denominator, bool):
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "exact integer construction requires integer operands")
        if denominator <= 0:
            raise _fail("STATISTICS_RATIONAL_NONCANONICAL", "exact rational denominator must be positive")
        fraction = Fraction(numerator, denominator)
        return cls.from_fraction(fraction)

    def as_fraction(self) -> Fraction:
        return Fraction(int(self.numerator), int(self.denominator))

    def canonical(self) -> dict[str, str]:
        return {"numerator": self.numerator, "denominator": self.denominator}


ZERO = ExactRational("0", "1")
ONE = ExactRational("1", "1")
HALF = ExactRational("1", "2")
HUNDRED = ExactRational("100", "1")
NINE = ExactRational("9", "1")
TWO = ExactRational("2", "1")
EIGHT = ExactRational("8", "1")
TENTH = ExactRational("1", "10")

THRESHOLDS = MappingProxyType(
    {
        "unit_win_margin_points": TENTH,
        "family_win_margin_points": TENTH,
        "concordance_margin_points": TENTH,
        "dev_ratio_maximum": ExactRational("9", "10"),
        "dev_beta_positive_probability_minimum": ExactRational("9", "10"),
        "confirm_raw_ratio_maximum": ExactRational("4", "5"),
        "confirm_constant_ratio_maximum": ExactRational("19", "20"),
        "support_epsilon": ExactRational("1", "1000000000000"),
        "sign_test_threshold": ExactRational("9", "256"),
    }
)


def _exact(value: Any, label: str) -> ExactRational:
    if type(value) is not ExactRational:
        raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"{label} must be an ExactRational")
    return value


def _fraction(value: ExactRational) -> Fraction:
    return value.as_fraction()


def _rational_binary(left: ExactRational, right: ExactRational, operation: Literal["add", "subtract", "multiply", "divide"]) -> ExactRational:
    left, right = _exact(left, "left"), _exact(right, "right")
    if operation == "add":
        result = _fraction(left) + _fraction(right)
    elif operation == "subtract":
        result = _fraction(left) - _fraction(right)
    elif operation == "multiply":
        result = _fraction(left) * _fraction(right)
    else:
        if right.numerator == "0":
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "exact division by zero is invalid")
        result = _fraction(left) / _fraction(right)
    return ExactRational.from_fraction(result)


def exact_add(left: ExactRational, right: ExactRational) -> ExactRational:
    return _rational_binary(left, right, "add")


def exact_subtract(left: ExactRational, right: ExactRational) -> ExactRational:
    return _rational_binary(left, right, "subtract")


def exact_multiply(left: ExactRational, right: ExactRational) -> ExactRational:
    return _rational_binary(left, right, "multiply")


def exact_divide(left: ExactRational, right: ExactRational) -> ExactRational:
    return _rational_binary(left, right, "divide")


def exact_mean(values: Sequence[ExactRational], *, label: str = "values") -> ExactRational:
    if not values:
        raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"{label} must not be empty")
    total = Fraction(0, 1)
    for index, value in enumerate(values):
        total += _fraction(_exact(value, f"{label}[{index}]"))
    return ExactRational.from_fraction(total / len(values))


def exact_abs(value: ExactRational) -> ExactRational:
    return ExactRational.from_fraction(abs(_fraction(_exact(value, "value"))))


@lru_cache(maxsize=262_144)
def _project_cached(value: ExactRational) -> Any:
    _require_runtime()
    with gmpy2.context(_ctx()):
        # This direct MPQ-to-MPFR conversion is the binding projection rule.
        return gmpy2.mpfr(gmpy2.mpq(int(value.numerator), int(value.denominator)))


def project_exact(value: ExactRational) -> Any:
    """Project an exact rational once under frozen MPFR256 RNDN."""

    return _project_cached(_exact(value, "value"))


def mpfr_c99_hex(value: Any) -> str:
    """Return the canonical full C99 hexadecimal retention form."""

    if not isinstance(value, _MPFR_TYPE) or not gmpy2.is_finite(value):
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "full precision artifacts require finite MPFR values")
    with gmpy2.context(_ctx()):
        rendered = format(value, ".64a")
    if _C99_HEX_RE.fullmatch(rendered) is None:
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "MPFR C99 encoding is not canonical full hex")
    return rendered


def parse_mpfr_c99_hex(value: Any, *, label: str = "value") -> Any:
    if type(value) is not str or _C99_HEX_RE.fullmatch(value) is None:
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", f"{label} must be canonical full C99 hexadecimal MPFR")
    with gmpy2.context(_ctx()):
        parsed = gmpy2.mpfr(value)
        if not gmpy2.is_finite(parsed) or mpfr_c99_hex(parsed) != value:
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", f"{label} does not round-trip as frozen MPFR256")
        return parsed


def display_mpfr(value: Any, places: int = 12) -> str:
    """Create a write-only display sibling; no parser consumes its output."""

    if type(places) is not int or places < 0:
        raise ValueError("places must be a nonnegative integer")
    if not isinstance(value, _MPFR_TYPE) or not gmpy2.is_finite(value):
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "display requires a finite MPFR value")
    with gmpy2.context(_ctx()):
        return format(value, f".{places}f")


def projection_record(value: ExactRational, *, display_places: int = 12) -> Mapping[str, Any]:
    exact = _exact(value, "value")
    projected = project_exact(exact)
    return freeze(
        {
            "exact": exact.canonical(),
            "mpfr256_c99_hex": mpfr_c99_hex(projected),
            "display": display_mpfr(projected, display_places),
        }
    )


def _bounded(value: ExactRational, minimum: ExactRational, maximum: ExactRational, label: str) -> None:
    if _fraction(value) < _fraction(minimum) or _fraction(value) > _fraction(maximum):
        raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", f"{label} is outside its exact frozen domain")


@dataclass(frozen=True, slots=True)
class FeaturePoint:
    """Exact F1--F6, derived x, and exact comparator R."""

    features: tuple[ExactRational, ExactRational, ExactRational, ExactRational, ExactRational, ExactRational]
    x: ExactRational
    r: ExactRational

    def __post_init__(self) -> None:
        if len(self.features) != 6:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "FeaturePoint requires exactly F1 through F6")
        for index, value in enumerate(self.features, 1):
            _exact(value, f"F{index}")
            _bounded(value, ExactRational("-1", "1"), ONE, f"F{index}")
        _bounded(self.features[5], ExactRational("-1", "1"), ZERO, "F6")
        _exact(self.x, "x")
        _exact(self.r, "R")
        _bounded(self.x, ExactRational("-1", "1"), ONE, "x")
        _bounded(self.r, ExactRational("-1", "1"), ONE, "R")
        expected_x = exact_mean(self.features, label="F1-F6")
        if self.x != expected_x:
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "x must equal the exact equal-weight F1-F6 mean")

    @classmethod
    def make(cls, features: Sequence[Any], r: Any) -> "FeaturePoint":
        if len(features) != 6:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "FeaturePoint requires six exact feature values")
        exact_features = tuple(ExactRational.make(value, label=f"F{index}") for index, value in enumerate(features, 1))
        return cls(exact_features, exact_mean(exact_features, label="F1-F6"), ExactRational.make(r, label="R"))  # type: ignore[arg-type]

    @classmethod
    def from_exact_mapping(cls, value: Any) -> "FeaturePoint":
        if not isinstance(value, Mapping):
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "FeaturePoint must be an exact feature mapping")
        if any("display" in str(key).lower() for key in value):
            raise _fail("STATISTICS_ROUNDED_INPUT_USED", "FeaturePoint mapping contains display siblings")
        expected = set(FEATURE_KEYS) | {"x", "R"}
        if set(value) != expected:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "FeaturePoint mapping has an invalid exact key set")
        return cls(
            tuple(ExactRational.make(value[key], label=key) for key in FEATURE_KEYS),  # type: ignore[arg-type]
            ExactRational.make(value["x"], label="x"),
            ExactRational.make(value["R"], label="R"),
        )

    def exact_canonical(self) -> dict[str, dict[str, str]]:
        return {
            **{key: value.canonical() for key, value in zip(FEATURE_KEYS, self.features, strict=True)},
            "x": self.x.canonical(),
            "R": self.r.canonical(),
        }

    def canonical(self) -> dict[str, Any]:
        return {
            "exact": self.exact_canonical(),
            "display_12": {
                **{key: display_mpfr(project_exact(value)) for key, value in zip(FEATURE_KEYS, self.features, strict=True)},
                "x": display_mpfr(project_exact(self.x)),
                "R": display_mpfr(project_exact(self.r)),
            },
            "mpfr256_projection_sha256": canonical_sha256(
                {
                    "schema": "eval.v6.3.1.exact-statistics.feature-point-projections",
                    "values": [mpfr_c99_hex(project_exact(value)) for value in self.features + (self.x, self.r)],
                }
            ),
        }


@dataclass(frozen=True, slots=True)
class HostedPollReceipt:
    """One dual-collected hosted score/cutoff poll in exact-rational form."""

    poll_id: str
    score: ExactRational
    rank10_cutoff: ExactRational
    collector_a_receipt_root_sha256: str
    collector_b_receipt_root_sha256: str

    def __post_init__(self) -> None:
        _component(self.poll_id, "poll_id")
        _exact(self.score, "score")
        _exact(self.rank10_cutoff, "rank10_cutoff")
        _bounded(self.score, ZERO, ExactRational("10000", "1"), "score")
        _bounded(self.rank10_cutoff, ZERO, ExactRational("10000", "1"), "rank10_cutoff")
        _sha256(self.collector_a_receipt_root_sha256, "collector_a_receipt_root_sha256")
        _sha256(self.collector_b_receipt_root_sha256, "collector_b_receipt_root_sha256")
        if self.collector_a_receipt_root_sha256 == self.collector_b_receipt_root_sha256:
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "dual collectors must retain distinct receipt roots")

    @property
    def gap(self) -> ExactRational:
        return exact_subtract(self.score, self.rank10_cutoff)

    def canonical(self) -> dict[str, Any]:
        return {
            "poll_id": self.poll_id,
            "score": self.score.canonical(),
            "rank10_cutoff": self.rank10_cutoff.canonical(),
            "gap": self.gap.canonical(),
            "collector_a_receipt_root_sha256": self.collector_a_receipt_root_sha256,
            "collector_b_receipt_root_sha256": self.collector_b_receipt_root_sha256,
            "display_12": {
                "score": display_mpfr(project_exact(self.score)),
                "rank10_cutoff": display_mpfr(project_exact(self.rank10_cutoff)),
                "gap": display_mpfr(project_exact(self.gap)),
            },
        }


@dataclass(frozen=True, slots=True)
class ExactHostedEndpoint:
    """The four-poll exact hosted endpoint for a single unit."""

    slot_id: str
    polls: tuple[HostedPollReceipt, HostedPollReceipt, HostedPollReceipt, HostedPollReceipt]

    def __post_init__(self) -> None:
        _component(self.slot_id, "slot_id")
        if len(self.polls) != 4 or any(type(poll) is not HostedPollReceipt for poll in self.polls):
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "hosted endpoints require exactly four HostedPollReceipt values")
        if len({poll.poll_id for poll in self.polls}) != 4:
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "the four hosted poll identifiers must be distinct")

    @property
    def gaps(self) -> tuple[ExactRational, ExactRational, ExactRational, ExactRational]:
        return tuple(poll.gap for poll in self.polls)  # type: ignore[return-value]

    @property
    def sorted_gaps(self) -> tuple[ExactRational, ExactRational, ExactRational, ExactRational]:
        return tuple(sorted(self.gaps, key=lambda item: (_fraction(item), item.numerator, item.denominator)))  # type: ignore[return-value]

    @property
    def middle_gaps(self) -> tuple[ExactRational, ExactRational]:
        gaps = self.sorted_gaps
        return gaps[1], gaps[2]

    @property
    def yobs(self) -> ExactRational:
        return exact_mean(self.middle_gaps, label="sorted middle hosted gaps")

    @property
    def model_y(self) -> ExactRational:
        return exact_divide(self.yobs, HUNDRED)

    @property
    def root_sha256(self) -> str:
        return canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.hosted-endpoint", **self.canonical()})

    def canonical(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "polls": [poll.canonical() for poll in self.polls],
            "gaps": [gap.canonical() for gap in self.gaps],
            "sorted_gaps": [gap.canonical() for gap in self.sorted_gaps],
            "middle_gaps": [gap.canonical() for gap in self.middle_gaps],
            "Yobs": self.yobs.canonical(),
            "model_y": self.model_y.canonical(),
            "display_12": {
                "Yobs": display_mpfr(project_exact(self.yobs)),
                "model_y": display_mpfr(project_exact(self.model_y)),
            },
        }


@dataclass(frozen=True, slots=True)
class ExactLocalUnit:
    """One local F1--F6/x/R unit, optionally joined to an exact endpoint.

    CONFIRM-local units deliberately carry ``endpoint=None`` during
    ``PRE_CONFIRM``.  The separate post-freeze endpoint artifact supplies their
    four-poll observations only after the prediction root is fixed.
    """

    slot_id: str
    archive_sha256: str
    source_component_id: str
    lineage_time_component_id: str
    development_control_component_id: str
    intervention_component_id: str
    point: FeaturePoint
    local_game_point_rate: ExactRational
    transcript_root_sha256: str
    extractor_root_sha256: str
    local_feature_root_sha256: str
    local_panel_root_sha256: str
    model_root_sha256: str
    endpoint: ExactHostedEndpoint | None = None

    def __post_init__(self) -> None:
        _component(self.slot_id, "slot_id")
        _sha256(self.archive_sha256, "archive_sha256")
        for label in (
            "source_component_id",
            "lineage_time_component_id",
            "development_control_component_id",
            "intervention_component_id",
        ):
            _component(getattr(self, label), label)
        if type(self.point) is not FeaturePoint:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", "point must be a FeaturePoint")
        _exact(self.local_game_point_rate, "local_game_point_rate")
        _bounded(self.local_game_point_rate, ZERO, ONE, "local_game_point_rate")
        expected_r = exact_subtract(exact_multiply(TWO, self.local_game_point_rate), ONE)
        if self.point.r != expected_r:
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "R must equal 2*exact_local_game_point_rate-1")
        for label in (
            "transcript_root_sha256",
            "extractor_root_sha256",
            "local_feature_root_sha256",
            "local_panel_root_sha256",
        ):
            _sha256(getattr(self, label), label)
        _sha256(self.model_root_sha256, "model_root_sha256", reject_retired=True)
        if self.endpoint is not None and (type(self.endpoint) is not ExactHostedEndpoint or self.endpoint.slot_id != self.slot_id):
            raise _fail("STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "local-unit endpoint must be exact and bind the same slot")

    def canonical(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "archive_sha256": self.archive_sha256,
            "source_component_id": self.source_component_id,
            "lineage_time_component_id": self.lineage_time_component_id,
            "development_control_component_id": self.development_control_component_id,
            "intervention_component_id": self.intervention_component_id,
            "feature_point": self.point.canonical(),
            "local_game_point_rate": self.local_game_point_rate.canonical(),
            "transcript_root_sha256": self.transcript_root_sha256,
            "extractor_root_sha256": self.extractor_root_sha256,
            "local_feature_root_sha256": self.local_feature_root_sha256,
            "local_panel_root_sha256": self.local_panel_root_sha256,
            "model_root_sha256": self.model_root_sha256,
            "endpoint_root_sha256": None if self.endpoint is None else self.endpoint.root_sha256,
        }

    @property
    def root_sha256(self) -> str:
        return canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.local-unit", **self.canonical()})


CORRECTION_DOCUMENT_SHA256 = MappingProxyType(
    {
        "evaluation_v6_3_1_sol_statistics_correction_20260716.md": "6a79d048cf2675fd1bef957bc5626cc83d8244a0858175afda7d2695da86678b",
        "evaluation_v6_3_1_sol_assignment_support_correction_20260717.md": "be0f6531689b94ef3b45344178da2a12da2272994cc83995cdfb18e3c113a1a8",
        "evaluation_v6_3_1_sol_local_feature_correction_20260717.md": "a5293b8eb26788b1aa8357dad86c2b1e575412b1a2c54236cc8622d64fcd0e8b",
        "evaluation_v6_3_1_sol_local_engine_admissibility_correction_20260717.md": "6eddc8b2a36b8462043aff2e377c60c2db5e701a275f7f95d1857db38ee51d53",
    }
)
FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256 = "cc28c44c5d89193ca0f23ffa633923a13fb6b36a51dea5fcb1e3e9950ab7687f"
LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX = "0x2.0000000000000000000000000000000000000000000000000080000000000000p+0"
GOLDEN_MANIFEST_ROOT_SHA256 = "50a15f07c81cb5f333a35b79356efc151a0675954e1e742e4fd283cfb8c489b3"
LARGE_RATIONAL_GOLDEN_INPUT = MappingProxyType(
    {
        "numerator": "737785679453402454187405477715146249808487369379778146523045645221473910504117165748619553877368131996186176477416091063",
        "denominator": "368892839726701227093702738857573124904243684689889073261522765220092517430977313542826648105801009023941496526947371301",
    }
)


def _manifest_payload() -> dict[str, Any]:
    return {
        "schema": "eval.v6.3.1.candidate-exact-statistics-model",
        "status": "CANDIDATE_EXACT_MODEL_UNPINNED",
        "retired_legacy_model_root_sha256": RETIRED_LEGACY_MODEL_ROOT_SHA256,
        "correction_document_sha256": dict(CORRECTION_DOCUMENT_SHA256),
        "scalar_schema": {"required_fields": ["numerator", "denominator"], "canonical_reduced": True, "decimal_float_decimal_mpfr_and_display_inputs_forbidden": True},
        "hosted_endpoint_schema": {"poll_count": 4, "dual_collector_receipt_roots": True, "gap": "score-rank10_cutoff", "endpoint": "mean(sorted_gaps[1],sorted_gaps[2])", "model_y": "Yobs/100"},
        "local_unit_schema": {"features": list(FEATURE_KEYS), "x": "exact_mean(F1..F6)", "R": "2*exact_local_game_point_rate-1", "full_roots_required": ["transcript", "extractor", "local_feature", "local_panel", "model"]},
        "numeric": {"library": "gmpy2", "required_version": "2.3.1", "precision_bits": MPFR_PRECISION_BITS, "rounding": MPFR_ROUNDING, "exact_projection": "gmpy2.mpfr(gmpy2.mpq(numerator,denominator))"},
        "operation_order": [
            "project_each_exact_input_once_via_mpq_to_mpfr256",
            "build_nig_precision_V0_inverse_plus_X_transpose_X",
            "invert_2x2_precision_then_compute_mn",
            "compute_an_and_bn_from_mn_and_precision",
            "compute_beta_student_t_probability_with_regularized_incomplete_beta_cf_v1",
            "derive_score_predictions_then_absolute_errors_totals_ratios_concordance",
        ],
        "nig": {"V0": [["9", "0"], ["0", "9"]], "a0": "2", "b0": "8", "minimum_fit_observations": 4, "condition_number_maximum": "1000000000000"},
        "thresholds_exact": {key: value.canonical() for key, value in THRESHOLDS.items()} | {"dev_unit_wins_minimum": 4, "confirm_wins_minimum": 7, "confirm_concordant_pairs_minimum": 20, "bootstrap_replicates": 10000, "bootstrap_passes_required": 9500},
        "retained_full_precision": ["fit_coefficients", "posterior_operands_and_results", "predictions", "errors", "totals", "ratios", "concordance_differences", "threshold_operands"],
        "full_precision_golden_vector": {
            "schema": "eval.v6.3.1.exact-statistics.full-precision-golden-vector.v1",
            "checked_in_manifest_root_sha256": GOLDEN_MANIFEST_ROOT_SHA256,
            "expected_artifact_root_sha256": FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256,
            "large_rational_input": dict(LARGE_RATIONAL_GOLDEN_INPUT),
            "large_rational_projection_c99_hex": LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX,
            "independent_ab_agreement_required": True,
            "independent_ab_agreement_verified": False,
        },
        "active_set_rule": {
            "source": "sealed_execution_ledger_artifact",
            "dev": {"primaries": list(DEV_PRIMARY_SLOTS), "reserve": DEV_RESERVE_SLOT, "active_count": 6},
            "confirm": {"primaries": list(CONFIRM_PRIMARY_SLOTS), "reserve": CONFIRM_RESERVE_SLOT, "active_count": 8},
            "reserve_requires_one_pre_maturity_failure": True,
            "post_outcome_best_subset_forbidden": True,
        },
        "phases": ["DEV_ACTIVE_SET", "PRE_CONFIRM", "DEV_CONTINUE", "PRE_CONFIRM_PREDICTION_FREEZE", "CONFIRM_ACTIVE_SET", "POST_FREEZE_CONFIRM_ENDPOINTS"],
        "failure_codes": ["STATISTICS_EXACT_VALUE_MISSING", "STATISTICS_RATIONAL_NONCANONICAL", "STATISTICS_ROUNDED_INPUT_USED", "STATISTICS_ENDPOINT_DERIVATION_MISMATCH", "STATISTICS_MPFR_PROJECTION_DIVERGENCE", "STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "STATISTICS_PHASE_ARTIFACT_INVALID", "STATISTICS_MODEL_ROOT_RETIRED"],
        "feature_spec_complete": False,
        "independent_review_pinned": False,
        "authority": {"calibration_upload_authorized": False, "production_upload_authorized": False, "sealed_holdout_access_authorized": False, "agent_modification_authorized": False, "calibration_slots_remaining": CALIBRATION_BUDGET, "production_slots_remaining": PRODUCTION_BUDGET},
    }


@dataclass(frozen=True, slots=True)
class ExactModelManifest:
    payload: Mapping[str, Any]
    root_sha256: str

    def __post_init__(self) -> None:
        _sha256(self.root_sha256, "model_root_sha256", reject_retired=True)
        if canonical_sha256(self.payload) != self.root_sha256:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "candidate model manifest root does not match canonical payload")
        if self.payload.get("schema") != "eval.v6.3.1.candidate-exact-statistics-model":
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "candidate model manifest schema is invalid")
        if self.payload.get("retired_legacy_model_root_sha256") != RETIRED_LEGACY_MODEL_ROOT_SHA256:
            raise _fail("STATISTICS_MODEL_ROOT_RETIRED", "candidate manifest does not explicitly retire the legacy model root")
        if self.payload.get("feature_spec_complete") is not False or self.payload.get("independent_review_pinned") is not False:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "candidate exact model cannot claim feature completeness or independent pinning")

    def canonical(self) -> dict[str, Any]:
        return {"payload": self.payload, "root_sha256": self.root_sha256}


def validate_model_root(model_root_sha256: Any) -> str:
    return _sha256(model_root_sha256, "model_root_sha256", reject_retired=True)


def _validate_manifest(value: Any) -> ExactModelManifest:
    if type(value) is not ExactModelManifest:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "statistics artifacts require an ExactModelManifest")
    # Re-run the checks so object.__setattr__ tampering cannot silently persist.
    ExactModelManifest(value.payload, value.root_sha256)
    if value.root_sha256 != CANDIDATE_EXACT_MODEL_ROOT_SHA256:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "only the candidate exact model manifest is admitted before a separate review pin")
    return value


def _mp_constant(value: ExactRational) -> Any:
    return project_exact(value)


def _hex_map(values: Mapping[str, Any]) -> Mapping[str, str]:
    return MappingProxyType({key: mpfr_c99_hex(value) for key, value in values.items()})


def _regularized_beta(a: Any, b: Any, x: Any) -> Any:
    """Frozen continued-fraction beta CDF used by the legacy NIG procedure."""

    zero, one = _mp_constant(ZERO), _mp_constant(ONE)
    if x <= zero:
        return zero
    if x >= one:
        return one
    epsilon = gmpy2.exp2(-220)
    floor = gmpy2.exp2(-240)

    def fraction(left: Any, right: Any, point: Any) -> Any:
        qab, qap, qam = left + right, left + one, left - one
        c = one
        d = one - qab * point / qap
        d = floor if abs(d) < floor else d
        d = one / d
        h = d
        for iteration in range(1, 10001):
            twice = _mp_constant(ExactRational.from_integers(2 * iteration))
            iteration_mp = _mp_constant(ExactRational.from_integers(iteration))
            aa = iteration_mp * (right - iteration_mp) * point / ((qam + twice) * (left + twice))
            d = one + aa * d
            d = floor if abs(d) < floor else d
            c = one + aa / c
            c = floor if abs(c) < floor else c
            d = one / d
            h *= d * c
            aa = -(left + iteration_mp) * (qab + iteration_mp) * point / ((left + twice) * (qap + twice))
            d = one + aa * d
            d = floor if abs(d) < floor else d
            c = one + aa / c
            c = floor if abs(c) < floor else c
            d = one / d
            delta = d * c
            h *= delta
            if abs(delta - one) < epsilon:
                return h
        raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "regularized beta continued fraction did not converge")

    log_term = gmpy2.exp(gmpy2.lngamma(a + b) - gmpy2.lngamma(a) - gmpy2.lngamma(b) + a * gmpy2.log(x) + b * gmpy2.log(one - x))
    if x < (a + one) / (a + b + _mp_constant(TWO)):
        return log_term * fraction(a, b, x) / a
    return one - log_term * fraction(b, a, one - x) / b


def _student_t_cdf(value: Any, degrees_of_freedom: Any) -> tuple[Any, Mapping[str, Any]]:
    zero, one, half = _mp_constant(ZERO), _mp_constant(ONE), _mp_constant(HALF)
    if degrees_of_freedom <= zero:
        raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "Student-t degrees of freedom must be positive")
    beta_argument = degrees_of_freedom / (degrees_of_freedom + value * value)
    beta_value = _regularized_beta(degrees_of_freedom / _mp_constant(TWO), half, beta_argument)
    result = half * beta_value if value < zero else one - half * beta_value
    return result, MappingProxyType({"student_t_argument": value, "student_t_degrees_of_freedom": degrees_of_freedom, "regularized_beta_argument": beta_argument, "regularized_beta_result": beta_value, "student_t_cdf": result})


@dataclass(frozen=True, slots=True)
class NIGFit:
    """Closed-form Normal-Inverse-Gamma fit with every later-used value in C99."""

    rows: tuple[Mapping[str, Any], ...]
    coefficients_c99_hex: Mapping[str, str]
    posterior_c99_hex: Mapping[str, str]
    condition_c99_hex: Mapping[str, str]
    root_sha256: str

    def coefficient(self, name: str) -> Any:
        try:
            return parse_mpfr_c99_hex(self.coefficients_c99_hex[name], label=f"fit coefficient {name}")
        except KeyError as exc:
            raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", f"unknown fit coefficient {name}") from exc

    def canonical(self) -> dict[str, Any]:
        return {
            "rows": [dict(row) for row in self.rows],
            "coefficients_c99_hex": dict(self.coefficients_c99_hex),
            "posterior_c99_hex": dict(self.posterior_c99_hex),
            "condition_c99_hex": dict(self.condition_c99_hex),
        }


def fit_nig(rows: Sequence[tuple[ExactRational, ExactRational]]) -> NIGFit:
    """Fit the frozen closed-form NIG model from exact x and model-y values."""

    _require_runtime()
    if len(rows) < 4:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "each NIG fit requires at least four exact observations")
    normalized: list[tuple[ExactRational, ExactRational]] = []
    for index, row in enumerate(rows):
        if type(row) is not tuple or len(row) != 2:
            raise _fail("STATISTICS_EXACT_VALUE_MISSING", f"row {index} must be an exact (x, model_y) tuple")
        x, y = _exact(row[0], f"row {index} x"), _exact(row[1], f"row {index} model_y")
        normalized.append((x, y))
    with gmpy2.context(_ctx()):
        one, two, nine, a0, b0 = _mp_constant(ONE), _mp_constant(TWO), _mp_constant(NINE), _mp_constant(TWO), _mp_constant(EIGHT)
        projected = [(project_exact(x), project_exact(y)) for x, y in normalized]
        n = _mp_constant(ExactRational.from_integers(len(projected)))
        a00 = one / nine + n
        a01 = sum((x for x, _ in projected), _mp_constant(ZERO))
        a11 = one / nine + sum((x * x for x, _ in projected), _mp_constant(ZERO))
        determinant = a00 * a11 - a01 * a01
        if determinant <= _mp_constant(ZERO):
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "NIG posterior precision is singular")
        trace = a00 + a11
        discriminant = gmpy2.sqrt((a00 - a11) * (a00 - a11) + _mp_constant(ExactRational.from_integers(4)) * a01 * a01)
        smallest = (trace - discriminant) / two
        largest = (trace + discriminant) / two
        condition_number = largest / smallest if smallest > _mp_constant(ZERO) else gmpy2.inf()
        if smallest <= _mp_constant(ZERO) or condition_number > _mp_constant(ExactRational("1000000000000", "1")):
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "NIG posterior condition number exceeds 1e12")
        v00, v01, v11 = a11 / determinant, -a01 / determinant, a00 / determinant
        rhs0 = sum((y for _, y in projected), _mp_constant(ZERO))
        rhs1 = sum((x * y for x, y in projected), _mp_constant(ZERO))
        alpha, beta = v00 * rhs0 + v01 * rhs1, v01 * rhs0 + v11 * rhs1
        yty = sum((y * y for _, y in projected), _mp_constant(ZERO))
        quadratic = alpha * (a00 * alpha + a01 * beta) + beta * (a01 * alpha + a11 * beta)
        an = a0 + n / two
        bn = b0 + (yty - quadratic) / two
        if not gmpy2.is_finite(bn) or bn <= _mp_constant(ZERO):
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "NIG posterior bn must be finite and positive")
        beta_scale = gmpy2.sqrt((bn / an) * v11)
        if not gmpy2.is_finite(beta_scale) or beta_scale <= _mp_constant(ZERO):
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "NIG beta posterior scale is invalid")
        beta_negative_standardized = (-beta) / beta_scale
        beta_cdf, cdf_operands = _student_t_cdf(beta_negative_standardized, two * an)
        beta_positive_probability = one - beta_cdf
        if not gmpy2.is_finite(beta_positive_probability) or beta_positive_probability < _mp_constant(ZERO) or beta_positive_probability > one:
            raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "NIG beta posterior probability is invalid")
        coefficients = _hex_map({"alpha": alpha, "beta": beta, "an": an, "bn": bn, "v_beta_beta": v11})
        posterior = _hex_map(
            {
                "beta_scale": beta_scale,
                "beta_negative_standardized": beta_negative_standardized,
                "beta_positive_probability": beta_positive_probability,
                **cdf_operands,
            }
        )
        condition = _hex_map(
            {
                "prior_precision_00": one / nine,
                "precision_00": a00,
                "precision_01": a01,
                "precision_11": a11,
                "determinant": determinant,
                "trace": trace,
                "discriminant": discriminant,
                "smallest_eigenvalue": smallest,
                "largest_eigenvalue": largest,
                "condition_number": condition_number,
                "v00": v00,
                "v01": v01,
                "v11": v11,
                "rhs0": rhs0,
                "rhs1": rhs1,
                "yty": yty,
                "quadratic": quadratic,
            }
        )
        retained_rows = tuple(
            freeze({"x": projection_record(x), "model_y": projection_record(y)}) for x, y in normalized
        )
        canonical = {
            "rows": [dict(row) for row in retained_rows],
            "coefficients_c99_hex": dict(coefficients),
            "posterior_c99_hex": dict(posterior),
            "condition_c99_hex": dict(condition),
        }
        return NIGFit(retained_rows, coefficients, posterior, condition, canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.nig-fit", **canonical}))


@dataclass(frozen=True, slots=True)
class ExactPrediction:
    input_x: ExactRational
    input_x_projection: Mapping[str, Any]
    alpha_c99_hex: str
    beta_c99_hex: str
    linear_predictor_c99_hex: str
    score_prediction_c99_hex: str
    display_score_points: str

    @property
    def value(self) -> Any:
        return parse_mpfr_c99_hex(self.score_prediction_c99_hex, label="score prediction")

    def canonical(self) -> dict[str, Any]:
        return {
            "input_x": self.input_x.canonical(),
            "input_x_projection": dict(self.input_x_projection),
            "alpha_c99_hex": self.alpha_c99_hex,
            "beta_c99_hex": self.beta_c99_hex,
            "linear_predictor_c99_hex": self.linear_predictor_c99_hex,
            "score_prediction_c99_hex": self.score_prediction_c99_hex,
            "display_score_points": self.display_score_points,
        }


def predict(fit: NIGFit, x: ExactRational) -> ExactPrediction:
    if type(fit) is not NIGFit:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "prediction requires an NIGFit")
    exact_x = _exact(x, "prediction x")
    with gmpy2.context(_ctx()):
        alpha, beta, projected_x = fit.coefficient("alpha"), fit.coefficient("beta"), project_exact(exact_x)
        linear = alpha + beta * projected_x
        score = _mp_constant(HUNDRED) * linear
        return ExactPrediction(
            exact_x,
            projection_record(exact_x),
            mpfr_c99_hex(alpha),
            mpfr_c99_hex(beta),
            mpfr_c99_hex(linear),
            mpfr_c99_hex(score),
            display_mpfr(score, 6),
        )


def constant_prediction(value: ExactRational) -> ExactPrediction:
    """Create a score-point constant from an exact Yobs mean, not a display."""

    exact_value = _exact(value, "constant prediction")
    with gmpy2.context(_ctx()):
        projected = project_exact(exact_value)
        zero = _mp_constant(ZERO)
        return ExactPrediction(ZERO, projection_record(ZERO), mpfr_c99_hex(projected), mpfr_c99_hex(zero), mpfr_c99_hex(projected), mpfr_c99_hex(projected), display_mpfr(projected, 6))


@dataclass(frozen=True, slots=True)
class ExactError:
    outcome: ExactRational
    outcome_projection: Mapping[str, Any]
    prediction_c99_hex: str
    absolute_error_c99_hex: str
    display_absolute_error: str

    @property
    def value(self) -> Any:
        return parse_mpfr_c99_hex(self.absolute_error_c99_hex, label="absolute error")

    def canonical(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.canonical(),
            "outcome_projection": dict(self.outcome_projection),
            "prediction_c99_hex": self.prediction_c99_hex,
            "absolute_error_c99_hex": self.absolute_error_c99_hex,
            "display_absolute_error": self.display_absolute_error,
        }


def absolute_error(outcome: ExactRational | ExactHostedEndpoint, prediction: ExactPrediction) -> ExactError:
    if type(outcome) is ExactHostedEndpoint:
        exact_outcome = outcome.yobs
    else:
        exact_outcome = _exact(outcome, "outcome")
    if type(prediction) is not ExactPrediction:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "absolute error requires an ExactPrediction")
    with gmpy2.context(_ctx()):
        projected_outcome, projected_prediction = project_exact(exact_outcome), prediction.value
        result = abs(projected_outcome - projected_prediction)
        return ExactError(exact_outcome, projection_record(exact_outcome), prediction.score_prediction_c99_hex, mpfr_c99_hex(result), display_mpfr(result, 6))


@dataclass(frozen=True, slots=True)
class ExactTotal:
    member_error_c99_hex: tuple[str, ...]
    total_c99_hex: str
    display_total: str

    @property
    def value(self) -> Any:
        return parse_mpfr_c99_hex(self.total_c99_hex, label="error total")

    def canonical(self) -> dict[str, Any]:
        return {"member_error_c99_hex": list(self.member_error_c99_hex), "total_c99_hex": self.total_c99_hex, "display_total": self.display_total}


def total_errors(errors: Sequence[ExactError]) -> ExactTotal:
    if not errors or any(type(error) is not ExactError for error in errors):
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "totals require one or more ExactError artifacts")
    with gmpy2.context(_ctx()):
        total = sum((error.value for error in errors), _mp_constant(ZERO))
        return ExactTotal(tuple(error.absolute_error_c99_hex for error in errors), mpfr_c99_hex(total), display_mpfr(total, 6))


@dataclass(frozen=True, slots=True)
class ExactRatio:
    numerator_total_c99_hex: str
    denominator_total_c99_hex: str
    classification: Literal["FINITE", "ZERO_OVER_ZERO", "POSITIVE_OVER_ZERO"]
    ratio_c99_hex: str | None
    display_ratio: str

    @property
    def finite_value(self) -> Any | None:
        return None if self.ratio_c99_hex is None else parse_mpfr_c99_hex(self.ratio_c99_hex, label="ratio")

    def canonical(self) -> dict[str, Any]:
        return {
            "numerator_total_c99_hex": self.numerator_total_c99_hex,
            "denominator_total_c99_hex": self.denominator_total_c99_hex,
            "classification": self.classification,
            "ratio_c99_hex": self.ratio_c99_hex,
            "display_ratio": self.display_ratio,
        }


def error_ratio(numerator: ExactTotal, denominator: ExactTotal) -> ExactRatio:
    if type(numerator) is not ExactTotal or type(denominator) is not ExactTotal:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "ratios require typed full-precision totals")
    with gmpy2.context(_ctx()):
        top, bottom = numerator.value, denominator.value
        if bottom == _mp_constant(ZERO):
            if top == _mp_constant(ZERO):
                result = _mp_constant(ONE)
                return ExactRatio(numerator.total_c99_hex, denominator.total_c99_hex, "ZERO_OVER_ZERO", mpfr_c99_hex(result), display_mpfr(result, 12))
            return ExactRatio(numerator.total_c99_hex, denominator.total_c99_hex, "POSITIVE_OVER_ZERO", None, "Infinity")
        result = top / bottom
        return ExactRatio(numerator.total_c99_hex, denominator.total_c99_hex, "FINITE", mpfr_c99_hex(result), display_mpfr(result, 12))


@dataclass(frozen=True, slots=True)
class ThresholdComparison:
    operand_c99_hex: str
    threshold_exact: ExactRational
    threshold_c99_hex: str
    relation: Literal["<=", ">=", "<", ">"]
    passed: bool

    def canonical(self) -> dict[str, Any]:
        return {
            "operand_c99_hex": self.operand_c99_hex,
            "threshold_exact": self.threshold_exact.canonical(),
            "threshold_c99_hex": self.threshold_c99_hex,
            "relation": self.relation,
            "passed": self.passed,
        }


def compare_exact_threshold(value: ExactRational, threshold: ExactRational, relation: Literal["<=", ">=", "<", ">"] = "<=") -> ThresholdComparison:
    exact_value, exact_threshold = _exact(value, "threshold value"), _exact(threshold, "threshold")
    if relation not in {"<=", ">=", "<", ">"}:
        raise ValueError("relation must be <=, >=, <, or >")
    with gmpy2.context(_ctx()):
        operand, projected_threshold = project_exact(exact_value), project_exact(exact_threshold)
        passed = {"<=": operand <= projected_threshold, ">=": operand >= projected_threshold, "<": operand < projected_threshold, ">": operand > projected_threshold}[relation]
        return ThresholdComparison(mpfr_c99_hex(operand), exact_threshold, mpfr_c99_hex(projected_threshold), relation, passed)


def compare_ratio_threshold(ratio: ExactRatio, threshold: ExactRational) -> ThresholdComparison:
    if type(ratio) is not ExactRatio:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "ratio threshold comparison requires ExactRatio")
    exact_threshold = _exact(threshold, "ratio threshold")
    with gmpy2.context(_ctx()):
        threshold_mp = project_exact(exact_threshold)
        if ratio.ratio_c99_hex is None:
            return ThresholdComparison("Infinity", exact_threshold, mpfr_c99_hex(threshold_mp), "<=", False)
        operand = ratio.finite_value
        assert operand is not None
        return ThresholdComparison(ratio.ratio_c99_hex, exact_threshold, mpfr_c99_hex(threshold_mp), "<=", operand <= threshold_mp)


@dataclass(frozen=True, slots=True)
class ExactConcordance:
    outcome_difference_c99_hex: str
    prediction_difference_c99_hex: str
    threshold_exact: ExactRational
    threshold_c99_hex: str
    strict_concordant: bool

    def canonical(self) -> dict[str, Any]:
        return {
            "outcome_difference_c99_hex": self.outcome_difference_c99_hex,
            "prediction_difference_c99_hex": self.prediction_difference_c99_hex,
            "threshold_exact": self.threshold_exact.canonical(),
            "threshold_c99_hex": self.threshold_c99_hex,
            "strict_concordant": self.strict_concordant,
        }


def strict_concordance(outcome_left: ExactRational, outcome_right: ExactRational, prediction_left: ExactPrediction, prediction_right: ExactPrediction) -> ExactConcordance:
    left, right = _exact(outcome_left, "outcome_left"), _exact(outcome_right, "outcome_right")
    if type(prediction_left) is not ExactPrediction or type(prediction_right) is not ExactPrediction:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "concordance requires typed full-precision predictions")
    with gmpy2.context(_ctx()):
        observed = project_exact(left) - project_exact(right)
        predicted = prediction_left.value - prediction_right.value
        threshold = project_exact(THRESHOLDS["concordance_margin_points"])
        result = abs(observed) >= threshold and abs(predicted) >= threshold and (observed > _mp_constant(ZERO)) == (predicted > _mp_constant(ZERO))
        return ExactConcordance(mpfr_c99_hex(observed), mpfr_c99_hex(predicted), THRESHOLDS["concordance_margin_points"], mpfr_c99_hex(threshold), result)


def sign_test_values(wins: int) -> Mapping[str, Any]:
    if type(wins) is not int or isinstance(wins, bool) or not 0 <= wins <= 8:
        raise ValueError("wins must be an integer in [0, 8]")
    observed_numerator = sum(math.comb(8, index) for index in range(wins, 9))
    observed = ExactRational.from_integers(observed_numerator, 256)
    threshold = THRESHOLDS["sign_test_threshold"]
    return freeze(
        {
            "wins": wins,
            "observed": observed.canonical(),
            "threshold": threshold.canonical(),
            "observed_projection": projection_record(observed),
            "threshold_projection": projection_record(threshold),
        }
    )


def _authority(state: str, detail: str, *, extra: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    return freeze(zero_authority(state, detail=detail, extra=extra))


def _build_full_precision_golden_vector() -> dict[str, Any]:
    r = ExactRational.from_integers
    rows = ((r(-3, 4), r(-1, 2)), (r(-1, 4), r(-1, 8)), (r(1, 4), r(1, 8)), (r(3, 4), r(1, 2)))
    fit = fit_nig(rows)
    prediction_minus = predict(fit, r(-1, 3))
    prediction_plus = predict(fit, r(1, 3))
    error_minus = absolute_error(r(-1, 5), prediction_minus)
    error_plus = absolute_error(r(7, 20), prediction_plus)
    mechanics_total = total_errors((error_plus, error_minus))
    constant = constant_prediction(r(0))
    constant_total = total_errors((absolute_error(r(7, 20), constant), absolute_error(r(-1, 5), constant)))
    return {
        "schema": "eval.v6.3.1.exact-statistics.full-precision-golden-vector.v1",
        "inputs": {
            "fit_rows": [[x.canonical(), y.canonical()] for x, y in rows],
            "prediction_x": [r(-1, 3).canonical(), r(1, 3).canonical()],
            "outcomes": [r(-1, 5).canonical(), r(7, 20).canonical()],
            "constant": r(0).canonical(),
        },
        "outputs": {
            "fit": fit.canonical() | {"root_sha256": fit.root_sha256},
            "prediction_minus": prediction_minus.canonical(),
            "prediction_plus": prediction_plus.canonical(),
            "error_minus": error_minus.canonical(),
            "error_plus": error_plus.canonical(),
            "mechanics_total": mechanics_total.canonical(),
            "constant_total": constant_total.canonical(),
            "ratio": error_ratio(mechanics_total, constant_total).canonical(),
            "concordance": strict_concordance(r(-1, 5), r(7, 20), prediction_minus, prediction_plus).canonical(),
        },
    }


_golden_manifest_path = Path(__file__).with_name("golden_exact_statistics_v1.json")
try:
    _GOLDEN_MANIFEST = freeze(json.loads(_golden_manifest_path.read_text(encoding="ascii")))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "checked-in exact-statistics golden manifest is missing or invalid") from exc
if canonical_sha256(_GOLDEN_MANIFEST) != GOLDEN_MANIFEST_ROOT_SHA256:
    raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "checked-in exact-statistics golden manifest root diverges")
if (
    _GOLDEN_MANIFEST.get("full_precision_vector", {}).get("expected_artifact_root_sha256") != FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256
    or _GOLDEN_MANIFEST.get("large_rational_projection", {}).get("input") != LARGE_RATIONAL_GOLDEN_INPUT
    or _GOLDEN_MANIFEST.get("large_rational_projection", {}).get("expected_mpfr256_c99_hex") != LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX
):
    raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "checked-in exact-statistics golden manifest content diverges")

_FULL_PRECISION_GOLDEN_VECTOR = freeze(_build_full_precision_golden_vector())
if canonical_sha256(_FULL_PRECISION_GOLDEN_VECTOR) != FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256:
    raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "full-precision golden vector root diverges from the frozen expected output")
_large_golden = ExactRational.make(LARGE_RATIONAL_GOLDEN_INPUT, label="large-rational golden input")
if mpfr_c99_hex(project_exact(_large_golden)) != LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX:
    raise _fail("STATISTICS_MPFR_PROJECTION_DIVERGENCE", "large-rational direct MPQ projection diverges from the frozen expected output")

_CANDIDATE_PAYLOAD = freeze(_manifest_payload())
CANDIDATE_EXACT_MODEL_ROOT_SHA256 = canonical_sha256(_CANDIDATE_PAYLOAD)
CANDIDATE_EXACT_MODEL_MANIFEST = ExactModelManifest(_CANDIDATE_PAYLOAD, CANDIDATE_EXACT_MODEL_ROOT_SHA256)


def full_precision_golden_vector() -> Mapping[str, Any]:
    return _FULL_PRECISION_GOLDEN_VECTOR


def exact_statistics_readiness() -> Mapping[str, Any]:
    return _authority(
        "POPULATION_INFEASIBLE_NO_UPLOAD",
        "candidate exact-statistics core is unpinned and zero-authority",
        extra={
            "candidate_exact_model_root_sha256": CANDIDATE_EXACT_MODEL_ROOT_SHA256,
            "feature_spec_complete": False,
            "independent_review_pinned": False,
            "trace_authenticity_verified": False,
            "assignment_support_authenticated": False,
        },
    )


@dataclass(frozen=True, slots=True)
class LedgerActiveSet:
    """Sealed TEST_ONLY representation of one ledger-derived active tranche.

    This candidate module cannot authenticate a Kaggle execution ledger.  The
    artifact therefore remains zero-authority, but it makes reserve semantics
    explicit and prevents endpoint-dependent subset selection inside the
    statistics API.
    """

    phase: Literal["LEDGER_ACTIVE_SET"]
    tranche: Literal["DEV", "CONFIRM"]
    assignment_root_sha256: str
    execution_ledger_root_sha256: str
    active_slots: tuple[str, ...]
    failed_primary_slot_id: str | None
    failure_event_root_sha256: str | None
    failure_before_mature_poll: bool
    artifact_root_sha256: str
    authority: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "tranche": self.tranche,
            "assignment_root_sha256": self.assignment_root_sha256,
            "execution_ledger_root_sha256": self.execution_ledger_root_sha256,
            "active_slots": list(self.active_slots),
            "failed_primary_slot_id": self.failed_primary_slot_id,
            "failure_event_root_sha256": self.failure_event_root_sha256,
            "failure_before_mature_poll": self.failure_before_mature_poll,
            "authority": dict(self.authority),
        }


@dataclass(frozen=True, slots=True)
class TestOnlyPreConfirmInput:
    """Typed exact inputs available before any CONFIRM endpoint exists."""

    model_manifest: ExactModelManifest
    campaign_nonce_root_sha256: str
    population_root_sha256: str
    assignment_root_sha256: str
    preregistration_root_sha256: str
    dev_active_set: LedgerActiveSet
    dev_units: tuple[ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit]
    confirm_units: tuple[ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit, ExactLocalUnit]

    def __post_init__(self) -> None:
        manifest = _validate_manifest(self.model_manifest)
        for label in ("campaign_nonce_root_sha256", "population_root_sha256", "assignment_root_sha256", "preregistration_root_sha256"):
            _sha256(getattr(self, label), label, reject_retired=True)
        _require_active_set(self.dev_active_set, "DEV")
        if self.dev_active_set.assignment_root_sha256 != self.assignment_root_sha256:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "DEV active set does not bind the PRE_CONFIRM assignment root")
        if len(self.dev_units) != 6 or len(self.confirm_units) != 9:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "PRE_CONFIRM requires six DEV and all nine CONFIRM local units")
        if tuple(unit.slot_id for unit in self.dev_units) != self.dev_active_set.active_slots or tuple(unit.slot_id for unit in self.confirm_units) != CONFIRM_SLOTS:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "PRE_CONFIRM units must use the sealed DEV active set and canonical nine-CONFIRM slot order")
        all_units = self.dev_units + self.confirm_units
        if any(type(unit) is not ExactLocalUnit for unit in all_units):
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "PRE_CONFIRM requires typed ExactLocalUnit values")
        if len({unit.archive_sha256 for unit in all_units}) != len(all_units):
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "PRE_CONFIRM archives must be distinct")
        if any(unit.model_root_sha256 != manifest.root_sha256 for unit in all_units):
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "every local unit must bind the candidate exact model root")
        if any(unit.endpoint is None for unit in self.dev_units) or any(unit.endpoint is not None for unit in self.confirm_units):
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "DEV endpoints are required and CONFIRM endpoints are forbidden in PRE_CONFIRM")
        for field_name in (
            "source_component_id",
            "lineage_time_component_id",
            "development_control_component_id",
        ):
            dev_components = {getattr(unit, field_name) for unit in self.dev_units}
            confirm_components = {getattr(unit, field_name) for unit in self.confirm_units}
            overlap = sorted(dev_components & confirm_components)
            if overlap:
                raise _fail(
                    "STATISTICS_PHASE_ARTIFACT_INVALID",
                    f"DEV and CONFIRM {field_name} values must be disjoint; overlap={overlap}",
                )

    @property
    def phase(self) -> str:
        return "PRE_CONFIRM"

    @property
    def root_sha256(self) -> str:
        return canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.pre-confirm-input", **self.canonical()})

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "model_root_sha256": self.model_manifest.root_sha256,
            "campaign_nonce_root_sha256": self.campaign_nonce_root_sha256,
            "population_root_sha256": self.population_root_sha256,
            "assignment_root_sha256": self.assignment_root_sha256,
            "preregistration_root_sha256": self.preregistration_root_sha256,
            "dev_active_set_root_sha256": self.dev_active_set.artifact_root_sha256,
            "dev_units": [unit.canonical() for unit in self.dev_units],
            "confirm_units": [unit.canonical() for unit in self.confirm_units],
        }


def make_test_only_pre_confirm_input(
    *,
    campaign_nonce_root_sha256: str,
    population_root_sha256: str,
    assignment_root_sha256: str,
    preregistration_root_sha256: str,
    dev_active_set: LedgerActiveSet,
    dev_units: Sequence[ExactLocalUnit],
    confirm_units: Sequence[ExactLocalUnit],
    model_manifest: ExactModelManifest = CANDIDATE_EXACT_MODEL_MANIFEST,
) -> TestOnlyPreConfirmInput:
    return TestOnlyPreConfirmInput(
        model_manifest,
        campaign_nonce_root_sha256,
        population_root_sha256,
        assignment_root_sha256,
        preregistration_root_sha256,
        dev_active_set,
        tuple(dev_units),  # type: ignore[arg-type]
        tuple(confirm_units),  # type: ignore[arg-type]
    )


@dataclass(frozen=True, slots=True)
class DevFold:
    source_component_id: str
    held_out_slots: tuple[str, ...]
    mechanics_fit: NIGFit
    comparator_fit: NIGFit
    mechanics_errors: tuple[ExactError, ...]
    comparator_errors: tuple[ExactError, ...]
    unit_win_differences_c99_hex: tuple[str, ...]
    unit_wins: tuple[bool, ...]
    family_mechanics_mean_c99_hex: str
    family_comparator_mean_c99_hex: str
    family_difference_c99_hex: str
    family_win: bool

    def canonical(self) -> dict[str, Any]:
        return {
            "source_component_id": self.source_component_id,
            "held_out_slots": list(self.held_out_slots),
            "mechanics_fit": self.mechanics_fit.canonical()
            | {"root_sha256": self.mechanics_fit.root_sha256},
            "comparator_fit": self.comparator_fit.canonical()
            | {"root_sha256": self.comparator_fit.root_sha256},
            "mechanics_errors": [error.canonical() for error in self.mechanics_errors],
            "comparator_errors": [error.canonical() for error in self.comparator_errors],
            "unit_win_differences_c99_hex": list(self.unit_win_differences_c99_hex),
            "unit_wins": list(self.unit_wins),
            "family_mechanics_mean_c99_hex": self.family_mechanics_mean_c99_hex,
            "family_comparator_mean_c99_hex": self.family_comparator_mean_c99_hex,
            "family_difference_c99_hex": self.family_difference_c99_hex,
            "family_win": self.family_win,
        }


@dataclass(frozen=True, slots=True)
class DevAnalysis:
    folds: tuple[DevFold, ...]
    full_mechanics_fit: NIGFit
    full_comparator_fit: NIGFit
    dev_constant: ExactPrediction
    mechanics_total: ExactTotal
    comparator_total: ExactTotal
    ratio: ExactRatio
    thresholds: Mapping[str, Any]
    unit_wins: int
    family_wins: int
    family_wins_required: int
    passes: bool

    def canonical(self) -> dict[str, Any]:
        return {
            "folds": [fold.canonical() for fold in self.folds],
            "full_mechanics_fit": self.full_mechanics_fit.canonical()
            | {"root_sha256": self.full_mechanics_fit.root_sha256},
            "full_comparator_fit": self.full_comparator_fit.canonical()
            | {"root_sha256": self.full_comparator_fit.root_sha256},
            "dev_constant": self.dev_constant.canonical(),
            "mechanics_total": self.mechanics_total.canonical(),
            "comparator_total": self.comparator_total.canonical(),
            "ratio": self.ratio.canonical(),
            "thresholds": dict(self.thresholds),
            "unit_wins": self.unit_wins,
            "family_wins": self.family_wins,
            "family_wins_required": self.family_wins_required,
            "passes": self.passes,
        }


def _mean_mpfr(values: Sequence[Any]) -> Any:
    if not values:
        raise _fail("STATISTICS_FULL_PRECISION_ARTIFACT_MISSING", "cannot average an empty MPFR collection")
    return sum(values, _mp_constant(ZERO)) / _mp_constant(ExactRational.from_integers(len(values)))


def _dev_analysis(pre_confirm: TestOnlyPreConfirmInput) -> DevAnalysis:
    units = pre_confirm.dev_units
    source_groups: dict[str, tuple[ExactLocalUnit, ...]] = {}
    for unit in units:
        source_groups[unit.source_component_id] = tuple(candidate for candidate in units if candidate.source_component_id == unit.source_component_id)
    folds: list[DevFold] = []
    all_mechanics_errors: list[ExactError] = []
    all_comparator_errors: list[ExactError] = []
    threshold = project_exact(THRESHOLDS["unit_win_margin_points"])
    for source, held in sorted(source_groups.items()):
        held_slots = {unit.slot_id for unit in held}
        training = tuple(unit for unit in units if unit.slot_id not in held_slots)
        if len(training) < 4 or len({unit.source_component_id for unit in training}) < 3:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "each LOFO fold needs four observations from three source components")
        mechanics_fit = fit_nig([(unit.point.x, unit.endpoint.model_y) for unit in training if unit.endpoint is not None])
        comparator_fit = fit_nig([(unit.point.r, unit.endpoint.model_y) for unit in training if unit.endpoint is not None])
        mechanics_errors: list[ExactError] = []
        comparator_errors: list[ExactError] = []
        differences: list[str] = []
        wins: list[bool] = []
        with gmpy2.context(_ctx()):
            for unit in held:
                assert unit.endpoint is not None
                mechanics_error = absolute_error(unit.endpoint, predict(mechanics_fit, unit.point.x))
                comparator_error = absolute_error(unit.endpoint, predict(comparator_fit, unit.point.r))
                difference = comparator_error.value - mechanics_error.value
                mechanics_errors.append(mechanics_error)
                comparator_errors.append(comparator_error)
                differences.append(mpfr_c99_hex(difference))
                wins.append(difference >= threshold)
            family_mechanics = _mean_mpfr([error.value for error in mechanics_errors])
            family_comparator = _mean_mpfr([error.value for error in comparator_errors])
            family_difference = family_comparator - family_mechanics
            folds.append(
                DevFold(
                    source,
                    tuple(unit.slot_id for unit in held),
                    mechanics_fit,
                    comparator_fit,
                    tuple(mechanics_errors),
                    tuple(comparator_errors),
                    tuple(differences),
                    tuple(wins),
                    mpfr_c99_hex(family_mechanics),
                    mpfr_c99_hex(family_comparator),
                    mpfr_c99_hex(family_difference),
                    family_difference >= threshold,
                )
            )
        all_mechanics_errors.extend(mechanics_errors)
        all_comparator_errors.extend(comparator_errors)
    full_mechanics = fit_nig([(unit.point.x, unit.endpoint.model_y) for unit in units if unit.endpoint is not None])
    full_comparator = fit_nig([(unit.point.r, unit.endpoint.model_y) for unit in units if unit.endpoint is not None])
    constant = constant_prediction(exact_mean([unit.endpoint.yobs for unit in units if unit.endpoint is not None], label="DEV Yobs"))
    mechanics_total, comparator_total = total_errors(all_mechanics_errors), total_errors(all_comparator_errors)
    ratio = error_ratio(mechanics_total, comparator_total)
    source_count = len(source_groups)
    family_required = math.ceil(2 * source_count / 3)
    unit_wins = sum(sum(fold.unit_wins) for fold in folds)
    family_wins = sum(fold.family_win for fold in folds)
    ratio_comparison = compare_ratio_threshold(ratio, THRESHOLDS["dev_ratio_maximum"])
    posterior_probability = parse_mpfr_c99_hex(full_mechanics.posterior_c99_hex["beta_positive_probability"], label="beta posterior probability")
    posterior_threshold = project_exact(THRESHOLDS["dev_beta_positive_probability_minimum"])
    thresholds = freeze(
        {
            "unit_win_margin": projection_record(THRESHOLDS["unit_win_margin_points"]),
            "family_win_margin": projection_record(THRESHOLDS["family_win_margin_points"]),
            "dev_ratio": ratio_comparison.canonical(),
            "posterior_beta_probability_c99_hex": mpfr_c99_hex(posterior_probability),
            "posterior_beta_threshold": projection_record(THRESHOLDS["dev_beta_positive_probability_minimum"]),
            "posterior_beta_passed": posterior_probability >= posterior_threshold,
            "dev_unit_wins_minimum": 4,
            "family_wins_required": family_required,
        }
    )
    passes = unit_wins >= 4 and family_wins >= family_required and ratio_comparison.passed and posterior_probability >= posterior_threshold
    return DevAnalysis(tuple(folds), full_mechanics, full_comparator, constant, mechanics_total, comparator_total, ratio, thresholds, unit_wins, family_wins, family_required, passes)


@dataclass(frozen=True, slots=True)
class PreConfirmPredictionFreeze:
    phase: Literal["PRE_CONFIRM"]
    model_root_sha256: str
    pre_confirm_root_sha256: str
    assignment_root_sha256: str
    dev_active_set_root_sha256: str
    dev_continue_root_sha256: str
    dev_analysis: DevAnalysis
    predictions: Mapping[str, Mapping[str, ExactPrediction]]
    artifact_root_sha256: str
    authority: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "model_root_sha256": self.model_root_sha256,
            "pre_confirm_root_sha256": self.pre_confirm_root_sha256,
            "assignment_root_sha256": self.assignment_root_sha256,
            "dev_active_set_root_sha256": self.dev_active_set_root_sha256,
            "dev_continue_root_sha256": self.dev_continue_root_sha256,
            "dev_analysis": self.dev_analysis.canonical(),
            "predictions": {slot: {name: prediction.canonical() for name, prediction in row.items()} for slot, row in self.predictions.items()},
            "authority": dict(self.authority),
        }


def _seal(value: Any, root: str) -> Any:
    _ARTIFACT_SNAPSHOTS[id(value)] = (root, canonical_json_bytes(value.canonical()))
    return value


def _require_sealed(value: Any, expected_type: type[Any], expected_phase: str) -> None:
    if type(value) is not expected_type or getattr(value, "phase", None) != expected_phase:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", f"expected typed {expected_phase} artifact")
    root = getattr(value, "artifact_root_sha256", None)
    _sha256(root, "artifact_root_sha256", reject_retired=True)
    expected_root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **value.canonical()})
    snapshot = _ARTIFACT_SNAPSHOTS.get(id(value))
    if root != expected_root or snapshot != (root, canonical_json_bytes(value.canonical())):
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "phase artifact root or issuance snapshot is stale, substituted, or mutated")


def _require_active_set(value: Any, tranche: Literal["DEV", "CONFIRM"]) -> None:
    _require_sealed(value, LedgerActiveSet, "LEDGER_ACTIVE_SET")
    if value.tranche != tranche:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", f"expected a sealed {tranche} active set")
    _sha256(value.assignment_root_sha256, "active-set assignment root", reject_retired=True)
    _sha256(value.execution_ledger_root_sha256, "active-set execution ledger root", reject_retired=True)
    primaries = DEV_PRIMARY_SLOTS if tranche == "DEV" else CONFIRM_PRIMARY_SLOTS
    reserve = DEV_RESERVE_SLOT if tranche == "DEV" else CONFIRM_RESERVE_SLOT
    expected_count = len(primaries)
    if value.failed_primary_slot_id is None:
        expected_slots = primaries
        if value.failure_event_root_sha256 is not None or value.failure_before_mature_poll:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "default active set cannot claim failure evidence")
    else:
        if value.failed_primary_slot_id not in primaries:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "only one primary slot may be replaced by its tranche reserve")
        if value.failure_event_root_sha256 is None or not value.failure_before_mature_poll:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "reserve activation requires a pre-maturity failure event root")
        _sha256(value.failure_event_root_sha256, "active-set failure event root", reject_retired=True)
        expected_slots = tuple(slot for slot in primaries if slot != value.failed_primary_slot_id) + (reserve,)
    if len(value.active_slots) != expected_count or value.active_slots != expected_slots:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "active slots do not match the sole permitted default or reserve scenario")


def make_test_only_ledger_active_set(
    *,
    tranche: Literal["DEV", "CONFIRM"],
    assignment_root_sha256: str,
    execution_ledger_root_sha256: str,
    failed_primary_slot_id: str | None = None,
    failure_event_root_sha256: str | None = None,
    failure_before_mature_poll: bool = False,
) -> LedgerActiveSet:
    """Seal a zero-authority active-set fixture for protocol conformance."""

    if tranche not in ("DEV", "CONFIRM"):
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "active-set tranche must be DEV or CONFIRM")
    _sha256(assignment_root_sha256, "active-set assignment root", reject_retired=True)
    _sha256(execution_ledger_root_sha256, "active-set execution ledger root", reject_retired=True)
    primaries = DEV_PRIMARY_SLOTS if tranche == "DEV" else CONFIRM_PRIMARY_SLOTS
    reserve = DEV_RESERVE_SLOT if tranche == "DEV" else CONFIRM_RESERVE_SLOT
    if failed_primary_slot_id is None:
        if failure_event_root_sha256 is not None or failure_before_mature_poll:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "default active set cannot include failure evidence")
        active_slots = primaries
    else:
        if failed_primary_slot_id not in primaries or failure_event_root_sha256 is None or failure_before_mature_poll is not True:
            raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "reserve activation requires one primary pre-maturity failure")
        _sha256(failure_event_root_sha256, "active-set failure event root", reject_retired=True)
        active_slots = tuple(slot for slot in primaries if slot != failed_primary_slot_id) + (reserve,)
    authority = _authority(
        "CANDIDATE_EXACT_LEDGER_ACTIVE_SET_NO_UPLOAD",
        "TEST_ONLY active-set fixture is caller-bound and not an authenticated execution ledger",
        extra={
            "tranche": tranche,
            "assignment_root_sha256": assignment_root_sha256,
            "execution_ledger_root_sha256": execution_ledger_root_sha256,
            "authenticated_ledger_verified": False,
        },
    )
    provisional = LedgerActiveSet(
        "LEDGER_ACTIVE_SET",
        tranche,
        assignment_root_sha256,
        execution_ledger_root_sha256,
        active_slots,
        failed_primary_slot_id,
        failure_event_root_sha256,
        failure_before_mature_poll,
        "0" * 64,
        authority,
    )
    root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **provisional.canonical()})
    sealed = replace(provisional, artifact_root_sha256=root)
    _seal(sealed, root)
    _require_active_set(sealed, tranche)
    return sealed


@dataclass(frozen=True, slots=True)
class DevContinueDecision:
    phase: Literal["DEV_CONTINUE"]
    model_root_sha256: str
    pre_confirm_root_sha256: str
    dev_active_set_root_sha256: str
    dev_analysis: DevAnalysis
    passes: bool
    artifact_root_sha256: str
    authority: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "model_root_sha256": self.model_root_sha256,
            "pre_confirm_root_sha256": self.pre_confirm_root_sha256,
            "dev_active_set_root_sha256": self.dev_active_set_root_sha256,
            "dev_analysis": self.dev_analysis.canonical(),
            "passes": self.passes,
            "authority": dict(self.authority),
        }


def evaluate_dev_continue(value: Any) -> DevContinueDecision:
    if type(value) is not TestOnlyPreConfirmInput or value.phase != "PRE_CONFIRM":
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "DEV_CONTINUE requires typed PRE_CONFIRM input")
    TestOnlyPreConfirmInput(
        value.model_manifest,
        value.campaign_nonce_root_sha256,
        value.population_root_sha256,
        value.assignment_root_sha256,
        value.preregistration_root_sha256,
        value.dev_active_set,
        value.dev_units,
        value.confirm_units,
    )
    with gmpy2.context(_ctx()):
        analysis = _dev_analysis(value)
        authority = _authority(
            "CANDIDATE_EXACT_DEV_CONTINUE_EVALUATED_NO_UPLOAD",
            "TEST_ONLY DEV_CONTINUE decision retains zero upload authority",
            extra={"model_root_sha256": value.model_manifest.root_sha256, "pre_confirm_root_sha256": value.root_sha256, "dev_thresholds_met": analysis.passes},
        )
        provisional = DevContinueDecision(
            "DEV_CONTINUE",
            value.model_manifest.root_sha256,
            value.root_sha256,
            value.dev_active_set.artifact_root_sha256,
            analysis,
            analysis.passes,
            "0" * 64,
            authority,
        )
        root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **provisional.canonical()})
        return _seal(replace(provisional, artifact_root_sha256=root), root)


def freeze_pre_confirm_predictions(value: Any, dev_continue: Any) -> PreConfirmPredictionFreeze:
    """Freeze all nine CONFIRM predictions without accepting CONFIRM outcomes."""

    if type(value) is not TestOnlyPreConfirmInput or value.phase != "PRE_CONFIRM":
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "prediction freeze requires typed PRE_CONFIRM input")
    # Reconstruct validation after a potential frozen-dataclass mutation.
    TestOnlyPreConfirmInput(
        value.model_manifest,
        value.campaign_nonce_root_sha256,
        value.population_root_sha256,
        value.assignment_root_sha256,
        value.preregistration_root_sha256,
        value.dev_active_set,
        value.dev_units,
        value.confirm_units,
    )
    _require_sealed(dev_continue, DevContinueDecision, "DEV_CONTINUE")
    if (
        dev_continue.model_root_sha256 != value.model_manifest.root_sha256
        or dev_continue.pre_confirm_root_sha256 != value.root_sha256
        or dev_continue.dev_active_set_root_sha256 != value.dev_active_set.artifact_root_sha256
        or not dev_continue.passes
        or not dev_continue.dev_analysis.passes
    ):
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "prediction freeze requires the sealed successful DEV_CONTINUE decision for this PRE_CONFIRM input")
    with gmpy2.context(_ctx()):
        analysis = dev_continue.dev_analysis
        predictions = MappingProxyType(
            {
                unit.slot_id: MappingProxyType(
                    {
                        "mechanics": predict(analysis.full_mechanics_fit, unit.point.x),
                        "comparator": predict(analysis.full_comparator_fit, unit.point.r),
                        "dev_constant": analysis.dev_constant,
                    }
                )
                for unit in value.confirm_units
            }
        )
        authority = _authority(
            "CANDIDATE_EXACT_PRE_CONFIRM_FROZEN_NO_UPLOAD",
            "TEST_ONLY PRE_CONFIRM predictions are frozen without CONFIRM endpoints",
            extra={"model_root_sha256": value.model_manifest.root_sha256, "pre_confirm_root_sha256": value.root_sha256, "dev_thresholds_met": analysis.passes},
        )
        provisional = PreConfirmPredictionFreeze(
            "PRE_CONFIRM",
            value.model_manifest.root_sha256,
            value.root_sha256,
            value.assignment_root_sha256,
            value.dev_active_set.artifact_root_sha256,
            dev_continue.artifact_root_sha256,
            analysis,
            predictions,
            "0" * 64,
            authority,
        )
        root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **provisional.canonical()})
        sealed = replace(provisional, artifact_root_sha256=root)
        # The root is part of the object but deliberately excluded from canonical content.
        return _seal(sealed, root)


@dataclass(frozen=True, slots=True)
class PostFreezeConfirmEndpoints:
    phase: Literal["POST_FREEZE_CONFIRM_ENDPOINTS"]
    model_root_sha256: str
    pre_confirm_root_sha256: str
    prediction_root_sha256: str
    active_set_root_sha256: str
    active_confirm_slots: tuple[str, ...]
    endpoints: tuple[ExactHostedEndpoint, ...]
    artifact_root_sha256: str
    authority: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "model_root_sha256": self.model_root_sha256,
            "pre_confirm_root_sha256": self.pre_confirm_root_sha256,
            "prediction_root_sha256": self.prediction_root_sha256,
            "active_set_root_sha256": self.active_set_root_sha256,
            "active_confirm_slots": list(self.active_confirm_slots),
            "endpoints": [endpoint.canonical() for endpoint in self.endpoints],
            "authority": dict(self.authority),
        }


def make_post_freeze_confirm_endpoints(
    freeze_artifact: Any,
    active_set: Any,
    endpoints: Sequence[ExactHostedEndpoint],
) -> PostFreezeConfirmEndpoints:
    _require_sealed(freeze_artifact, PreConfirmPredictionFreeze, "PRE_CONFIRM")
    _require_active_set(active_set, "CONFIRM")
    if active_set.assignment_root_sha256 != freeze_artifact.assignment_root_sha256:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "CONFIRM active set does not bind the frozen assignment root")
    if not freeze_artifact.dev_analysis.passes:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "CONFIRM endpoints require a successful frozen DEV_CONTINUE decision")
    if len(endpoints) != 8 or any(type(endpoint) is not ExactHostedEndpoint for endpoint in endpoints):
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "POST_FREEZE requires exactly eight typed active CONFIRM endpoints")
    typed_endpoints = tuple(endpoints)
    if tuple(endpoint.slot_id for endpoint in typed_endpoints) != active_set.active_slots:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "POST_FREEZE endpoints must match the sealed CONFIRM active set")
    authority = _authority(
        "CANDIDATE_EXACT_POST_FREEZE_ENDPOINTS_NO_UPLOAD",
        "TEST_ONLY CONFIRM endpoints are bound after the frozen prediction root",
        extra={"model_root_sha256": freeze_artifact.model_root_sha256, "pre_confirm_root_sha256": freeze_artifact.pre_confirm_root_sha256, "prediction_root_sha256": freeze_artifact.artifact_root_sha256},
    )
    provisional = PostFreezeConfirmEndpoints(
        "POST_FREEZE_CONFIRM_ENDPOINTS",
        freeze_artifact.model_root_sha256,
        freeze_artifact.pre_confirm_root_sha256,
        freeze_artifact.artifact_root_sha256,
        active_set.artifact_root_sha256,
        active_set.active_slots,
        typed_endpoints,
        "0" * 64,
        authority,
    )
    root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **provisional.canonical()})
    return _seal(replace(provisional, artifact_root_sha256=root), root)


@dataclass(frozen=True, slots=True)
class PostFreezeConfirmEvaluation:
    phase: Literal["POST_FREEZE_CONFIRM_ENDPOINTS"]
    model_root_sha256: str
    pre_confirm_root_sha256: str
    prediction_root_sha256: str
    endpoints_root_sha256: str
    dev_continue_root_sha256: str
    active_set_root_sha256: str
    active_confirm_slots: tuple[str, ...]
    unit_rows: Mapping[str, Mapping[str, Any]]
    mechanics_total: ExactTotal
    comparator_total: ExactTotal
    constant_total: ExactTotal
    mechanics_comparator_ratio: ExactRatio
    mechanics_constant_ratio: ExactRatio
    concordances: tuple[ExactConcordance, ...]
    sign_test: Mapping[str, Any]
    thresholds: Mapping[str, Any]
    passes: bool
    artifact_root_sha256: str
    authority: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "model_root_sha256": self.model_root_sha256,
            "pre_confirm_root_sha256": self.pre_confirm_root_sha256,
            "prediction_root_sha256": self.prediction_root_sha256,
            "endpoints_root_sha256": self.endpoints_root_sha256,
            "dev_continue_root_sha256": self.dev_continue_root_sha256,
            "active_set_root_sha256": self.active_set_root_sha256,
            "active_confirm_slots": list(self.active_confirm_slots),
            "unit_rows": {slot: dict(row) for slot, row in self.unit_rows.items()},
            "mechanics_total": self.mechanics_total.canonical(),
            "comparator_total": self.comparator_total.canonical(),
            "constant_total": self.constant_total.canonical(),
            "mechanics_comparator_ratio": self.mechanics_comparator_ratio.canonical(),
            "mechanics_constant_ratio": self.mechanics_constant_ratio.canonical(),
            "concordances": [item.canonical() for item in self.concordances],
            "sign_test": dict(self.sign_test),
            "thresholds": dict(self.thresholds),
            "passes": self.passes,
            "authority": dict(self.authority),
        }


def evaluate_post_freeze(
    freeze_artifact: Any,
    endpoint_artifact: Any,
) -> PostFreezeConfirmEvaluation:
    """Evaluate a typed post-freeze endpoint artifact under unchanged thresholds."""

    _require_sealed(freeze_artifact, PreConfirmPredictionFreeze, "PRE_CONFIRM")
    _require_sealed(endpoint_artifact, PostFreezeConfirmEndpoints, "POST_FREEZE_CONFIRM_ENDPOINTS")
    if (
        endpoint_artifact.model_root_sha256 != freeze_artifact.model_root_sha256
        or endpoint_artifact.pre_confirm_root_sha256 != freeze_artifact.pre_confirm_root_sha256
        or endpoint_artifact.prediction_root_sha256 != freeze_artifact.artifact_root_sha256
    ):
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "POST_FREEZE endpoint roots do not bind the exact PRE_CONFIRM prediction freeze")
    if not freeze_artifact.dev_analysis.passes:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "CONFIRM evaluation requires a successful frozen DEV_CONTINUE decision")
    slots = endpoint_artifact.active_confirm_slots
    if len(slots) != 8 or tuple(endpoint.slot_id for endpoint in endpoint_artifact.endpoints) != slots:
        raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "CONFIRM endpoints do not match their sealed eight-unit active set")
    endpoints = {endpoint.slot_id: endpoint for endpoint in endpoint_artifact.endpoints}
    mechanics_errors: list[ExactError] = []
    comparator_errors: list[ExactError] = []
    constant_errors: list[ExactError] = []
    rows: dict[str, Mapping[str, Any]] = {}
    threshold = project_exact(THRESHOLDS["unit_win_margin_points"])
    wins = 0
    with gmpy2.context(_ctx()):
        for slot in slots:
            prediction_row = freeze_artifact.predictions.get(slot)
            endpoint = endpoints.get(slot)
            if prediction_row is None or endpoint is None:
                raise _fail("STATISTICS_PHASE_ARTIFACT_INVALID", "active endpoint is absent from frozen predictions")
            mechanics_error = absolute_error(endpoint, prediction_row["mechanics"])
            comparator_error = absolute_error(endpoint, prediction_row["comparator"])
            constant_error = absolute_error(endpoint, prediction_row["dev_constant"])
            win_difference = comparator_error.value - mechanics_error.value
            win = win_difference >= threshold
            wins += int(win)
            mechanics_errors.append(mechanics_error)
            comparator_errors.append(comparator_error)
            constant_errors.append(constant_error)
            rows[slot] = freeze(
                {
                    "endpoint_root_sha256": endpoint.root_sha256,
                    "mechanics_prediction": prediction_row["mechanics"].canonical(),
                    "comparator_prediction": prediction_row["comparator"].canonical(),
                    "dev_constant_prediction": prediction_row["dev_constant"].canonical(),
                    "mechanics_error": mechanics_error.canonical(),
                    "comparator_error": comparator_error.canonical(),
                    "constant_error": constant_error.canonical(),
                    "unit_win_difference_c99_hex": mpfr_c99_hex(win_difference),
                    "unit_win_threshold": projection_record(THRESHOLDS["unit_win_margin_points"]),
                    "mechanics_win": win,
                }
            )
        concordances = tuple(
            strict_concordance(endpoints[left].yobs, endpoints[right].yobs, freeze_artifact.predictions[left]["mechanics"], freeze_artifact.predictions[right]["mechanics"])
            for left_index, left in enumerate(slots)
            for right in slots[left_index + 1 :]
        )
        mechanics_total = total_errors(mechanics_errors)
        comparator_total = total_errors(comparator_errors)
        constant_total = total_errors(constant_errors)
        comparator_ratio = error_ratio(mechanics_total, comparator_total)
        constant_ratio = error_ratio(mechanics_total, constant_total)
        comparator_ratio_threshold = compare_ratio_threshold(comparator_ratio, THRESHOLDS["confirm_raw_ratio_maximum"])
        constant_ratio_threshold = compare_ratio_threshold(constant_ratio, THRESHOLDS["confirm_constant_ratio_maximum"])
        concordant_count = sum(item.strict_concordant for item in concordances)
        sign = sign_test_values(wins)
        thresholds = freeze(
            {
                "unit_win_margin": projection_record(THRESHOLDS["unit_win_margin_points"]),
                "confirm_raw_ratio": comparator_ratio_threshold.canonical(),
                "confirm_constant_ratio": constant_ratio_threshold.canonical(),
                "concordance_margin": projection_record(THRESHOLDS["concordance_margin_points"]),
                "confirm_wins_minimum": 7,
                "confirm_concordant_pairs_minimum": 20,
                "concordant_pairs": concordant_count,
                "total_pairs": 28,
                "dev_continue_passed": freeze_artifact.dev_analysis.passes,
            }
        )
        passes = freeze_artifact.dev_analysis.passes and wins >= 7 and comparator_ratio_threshold.passed and constant_ratio_threshold.passed and concordant_count >= 20
        authority = _authority(
            "CANDIDATE_EXACT_POST_FREEZE_EVALUATED_NO_UPLOAD",
            "TEST_ONLY POST_FREEZE diagnostics retain zero authority regardless of thresholds",
            extra={"model_root_sha256": freeze_artifact.model_root_sha256, "prediction_root_sha256": freeze_artifact.artifact_root_sha256, "endpoint_artifact_root_sha256": endpoint_artifact.artifact_root_sha256, "confirm_thresholds_met": passes},
        )
        provisional = PostFreezeConfirmEvaluation(
            "POST_FREEZE_CONFIRM_ENDPOINTS",
            freeze_artifact.model_root_sha256,
            freeze_artifact.pre_confirm_root_sha256,
            freeze_artifact.artifact_root_sha256,
            endpoint_artifact.artifact_root_sha256,
            freeze_artifact.dev_continue_root_sha256,
            endpoint_artifact.active_set_root_sha256,
            slots,
            MappingProxyType(rows),
            mechanics_total,
            comparator_total,
            constant_total,
            comparator_ratio,
            constant_ratio,
            concordances,
            sign,
            thresholds,
            passes,
            "0" * 64,
            authority,
        )
        root = canonical_sha256({"schema": "eval.v6.3.1.exact-statistics.phase-artifact", **provisional.canonical()})
        return _seal(replace(provisional, artifact_root_sha256=root), root)


__all__ = [
    "CALIBRATION_BUDGET",
    "CANDIDATE_EXACT_MODEL_MANIFEST",
    "CANDIDATE_EXACT_MODEL_ROOT_SHA256",
    "CONFIRM_PRIMARY_SLOTS",
    "CONFIRM_RESERVE_SLOT",
    "CONFIRM_SLOTS",
    "CORRECTION_DOCUMENT_SHA256",
    "DEV_PRIMARY_SLOTS",
    "DEV_RESERVE_SLOT",
    "DEV_SLOTS",
    "DevContinueDecision",
    "ExactConcordance",
    "ExactError",
    "ExactHostedEndpoint",
    "ExactLocalUnit",
    "ExactModelManifest",
    "ExactPrediction",
    "ExactRatio",
    "ExactRational",
    "ExactStatisticsError",
    "ExactTotal",
    "FeaturePoint",
    "FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256",
    "GOLDEN_MANIFEST_ROOT_SHA256",
    "HostedPollReceipt",
    "LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX",
    "LARGE_RATIONAL_GOLDEN_INPUT",
    "LedgerActiveSet",
    "MPFR_PRECISION_BITS",
    "MPFR_ROUNDING",
    "NIGFit",
    "PostFreezeConfirmEndpoints",
    "PostFreezeConfirmEvaluation",
    "PreConfirmPredictionFreeze",
    "PRODUCTION_BUDGET",
    "RETIRED_LEGACY_MODEL_ROOT_SHA256",
    "THRESHOLDS",
    "TestOnlyPreConfirmInput",
    "ThresholdComparison",
    "absolute_error",
    "compare_exact_threshold",
    "compare_ratio_threshold",
    "constant_prediction",
    "display_mpfr",
    "error_ratio",
    "exact_abs",
    "exact_add",
    "exact_divide",
    "exact_mean",
    "exact_multiply",
    "exact_statistics_readiness",
    "exact_subtract",
    "evaluate_post_freeze",
    "evaluate_dev_continue",
    "fit_nig",
    "freeze_pre_confirm_predictions",
    "full_precision_golden_vector",
    "make_post_freeze_confirm_endpoints",
    "make_test_only_ledger_active_set",
    "make_test_only_pre_confirm_input",
    "mpfr_c99_hex",
    "parse_mpfr_c99_hex",
    "predict",
    "project_exact",
    "projection_record",
    "sign_test_values",
    "strict_concordance",
    "total_errors",
    "validate_model_root",
]
