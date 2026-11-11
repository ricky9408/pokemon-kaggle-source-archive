"""V6.3.1 assignment/support *offline conformance* core.

This module deliberately has no policy pin, signature verifier, timestamp
client, permit issuer, uploader, holdout reader, or live composer.  Its typed
objects are useful for reproducing the binding deterministic calculations with
offline fixtures only; every public result is zero-authority.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
import hashlib
from itertools import combinations
import math
import re
from types import MappingProxyType
from typing import Any

import gmpy2

from .common import CALIBRATION_BUDGET, PRODUCTION_BUDGET, canonical_json_bytes, canonical_sha256, zero_authority


UNIT_IDS = tuple(f"U{i:02d}" for i in range(1, 17))
FEATURE_KEYS = tuple(f"F{i}" for i in range(1, 7))
BOOTSTRAP_REPLICATES = 10_000
CONTROL_COUNT = 4
SEEDS_PER_CONTROL = 300
EPSILON = Decimal("0.000000000001")
FEATURE_PLACES = Decimal("0.000000000001")
MPFR_PRECISION_BITS = 256
BOOTSTRAP_DOMAIN = b"V631/ASSIGNMENT-SUPPORT/BOOTSTRAP"
SELECTION_DOMAIN = b"V631/G4/DRAND-SELECTION"
FAS_MAGIC = b"V631FAS1"
FAS_HEADER_BYTES = 140
FAS_RECORD_BYTES = 4
_HEX = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_SIGNED_INTEGER = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")
_CANONICAL_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_ISSUED: dict[int, tuple[bytes, object, tuple[int, ...], tuple[tuple[int, bytes], ...]]] = {}
TEST_ONLY_COMPONENT_PROVENANCE = "TEST_ONLY_CALLER_LABELS"
TEST_ONLY_BOOTSTRAP_DERIVATION = "TEST_ONLY_CALLER_SUPPLIED_ENDPOINTS"
DERIVED_COMPONENT_PROVENANCE = "GRAPH_DERIVED_FROM_AUTHENTICATED_POPULATION"
DERIVED_BOOTSTRAP_DERIVATION = "DERIVED_FROM_REPLAY_VERIFIED_PAIRED_BLOCKS"
SYNTAX_ONLY_FEASIBLE_LIST = "TEST_ONLY_SYNTAX_ONLY_UNVERIFIED"
DERIVED_FEASIBLE_LIST = "DERIVED_FROM_COMPLETE_SUPPORT"


class AssignmentSupportError(ValueError):
    """A binding assignment/support conformance check failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> AssignmentSupportError:
    return AssignmentSupportError(code, message)


def _digest(value: str, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise _fail("ROOT_ORDER_VIOLATION", f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ExactRational:
    """Canonical reduced rational used as the only authoritative scalar."""

    numerator: str
    denominator: str

    def __post_init__(self) -> None:
        if (
            type(self.numerator) is not str
            or type(self.denominator) is not str
            or _CANONICAL_SIGNED_INTEGER.fullmatch(self.numerator) is None
            or _CANONICAL_POSITIVE_INTEGER.fullmatch(self.denominator) is None
        ):
            raise _fail("LOCAL_FEATURE_RATIONAL_NONCANONICAL", "rational integers are not canonical decimal strings")
        numerator, denominator = int(self.numerator), int(self.denominator)
        if math.gcd(abs(numerator), denominator) != 1 or (numerator == 0 and denominator != 1):
            raise _fail("LOCAL_FEATURE_RATIONAL_NONCANONICAL", "rational must be gcd-reduced and zero must be 0/1")

    @classmethod
    def from_fraction(cls, value: Fraction, *, label: str = "value") -> "ExactRational":
        if type(value) is not Fraction:
            raise _fail("LOCAL_FEATURE_RATIONAL_NONCANONICAL", f"{label} must be an exact Fraction")
        if value < -1 or value > 1:
            raise _fail("LOCAL_FEATURE_BOOTSTRAP_INVALID", f"{label} must be in [-1, 1]")
        return cls(str(value.numerator), str(value.denominator))

    @classmethod
    def make(cls, value: Any, *, label: str = "value") -> "ExactRational":
        if type(value) is ExactRational:
            return value
        if isinstance(value, Mapping) and set(value) == {"numerator", "denominator"}:
            try:
                return cls(value["numerator"], value["denominator"])
            except AssignmentSupportError:
                raise
            except Exception as exc:
                raise _fail("LOCAL_FEATURE_RATIONAL_NONCANONICAL", f"{label} rational object is malformed") from exc
        raise _fail(
            "LOCAL_FEATURE_EXACT_VALUE_MISSING",
            f"{label} must be an ExactRational or the canonical numerator/denominator object",
        )

    def as_fraction(self) -> Fraction:
        return Fraction(int(self.numerator), int(self.denominator))

    def canonical(self) -> dict[str, str]:
        return {"numerator": self.numerator, "denominator": self.denominator}


def _mpfr_context() -> Any:
    context = gmpy2.get_context().copy()
    context.precision = MPFR_PRECISION_BITS
    context.round = gmpy2.RoundToNearest
    return context


@lru_cache(maxsize=262_144)
def _project_mpfr(value: ExactRational) -> Any:
    with gmpy2.context(_mpfr_context()):
        return gmpy2.mpfr(gmpy2.mpq(int(value.numerator), int(value.denominator)))


@lru_cache(maxsize=262_144)
def _mpfr_projection_ratio(value: ExactRational) -> tuple[str, str]:
    numerator, denominator = _project_mpfr(value).as_integer_ratio()
    return str(numerator), str(denominator)


@lru_cache(maxsize=262_144)
def _display(value: ExactRational) -> str:
    with gmpy2.context(_mpfr_context()):
        rendered = format(_project_mpfr(value), ".12f")
    if Decimal(rendered) == 0:
        return "0.000000000000"
    return rendered


def _mpfr_distance(left: ExactRational, right: ExactRational) -> Any:
    """Compute an unrounded MPFR-256 distance from exact rational operands."""
    with gmpy2.context(_mpfr_context()):
        return abs(_project_mpfr(left) - _project_mpfr(right))


@dataclass(frozen=True)
class FeaturePoint:
    """Exact F1-F6, equal-weight x, and comparator R for one endpoint."""

    features: tuple[ExactRational, ExactRational, ExactRational, ExactRational, ExactRational, ExactRational]
    x: ExactRational
    r: ExactRational

    @classmethod
    def make(cls, features: Sequence[Any], r: Any) -> "FeaturePoint":
        if len(features) != 6:
            raise _fail("LOCAL_FEATURE_ROOT_INVALID", "F1-F6 must contain exactly six values")
        values = tuple(ExactRational.make(value, label=f"F{i + 1}") for i, value in enumerate(features))
        if values[5].as_fraction() > 0:
            raise _fail(
                "LOCAL_FEATURE_BOOTSTRAP_INVALID",
                "F6 is a seat-sensitivity penalty and must be in [-1, 0]",
            )
        raw_r = ExactRational.make(r, label="R")
        x_fraction = sum((value.as_fraction() for value in values), Fraction(0, 1)) / 6
        x = ExactRational.from_fraction(x_fraction, label="x")
        return cls(values, x, raw_r)  # type: ignore[arg-type]

    @property
    def display_features(self) -> tuple[str, str, str, str, str, str]:
        return tuple(_display(value) for value in self.features)  # type: ignore[return-value]

    @property
    def display_x(self) -> str:
        return _display(self.x)

    @property
    def display_r(self) -> str:
        return _display(self.r)

    @property
    def mpfr256_projection_sha256(self) -> str:
        values = self.features + (self.x, self.r)
        return canonical_sha256(
            {
                "schema": "eval.v6.3.1.mpfr256-projections",
                "precision_bits": MPFR_PRECISION_BITS,
                "rounding": "MPFR_RNDN",
                "values": [
                    {"numerator": numerator, "denominator": denominator}
                    for numerator, denominator in (_mpfr_projection_ratio(value) for value in values)
                ],
            }
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
            "mpfr256_projection_sha256": self.mpfr256_projection_sha256,
            "display_12": {
                **dict(zip(FEATURE_KEYS, self.display_features, strict=True)),
                "x": self.display_x,
                "R": self.display_r,
            },
        }


EPSILON_RATIONAL = ExactRational("1", "1000000000000")


def _validated_point(value: Any, label: str) -> FeaturePoint:
    if type(value) is not FeaturePoint:
        raise _fail("LOCAL_FEATURE_BOOTSTRAP_INVALID", f"{label} must be a FeaturePoint")
    try:
        rebuilt = FeaturePoint.make(value.features, value.r)
    except (TypeError, ValueError, AssignmentSupportError) as exc:
        raise _fail("LOCAL_FEATURE_BOOTSTRAP_INVALID", f"{label} is invalid") from exc
    if rebuilt != value:
        raise _fail("LOCAL_FEATURE_RATIONAL_DIVERGENCE", f"{label} x must be the exact equal-weight F1-F6 composite")
    return value


@dataclass(frozen=True)
class OfflineUnitCandidate:
    """One TEST_ONLY neutral unit before U01-U16 canonical indexing.

    The component strings remain non-authoritative until a separate semantic
    population composer derives them from the authenticated pair graphs.
    """

    archive_sha256: str
    source_component_id: str
    lineage_time_component_id: str
    development_control_component_id: str
    intervention_component_id: str
    point: FeaturePoint
    component_provenance: str = TEST_ONLY_COMPONENT_PROVENANCE

    def __post_init__(self) -> None:
        _digest(self.archive_sha256, "archive_sha256")
        for name in ("source_component_id", "lineage_time_component_id", "development_control_component_id", "intervention_component_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value.encode("utf-8")) > 255:
                raise _fail("POPULATION_COMPONENT_CONSTRAINT_FAILURE", f"{name} must be a nonempty bounded string")
        if self.component_provenance != TEST_ONLY_COMPONENT_PROVENANCE:
            raise _fail(
                "POPULATION_COMPONENT_CONSTRAINT_FAILURE",
                "raw OfflineUnitCandidate component labels are TEST_ONLY and never graph-derived",
            )
        _validated_point(self.point, "point")


@dataclass(frozen=True)
class IndexedUnit:
    index: int
    unit_id: str
    candidate: OfflineUnitCandidate

    def canonical(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "unit_id": self.unit_id,
            "archive_sha256": self.candidate.archive_sha256,
            "source_component_id": self.candidate.source_component_id,
            "lineage_time_component_id": self.candidate.lineage_time_component_id,
            "development_control_component_id": self.candidate.development_control_component_id,
            "intervention_component_id": self.candidate.intervention_component_id,
            "component_provenance": self.candidate.component_provenance,
        }


@dataclass(frozen=True)
class OfflineFeatureTensorCandidate:
    """A retained, canonical offline point/bootstrap tensor, never live evidence."""

    model_root: str
    population_root: str
    local_panel_root: str
    units: tuple[IndexedUnit, ...]
    point: tuple[FeaturePoint, ...]
    bootstrap: tuple[tuple[FeaturePoint, ...], ...]
    bootstrap_root: str
    component_derivation_state: str
    bootstrap_derivation_state: str
    _token: object

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": "eval.v6.3.1.offline-feature-tensor-candidate",
            "model_root": self.model_root,
            "population_root": self.population_root,
            "local_panel_root": self.local_panel_root,
            "units": [item.canonical() for item in self.units],
            "point": [item.canonical() for item in self.point],
            "bootstrap_shape": [len(self.bootstrap), len(self.bootstrap[0]) if self.bootstrap else 0],
            "bootstrap_root": self.bootstrap_root,
            "component_derivation_state": self.component_derivation_state,
            "bootstrap_derivation_state": self.bootstrap_derivation_state,
            "offline_conformance_only": True,
        }


def _tensor_points(value: OfflineFeatureTensorCandidate) -> tuple[FeaturePoint, ...]:
    return value.point + tuple(point for row in value.bootstrap for point in row)


def _point_receipts(points: Sequence[FeaturePoint]) -> tuple[tuple[int, bytes], ...]:
    unique: dict[int, FeaturePoint] = {}
    for point in points:
        unique.setdefault(id(point), point)
    return tuple(
        (identity, canonical_json_bytes(point.canonical()))
        for identity, point in sorted(unique.items())
    )


def _bootstrap_content_root(
    matrix: Sequence[Sequence[FeaturePoint]],
    *,
    model_root: str,
    population_root: str,
    local_panel_root: str,
) -> str:
    """Stream an order-sensitive exact endpoint root without display feedback."""

    digest = hashlib.sha256()
    digest.update(b"V631/OFFLINE-TEST-FIXTURE/EXACT-BOOTSTRAP-TENSOR\x00")
    digest.update(bytes.fromhex(model_root))
    digest.update(bytes.fromhex(population_root))
    digest.update(bytes.fromhex(local_panel_root))
    digest.update(len(matrix).to_bytes(4, "big"))
    digest.update((len(matrix[0]) if matrix else 0).to_bytes(2, "big"))
    point_roots: dict[FeaturePoint, bytes] = {}
    for row in matrix:
        for point in row:
            root = point_roots.get(point)
            if root is None:
                root = bytes.fromhex(canonical_sha256(point.canonical()))
                point_roots[point] = root
            digest.update(root)
    return digest.hexdigest()


def _issue(value: OfflineFeatureTensorCandidate) -> OfflineFeatureTensorCandidate:
    points = _tensor_points(value)
    _ISSUED[id(value)] = (
        canonical_json_bytes(value.canonical()),
        value._token,
        tuple(id(point) for point in points),
        _point_receipts(points),
    )
    return value


def validate_offline_feature_tensor(value: Any) -> OfflineFeatureTensorCandidate:
    if type(value) is not OfflineFeatureTensorCandidate or value._token is None:
        raise _fail("LOCAL_FEATURE_ROOT_INVALID", "an issued OfflineFeatureTensorCandidate is required")
    issued = _ISSUED.get(id(value))
    if issued is None or issued[1] is not value._token:
        raise _fail("LOCAL_FEATURE_ROOT_INVALID", "feature tensor was not issued by this module")
    try:
        current = canonical_json_bytes(value.canonical())
        points = _tensor_points(value)
    except Exception as exc:
        raise _fail("LOCAL_FEATURE_ROOT_INVALID", "feature tensor is not canonical") from exc
    if (
        current != issued[0]
        or tuple(id(point) for point in points) != issued[2]
        or _point_receipts(points) != issued[3]
    ):
        raise _fail("LOCAL_FEATURE_ROOT_INVALID", "feature tensor mutated after issuance")
    return value


def make_test_only_offline_feature_tensor_fixture(
    units: Sequence[OfflineUnitCandidate],
    bootstrap_by_archive: Mapping[str, Sequence[FeaturePoint]],
    *,
    model_root: str,
    population_root: str,
    local_panel_root: str,
) -> OfflineFeatureTensorCandidate:
    """Bind caller-supplied TEST_ONLY endpoints for arithmetic conformance.

    These rows are not recomputed from the required paired-seat transcript
    blocks and therefore can never feed the feasible-list builder.
    """
    model_root, population_root, local_panel_root = (
        _digest(model_root, "model_root"),
        _digest(population_root, "population_root"),
        _digest(local_panel_root, "local_panel_root"),
    )
    if len(units) != 16:
        raise _fail("POPULATION_COMPONENT_CONSTRAINT_FAILURE", "exactly sixteen neutral units are required")
    ordered = tuple(sorted(units, key=lambda unit: unit.archive_sha256))
    if len({unit.archive_sha256 for unit in ordered}) != 16:
        raise _fail("POPULATION_COMPONENT_CONSTRAINT_FAILURE", "archive_sha256 values must be unique")
    if set(bootstrap_by_archive) != {unit.archive_sha256 for unit in ordered}:
        raise _fail("LOCAL_PANEL_INCOMPLETE", "bootstrap rows must bind exactly the sixteen archive hashes")
    columns = []
    for unit in ordered:
        _validated_point(unit.point, "point")
        rows = tuple(bootstrap_by_archive[unit.archive_sha256])
        if len(rows) != BOOTSTRAP_REPLICATES:
            raise _fail("LOCAL_PANEL_INCOMPLETE", "every unit must have exactly 10,000 bootstrap endpoints")
        for row in rows:
            _validated_point(row, "bootstrap endpoint")
        columns.append(rows)
    matrix = tuple(tuple(column[replicate] for column in columns) for replicate in range(BOOTSTRAP_REPLICATES))
    indexed = tuple(IndexedUnit(index, UNIT_IDS[index], unit) for index, unit in enumerate(ordered))
    bootstrap_root = _bootstrap_content_root(
        matrix,
        model_root=model_root,
        population_root=population_root,
        local_panel_root=local_panel_root,
    )
    return _issue(
        OfflineFeatureTensorCandidate(
            model_root,
            population_root,
            local_panel_root,
            indexed,
            tuple(unit.point for unit in ordered),
            matrix,
            bootstrap_root,
            TEST_ONLY_COMPONENT_PROVENANCE,
            TEST_ONLY_BOOTSTRAP_DERIVATION,
            object(),
        )
    )


def make_offline_feature_tensor(*_: Any, **__: Any) -> OfflineFeatureTensorCandidate:
    """Retired unsafe surface: caller-provided bootstrap rows are not evidence."""

    raise _fail(
        "LOCAL_FEATURE_BOOTSTRAP_INVALID",
        "use make_test_only_offline_feature_tensor_fixture for conformance only; "
        "a replay-derived tensor composer is not implemented",
    )


class _ShakeReader:
    def __init__(self, seed: bytes) -> None:
        self.seed = seed
        self.offset = 0
        self._data = b""

    def take(self, width: int) -> bytes:
        required = self.offset + width
        if required > len(self._data):
            length = max(required, max(64, len(self._data) * 2))
            self._data = hashlib.shake_256(self.seed).digest(length)
        value = self._data[self.offset:required]
        self.offset = required
        return value


def _draw_bounded(reader: _ShakeReader, modulus: int, width: int) -> tuple[int, int]:
    if modulus < 1:
        raise _fail("DRAND_EXPANSION_FAILURE", "bounded selection modulus must be positive")
    limit = (1 << (width * 8)) - ((1 << (width * 8)) % modulus)
    rejected = 0
    while True:
        draw = int.from_bytes(reader.take(width), "big")
        if draw < limit:
            return draw % modulus, rejected
        rejected += 1


def bounded_rejection_from_draws(draws: Iterable[int], *, modulus: int, width: int) -> tuple[int, int]:
    """Reference rejection sampler used by conformance tests and audit vectors."""
    if modulus < 1 or width < 1:
        raise _fail("DRAND_EXPANSION_FAILURE", "invalid bounded-draw parameters")
    limit = (1 << (width * 8)) - ((1 << (width * 8)) % modulus)
    rejected = 0
    for draw in draws:
        if type(draw) is not int or draw < 0 or draw >= 1 << (width * 8):
            raise _fail("DRAND_EXPANSION_FAILURE", "bounded draw is out of range")
        if draw < limit:
            return draw % modulus, rejected
        rejected += 1
    raise _fail("DRAND_EXPANSION_FAILURE", "draw stream ended before an unbiased value was accepted")


@dataclass(frozen=True)
class BootstrapIndexMatrix:
    """Packed 10000 x 4 x 300 common-resample matrix and rejection receipt."""

    packed: bytes
    rejection_counts: tuple[tuple[int, int, int, int], ...]
    key_sha256: str

    def indices(self, replicate: int, control: int) -> tuple[int, ...]:
        if not 0 <= replicate < BOOTSTRAP_REPLICATES or not 0 <= control < CONTROL_COUNT:
            raise IndexError("bootstrap index out of range")
        start = ((replicate * CONTROL_COUNT + control) * SEEDS_PER_CONTROL) * 2
        return tuple(int.from_bytes(self.packed[start + 2 * i:start + 2 * i + 2], "big") for i in range(SEEDS_PER_CONTROL))


def generate_bootstrap_index_matrix(*, model_root: str, population_root: str, local_panel_root: str) -> BootstrapIndexMatrix:
    """Generate the exact SHA256/SHAKE256/rejection common-seed matrix."""
    roots = (_digest(model_root, "model_root"), _digest(population_root, "population_root"), _digest(local_panel_root, "local_panel_root"))
    key = hashlib.sha256(BOOTSTRAP_DOMAIN + b"".join(bytes.fromhex(root) for root in roots)).digest()
    packed = bytearray(BOOTSTRAP_REPLICATES * CONTROL_COUNT * SEEDS_PER_CONTROL * 2)
    cursor = 0
    receipts: list[tuple[int, int, int, int]] = []
    for replicate in range(BOOTSTRAP_REPLICATES):
        counts = []
        for control in range(CONTROL_COUNT):
            reader = _ShakeReader(key + replicate.to_bytes(4, "big") + bytes((control,)))
            rejected = 0
            for _ in range(SEEDS_PER_CONTROL):
                index, rejections = _draw_bounded(reader, SEEDS_PER_CONTROL, 4)
                rejected += rejections
                packed[cursor:cursor + 2] = index.to_bytes(2, "big")
                cursor += 2
            counts.append(rejected)
        receipts.append(tuple(counts))
    return BootstrapIndexMatrix(bytes(packed), tuple(receipts), hashlib.sha256(key).hexdigest())


def _distance(metric: str, left: FeaturePoint, right: FeaturePoint) -> Any:
    if metric == "F":
        return max(_mpfr_distance(a, b) for a, b in zip(left.features, right.features, strict=True))
    if metric == "x":
        return _mpfr_distance(left.x, right.x)
    if metric == "R":
        return _mpfr_distance(left.r, right.r)
    raise AssertionError(metric)


def _supported(active: Sequence[FeaturePoint], target: FeaturePoint) -> bool:
    if len(active) != 6:
        raise _fail("ASSIGNMENT_STRUCTURAL_INELIGIBLE", "active DEV support requires six units")
    for metric in ("F", "x", "R"):
        radii = []
        for index, point in enumerate(active):
            distances = sorted(_distance(metric, point, other) for other_index, other in enumerate(active) if other_index != index)
            radii.append(distances[1])
        target_distance = sorted(_distance(metric, target, item) for item in active)[1]
        with gmpy2.context(_mpfr_context()):
            if target_distance > max(radii) + _project_mpfr(EPSILON_RATIONAL):
                return False
    return True


@dataclass(frozen=True)
class SupportRelation:
    dev_indices: tuple[int, int, int, int, int, int]
    target_index: int
    point_supported: bool
    bootstrap_pass_count: int

    @property
    def passed(self) -> bool:
        return self.point_supported and self.bootstrap_pass_count >= 9500


@dataclass(frozen=True)
class OfflineSupportLookupCandidate:
    tensor_root: str
    relations: tuple[SupportRelation, ...]
    root: str
    _token: object

    def _mapping(self) -> dict[tuple[tuple[int, ...], int], SupportRelation]:
        return {(relation.dev_indices, relation.target_index): relation for relation in self.relations}

    def relation(self, dev_indices: Iterable[int], target_index: int) -> SupportRelation:
        _assert_lookup(self)
        key = (tuple(sorted(dev_indices)), target_index)
        try:
            return self._mapping()[key]
        except KeyError as exc:
            raise _fail("SUPPORT_RECOMPUTATION_DIVERGENCE", "required DEV-set/target relation was not precomputed") from exc

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": "eval.v6.3.1.offline-support-lookup-candidate",
            "tensor_root": self.tensor_root,
            "relations": [
                {
                    "dev_indices": list(item.dev_indices),
                    "target_index": item.target_index,
                    "point_supported": item.point_supported,
                    "bootstrap_pass_count": item.bootstrap_pass_count,
                }
                for item in self.relations
            ],
            "root": self.root,
            "offline_conformance_only": True,
        }


_LOOKUPS: dict[int, bytes] = {}


def _tensor_root(tensor: OfflineFeatureTensorCandidate) -> str:
    return canonical_sha256(tensor.canonical())


def _assert_lookup(value: Any) -> OfflineSupportLookupCandidate:
    if type(value) is not OfflineSupportLookupCandidate or value._token is None:
        raise _fail("SUPPORT_RECOMPUTATION_DIVERGENCE", "an issued OfflineSupportLookupCandidate is required")
    expected = _LOOKUPS.get(id(value))
    body = {
        "schema": "eval.v6.3.1.support-lookup",
        "tensor_root": value.tensor_root,
        "relations": [
            {
                "dev_indices": list(item.dev_indices),
                "target_index": item.target_index,
                "point_supported": item.point_supported,
                "bootstrap_pass_count": item.bootstrap_pass_count,
            }
            for item in value.relations
        ],
    }
    if (
        expected is None
        or value.root != canonical_sha256(body)
        or canonical_json_bytes(value.canonical()) != expected
    ):
        raise _fail("SUPPORT_RECOMPUTATION_DIVERGENCE", "support lookup mutated or was not issued")
    return value


def precompute_support_lookup(
    tensor: OfflineFeatureTensorCandidate,
    dev_sets: Iterable[Iterable[int]],
) -> OfflineSupportLookupCandidate:
    """Precompute each requested six-unit DEV set/target once, never per record."""
    tensor = validate_offline_feature_tensor(tensor)
    sets = tuple(sorted({tuple(sorted(group)) for group in dev_sets}))
    if not sets:
        raise _fail("SUPPORT_RECOMPUTATION_DIVERGENCE", "at least one DEV set is required")
    relations: list[SupportRelation] = []
    for dev in sets:
        if len(dev) != 6 or len(set(dev)) != 6 or any(index not in range(16) for index in dev):
            raise _fail("SUPPORT_RECOMPUTATION_DIVERGENCE", "DEV lookup keys must be six distinct canonical indices")
        targets = tuple(index for index in range(16) if index not in dev)
        point_active = tuple(tensor.point[index] for index in dev)
        for target in targets:
            support_cache: dict[tuple[FeaturePoint, ...], bool] = {}
            count = 0
            for row in tensor.bootstrap:
                key = tuple(row[index] for index in dev) + (row[target],)
                supported = support_cache.get(key)
                if supported is None:
                    supported = _supported(key[:-1], key[-1])
                    support_cache[key] = supported
                if supported:
                    count += 1
            relations.append(SupportRelation(dev, target, _supported(point_active, tensor.point[target]), count))
    relations.sort(key=lambda item: (item.dev_indices, item.target_index))
    body = {"schema": "eval.v6.3.1.support-lookup", "tensor_root": _tensor_root(tensor), "relations": [{"dev_indices": list(item.dev_indices), "target_index": item.target_index, "point_supported": item.point_supported, "bootstrap_pass_count": item.bootstrap_pass_count} for item in relations]}
    value = OfflineSupportLookupCandidate(_tensor_root(tensor), tuple(relations), canonical_sha256(body), object())
    _LOOKUPS[id(value)] = canonical_json_bytes(value.canonical())
    return value


def _components(units: Sequence[IndexedUnit], indices: Iterable[int], field: str) -> Counter[str]:
    return Counter(getattr(units[index].candidate, field) for index in indices)


def _dev_pool_structural(units: Sequence[IndexedUnit], pool: Sequence[int]) -> bool:
    for field in ("source_component_id", "lineage_time_component_id", "development_control_component_id"):
        counts = _components(units, pool, field)
        if len(counts) < 5 or max(counts.values()) > 2:
            return False
    return True


def _active_dev_structural(units: Sequence[IndexedUnit], active: Sequence[int]) -> bool:
    for field in ("source_component_id", "lineage_time_component_id", "development_control_component_id"):
        counts = _components(units, active, field)
        if len(counts) < 4 or max(counts.values()) > 2:
            return False
    return len(_components(units, active, "intervention_component_id")) >= 3


def _confirm_structural(units: Sequence[IndexedUnit], pool: Sequence[int]) -> bool:
    for field in ("source_component_id", "lineage_time_component_id", "development_control_component_id"):
        counts = _components(units, pool, field)
        if len(counts) != 9 or max(counts.values()) != 1:
            return False
    return True


@dataclass(frozen=True)
class FeasibleAssignmentRecord:
    dev_pool_mask: int
    dev_reserve_index: int
    confirm_reserve_index: int

    def encode(self) -> bytes:
        return self.dev_pool_mask.to_bytes(2, "big") + bytes((self.dev_reserve_index, self.confirm_reserve_index))

    @property
    def dev_indices(self) -> tuple[int, ...]:
        return tuple(index for index in range(16) if self.dev_pool_mask & (1 << index) and index != self.dev_reserve_index)

    @property
    def confirm_indices(self) -> tuple[int, ...]:
        return tuple(index for index in range(16) if not (self.dev_pool_mask & (1 << index)) and index != self.confirm_reserve_index)


def _record_key(record: FeasibleAssignmentRecord) -> tuple[int, int, int]:
    return record.dev_pool_mask, record.dev_reserve_index, record.confirm_reserve_index


def _validate_record(record: FeasibleAssignmentRecord) -> None:
    if type(record.dev_pool_mask) is not int or record.dev_pool_mask < 0 or record.dev_pool_mask > 0xFFFF or record.dev_pool_mask.bit_count() != 7:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "record has an invalid seven-unit DEV pool mask")
    if record.dev_reserve_index not in range(16) or not record.dev_pool_mask & (1 << record.dev_reserve_index):
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "DEV reserve must be in DEV pool")
    if record.confirm_reserve_index not in range(16) or record.dev_pool_mask & (1 << record.confirm_reserve_index):
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "CONFIRM reserve must be outside DEV pool")


def assignment_structurally_eligible(units: Sequence[IndexedUnit], record: FeasibleAssignmentRecord) -> bool:
    _validate_record(record)
    if (
        len(units) != 16
        or any(type(unit) is not IndexedUnit for unit in units)
        or any(unit.index != index or unit.unit_id != UNIT_IDS[index] for index, unit in enumerate(units))
    ):
        raise _fail(
            "ASSIGNMENT_STRUCTURAL_INELIGIBLE",
            "assignment requires the complete canonical U01-U16 index",
        )
    pool = tuple(index for index in range(16) if record.dev_pool_mask & (1 << index))
    confirm_pool = tuple(index for index in range(16) if index not in pool)
    if not _dev_pool_structural(units, pool) or not _confirm_structural(units, confirm_pool):
        return False
    for field in ("source_component_id", "lineage_time_component_id", "development_control_component_id"):
        if set(_components(units, pool, field)).intersection(_components(units, confirm_pool, field)):
            return False
    if len(_components(units, range(16), "intervention_component_id")) < 5:
        return False
    dev_scenarios = (record.dev_indices,) + tuple(tuple(index for index in record.dev_indices if index != missing) + (record.dev_reserve_index,) for missing in record.dev_indices)
    confirm_scenarios = (record.confirm_indices,) + tuple(tuple(index for index in record.confirm_indices if index != missing) + (record.confirm_reserve_index,) for missing in record.confirm_indices)
    return all(_active_dev_structural(units, scenario) for scenario in dev_scenarios) and all(len(_components(units, scenario, "intervention_component_id")) >= 4 for scenario in confirm_scenarios)


def required_dev_sets(units: Sequence[IndexedUnit]) -> tuple[tuple[int, ...], ...]:
    """Structural prepass yielding unique active DEV sets for support precompute."""
    if (
        len(units) != 16
        or any(type(unit) is not IndexedUnit for unit in units)
        or any(unit.index != index or unit.unit_id != UNIT_IDS[index] for index, unit in enumerate(units))
    ):
        raise _fail(
            "ASSIGNMENT_STRUCTURAL_INELIGIBLE",
            "support precomputation requires the complete canonical U01-U16 index",
        )
    result: set[tuple[int, ...]] = set()
    for mask in range(1 << 16):
        if mask.bit_count() != 7:
            continue
        pool = tuple(index for index in range(16) if mask & (1 << index))
        if not _dev_pool_structural(units, pool):
            continue
        for reserve in pool:
            primary = tuple(index for index in pool if index != reserve)
            scenarios = (primary,) + tuple(tuple(index for index in primary if index != missing) + (reserve,) for missing in primary)
            if all(_active_dev_structural(units, scenario) for scenario in scenarios):
                result.update(tuple(sorted(scenario)) for scenario in scenarios)
    return tuple(sorted(result))


def _support_passes(record: FeasibleAssignmentRecord, lookup: OfflineSupportLookupCandidate) -> bool:
    dev_scenarios = (record.dev_indices,) + tuple(tuple(index for index in record.dev_indices if index != missing) + (record.dev_reserve_index,) for missing in record.dev_indices)
    confirm_pool = tuple(index for index in range(16) if not (record.dev_pool_mask & (1 << index)))
    try:
        if not lookup.relation(record.dev_indices, record.dev_reserve_index).passed:
            return False
        return all(lookup.relation(scenario, target).passed for scenario in dev_scenarios for target in confirm_pool)
    except AssignmentSupportError:
        raise


def enumerate_feasible_assignments(tensor: OfflineFeatureTensorCandidate, lookup: OfflineSupportLookupCandidate) -> tuple[FeasibleAssignmentRecord, ...]:
    """Exact mask/reserve enumeration; role permutations are deliberately absent."""
    tensor = validate_offline_feature_tensor(tensor)
    lookup = _assert_lookup(lookup)
    if lookup.tensor_root != _tensor_root(tensor):
        raise _fail("ROOT_ORDER_VIOLATION", "support lookup belongs to a substituted feature tensor")
    records: list[FeasibleAssignmentRecord] = []
    for mask in range(65536):
        if mask.bit_count() != 7:
            continue
        for dev_reserve in range(16):
            if not mask & (1 << dev_reserve):
                continue
            for confirm_reserve in range(16):
                if mask & (1 << confirm_reserve):
                    continue
                record = FeasibleAssignmentRecord(mask, dev_reserve, confirm_reserve)
                if assignment_structurally_eligible(tensor.units, record) and _support_passes(record, lookup):
                    records.append(record)
    return tuple(records)


@dataclass(frozen=True)
class OfflineFeasibleAssignmentListCandidate:
    binary: bytes
    manifest: Mapping[str, Any]
    records: tuple[FeasibleAssignmentRecord, ...]
    root: str
    derivation_state: str
    derivation_root: str | None
    _token: object

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": "eval.v6.3.1.offline-feasible-assignment-list-candidate",
            "binary_sha256": hashlib.sha256(self.binary).hexdigest(),
            "manifest": dict(self.manifest),
            "records": [record.encode().hex() for record in self.records],
            "root": self.root,
            "derivation_state": self.derivation_state,
            "derivation_root": self.derivation_root,
            "offline_conformance_only": True,
        }


_FEASIBLE: dict[int, tuple[bytes, object]] = {}


def validate_offline_feasible_assignment_list(value: Any) -> OfflineFeasibleAssignmentListCandidate:
    if type(value) is not OfflineFeasibleAssignmentListCandidate or value._token is None:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "an issued OfflineFeasibleAssignmentListCandidate is required")
    issued = _FEASIBLE.get(id(value))
    if issued is None or issued[1] is not value._token or canonical_json_bytes(value.canonical()) != issued[0]:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "feasible assignment list mutated or was not issued")
    return value


def _serialize_feasible_assignment_list(
    records: Sequence[FeasibleAssignmentRecord],
    *,
    population_root: str,
    local_panel_root: str,
    support_artifact_root: str,
    assignment_protocol_root: str,
    derivation_state: str,
    derivation_root: str | None,
) -> OfflineFeasibleAssignmentListCandidate:
    roots = tuple(_digest(root, label) for root, label in ((population_root, "population_root"), (local_panel_root, "local_panel_root"), (support_artifact_root, "support_artifact_root"), (assignment_protocol_root, "assignment_protocol_root")))
    typed = tuple(records)
    if any(type(record) is not FeasibleAssignmentRecord for record in typed):
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "records must be FeasibleAssignmentRecord values")
    for record in typed:
        _validate_record(record)
    if tuple(sorted(typed, key=_record_key)) != typed or len(set(typed)) != len(typed):
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "records must be unique and canonical mask/reserve order")
    header = FAS_MAGIC + b"".join(bytes.fromhex(root) for root in roots) + len(typed).to_bytes(4, "big")
    binary = header + b"".join(record.encode() for record in typed)
    digest = hashlib.sha256(binary).hexdigest()
    if derivation_state not in {SYNTAX_ONLY_FEASIBLE_LIST, DERIVED_FEASIBLE_LIST}:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "unknown feasible-list derivation state")
    if derivation_state == DERIVED_FEASIBLE_LIST:
        derivation_root = _digest(derivation_root, "feasible-list derivation root")  # type: ignore[arg-type]
    elif derivation_root is not None:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "syntax-only lists cannot claim a derivation root")
    manifest = MappingProxyType(
        {
            "schema": "eval.v6.3.1.feasible-assignment-list-manifest",
            "format": "V631FAS1",
            "population_root": roots[0],
            "local_panel_root": roots[1],
            "support_artifact_root": roots[2],
            "assignment_protocol_root": roots[3],
            "record_bytes": FAS_RECORD_BYTES,
            "record_count": len(typed),
            "byte_length": len(binary),
            "feasible_assignment_list_sha256": digest,
            "derivation_state": derivation_state,
            "derivation_root": derivation_root,
            "offline_conformance_only": True,
        }
    )
    value = OfflineFeasibleAssignmentListCandidate(
        binary,
        manifest,
        typed,
        canonical_sha256(dict(manifest)),
        derivation_state,
        derivation_root,
        object(),
    )
    _FEASIBLE[id(value)] = (canonical_json_bytes(value.canonical()), value._token)
    return value


def serialize_test_only_feasible_assignment_list_fixture(
    records: Sequence[FeasibleAssignmentRecord],
    *,
    population_root: str,
    local_panel_root: str,
    support_artifact_root: str,
    assignment_protocol_root: str,
) -> OfflineFeasibleAssignmentListCandidate:
    """Serialize syntax vectors only; the result is rejected by selection."""

    return _serialize_feasible_assignment_list(
        records,
        population_root=population_root,
        local_panel_root=local_panel_root,
        support_artifact_root=support_artifact_root,
        assignment_protocol_root=assignment_protocol_root,
        derivation_state=SYNTAX_ONLY_FEASIBLE_LIST,
        derivation_root=None,
    )


def serialize_feasible_assignment_list(*_: Any, **__: Any) -> OfflineFeasibleAssignmentListCandidate:
    """Retired unsafe surface: arbitrary records are not feasible evidence."""

    raise _fail(
        "FEASIBLE_LIST_CANONICALIZATION_FAILURE",
        "feasible lists must be derived by build_offline_feasible_assignment_list",
    )


def parse_feasible_assignment_list(binary: bytes, *, population_root: str, local_panel_root: str, support_artifact_root: str, assignment_protocol_root: str) -> tuple[FeasibleAssignmentRecord, ...]:
    expected = FAS_MAGIC + b"".join(bytes.fromhex(_digest(root, label)) for root, label in ((population_root, "population_root"), (local_panel_root, "local_panel_root"), (support_artifact_root, "support_artifact_root"), (assignment_protocol_root, "assignment_protocol_root")))
    if not isinstance(binary, bytes) or len(binary) < FAS_HEADER_BYTES or binary[:136] != expected:
        raise _fail("FEASIBLE_LIST_ROOT_MISMATCH", "feasible-list header roots do not match the frozen root order")
    count = int.from_bytes(binary[136:140], "big")
    if len(binary) != FAS_HEADER_BYTES + count * FAS_RECORD_BYTES:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "feasible-list binary length is malformed")
    records = tuple(FeasibleAssignmentRecord(int.from_bytes(binary[offset:offset + 2], "big"), binary[offset + 2], binary[offset + 3]) for offset in range(FAS_HEADER_BYTES, len(binary), FAS_RECORD_BYTES))
    _serialize_feasible_assignment_list(
        records,
        population_root=population_root,
        local_panel_root=local_panel_root,
        support_artifact_root=support_artifact_root,
        assignment_protocol_root=assignment_protocol_root,
        derivation_state=SYNTAX_ONLY_FEASIBLE_LIST,
        derivation_root=None,
    )
    return records


def build_offline_feasible_assignment_list(
    tensor: OfflineFeatureTensorCandidate,
    lookup: OfflineSupportLookupCandidate,
    *,
    assignment_protocol_root: str,
) -> OfflineFeasibleAssignmentListCandidate:
    """The only list builder that derives retained records from full support data."""
    tensor = validate_offline_feature_tensor(tensor)
    if tensor.component_derivation_state != DERIVED_COMPONENT_PROVENANCE:
        raise _fail(
            "POPULATION_COMPONENT_CONSTRAINT_FAILURE",
            "component IDs were not derived from an authenticated population graph",
        )
    if tensor.bootstrap_derivation_state != DERIVED_BOOTSTRAP_DERIVATION:
        raise _fail(
            "LOCAL_FEATURE_BOOTSTRAP_INVALID",
            "bootstrap endpoints were not recomputed from replay-verified paired blocks",
        )
    lookup = _assert_lookup(lookup)
    records = enumerate_feasible_assignments(tensor, lookup)
    derivation_root = canonical_sha256(
        {
            "schema": "eval.v6.3.1.complete-feasible-assignment-derivation",
            "tensor_root": _tensor_root(tensor),
            "support_lookup_root": lookup.root,
            "record_count": len(records),
            "record_sha256": canonical_sha256([record.encode().hex() for record in records]),
        }
    )
    return _serialize_feasible_assignment_list(
        records,
        population_root=tensor.population_root,
        local_panel_root=tensor.local_panel_root,
        support_artifact_root=lookup.root,
        assignment_protocol_root=assignment_protocol_root,
        derivation_state=DERIVED_FEASIBLE_LIST,
        derivation_root=derivation_root,
    )


@dataclass(frozen=True)
class OfflineDrandAssignmentCandidate:
    selected_index: int
    selected_record: FeasibleAssignmentRecord
    dev_order: tuple[str, ...]
    confirm_order: tuple[str, ...]
    dev_reserve: str
    confirm_reserve: str
    index_rejections: int
    dev_rejections: int
    confirm_rejections: int
    index_offset: int
    dev_offset: int
    confirm_offset: int
    report: Mapping[str, Any]


def _selection_reader(seed: bytes, domain: bytes) -> _ShakeReader:
    return _ShakeReader(seed + domain)


def _expand_drand_assignment(
    feasible: OfflineFeasibleAssignmentListCandidate,
    *,
    future_round_commitment_root: str,
    drand_chain_hash: str,
    round_number: int,
    randomness: bytes,
    drand_signature: bytes,
    test_only_fixture: bool,
) -> OfflineDrandAssignmentCandidate:
    """Pure deterministic expansion after the caller's derivation gate."""
    if not feasible.records:
        raise _fail("ASSIGNMENT_INFEASIBLE", "no feasible assignment exists")
    commitment, chain = _digest(future_round_commitment_root, "future_round_commitment_root"), _digest(drand_chain_hash, "drand_chain_hash")
    if (
        type(round_number) is not int
        or round_number < 1
        or round_number > (1 << 64) - 1
        or type(randomness) is not bytes
        or type(drand_signature) is not bytes
        or not randomness
        or not drand_signature
    ):
        raise _fail("DRAND_RESULT_INVALID", "drand expansion inputs are malformed")
    seed = hashlib.sha256(SELECTION_DOMAIN + bytes.fromhex(commitment) + bytes.fromhex(chain) + round_number.to_bytes(8, "big") + randomness + hashlib.sha256(drand_signature).digest()).digest()
    index_reader = _selection_reader(seed, b"ASSIGNMENT_INDEX")
    selected, index_rejections = _draw_bounded(index_reader, len(feasible.records), 32)
    record = feasible.records[selected]
    def shuffle(indices: Sequence[int], domain: bytes) -> tuple[tuple[str, ...], int, int]:
        reader = _selection_reader(seed, domain)
        values = list(indices)
        rejected = 0
        for position in range(len(values) - 1, 0, -1):
            swap, count = _draw_bounded(reader, position + 1, 32)
            rejected += count
            values[position], values[swap] = values[swap], values[position]
        return tuple(UNIT_IDS[index] for index in values), rejected, reader.offset
    dev_order, dev_rejections, dev_offset = shuffle(record.dev_indices, b"DEV_PRIMARY_ORDER")
    confirm_order, confirm_rejections, confirm_offset = shuffle(record.confirm_indices, b"CONFIRM_PRIMARY_ORDER")
    report = MappingProxyType(
        zero_authority(
            "TestOnlyDrandAssignmentFixture" if test_only_fixture else "OfflineDrandAssignmentCandidate",
            detail="Deterministic offline drand expansion only; live result authentication and campaign composition are absent.",
            extra={
                "selected_index": selected,
                "selected_record": record.encode().hex(),
                "drand_signature_verified": False,
                "future_round_commitment_authenticated": False,
                "feasible_list_derivation_state": feasible.derivation_state,
                "test_only_fixture": test_only_fixture,
                "offline_conformance_only": True,
            },
        )
    )
    return OfflineDrandAssignmentCandidate(selected, record, dev_order, confirm_order, UNIT_IDS[record.dev_reserve_index], UNIT_IDS[record.confirm_reserve_index], index_rejections, dev_rejections, confirm_rejections, index_reader.offset, dev_offset, confirm_offset, report)


def select_offline_drand_assignment(
    feasible: OfflineFeasibleAssignmentListCandidate,
    *,
    future_round_commitment_root: str,
    drand_chain_hash: str,
    round_number: int,
    randomness: bytes,
    drand_signature: bytes,
) -> OfflineDrandAssignmentCandidate:
    """Expand only a list derived from complete population and support inputs."""

    feasible = validate_offline_feasible_assignment_list(feasible)
    if feasible.derivation_state != DERIVED_FEASIBLE_LIST or feasible.derivation_root is None:
        raise _fail(
            "FEASIBLE_LIST_CANONICALIZATION_FAILURE",
            "syntax-only or caller-supplied records cannot enter assignment selection",
        )
    return _expand_drand_assignment(
        feasible,
        future_round_commitment_root=future_round_commitment_root,
        drand_chain_hash=drand_chain_hash,
        round_number=round_number,
        randomness=randomness,
        drand_signature=drand_signature,
        test_only_fixture=False,
    )


def select_test_only_drand_assignment_fixture(
    feasible: OfflineFeasibleAssignmentListCandidate,
    *,
    future_round_commitment_root: str,
    drand_chain_hash: str,
    round_number: int,
    randomness: bytes,
    drand_signature: bytes,
) -> OfflineDrandAssignmentCandidate:
    """Exercise expansion vectors without claiming the records are feasible."""

    feasible = validate_offline_feasible_assignment_list(feasible)
    if feasible.derivation_state != SYNTAX_ONLY_FEASIBLE_LIST:
        raise _fail("FEASIBLE_LIST_CANONICALIZATION_FAILURE", "fixture expansion requires a syntax-only list")
    return _expand_drand_assignment(
        feasible,
        future_round_commitment_root=future_round_commitment_root,
        drand_chain_hash=drand_chain_hash,
        round_number=round_number,
        randomness=randomness,
        drand_signature=drand_signature,
        test_only_fixture=True,
    )


def offline_assignment_result(*, state: str, detail: str, extra: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """The only public result surface: explicit Offline*Candidate, zero authority."""
    protected_extra = {"offline_conformance_only": True, "authenticated_assignment_composer_present": False}
    if extra:
        protected_extra.update(extra)
    return MappingProxyType(zero_authority(f"Offline{state}Candidate", detail=detail, extra=protected_extra))


class AuthenticatedAssignmentComposer:
    """Intentionally absent until a separately reviewed live implementation exists."""

    def __init__(self, *_: Any, **__: Any) -> None:
        raise ValueError("the live authenticated assignment composer is intentionally absent")


__all__ = [
    "AssignmentSupportError", "AuthenticatedAssignmentComposer", "BOOTSTRAP_REPLICATES", "BootstrapIndexMatrix", "CONTROL_COUNT", "DERIVED_BOOTSTRAP_DERIVATION", "DERIVED_COMPONENT_PROVENANCE", "DERIVED_FEASIBLE_LIST", "EPSILON", "EPSILON_RATIONAL", "ExactRational", "FAS_HEADER_BYTES", "FAS_MAGIC", "FAS_RECORD_BYTES", "FEATURE_KEYS", "FeaturePoint", "FeasibleAssignmentRecord", "IndexedUnit", "OfflineDrandAssignmentCandidate", "OfflineFeatureTensorCandidate", "OfflineFeasibleAssignmentListCandidate", "OfflineSupportLookupCandidate", "OfflineUnitCandidate", "SEEDS_PER_CONTROL", "SYNTAX_ONLY_FEASIBLE_LIST", "SupportRelation", "TEST_ONLY_BOOTSTRAP_DERIVATION", "TEST_ONLY_COMPONENT_PROVENANCE", "UNIT_IDS", "assignment_structurally_eligible", "bounded_rejection_from_draws", "build_offline_feasible_assignment_list", "enumerate_feasible_assignments", "generate_bootstrap_index_matrix", "make_test_only_offline_feature_tensor_fixture", "offline_assignment_result", "parse_feasible_assignment_list", "precompute_support_lookup", "required_dev_sets", "select_offline_drand_assignment", "select_test_only_drand_assignment_fixture", "serialize_test_only_feasible_assignment_list_fixture", "validate_offline_feature_tensor", "validate_offline_feasible_assignment_list",
]
