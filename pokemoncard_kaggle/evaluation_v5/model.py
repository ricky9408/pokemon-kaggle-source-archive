"""Frozen, outcome-blind prediction manifests for evaluation v5.

The objects in this module are intentionally small.  They describe a model
that was already selected on development evidence; this module has no fitting,
recalibration, file access, or outcome-selection path.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
from types import MappingProxyType
from typing import Any

from .canonical import canonical_sha256
from .charter import FEATURE_NAMES, PROTOCOL_ID
from .transfer import INPUT_SCHEMA


MODEL_SCHEMA = "evaluation_v5_prediction_manifest_v1"
PREDICTION_MANIFEST_SCHEMA = MODEL_SCHEMA
MODEL_KINDS = ("MCI", "FROZEN_COMPARATOR")
RATING_INTERPOLATIONS = ("piecewise_linear_clamp", "piecewise_linear_extrapolate")
COMPARATOR_IDENTITIES = (
    "nuisance-only null model",
    "raw local win-rate model",
    "L/T mean model",
    "local CVaR model",
    "action-imitation model",
    "search-rank model",
    "accepted-exploration model",
)
COMPARATOR_INPUT_KEYS = MappingProxyType(
    {
        "nuisance-only null model": None,
        "raw local win-rate model": "raw_local_win_rate",
        "L/T mean model": "lt_mean",
        "local CVaR model": "local_cvar",
        "action-imitation model": "action_imitation_score",
        "search-rank model": "search_rank_score",
        "accepted-exploration model": "accepted_exploration",
    }
)

_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "feature_names",
        "standardization_means",
        "standardization_scales",
        "feature_weights",
        "intercept",
        "mci_slope",
        "era_effects",
        "seat_effects",
        "opponent_rating_knots",
        "opponent_rating_values",
        "rating_interpolation",
        "probability_epsilon",
        "model_kind",
        "comparator_identity",
        "comparator_input_key",
        "comparator_input_mean",
        "comparator_input_scale",
        "comparator_slope",
        "comparator_null_value",
        "comparator_missing_behavior",
        "development_evidence_sha256",
        "executable_sha256",
        "created_at_utc",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class PredictionManifestError(ValueError):
    """A frozen model manifest or prediction input is invalid."""


class _FrozenMap(Mapping[str, float]):
    """Hashable, immutable mapping used by the typed manifest."""

    __slots__ = ("_items", "_values")

    def __init__(self, values: Mapping[str, float]) -> None:
        self._items = tuple(sorted(values.items()))
        self._values = MappingProxyType(dict(self._items))

    def __getitem__(self, key: str) -> float:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"_FrozenMap({dict(self._items)!r})"


@dataclass(frozen=True, slots=True)
class PredictionManifest:
    """The complete immutable model input needed for one prediction.

    Feature maps are keyed by the exact charter feature names.  Values are
    normalized to immutable mappings during construction, so a caller cannot
    change a manifest after its hash has been used for registration.
    """

    schema: str
    protocol_id: str
    feature_names: tuple[str, ...]
    standardization_means: Mapping[str, float]
    standardization_scales: Mapping[str, float]
    feature_weights: Mapping[str, float]
    intercept: float
    mci_slope: float
    era_effects: Mapping[str, float]
    seat_effects: Mapping[str, float]
    opponent_rating_knots: tuple[float, ...]
    opponent_rating_values: tuple[float, ...]
    rating_interpolation: str
    probability_epsilon: float
    model_kind: str
    comparator_identity: str | None
    comparator_input_key: str | None
    comparator_input_mean: float | None
    comparator_input_scale: float | None
    comparator_slope: float | None
    comparator_null_value: float | None
    comparator_missing_behavior: str
    development_evidence_sha256: str
    executable_sha256: str
    created_at_utc: str
    _manifest_hash: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _validate_manifest_values(self)
        object.__setattr__(self, "feature_names", tuple(self.feature_names))
        object.__setattr__(self, "standardization_means", _feature_map(self.standardization_means, "standardization_means"))
        object.__setattr__(self, "standardization_scales", _feature_map(self.standardization_scales, "standardization_scales"))
        object.__setattr__(self, "feature_weights", _feature_map(self.feature_weights, "feature_weights"))
        object.__setattr__(self, "era_effects", _effect_map(self.era_effects, "era_effects"))
        object.__setattr__(self, "seat_effects", _seat_map(self.seat_effects))
        object.__setattr__(self, "opponent_rating_knots", tuple(float(value) for value in self.opponent_rating_knots))
        object.__setattr__(self, "opponent_rating_values", tuple(float(value) for value in self.opponent_rating_values))
        object.__setattr__(self, "created_at_utc", _timestamp(self.created_at_utc, label="created_at_utc")[1])
        object.__setattr__(self, "_manifest_hash", canonical_sha256(self.as_dict()))

    @property
    def manifest_sha256(self) -> str:
        """SHA-256 of the exact canonical manifest wire representation."""

        return self._manifest_hash

    @property
    def content_sha256(self) -> str:
        """Compatibility spelling for the canonical manifest hash."""

        return self.manifest_sha256

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-native canonical manifest representation."""

        return {
            "schema": self.schema,
            "protocol_id": self.protocol_id,
            "feature_names": list(self.feature_names),
            "standardization_means": dict(self.standardization_means),
            "standardization_scales": dict(self.standardization_scales),
            "feature_weights": dict(self.feature_weights),
            "intercept": self.intercept,
            "mci_slope": self.mci_slope,
            "era_effects": dict(self.era_effects),
            "seat_effects": dict(self.seat_effects),
            "opponent_rating_knots": list(self.opponent_rating_knots),
            "opponent_rating_values": list(self.opponent_rating_values),
            "rating_interpolation": self.rating_interpolation,
            "probability_epsilon": self.probability_epsilon,
            "model_kind": self.model_kind,
            "comparator_identity": self.comparator_identity,
            "comparator_input_key": self.comparator_input_key,
            "comparator_input_mean": self.comparator_input_mean,
            "comparator_input_scale": self.comparator_input_scale,
            "comparator_slope": self.comparator_slope,
            "comparator_null_value": self.comparator_null_value,
            "comparator_missing_behavior": self.comparator_missing_behavior,
            "development_evidence_sha256": self.development_evidence_sha256,
            "executable_sha256": self.executable_sha256,
            "created_at_utc": self.created_at_utc,
        }

    def predict_probability(
        self,
        features: Mapping[str, Any] | None,
        *,
        era: str,
        seat: int,
        opponent_rating: int | float,
        comparator_input: Any = None,
    ) -> float:
        """Compute one deterministic probability from frozen inputs only."""

        checked_features = _features(features) if self.model_kind == "MCI" else None
        if type(era) is not str or era not in self.era_effects:
            raise PredictionManifestError(f"era {era!r} is not present in the frozen era effects")
        if type(seat) is not int or seat not in (0, 1):
            raise PredictionManifestError("seat must be exactly 0 or 1")
        rating = _finite_number(opponent_rating, label="opponent_rating")
        if rating < 0.0:
            raise PredictionManifestError("opponent_rating must be non-negative")

        if self.model_kind == "MCI":
            assert checked_features is not None
            capability = 0.0
            for feature_name in FEATURE_NAMES:
                capability += self.feature_weights[feature_name] * (
                    (checked_features[feature_name] - self.standardization_means[feature_name])
                    / self.standardization_scales[feature_name]
                )
            model_term = self.mci_slope * capability
        elif self.comparator_identity == "nuisance-only null model":
            model_term = 0.0
        else:
            value = self.comparator_null_value if comparator_input is None else _finite_number(
                comparator_input, label="comparator_input"
            )
            assert self.comparator_input_mean is not None
            assert self.comparator_input_scale is not None
            assert self.comparator_slope is not None
            model_term = self.comparator_slope * (
                (value - self.comparator_input_mean) / self.comparator_input_scale
            )
        logit = (
            self.intercept
            + self.era_effects[era]
            + self.seat_effects[str(seat)]
            + model_term
            + _piecewise_linear(
                rating,
                self.opponent_rating_knots,
                self.opponent_rating_values,
                self.rating_interpolation,
            )
        )
        probability = _sigmoid(logit)
        if not self.probability_epsilon < probability < 1.0 - self.probability_epsilon:
            raise PredictionManifestError(
                "predicted probability is outside the strict epsilon bounds; probability was not clipped"
            )
        return probability

    predict = predict_probability


def build_prediction_manifest(value: Mapping[str, Any] | None = None, **fields: Any) -> PredictionManifest:
    """Build and validate a frozen manifest without fitting anything."""

    if value is not None and fields:
        raise PredictionManifestError("provide a manifest mapping or keyword fields, not both")
    raw: Mapping[str, Any] = value if value is not None else fields
    if not isinstance(raw, Mapping) or set(raw) != _MANIFEST_FIELDS:
        actual = sorted(raw) if isinstance(raw, Mapping) else type(raw).__name__
        raise PredictionManifestError(
            f"manifest fields must exactly be {sorted(_MANIFEST_FIELDS)}; got {actual}"
        )
    try:
        return PredictionManifest(
            schema=raw["schema"],
            protocol_id=raw["protocol_id"],
            feature_names=tuple(raw["feature_names"]),
            standardization_means=raw["standardization_means"],
            standardization_scales=raw["standardization_scales"],
            feature_weights=raw["feature_weights"],
            intercept=raw["intercept"],
            mci_slope=raw["mci_slope"],
            era_effects=raw["era_effects"],
            seat_effects=raw["seat_effects"],
            opponent_rating_knots=tuple(raw["opponent_rating_knots"]),
            opponent_rating_values=tuple(raw["opponent_rating_values"]),
            rating_interpolation=raw["rating_interpolation"],
            probability_epsilon=raw["probability_epsilon"],
            model_kind=raw["model_kind"],
            comparator_identity=raw["comparator_identity"],
            comparator_input_key=raw["comparator_input_key"],
            comparator_input_mean=raw["comparator_input_mean"],
            comparator_input_scale=raw["comparator_input_scale"],
            comparator_slope=raw["comparator_slope"],
            comparator_null_value=raw["comparator_null_value"],
            comparator_missing_behavior=raw["comparator_missing_behavior"],
            development_evidence_sha256=raw["development_evidence_sha256"],
            executable_sha256=raw["executable_sha256"],
            created_at_utc=raw["created_at_utc"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, PredictionManifestError):
            raise
        raise PredictionManifestError(f"malformed prediction manifest: {exc}") from exc


def validate_prediction_manifest(value: PredictionManifest | Mapping[str, Any]) -> PredictionManifest:
    """Validate a typed manifest or its exact wire representation."""

    if isinstance(value, PredictionManifest):
        return value
    return build_prediction_manifest(value)


def prediction_manifest_sha256(value: PredictionManifest | Mapping[str, Any]) -> str:
    """Return the canonical hash after exact manifest validation."""

    return validate_prediction_manifest(value).manifest_sha256


def predict_probability(
    manifest: PredictionManifest | Mapping[str, Any],
    features: Mapping[str, Any] | None,
    *,
    era: str,
    seat: int,
    opponent_rating: int | float,
    comparator_input: Any = None,
) -> float:
    """Functional spelling of :meth:`PredictionManifest.predict_probability`."""

    return validate_prediction_manifest(manifest).predict_probability(
        features,
        era=era,
        seat=seat,
        opponent_rating=opponent_rating,
        comparator_input=comparator_input,
    )


def predict_game_probability(
    manifest: PredictionManifest | Mapping[str, Any], game: Mapping[str, Any]
) -> float:
    """Predict from one game input without consulting its outcome field."""

    if not isinstance(game, Mapping):
        raise PredictionManifestError("game must be a mapping")
    manifest_obj = validate_prediction_manifest(manifest)
    required = {"era", "seat", "opponent_rating"}
    if manifest_obj.model_kind == "MCI":
        required.add("features")
    missing = required - set(game)
    if missing:
        raise PredictionManifestError(f"game is missing prediction inputs: {sorted(missing)}")
    return predict_probability(
        manifest_obj,
        game.get("features") if manifest_obj.model_kind == "MCI" else None,
        era=game["era"],
        seat=game["seat"],
        opponent_rating=game["opponent_rating"],
        comparator_input=_comparator_input(manifest_obj, game),
    )


def build_prediction_rows(
    mci_manifest: PredictionManifest | Mapping[str, Any],
    comparator_manifest: PredictionManifest | Mapping[str, Any],
    games: Iterable[Mapping[str, Any]],
    *,
    archive_id: str,
    family_id: str,
    registered_package_hash: str,
    registration_at_utc: str,
    hosted_package_hash: str | None = None,
    independent_family: bool = True,
    literal_valid_hosted_game: bool = True,
    runtime_substituted: bool = False,
    validation_substituted: bool = False,
) -> list[dict[str, Any]]:
    """Build exact ``evaluation_v5.transfer`` rows from frozen predictions.

    ``outcome`` is copied as an opaque transfer payload and is never passed to
    either model.  All prediction inputs are the six local features plus the
    frozen nuisance inputs: era, seat, and pregame opponent rating.
    """

    mci = validate_prediction_manifest(mci_manifest)
    comparator = validate_prediction_manifest(comparator_manifest)
    if mci.model_kind != "MCI":
        raise PredictionManifestError("mci_manifest must have model_kind 'MCI'")
    if comparator.model_kind != "FROZEN_COMPARATOR":
        raise PredictionManifestError("comparator_manifest must have model_kind 'FROZEN_COMPARATOR'")
    if mci.protocol_id != PROTOCOL_ID or comparator.protocol_id != PROTOCOL_ID:
        raise PredictionManifestError("model protocol identity must be MCI_TRANSFER_V1")
    if type(independent_family) is not bool:
        raise PredictionManifestError("independent_family must be a boolean")
    for label, value in (
        ("literal_valid_hosted_game", literal_valid_hosted_game),
        ("runtime_substituted", runtime_substituted),
        ("validation_substituted", validation_substituted),
    ):
        if type(value) is not bool:
            raise PredictionManifestError(f"{label} must be a boolean")
    archive = _identifier(archive_id, "archive_id")
    family = _identifier(family_id, "family_id")
    registered_hash = _sha256(registered_package_hash, "registered_package_hash")
    hosted_hash = _sha256(hosted_package_hash or registered_package_hash, "hosted_package_hash")
    if hosted_hash != registered_hash:
        raise PredictionManifestError("hosted_package_hash must match registered_package_hash")
    registered_dt, registered_text = _timestamp(registration_at_utc, label="registration_at_utc")
    if mci.created_at_utc >= registered_text or comparator.created_at_utc >= registered_text:
        raise PredictionManifestError("both manifests must be created before confirmatory registration")

    if isinstance(games, (str, bytes)):
        raise PredictionManifestError("games must be an iterable of mappings")
    try:
        source_games = list(games)
    except TypeError as exc:
        raise PredictionManifestError("games must be an iterable of mappings") from exc
    if not source_games:
        raise PredictionManifestError("games must not be empty")

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, game in enumerate(source_games):
        if not isinstance(game, Mapping):
            raise PredictionManifestError(f"game {index} must be a mapping")
        game_id = _identifier(game.get("game_id"), f"game {index} game_id")
        if game_id in seen:
            raise PredictionManifestError(f"duplicate game_id {game_id!r}")
        seen.add(game_id)
        _check_optional_identity(game, archive, family, registered_hash, hosted_hash, index)
        _, hosted_text = _timestamp(game.get("hosted_at_utc"), label=f"game {index} hosted_at_utc")
        hosted_dt = _parse_canonical_timestamp(hosted_text)
        if registered_dt >= hosted_dt:
            raise PredictionManifestError(f"game {index} is not after archive registration")
        if "outcome" not in game:
            raise PredictionManifestError(f"game {index} is missing outcome for transfer row")

        # Deliberately select only outcome-independent model inputs here.
        mci_probability = predict_game_probability(mci, game)
        baseline_probability = predict_game_probability(comparator, game)
        rows.append(
            {
                "schema": INPUT_SCHEMA,
                "archive_id": archive,
                "family_id": family,
                "independent_family": independent_family,
                "registered_package_hash": registered_hash,
                "hosted_package_hash": hosted_hash,
                "registration_at_utc": registered_text,
                "hosted_at_utc": hosted_text,
                "game_id": game_id,
                "outcome": game["outcome"],
                "baseline_probability": baseline_probability,
                "mci_probability": mci_probability,
                "literal_valid_hosted_game": literal_valid_hosted_game,
                "runtime_substituted": runtime_substituted,
                "validation_substituted": validation_substituted,
            }
        )
    return sorted(rows, key=lambda row: row["game_id"])


def _validate_manifest_values(manifest: PredictionManifest) -> None:
    if type(manifest.schema) is not str or manifest.schema != MODEL_SCHEMA:
        raise PredictionManifestError(f"schema must be {MODEL_SCHEMA!r}")
    if type(manifest.protocol_id) is not str or manifest.protocol_id != PROTOCOL_ID:
        raise PredictionManifestError(f"protocol_id must be {PROTOCOL_ID!r}")
    if type(manifest.feature_names) is not tuple or manifest.feature_names != FEATURE_NAMES:
        raise PredictionManifestError("feature_names must exactly match the six v5 charter features")
    if type(manifest.model_kind) is not str or manifest.model_kind not in MODEL_KINDS:
        raise PredictionManifestError(f"model_kind must be one of {MODEL_KINDS!r}")
    for field_name in ("standardization_means", "standardization_scales", "feature_weights"):
        _feature_map(manifest.__getattribute__(field_name), field_name)
    for feature_name, scale in manifest.standardization_scales.items():
        if scale <= 0.0:
            raise PredictionManifestError(
                f"standardization_scales.{feature_name} must be positive"
            )
    for field_name in ("intercept", "mci_slope", "probability_epsilon"):
        _finite_number(manifest.__getattribute__(field_name), label=field_name)
    if manifest.mci_slope < 0.0:
        raise PredictionManifestError("mci_slope must be non-negative")
    if not 0.0 < manifest.probability_epsilon < 0.5:
        raise PredictionManifestError("probability_epsilon must be strictly between 0 and 0.5")
    _effect_map(manifest.era_effects, "era_effects")
    _seat_map(manifest.seat_effects)
    if type(manifest.opponent_rating_knots) is not tuple or type(manifest.opponent_rating_values) is not tuple:
        raise PredictionManifestError("opponent rating knots and values must be tuples")
    if len(manifest.opponent_rating_knots) < 2 or len(manifest.opponent_rating_knots) != len(manifest.opponent_rating_values):
        raise PredictionManifestError("opponent rating knots and values must have equal length >= 2")
    knots = [_finite_number(value, label="opponent_rating_knots") for value in manifest.opponent_rating_knots]
    for left, right in zip(knots, knots[1:]):
        if right <= left:
            raise PredictionManifestError("opponent rating knots must be ordered and unique")
    for value in manifest.opponent_rating_values:
        _finite_number(value, label="opponent_rating_values")
    if manifest.rating_interpolation not in RATING_INTERPOLATIONS:
        raise PredictionManifestError(
            f"rating_interpolation must explicitly freeze one of {RATING_INTERPOLATIONS!r}"
        )
    _sha256(manifest.development_evidence_sha256, "development_evidence_sha256")
    _sha256(manifest.executable_sha256, "executable_sha256")
    _timestamp(manifest.created_at_utc, label="created_at_utc")
    _validate_comparator_fields(manifest)


def _validate_comparator_fields(manifest: PredictionManifest) -> None:
    """Enforce disjoint MCI and comparator input vocabularies."""

    comparator_fields = (
        manifest.comparator_identity,
        manifest.comparator_input_key,
        manifest.comparator_input_mean,
        manifest.comparator_input_scale,
        manifest.comparator_slope,
        manifest.comparator_null_value,
    )
    if manifest.model_kind == "MCI":
        if any(value is not None for value in comparator_fields):
            raise PredictionManifestError("MCI manifests cannot bind comparator inputs or identities")
        if manifest.comparator_missing_behavior != "NOT_APPLICABLE":
            raise PredictionManifestError("MCI comparator_missing_behavior must be 'NOT_APPLICABLE'")
        return

    if manifest.comparator_identity not in COMPARATOR_IDENTITIES:
        raise PredictionManifestError(
            f"comparator_identity must be one of {COMPARATOR_IDENTITIES!r}"
        )
    expected_key = COMPARATOR_INPUT_KEYS[manifest.comparator_identity]
    if manifest.comparator_input_key != expected_key:
        raise PredictionManifestError(
            f"comparator_input_key must be the frozen key {expected_key!r} for "
            f"{manifest.comparator_identity!r}"
        )
    if manifest.mci_slope != 0.0 or any(value != 0.0 for value in manifest.feature_weights.values()):
        raise PredictionManifestError("FROZEN_COMPARATOR manifests cannot consume MCI feature terms")
    if manifest.comparator_identity == "nuisance-only null model":
        if any(value is not None for value in comparator_fields[1:]):
            raise PredictionManifestError("nuisance-only comparator cannot bind a scalar input")
        if manifest.comparator_missing_behavior != "NUISANCE_ONLY":
            raise PredictionManifestError("nuisance-only comparator must freeze NUISANCE_ONLY behavior")
        return

    assert manifest.comparator_input_key is not None
    for field_name in ("comparator_input_mean", "comparator_slope", "comparator_null_value"):
        value = getattr(manifest, field_name)
        _finite_number(value, label=field_name)
    assert manifest.comparator_input_scale is not None
    _finite_number(manifest.comparator_input_scale, label="comparator_input_scale")
    if manifest.comparator_input_scale <= 0.0:
        raise PredictionManifestError("comparator_input_scale must be positive")
    assert manifest.comparator_null_value is not None
    assert manifest.comparator_input_mean is not None
    if manifest.comparator_null_value != manifest.comparator_input_mean:
        raise PredictionManifestError(
            "comparator_null_value must equal comparator_input_mean so missing data has a zero model term"
        )
    if manifest.comparator_missing_behavior != "USE_FROZEN_NULL_VALUE":
        raise PredictionManifestError(
            "non-nuisance comparator must freeze USE_FROZEN_NULL_VALUE behavior"
        )


def _feature_map(value: object, label: str) -> _FrozenMap:
    if not isinstance(value, Mapping) or set(value) != set(FEATURE_NAMES):
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise PredictionManifestError(f"{label} must contain exactly the six charter features; got {actual}")
    checked: dict[str, float] = {}
    for feature_name in FEATURE_NAMES:
        checked[feature_name] = _finite_number(value[feature_name], label=f"{label}.{feature_name}")
    return _FrozenMap(checked)


def _features(value: object) -> dict[str, float]:
    checked = _feature_map(value, "features")
    for feature_name, feature_value in checked.items():
        if not 0.0 <= feature_value <= 1.0:
            raise PredictionManifestError(f"features.{feature_name} must be in [0, 1]")
    return dict(checked)


def _comparator_input(manifest: PredictionManifest, game: Mapping[str, Any]) -> Any:
    """Read only the comparator's declared non-outcome scalar, if present."""

    if manifest.model_kind != "FROZEN_COMPARATOR" or manifest.comparator_identity == "nuisance-only null model":
        return None
    key = manifest.comparator_input_key
    assert key is not None
    source = game.get("comparator_inputs")
    if source is None:
        return None
    if not isinstance(source, Mapping):
        raise PredictionManifestError("comparator_inputs must be a mapping when supplied")
    if key not in source or source[key] is None:
        return None
    return source[key]


def _effect_map(value: object, label: str) -> _FrozenMap:
    if not isinstance(value, Mapping) or not value:
        raise PredictionManifestError(f"{label} must be a non-empty mapping")
    checked: dict[str, float] = {}
    for key, item in value.items():
        if type(key) is not str or not key or key.strip() != key:
            raise PredictionManifestError(f"{label} keys must be non-empty trimmed strings")
        checked[key] = _finite_number(item, label=f"{label}.{key}")
    return _FrozenMap(checked)


def _seat_map(value: object) -> _FrozenMap:
    if not isinstance(value, Mapping):
        raise PredictionManifestError("seat_effects must be a mapping")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key in (0, 1) and type(key) is int:
            key = str(key)
        normalized[key] = item
    if set(normalized) != {"0", "1"}:
        raise PredictionManifestError("seat_effects must contain exactly seats 0 and 1")
    return _effect_map(normalized, "seat_effects")


def _finite_number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PredictionManifestError(f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise PredictionManifestError(f"{label} must be a finite number")
    return number


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise PredictionManifestError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise PredictionManifestError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _timestamp(value: object, *, label: str) -> tuple[datetime, str]:
    if type(value) is not str or not value.strip():
        raise PredictionManifestError(f"{label} must be an ISO-8601 UTC timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PredictionManifestError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PredictionManifestError(f"{label} must include a UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return parsed, normalized


def _parse_canonical_timestamp(value: str) -> datetime:
    if _UTC_RE.fullmatch(value) is None:
        raise PredictionManifestError("internal timestamp is not canonical UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _piecewise_linear(rating: float, knots: tuple[float, ...], values: tuple[float, ...], behavior: str) -> float:
    if rating <= knots[0]:
        if behavior == "piecewise_linear_clamp":
            return values[0]
        index = 0
    elif rating >= knots[-1]:
        if behavior == "piecewise_linear_clamp":
            return values[-1]
        index = len(knots) - 2
    else:
        index = next(position - 1 for position, knot in enumerate(knots) if rating < knot)
    left_knot, right_knot = knots[index], knots[index + 1]
    fraction = (rating - left_knot) / (right_knot - left_knot)
    return values[index] + fraction * (values[index + 1] - values[index])


def _sigmoid(logit: float) -> float:
    if logit >= 0.0:
        scaled = math.exp(-logit) if logit < 745.0 else 0.0
        return 1.0 / (1.0 + scaled)
    scaled = math.exp(logit) if logit > -745.0 else 0.0
    return scaled / (1.0 + scaled)


def _check_optional_identity(
    game: Mapping[str, Any], archive: str, family: str, registered_hash: str, hosted_hash: str, index: int
) -> None:
    expected = {
        "archive_id": archive,
        "family_id": family,
        "registered_package_hash": registered_hash,
        "hosted_package_hash": hosted_hash,
    }
    for key, expected_value in expected.items():
        if key in game and game[key] != expected_value:
            raise PredictionManifestError(f"game {index} {key} does not match bound archive metadata")


__all__ = [
    "COMPARATOR_IDENTITIES",
    "COMPARATOR_INPUT_KEYS",
    "MODEL_KINDS",
    "MODEL_SCHEMA",
    "PREDICTION_MANIFEST_SCHEMA",
    "PREDICTION_ROW_SCHEMA",
    "PredictionManifest",
    "PredictionManifestError",
    "RATING_INTERPOLATIONS",
    "build_prediction_manifest",
    "build_prediction_rows",
    "predict_game_probability",
    "predict_probability",
    "prediction_manifest_sha256",
    "validate_prediction_manifest",
]


PREDICTION_ROW_SCHEMA = INPUT_SCHEMA
