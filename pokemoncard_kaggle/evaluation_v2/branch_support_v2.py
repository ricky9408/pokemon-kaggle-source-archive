"""Outcome-free, fail-closed Stage-A core for ``branch_bridge_v2``.

The core deliberately accepts already-loaded structural rows and a frozen root
schedule.  It performs no file I/O, and has no code path for native roots,
successors, rewards, or outcomes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
import warnings
from typing import Any, Iterable, Mapping, Sequence


SUPPORT_FAMILIES = (
    "PLAY_POKEMON_BASIC", "PLAY_POKEMON_EVOLUTION", "PLAY_ITEM",
    "PLAY_SUPPORTER", "PLAY_STADIUM", "ABILITY", "ATTACH_ACTIVE",
    "ATTACH_BENCH", "RETREAT", "ATTACK", "END",
)
EXECUTION_MANIFEST_DEPENDENCIES = {
    "python": "3.11.15",
    "numpy": "2.4.6",
    "scipy": "1.17.1",
    "scikit_learn": "1.9.0",
}
FORBIDDEN_DATA_KEYS = frozenset({
    "outcome", "outcomes", "outcome_label", "reward", "rewards",
    "target_reward", "teacher_reward", "terminal_reward",
    "opponent_terminal_reward", "winner", "winner_team", "is_winner_player",
    "public_score", "public_scores", "score", "scores", "result",
    "successor", "successors", "native_successor", "native_successors",
    "next_state", "future", "future_state", "native_root", "native_roots",
})
_FORBIDDEN_NORMALIZED_KEYS = frozenset("".join(character for character in key if character.isalnum()) for key in FORBIDDEN_DATA_KEYS)
_FORBIDDEN_NORMALIZED_FRAGMENTS = ("outcome", "reward", "winner", "successor", "future", "publicscore")


@dataclass(frozen=True)
class StageAConfig:
    """Frozen Stage-A settings, with test-only overrides accepted by ``from_mapping``."""

    families: tuple[str, ...] = SUPPORT_FAMILIES
    min_selected_training_games: int = 50
    min_selected_training_pilots: int = 5
    accepted_low: float = 0.05
    accepted_high: float = 0.95
    bootstrap_samples: int = 500
    bootstrap_master_seed: int = 2026071101
    bootstrap_min_q10: float = 0.025
    bootstrap_max_q90: float = 0.975
    logistic_c: float = 1.0
    logistic_max_iter: int = 2000
    logistic_random_state: int = 2026071100
    conformal_min_games: int = 25
    conformal_min_pilots: int = 5
    conformal_min_p: float = 0.05
    activation_min_overall_supported_mass: float = 0.85
    activation_min_every_pilot_supported_mass: float = 0.7

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None = None) -> "StageAConfig":
        if value is None:
            return cls()
        allowed = frozenset(cls.__dataclass_fields__)
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown Stage-A configuration keys: {sorted(unknown)}")
        kwargs = dict(value)
        if "families" in kwargs:
            kwargs["families"] = tuple(str(item) for item in kwargs["families"])
        config = cls(**kwargs)
        if not config.families or len(set(config.families)) != len(config.families):
            raise ValueError("families must be a nonempty unique sequence")
        if config.logistic_c != 1.0 or config.logistic_max_iter != 2000:
            raise ValueError("Stage A requires L2 logistic C=1 and max_iter=2000")
        if config.bootstrap_samples <= 0:
            raise ValueError("bootstrap_samples must be positive")
        if config.min_selected_training_games <= 0 or config.min_selected_training_pilots <= 0:
            raise ValueError("family eligibility thresholds must be positive")
        if config.conformal_min_games <= 0 or config.conformal_min_pilots <= 0:
            raise ValueError("conformal neighborhood thresholds must be positive")
        for item in (config.accepted_low, config.accepted_high, config.bootstrap_min_q10,
                     config.bootstrap_max_q90, config.conformal_min_p,
                     config.activation_min_overall_supported_mass,
                     config.activation_min_every_pilot_supported_mass):
            if not 0.0 <= item <= 1.0:
                raise ValueError("probability thresholds must be in [0, 1]")
        if config.accepted_low > config.accepted_high or config.bootstrap_min_q10 > config.bootstrap_max_q90:
            raise ValueError("invalid support interval")
        return config


@dataclass(frozen=True)
class _PreparedRow:
    row_id: str
    game_id: str
    replay_sha256: str
    pilot: str
    side_id: str
    native_root_id: str
    selected_family: str
    selected_action_key: str
    actions: tuple[tuple[str, str], ...]
    numeric: Mapping[str, float]
    categorical: Mapping[str, str]


@dataclass(frozen=True)
class _FeatureSpace:
    numeric_keys: tuple[str, ...]
    categorical_keys: tuple[str, ...]
    categories: Mapping[str, tuple[str, ...]]
    means: tuple[float, ...]
    population_sds: tuple[float, ...]

    def transform(self, row: _PreparedRow) -> tuple[list[float] | None, str | None]:
        if tuple(sorted(row.numeric)) != self.numeric_keys or tuple(sorted(row.categorical)) != self.categorical_keys:
            return None, "representation_shape_mismatch"
        vector: list[float] = []
        for index, key in enumerate(self.numeric_keys):
            vector.append((row.numeric[key] - self.means[index]) / self.population_sds[index])
        for key in self.categorical_keys:
            value = row.categorical[key]
            known = self.categories[key]
            if value not in known:
                return None, f"unseen_category:{key}"
            vector.extend(1.0 if value == category else 0.0 for category in known)
        return vector, None


@dataclass(frozen=True)
class _LogisticModel:
    intercept: float
    coefficients: tuple[float, ...]

    def probability(self, vector: Sequence[float]) -> float:
        score = self.intercept + sum(weight * item for weight, item in zip(self.coefficients, vector))
        if score >= 0.0:
            return 1.0 / (1.0 + math.exp(-score))
        exp_score = math.exp(score)
        return exp_score / (1.0 + exp_score)


class StageAExecutionError(RuntimeError):
    """A preregistered global-failure condition, not ordinary unsupported mass."""


def canonical_json(value: Any) -> str:
    """Canonical JSON used by the frozen exact-action identity contract."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha_derived_seed(master_seed: int, *parts: str | int) -> int:
    """Return the first unsigned 64 bits from the preregistered SHA scheme."""
    material = "\0".join((str(master_seed), *(str(part) for part in parts))).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def type7_quantile(values: Sequence[float], probability: float) -> float:
    if not values or not 0.0 <= probability <= 1.0:
        raise ValueError("type-7 quantile requires nonempty values and probability in [0, 1]")
    ordered = sorted(float(value) for value in values)
    index = (len(ordered) - 1) * probability
    low = int(math.floor(index))
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def flatten_representation(representation: Mapping[str, Any]) -> tuple[dict[str, float], dict[str, str]]:
    """Strictly flatten the frozen numeric/categorical representation contract.

    Numeric leaves and numeric count-map leaves become scalar numeric columns.
    Non-numeric categorical leaves become scalar categories; their one-hot
    expansion is intentionally deferred until a training fold is known.
    """
    if not isinstance(representation, Mapping) or set(representation) != {"numeric", "categorical"}:
        raise ValueError("representation must contain exactly numeric and categorical mappings")
    numeric_root = representation["numeric"]
    categorical_root = representation["categorical"]
    if not isinstance(numeric_root, Mapping) or not isinstance(categorical_root, Mapping):
        raise ValueError("representation roots must be mappings")
    numeric: dict[str, float] = {}
    categorical: dict[str, str] = {}

    def walk(value: Any, path: tuple[str, ...], *, numeric_only: bool) -> None:
        if isinstance(value, Mapping):
            if not value:
                raise ValueError(f"empty representation mapping at {'.'.join(path)}")
            for key in sorted(value, key=str):
                if not isinstance(key, str) or not key:
                    raise ValueError("representation keys must be nonempty strings")
                walk(value[key], (*path, key), numeric_only=numeric_only)
            return
        key = ".".join(path)
        if isinstance(value, bool) or value is None:
            if numeric_only:
                raise ValueError(f"numeric representation leaf is not finite numeric: {key}")
            categorical[key] = canonical_json(value)
            return
        if isinstance(value, (int, float)):
            item = float(value)
            if not math.isfinite(item):
                raise ValueError(f"non-finite representation leaf: {key}")
            # Nested categorical count maps are numeric by contract.
            if numeric_only or len(path) > 2:
                numeric[key] = item
            else:
                categorical[key] = canonical_json(value)
            return
        if isinstance(value, str) and not numeric_only:
            categorical[key] = canonical_json(value)
            return
        raise ValueError(f"unsupported representation leaf at {key}")

    walk(numeric_root, ("numeric",), numeric_only=True)
    walk(categorical_root, ("categorical",), numeric_only=False)
    if not numeric or not categorical:
        raise ValueError("representation must produce numeric and categorical columns")
    return dict(sorted(numeric.items())), dict(sorted(categorical.items()))


def leave_one_pilot_out_folds(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, tuple[int, ...]]]:
    """Return deterministic LOP0 folds, removing shared game/replay identities."""
    prepared = [_prepare_row(row, index) for index, row in enumerate(rows)]
    folds: dict[str, dict[str, tuple[int, ...]]] = {}
    for pilot in sorted({row.pilot for row in prepared}):
        held = [index for index, row in enumerate(prepared) if row.pilot == pilot]
        games = {prepared[index].game_id for index in held}
        replays = {prepared[index].replay_sha256 for index in held}
        train = [
            index for index, row in enumerate(prepared)
            if row.pilot != pilot and row.game_id not in games and row.replay_sha256 not in replays
        ]
        folds[pilot] = {"train": tuple(train), "test": tuple(held)}
    return folds


def run_stage_a(
    structural_rows: Sequence[Mapping[str, Any]],
    root_schedule: Sequence[Mapping[str, Any]],
    *,
    config: StageAConfig | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce the deterministic JSON-ready Stage-A support payload.

    Any malformed input or invalid model/bootstrap fold is represented as
    unsupported diagnostics where possible; unsafe input fields fail globally.
    """
    settings = config if isinstance(config, StageAConfig) else StageAConfig.from_mapping(config)
    _reject_forbidden(structural_rows)
    _reject_forbidden(root_schedule)
    prepared = tuple(_prepare_row(row, index) for index, row in enumerate(structural_rows))
    if not prepared:
        raise ValueError("Stage A requires structural rows")
    schedules = tuple(_prepare_schedule(row, index) for index, row in enumerate(root_schedule))
    if not schedules:
        raise ValueError("Stage A requires frozen root schedule rows")
    _validate_unique_inputs(prepared, schedules)
    folds = leave_one_pilot_out_folds(structural_rows)
    row_support: dict[int, dict[str, dict[str, Any]]] = defaultdict(dict)
    family_fold_diagnostics: list[dict[str, Any]] = []

    for pilot in sorted(folds):
        train_indices = folds[pilot]["train"]
        test_indices = folds[pilot]["test"]
        for family in settings.families:
            result = _evaluate_family_fold(prepared, train_indices, test_indices, pilot, family, settings)
            family_fold_diagnostics.append(result["diagnostic"])
            for row_index, support in result["supports"].items():
                row_support[row_index][family] = support

    by_native_root = {row.native_root_id: (index, row) for index, row in enumerate(prepared)}
    side_pilots: dict[str, set[str]] = defaultdict(set)
    for row in prepared:
        side_pilots[row.side_id].add(row.pilot)
    root_diagnostics: list[dict[str, Any]] = []
    pilot_denominator: Counter[str] = Counter()
    pilot_supported: Counter[str] = Counter()
    for schedule in schedules:
        pilot = _schedule_pilot(schedule, by_native_root, side_pilots)
        if pilot is not None:
            pilot_denominator[pilot] += 1
        if schedule["status"] != "scheduled":
            root_diagnostics.append({
                "slot_id": schedule["slot_id"], "side_id": schedule["side_id"], "slot_index": schedule["slot_index"],
                "pilot": pilot, "native_root_id": None, "scheduled": False, "supported": False,
                "reason": "missing_scheduled_root", "selected_exact_action": None, "actions": [],
            })
            continue
        root_pair = by_native_root.get(schedule["native_root_id"])
        if root_pair is None:
            root_diagnostics.append({
                "slot_id": schedule["slot_id"], "side_id": schedule["side_id"], "slot_index": schedule["slot_index"],
                "pilot": pilot, "native_root_id": schedule["native_root_id"], "scheduled": True, "supported": False,
                "reason": "scheduled_root_absent_from_structural_rows", "selected_exact_action": None, "actions": [],
            })
            continue
        row_index, row = root_pair
        action_rows = []
        for action_key, family in row.actions:
            support = row_support[row_index].get(family)
            action_rows.append({
                "action_key": action_key, "family": family,
                "supported": bool(support and support["supported"]),
                "reason": None if support and support["supported"] else (support or {"reason": "family_not_preregistered"})["reason"],
            })
        selected = next((action for action in action_rows if action["action_key"] == row.selected_action_key), None)
        alternate = any(action["supported"] and action["family"] != row.selected_family for action in action_rows)
        supported = bool(selected and selected["supported"] and alternate)
        reason = "supported" if supported else (
            "selected_exact_action_unsupported" if not selected or not selected["supported"] else "no_supported_other_family_action"
        )
        diagnostic = {
            "slot_id": schedule["slot_id"], "side_id": schedule["side_id"], "slot_index": schedule["slot_index"],
            "pilot": row.pilot, "native_root_id": row.native_root_id, "scheduled": True, "supported": supported,
            "reason": reason, "selected_exact_action": row.selected_action_key, "selected_family": row.selected_family,
            "actions": action_rows,
        }
        root_diagnostics.append(diagnostic)
        if supported:
            pilot_supported[row.pilot] += 1

    rates = _support_rates(root_diagnostics, pilot_denominator, pilot_supported, {row.pilot for row in prepared})
    return {
        "schema": "branch_bridge_stage_a_core_v2",
        "outcome_free": True,
        "native_successor_accessed": False,
        "config": _config_payload(settings),
        "row_diagnostics": _row_diagnostics(prepared, row_support),
        "family_fold_diagnostics": family_fold_diagnostics,
        "root_diagnostics": root_diagnostics,
        "support_rates": rates,
        "gate_checks": {
            "overall_supported_mass": {"passed": rates["overall"] >= settings.activation_min_overall_supported_mass,
                                       "observed": rates["overall"], "minimum": settings.activation_min_overall_supported_mass},
            "every_pilot_supported_mass": {"passed": all(
                item["rate"] is not None and item["rate"] >= settings.activation_min_every_pilot_supported_mass for item in rates["pilots"]
            ), "minimum": settings.activation_min_every_pilot_supported_mass,
                "failing_pilots": [item["pilot"] for item in rates["pilots"] if item["rate"] is None or item["rate"] < settings.activation_min_every_pilot_supported_mass]},
        },
        "passed": (
            rates["overall"] >= settings.activation_min_overall_supported_mass
            and all(
                item["rate"] is not None
                and item["rate"] >= settings.activation_min_every_pilot_supported_mass
                for item in rates["pilots"]
            )
        ),
    }


def evaluate_stage_a(
    rows: Sequence[Mapping[str, Any]],
    schedule: Sequence[Mapping[str, Any]],
    preregistration: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate Stage A using only the frozen v2 preregistration mapping.

    Callers must pass the already-loaded preregistration JSON object.  This
    function intentionally does not accept paths and therefore cannot load an
    outcome artifact or a native-successor capsule by accident.
    """
    if not isinstance(preregistration, Mapping) or preregistration.get("schema") != "branch_bridge_preregistration_v2":
        raise ValueError("evaluate_stage_a requires branch_bridge_preregistration_v2")
    stage = preregistration.get("stage_a")
    activation = preregistration.get("activation")
    families = preregistration.get("support_families")
    if not isinstance(stage, Mapping) or not isinstance(activation, Mapping) or not isinstance(families, list):
        raise ValueError("preregistration is missing Stage-A support fields")
    eligibility = stage.get("family_eligibility")
    propensity = stage.get("propensity")
    bootstrap = stage.get("bootstrap_stability")
    conformal = stage.get("prestate_conformal")
    if not all(isinstance(value, Mapping) for value in (eligibility, propensity, bootstrap, conformal)):
        raise ValueError("preregistration Stage-A sections are malformed")
    if (propensity.get("model") != "L2 logistic regression" or propensity.get("solver") != "lbfgs"
            or propensity.get("class_weight") is not None
            or propensity.get("sample_weight") != "within each independent game, divide weight one equally across eligible rows"):
        raise ValueError("preregistration does not retain the frozen propensity contract")
    if (bootstrap.get("unit") != "whole game_id with replacement; a repeated game is retained once per draw and receives one unit of total draw weight"
            or bootstrap.get("quantile_method") != "type7"
            or bootstrap.get("failed_or_single_class_replicate") != "invalidate the entire family-fold result; never skip a replicate"):
        raise ValueError("preregistration does not retain the frozen bootstrap contract")
    config = StageAConfig.from_mapping({
        "families": families,
        "min_selected_training_games": eligibility.get("min_selected_training_games"),
        "min_selected_training_pilots": eligibility.get("min_selected_training_pilots"),
        "accepted_low": (propensity.get("accepted_interval_inclusive") or [None, None])[0],
        "accepted_high": (propensity.get("accepted_interval_inclusive") or [None, None])[1],
        "bootstrap_samples": bootstrap.get("samples"),
        "bootstrap_master_seed": bootstrap.get("master_seed"),
        "bootstrap_min_q10": bootstrap.get("min_q10_inclusive"),
        "bootstrap_max_q90": bootstrap.get("max_q90_inclusive"),
        "logistic_c": propensity.get("c"),
        "logistic_max_iter": propensity.get("max_iter"),
        "logistic_random_state": propensity.get("random_state"),
        "conformal_min_games": conformal.get("min_games"),
        "conformal_min_pilots": conformal.get("min_pilots"),
        "conformal_min_p": conformal.get("min_p_inclusive"),
        "activation_min_overall_supported_mass": activation.get("min_overall_supported_mass"),
        "activation_min_every_pilot_supported_mass": activation.get("min_every_pilot_supported_mass"),
    })
    payload = run_stage_a(rows, schedule, config=config)
    payload["execution_manifest_dependencies"] = dict(EXECUTION_MANIFEST_DEPENDENCIES)
    return payload


def _prepare_row(value: Mapping[str, Any], index: int) -> _PreparedRow:
    if not isinstance(value, Mapping):
        raise ValueError("structural row must be a mapping")
    required = ("game_id", "replay_sha256", "pilot", "side_id", "native_root_id", "selected_family",
                "selected_action", "selected_action_key", "legal_actions", "representation")
    missing = [key for key in required if key not in value]
    if missing:
        raise ValueError(f"structural row missing required keys: {missing}")
    actions = tuple(_exact_action(action) for action in value["legal_actions"])
    if not actions or len({item[0] for item in actions}) != len(actions):
        raise ValueError("legal actions must contain unique exact action identities")
    selected_key, selected_family = _exact_action(value["selected_action"])
    if selected_key != value["selected_action_key"] or selected_key not in {item[0] for item in actions}:
        raise ValueError("selected exact action identity is invalid")
    if selected_family != value["selected_family"]:
        raise ValueError("selected family does not match exact selected action")
    numeric, categorical = flatten_representation(value["representation"])
    identifiers = {key: str(value[key]) for key in ("game_id", "replay_sha256", "pilot", "side_id", "native_root_id")}
    if any(not item for item in identifiers.values()):
        raise ValueError("structural row identity fields must be nonempty")
    return _PreparedRow(
        row_id=f"{identifiers['native_root_id']}:{index}", selected_family=selected_family,
        selected_action_key=selected_key, actions=tuple(sorted(actions)), numeric=numeric, categorical=categorical,
        **identifiers,
    )


def _exact_action(value: Any) -> tuple[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"selection", "payload", "payload_key", "action_key", "family"}:
        raise ValueError("exact action must satisfy the frozen structural action schema")
    payload = value["payload"]
    expected_payload = canonical_json(payload)
    expected_action = canonical_json({"selection": value["selection"], "payload": payload})
    if value["payload_key"] != expected_payload or value["action_key"] != expected_action:
        raise ValueError("exact action identity must be canonical raw selection plus resolved payload")
    if not isinstance(value["family"], str) or not value["family"]:
        raise ValueError("action family must be a nonempty string")
    return expected_action, value["family"]


def _prepare_schedule(value: Mapping[str, Any], index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("root schedule row must be a mapping")
    required = {"schema", "side_id", "slot_index", "native_root_id", "root_priority_sha256", "status"}
    if set(value) != required or value.get("schema") != "branch_bridge_root_schedule_v2":
        raise ValueError("root schedule must satisfy the frozen v2 schema")
    status = value["status"]
    if status not in {"scheduled", "missing_eligible_root"}:
        raise ValueError("unsupported root schedule status")
    scheduled = status == "scheduled"
    if scheduled != (value["native_root_id"] is not None and value["root_priority_sha256"] is not None):
        raise ValueError("root schedule scheduled/missing identity mismatch")
    return {"slot_id": f"{value['side_id']}:{value['slot_index']}:{index}", "side_id": str(value["side_id"]),
            "slot_index": int(value["slot_index"]), "native_root_id": None if value["native_root_id"] is None else str(value["native_root_id"]),
            "status": status}


def _validate_unique_inputs(rows: Sequence[_PreparedRow], schedules: Sequence[Mapping[str, Any]]) -> None:
    if len({row.row_id for row in rows}) != len(rows) or len({row.native_root_id for row in rows}) != len(rows):
        raise ValueError("structural roots must be uniquely identified")
    slots = [(item["side_id"], item["slot_index"]) for item in schedules]
    if len(set(slots)) != len(slots):
        raise ValueError("frozen root schedule contains duplicate slots")
    by_side: dict[str, set[int]] = defaultdict(set)
    scheduled_roots: list[str] = []
    for item in schedules:
        by_side[item["side_id"]].add(item["slot_index"])
        if item["status"] == "scheduled":
            scheduled_roots.append(str(item["native_root_id"]))
    if any(indices != {0, 1, 2, 3} for indices in by_side.values()):
        raise ValueError("every target side must retain exactly root slots 0..3")
    if len(set(scheduled_roots)) != len(scheduled_roots):
        raise ValueError("frozen root schedule reuses a native root")


def _evaluate_family_fold(rows: Sequence[_PreparedRow], train_indices: Sequence[int], test_indices: Sequence[int], pilot: str,
                          family: str, config: StageAConfig) -> dict[str, Any]:
    applicable_test = [index for index in test_indices if family in {item[1] for item in rows[index].actions}]
    selected_train = [index for index in train_indices if rows[index].selected_family == family]
    available_train = [index for index in train_indices if family in {item[1] for item in rows[index].actions}]
    diagnostic: dict[str, Any] = {"pilot": pilot, "family": family, "status": "unsupported", "reason": None,
                                  "training_selected_games": len({rows[index].game_id for index in selected_train}),
                                  "training_selected_pilots": len({rows[index].pilot for index in selected_train}),
                                  "training_available_rows": len(available_train), "bootstrap_samples": config.bootstrap_samples}
    if not applicable_test:
        diagnostic.update(status="not_applicable", reason="family_unavailable_in_held_pilot")
        return {"diagnostic": diagnostic, "supports": {}}
    if diagnostic["training_selected_games"] < config.min_selected_training_games or diagnostic["training_selected_pilots"] < config.min_selected_training_pilots:
        diagnostic["reason"] = "insufficient_selected_training_support"
        return {"diagnostic": diagnostic, "supports": _unsupported(applicable_test, "insufficient_selected_training_support")}
    if not available_train:
        diagnostic["reason"] = "no_available_training_rows"
        return {"diagnostic": diagnostic, "supports": _unsupported(applicable_test, "no_available_training_rows")}
    labels = [1 if rows[index].selected_family == family else 0 for index in available_train]
    if len(set(labels)) != 2:
        diagnostic["reason"] = "single_class_training_labels"
        return {"diagnostic": diagnostic, "supports": _unsupported(applicable_test, "single_class_training_labels")}
    feature_space = _fit_feature_space([rows[index] for index in train_indices])
    train_vectors, train_error = _vectors(feature_space, [rows[index] for index in available_train])
    if train_error:
        raise StageAExecutionError(f"training feature transform failed: {train_error}")
    supports: dict[int, dict[str, Any]] = {}
    valid_test: list[int] = []
    test_vectors: list[list[float]] = []
    for row_index in applicable_test:
        vector, error = feature_space.transform(rows[row_index])
        if error or vector is None:
            supports[row_index] = _unsupported((row_index,), error or "feature_transform_failed")[row_index]
        else:
            valid_test.append(row_index)
            test_vectors.append(vector)
    if not valid_test:
        diagnostic.update(status="evaluated", reason="all_applicable_rows_have_unseen_categories")
        return {"diagnostic": diagnostic, "supports": supports}
    weights = _game_total_one_weights([rows[index] for index in available_train])
    base = _fit_logistic(train_vectors, labels, weights, random_state=config.logistic_random_state, max_iter=config.logistic_max_iter)
    if base is None:
        raise StageAExecutionError("base logistic fit has no positive-weight class overlap")
    bootstrap_predictions: list[list[float]] = [[] for _ in valid_test]
    train_games = sorted({rows[index].game_id for index in available_train})
    for replicate in range(config.bootstrap_samples):
        seed = sha_derived_seed(
            config.bootstrap_master_seed,
            "branch_bridge_v2",
            pilot,
            family,
            "",
            "",
            "",
            replicate,
        )
        counts = _whole_game_draw_counts(train_games, seed)
        sampled_weights = [weights[position] * counts[rows[index].game_id] for position, index in enumerate(available_train)]
        model = _fit_logistic(
            train_vectors,
            labels,
            sampled_weights,
            random_state=seed % (2**32 - 1),
            max_iter=config.logistic_max_iter,
        )
        if model is None:
            diagnostic.update(reason="bootstrap_replicate_invalid", invalid_replicate=replicate, invalid_seed=seed)
            return {"diagnostic": diagnostic, "supports": _unsupported(applicable_test, "bootstrap_replicate_invalid")}
        for position, vector in enumerate(test_vectors):
            bootstrap_predictions[position].append(model.probability(vector))
    conformal = _conformal_support(rows, selected_train, valid_test, feature_space, config)
    for position, row_index in enumerate(valid_test):
        point = base.probability(test_vectors[position])
        q10 = type7_quantile(bootstrap_predictions[position], 0.10)
        q90 = type7_quantile(bootstrap_predictions[position], 0.90)
        conformal_item = conformal[row_index]
        propensity = config.accepted_low <= point <= config.accepted_high
        stability = config.bootstrap_min_q10 <= q10 and q90 <= config.bootstrap_max_q90
        passed = propensity and stability and conformal_item["supported"]
        supports[row_index] = {"supported": passed, "reason": "supported" if passed else _first_reason(
            (propensity, "propensity_outside_interval"), (stability, "bootstrap_interval_outside_bounds"),
            (conformal_item["supported"], conformal_item["reason"])), "propensity": point, "q10": q10, "q90": q90,
            "conformal_p": conformal_item.get("p_value"), "conformal_neighborhood_games": conformal_item.get("neighborhood_games"),
            "conformal_neighborhood_pilots": conformal_item.get("neighborhood_pilots"),
        }
    diagnostic.update(status="evaluated", reason="evaluated", base_fit="l2_logistic_lbfgs", bootstrap_valid=True)
    return {"diagnostic": diagnostic, "supports": supports}


def _fit_feature_space(rows: Sequence[_PreparedRow]) -> _FeatureSpace:
    if not rows:
        raise ValueError("feature space requires training rows")
    numeric_keys = tuple(sorted(rows[0].numeric))
    categorical_keys = tuple(sorted(rows[0].categorical))
    if not numeric_keys or not categorical_keys:
        raise ValueError("empty representation feature space")
    for row in rows:
        if tuple(sorted(row.numeric)) != numeric_keys or tuple(sorted(row.categorical)) != categorical_keys:
            raise ValueError("training representations have inconsistent shapes")
    means = tuple(sum(row.numeric[key] for row in rows) / len(rows) for key in numeric_keys)
    sds = tuple(math.sqrt(sum((row.numeric[key] - mean) ** 2 for row in rows) / len(rows)) or 1.0
                for key, mean in zip(numeric_keys, means))
    categories = {key: tuple(sorted({row.categorical[key] for row in rows})) for key in categorical_keys}
    return _FeatureSpace(numeric_keys, categorical_keys, categories, means, sds)


def _vectors(space: _FeatureSpace, rows: Sequence[_PreparedRow]) -> tuple[list[list[float]], str | None]:
    vectors: list[list[float]] = []
    for row in rows:
        vector, error = space.transform(row)
        if error:
            return [], error
        assert vector is not None
        vectors.append(vector)
    return vectors, None


def _game_total_one_weights(rows: Sequence[_PreparedRow]) -> list[float]:
    counts = Counter(row.game_id for row in rows)
    return [1.0 / counts[row.game_id] for row in rows]


def _whole_game_draw_counts(games: Sequence[str], seed: int) -> Counter[str]:
    # A tiny deterministic PRNG avoids an implicit global RNG dependency.
    state = seed or 1
    counts: Counter[str] = Counter()
    for _ in games:
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        counts[games[state % len(games)]] += 1
    return counts


def _fit_logistic(vectors: Sequence[Sequence[float]], labels: Sequence[int], weights: Sequence[float], *, random_state: int,
                  max_iter: int) -> _LogisticModel | None:
    """Fit the preregistered L2 logistic/lbfgs model, returning None on any failure.

    scikit-learn is used in the locked production environment.  The small
    The execution manifest pins scikit-learn; a missing dependency is a failed
    execution rather than permission to switch solvers.
    """
    if not vectors or len(vectors) != len(labels) or len(labels) != len(weights) or len(set(labels)) != 2:
        raise ValueError("logistic inputs are malformed")
    if any(weight < 0.0 or not math.isfinite(weight) for weight in weights):
        raise ValueError("logistic weights are malformed")
    if len({label for label, weight in zip(labels, weights) if weight > 0.0}) != 2:
        return None
    try:
        from sklearn.exceptions import ConvergenceWarning  # type: ignore[import-not-found]
        from sklearn.linear_model import LogisticRegression  # type: ignore[import-not-found]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ConvergenceWarning)
            model = LogisticRegression(C=1.0, penalty="l2", solver="lbfgs", max_iter=max_iter,
                                       class_weight=None, random_state=random_state)
            model.fit(vectors, labels, sample_weight=weights)
        if any(issubclass(item.category, ConvergenceWarning) for item in caught):
            raise StageAExecutionError("lbfgs convergence failure")
        return _LogisticModel(float(model.intercept_[0]), tuple(float(value) for value in model.coef_[0]))
    except StageAExecutionError:
        raise
    except ImportError as error:
        raise StageAExecutionError("pinned scikit-learn is unavailable") from error
    except Exception as error:
        raise StageAExecutionError(f"logistic execution failure: {type(error).__name__}") from error


def _conformal_support(rows: Sequence[_PreparedRow], selected_train: Sequence[int], test_indices: Sequence[int], space: _FeatureSpace,
                       config: StageAConfig) -> dict[int, dict[str, Any]]:
    vectors, error = _vectors(space, [rows[index] for index in selected_train])
    if error:
        return _unsupported(test_indices, error)
    by_game: dict[str, list[tuple[_PreparedRow, Sequence[float]]]] = defaultdict(list)
    for index, vector in zip(selected_train, vectors):
        by_game[rows[index].game_id].append((rows[index], vector))
    centroids: list[dict[str, Any]] = []
    for game_id in sorted(by_game):
        members = by_game[game_id]
        centroids.append({"game_id": game_id, "pilot_set": tuple(sorted({row.pilot for row, _ in members})),
                          "vector": [sum(vector[axis] for _, vector in members) / len(members) for axis in range(len(members[0][1]))]})
    if len(centroids) < max(config.conformal_min_games, 2):
        return _unsupported(test_indices, "insufficient_conformal_reference_games")
    alpha: dict[str, float] = {}
    for current in centroids:
        others = [_rms_distance(current["vector"], other["vector"]) for other in centroids if other["game_id"] != current["game_id"]]
        alpha[current["game_id"]] = min(others)
    result: dict[int, dict[str, Any]] = {}
    for index in test_indices:
        query, error = space.transform(rows[index])
        if error or query is None:
            result[index] = {"supported": False, "reason": error or "feature_transform_failed"}
            continue
        ordered = sorted(centroids, key=lambda item: (_rms_distance(query, item["vector"]), item["game_id"]))
        neighborhood: list[dict[str, Any]] = []
        games: set[str] = set()
        pilots: set[str] = set()
        for item in ordered:
            neighborhood.append(item)
            games.add(item["game_id"])
            pilots.update(item["pilot_set"])
            if len(games) >= config.conformal_min_games and len(pilots) >= config.conformal_min_pilots:
                break
        if len(games) < config.conformal_min_games or len(pilots) < config.conformal_min_pilots:
            result[index] = {"supported": False, "reason": "insufficient_conformal_neighborhood",
                             "neighborhood_games": len(games), "neighborhood_pilots": len(pilots)}
            continue
        query_alpha = min(_rms_distance(query, item["vector"]) for item in neighborhood)
        p_value = (1 + sum(alpha[item["game_id"]] >= query_alpha for item in neighborhood)) / (len(neighborhood) + 1)
        result[index] = {"supported": p_value >= config.conformal_min_p,
                         "reason": "supported" if p_value >= config.conformal_min_p else "conformal_p_below_minimum",
                         "p_value": p_value, "neighborhood_games": len(games), "neighborhood_pilots": len(pilots)}
    return result


def _rms_distance(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("RMS distance vectors must have equal nonzero length")
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)) / len(left))


def _unsupported(indices: Iterable[int], reason: str) -> dict[int, dict[str, Any]]:
    return {index: {"supported": False, "reason": reason, "propensity": None, "q10": None, "q90": None,
                    "conformal_p": None, "conformal_neighborhood_games": None, "conformal_neighborhood_pilots": None} for index in indices}


def _first_reason(*checks: tuple[bool, str]) -> str:
    return next(reason for passed, reason in checks if not passed)


def _row_diagnostics(rows: Sequence[_PreparedRow], support: Mapping[int, Mapping[str, Mapping[str, Any]]]) -> list[dict[str, Any]]:
    result = []
    for index, row in enumerate(rows):
        families = support.get(index, {})
        result.append({"row_id": row.row_id, "game_id": row.game_id, "replay_sha256": row.replay_sha256,
                       "pilot": row.pilot, "side_id": row.side_id, "native_root_id": row.native_root_id,
                       "selected_exact_action": row.selected_action_key, "selected_family": row.selected_family,
                       "family_support": {family: families[family] for family in sorted(families)}})
    return result


def _schedule_pilot(schedule: Mapping[str, Any], roots: Mapping[str, tuple[int, _PreparedRow]], side_pilots: Mapping[str, set[str]]) -> str | None:
    if schedule["native_root_id"] is not None and schedule["native_root_id"] in roots:
        return roots[schedule["native_root_id"]][1].pilot
    pilots = side_pilots.get(schedule["side_id"], set())
    if len(pilots) == 1:
        return next(iter(pilots))
    return None


def _support_rates(root_diagnostics: Sequence[Mapping[str, Any]], denominator: Mapping[str, int], supported: Mapping[str, int],
                   all_pilots: set[str]) -> dict[str, Any]:
    overall_denominator = len(root_diagnostics)
    overall_supported = sum(bool(item["supported"]) for item in root_diagnostics)
    if not overall_denominator:
        raise ValueError("support denominator must include frozen schedule slots")
    unknown = [item["slot_id"] for item in root_diagnostics if item["pilot"] is None]
    pilots = [{"pilot": pilot, "supported": supported.get(pilot, 0), "denominator": denominator.get(pilot, 0),
               "rate": (supported.get(pilot, 0) / denominator[pilot]) if denominator.get(pilot, 0) else None}
              for pilot in sorted(all_pilots)]
    return {"overall": overall_supported / overall_denominator, "supported": overall_supported,
            "denominator": overall_denominator, "pilots": pilots, "unassigned_slots": sorted(unknown)}


def _config_payload(config: StageAConfig) -> dict[str, Any]:
    result = {key: getattr(config, key) for key in config.__dataclass_fields__}
    result["families"] = list(config.families)
    return result


def _reject_forbidden(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = "".join(character for character in str(key).lower() if character.isalnum())
            if normalized in _FORBIDDEN_NORMALIZED_KEYS or any(fragment in normalized for fragment in _FORBIDDEN_NORMALIZED_FRAGMENTS):
                raise ValueError(f"Stage A forbids outcome/future data at {'.'.join((*path, str(key)))}")
            _reject_forbidden(item, (*path, str(key)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_forbidden(item, (*path, str(index)))


__all__ = [
    "EXECUTION_MANIFEST_DEPENDENCIES", "FORBIDDEN_DATA_KEYS", "SUPPORT_FAMILIES", "StageAConfig", "StageAExecutionError", "canonical_json",
    "evaluate_stage_a", "flatten_representation", "leave_one_pilot_out_folds", "run_stage_a", "sha_derived_seed",
    "type7_quantile",
]
