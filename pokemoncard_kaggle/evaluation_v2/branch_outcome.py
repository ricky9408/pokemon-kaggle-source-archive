"""Pure, fail-closed primitives for the preregistered ``branch_bridge_v1``.

This module intentionally contains no replay ingestion, model fitting, or CLI
code.  Its inputs are actor-visible state snapshots and already cross-fitted
root rows; callers own all orchestration and fold assignment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
import hashlib
import json
import math
from pathlib import Path
from random import Random
import statistics
from typing import Any, Iterable, Mapping, Sequence


FEATURE_BUCKETS = 32_768
BURNED_PANEL_ID = "f4414154ee58038ac1da"
BURNED_PANEL_SHA256 = "5d6dfbcb956aa31ce4365fb536a9574fe88230b35b293bfa6f8c0648d43f410d"
BURNED_VALIDATION_SHA256 = "b1b4e5fa39451948269fd1096725b28ecfadb8fc80c3f7e7a7966630837f3d4e"
TECHNICAL_DENYLIST_SHA256 = frozenset({BURNED_PANEL_SHA256, BURNED_VALIDATION_SHA256})
PANEL_ID = BURNED_PANEL_ID
PANEL_SHA256 = BURNED_PANEL_SHA256
VALIDATION_SHA256 = BURNED_VALIDATION_SHA256
TECHNICAL_DENYLIST = TECHNICAL_DENYLIST_SHA256


def canonical_json(value: Any) -> str:
    """Serialize an evidence value deterministically, rejecting non-finite data."""
    return json.dumps(
        _json_ready(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_burned_artifact(path: str | Path | None = None, payload: Any = None) -> None:
    """Raise when an artifact or payload could reuse the burned public panel."""
    if path is not None:
        actual = sha256_file(path)
        if actual in TECHNICAL_DENYLIST_SHA256:
            raise ValueError(f"denylisted artifact sha256: {actual}")
    if _contains_burned_panel_id(payload):
        raise ValueError(f"burned panel id is forbidden: {BURNED_PANEL_ID}")


validate_artifact_not_burned = reject_burned_artifact


def sha1_feature_bucket(feature: str, buckets: int = FEATURE_BUCKETS) -> int:
    if buckets <= 0:
        raise ValueError("buckets must be positive")
    return int.from_bytes(hashlib.sha1(feature.encode("utf-8")).digest(), "big") % buckets


def actor_visible_state_features(state: Mapping[str, Any]) -> tuple[int, ...]:
    """Hash only the preregistered actor-visible state whitelist.

    In particular, arbitrary mapping keys are never traversed: opponent hands,
    prize identities, logs, selection payloads, and experiment metadata cannot
    accidentally become features merely because they happen to be present.
    """
    current = _current_mapping(state)
    global_keys = {
        "currentTurn": ("currentTurn", "turn"),
        "firstPlayer": ("firstPlayer",),
        "yourIndex": ("yourIndex",),
        "turnActionCount": ("turnActionCount",),
        "retreated": ("retreated",),
        "energyAttached": ("energyAttached",),
        "supporterPlayed": ("supporterPlayed",),
        "stadiumPlayed": ("stadiumPlayed",),
    }
    features = [f"g:{key}={_token(_lookup(current, *aliases))}" for key, aliases in global_keys.items()]
    your_index = _as_int(_lookup(current, "yourIndex"), 0)
    sides = _state_sides(current)
    for ordinal, side in enumerate(sides[:2]):
        label = "own" if ordinal == your_index else "opp"
        features.extend(_side_features(label, side, include_hand=label == "own"))
    return tuple(sorted(sha1_feature_bucket(feature) for feature in features))


hashed_actor_visible_features = actor_visible_state_features


@dataclass(frozen=True)
class FrozenHashedLogistic:
    """A portable 32,768-bucket logistic scorer with immutable parameters."""

    intercept: float = 0.0
    weights: Sequence[float] | Mapping[int | str, float] = ()
    buckets: int = FEATURE_BUCKETS

    def __post_init__(self) -> None:
        if self.buckets != FEATURE_BUCKETS:
            raise ValueError(f"branch_bridge_v1 requires {FEATURE_BUCKETS} buckets")
        if isinstance(self.weights, Mapping):
            values = [0.0] * self.buckets
            for bucket, weight in self.weights.items():
                index = int(bucket)
                if not 0 <= index < self.buckets:
                    raise ValueError("weight bucket out of range")
                values[index] = float(weight)
        else:
            values = list(self.weights)
            if not values:
                values = [0.0] * self.buckets
            if len(values) != self.buckets:
                raise ValueError(f"weights must contain exactly {self.buckets} values")
            values = [float(value) for value in values]
        object.__setattr__(self, "intercept", float(self.intercept))
        object.__setattr__(self, "weights", tuple(values))

    def score(self, features: Iterable[int] | Mapping[str, Any]) -> float:
        buckets = actor_visible_state_features(features) if isinstance(features, Mapping) else tuple(features)
        total = self.intercept
        for bucket in buckets:
            index = int(bucket)
            if not 0 <= index < self.buckets:
                raise ValueError("feature bucket out of range")
            total += self.weights[index]  # type: ignore[index]
        return total

    def probability(self, features: Iterable[int] | Mapping[str, Any]) -> float:
        return _sigmoid(self.score(features))

    predict_proba = probability

    def export_dict(self, *, sparse: bool = True) -> dict[str, Any]:
        weights = self.weights  # type: ignore[assignment]
        encoded: dict[str, float] | list[float]
        if sparse:
            encoded = {str(index): value for index, value in enumerate(weights) if value != 0.0}
        else:
            encoded = list(weights)
        return {
            "schema": "frozen_hashed_logistic_v1",
            "buckets": self.buckets,
            "intercept": self.intercept,
            "weights": encoded,
        }

    to_dict = export_dict

    @classmethod
    def import_dict(cls, payload: Mapping[str, Any]) -> "FrozenHashedLogistic":
        if payload.get("schema") not in {None, "frozen_hashed_logistic_v1"}:
            raise ValueError("unsupported frozen logistic schema")
        return cls(
            intercept=float(payload.get("intercept", 0.0)),
            weights=payload.get("weights", {}),
            buckets=int(payload.get("buckets", FEATURE_BUCKETS)),
        )

    from_dict = import_dict


def semantic_action_family(option: Mapping[str, Any] | Any, selection: Mapping[str, Any] | Any = None) -> str:
    """Return the fixed semantic family for a raw option and its selection."""
    option_map = option if isinstance(option, Mapping) else {"type": option}
    wrapper = option_map
    semantic = _as_mapping(_lookup(option_map, "semantic", "option"))
    if semantic and _lookup(option_map, "type", "actionType", "action_type", "kind") is None:
        option_map = semantic
    selection_map = selection if isinstance(selection, Mapping) else _as_mapping(_lookup(wrapper, "selection"))
    raw_type = _lookup(option_map, "type", "actionType", "action_type", "kind")
    action_type = _numeric_action_type(raw_type) or _token(raw_type).upper()
    if action_type in {"PLAY", "PLAY_CARD", "CARD"}:
        return f"PLAY({_action_value(option_map, selection_map, 'card_id', 'cardId', 'card')})"
    if action_type in {"ATTACK", "USE_ATTACK"}:
        return f"ATTACK({_action_value(option_map, selection_map, 'attack_id', 'attackId', 'attack')})"
    if action_type in {"ABILITY", "USE_ABILITY"}:
        source = _action_value(option_map, selection_map, "source_card_id", "sourceCardId", "source")
        effect = _action_value(option_map, selection_map, "effect_id", "effectId", "effect")
        return f"ABILITY({source},{effect})"
    if action_type in {"ATTACH", "ATTACH_ENERGY"}:
        energy = _action_value(option_map, selection_map, "energy_id", "energyId", "energy")
        target = _action_value(option_map, selection_map, "target_area", "targetArea", "target")
        return f"ATTACH({energy},{target})"
    if action_type in {"RETREAT", "SWITCH"}:
        target = _action_value(option_map, selection_map, "target_card_id", "targetCardId", "target")
        return f"RETREAT({target})"
    if action_type in {"END", "END_TURN", "PASS"}:
        return "END"
    return f"OTHER({action_type or 'UNKNOWN'})"


action_family = semantic_action_family


@dataclass(frozen=True, order=True)
class OverlapClusterKey:
    module: str
    turn_bin: str
    own_active_id: str
    opp_active_id: str
    own_prize_bin: str
    opp_prize_bin: str
    own_bench_bin: str
    opp_bench_bin: str
    energy_attached: bool
    supporter_played: bool
    stadium_played: bool
    legal_families: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def token(self) -> str:
        return canonical_json(self.as_dict())


def fixed_overlap_cluster_key(
    state: Mapping[str, Any], legal_actions: Iterable[Mapping[str, Any] | str | tuple[Any, Any]]
) -> OverlapClusterKey:
    current = _current_mapping(state)
    sides = _state_sides(current)
    your_index = _as_int(_lookup(current, "yourIndex"), 0)
    own = sides[your_index] if your_index < len(sides) else {}
    opp_index = 1 - your_index if len(sides) == 2 else 1
    opponent = sides[opp_index] if opp_index < len(sides) else {}
    families = sorted({_legal_family(action) for action in legal_actions})
    return OverlapClusterKey(
        module=_token(_lookup(state, "module_version", "module", "moduleVersion") or _lookup(current, "module")),
        turn_bin=_turn_bin(_as_int(_lookup(current, "currentTurn", "turn"), 0)),
        own_active_id=_card_id(_active_card(_lookup(own, "active"))),
        opp_active_id=_card_id(_active_card(_lookup(opponent, "active"))),
        own_prize_bin=_count_bin(_prize_count(own), ((0, 2), (3, 4), (5, 6))),
        opp_prize_bin=_count_bin(_prize_count(opponent), ((0, 2), (3, 4), (5, 6))),
        own_bench_bin=_count_bin(len(_as_list(_lookup(own, "bench"))), ((0, 1), (2, 3), (4, 5))),
        opp_bench_bin=_count_bin(len(_as_list(_lookup(opponent, "bench"))), ((0, 1), (2, 3), (4, 5))),
        energy_attached=_flag(current, own, "energyAttached"),
        supporter_played=_flag(current, own, "supporterPlayed"),
        stadium_played=_flag(current, own, "stadiumPlayed"),
        legal_families=tuple(families),
    )


overlap_cluster_key = fixed_overlap_cluster_key


@dataclass(frozen=True)
class BranchRoot:
    pilot: str
    episode_id: str
    replay_cluster: str
    cluster_key: OverlapClusterKey | str
    selected_family: str
    outcome: float | None
    q_values: Mapping[str, float]
    selected_action: str = ""
    action_families: Mapping[str, str] = field(default_factory=dict)
    supported: bool = False
    error: str | None = None
    game_id: str = ""
    fold: str = ""
    chronological_index: int = 0

    @property
    def b(self) -> float | None:
        if self.selected_action not in self.q_values or not self.q_values:
            return None
        return float(self.q_values[self.selected_action]) - statistics.fmean(
            float(value) for value in self.q_values.values()
        )

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["cluster_key"] = (
            self.cluster_key.as_dict() if isinstance(self.cluster_key, OverlapClusterKey) else self.cluster_key
        )
        data["b"] = self.b
        return data

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> "BranchRoot":
        key = row.get("cluster_key", "")
        if isinstance(key, Mapping):
            key = OverlapClusterKey(
                module=str(key["module"]), turn_bin=str(key["turn_bin"]),
                own_active_id=str(key["own_active_id"]), opp_active_id=str(key["opp_active_id"]),
                own_prize_bin=str(key["own_prize_bin"]), opp_prize_bin=str(key["opp_prize_bin"]),
                own_bench_bin=str(key["own_bench_bin"]), opp_bench_bin=str(key["opp_bench_bin"]),
                energy_attached=bool(key["energy_attached"]), supporter_played=bool(key["supporter_played"]),
                stadium_played=bool(key["stadium_played"]), legal_families=tuple(key["legal_families"]),
            )
        q_values = {str(name): float(value) for name, value in (row.get("q_values") or {}).items()}
        action_families = {
            str(action): str(family) for action, family in (row.get("action_families") or {}).items()
        }
        selected_family = str(row.get("selected_family", row.get("selected_action_family", "")))
        selected_action = str(row.get("selected_action", ""))
        if not selected_action:
            candidates = [action for action, family in action_families.items() if family == selected_family]
            if len(candidates) == 1 and candidates[0] in q_values:
                selected_action = candidates[0]
            elif len(q_values) == 1 and selected_family in q_values:
                # Legacy family-keyed rows are usable only when no collapse is possible.
                selected_action = selected_family
                action_families = {selected_action: selected_family}
        return cls(
            pilot=str(row.get("pilot", "")),
            episode_id=str(row.get("episode_id", row.get("episode", ""))),
            replay_cluster=str(row.get("replay_cluster", row.get("cluster", ""))),
            cluster_key=key if isinstance(key, OverlapClusterKey) else str(key),
            selected_family=selected_family,
            outcome=None if row.get("outcome") is None else float(row["outcome"]),
            q_values=q_values,
            selected_action=selected_action,
            action_families=action_families,
            supported=bool(row.get("supported", False)), error=row.get("error"),
            game_id=str(row.get("game_id", row.get("episode_id", row.get("episode", "")))),
            fold=str(row.get("fold", "")),
            chronological_index=_as_int(row.get("chronological_index", row.get("root_index", 0)), 0),
        )


branch_root_from_dict = BranchRoot.from_dict


def branch_root_dict(root: BranchRoot | Mapping[str, Any]) -> dict[str, Any]:
    return root.as_dict() if isinstance(root, BranchRoot) else BranchRoot.from_dict(root).as_dict()


@dataclass(frozen=True)
class FamilySupport:
    games: int
    pilots: int
    propensity: float


@dataclass(frozen=True)
class ClusterSupport:
    games: int
    pilots: int
    outcome_classes: int
    chosen_families: int
    families: Mapping[str, FamilySupport]


@dataclass(frozen=True)
class SupportTable:
    clusters: Mapping[str, ClusterSupport]
    training_folds: tuple[str, ...]

    def evaluate(self, cluster_key: OverlapClusterKey | str, family: str) -> dict[str, Any]:
        key = _cluster_token(cluster_key)
        cluster = self.clusters.get(key)
        family_support = cluster.families.get(family) if cluster else None
        cluster_ok = bool(cluster) and cluster.games >= 12 and cluster.pilots >= 3 and cluster.outcome_classes >= 2 and cluster.chosen_families >= 2
        family_ok = bool(family_support) and family_support.games >= 4 and family_support.pilots >= 2
        propensity_ok = bool(family_support) and 0.10 <= family_support.propensity <= 0.90
        return {
            "supported": bool(cluster_ok and family_ok and propensity_ok),
            "cluster_games": cluster.games if cluster else 0,
            "cluster_pilots": cluster.pilots if cluster else 0,
            "outcome_classes": cluster.outcome_classes if cluster else 0,
            "chosen_families": cluster.chosen_families if cluster else 0,
            "family_games": family_support.games if family_support else 0,
            "family_pilots": family_support.pilots if family_support else 0,
            "propensity": family_support.propensity if family_support else 0.0,
        }


def build_support_table(
    rows: Iterable[BranchRoot | Mapping[str, Any]], *, training_folds: Iterable[str]
) -> SupportTable:
    """Build support exclusively from explicitly named training folds."""
    allowed = tuple(sorted(str(fold) for fold in training_folds))
    if not allowed:
        raise ValueError("training_folds must be nonempty")
    grouped: dict[str, list[BranchRoot]] = {}
    for value in rows:
        root = value if isinstance(value, BranchRoot) else BranchRoot.from_dict(value)
        if root.fold not in allowed or root.error is not None or root.outcome is None:
            continue
        grouped.setdefault(_cluster_token(root.cluster_key), []).append(root)
    clusters: dict[str, ClusterSupport] = {}
    for key, group in grouped.items():
        games = {root.game_id or root.episode_id for root in group}
        pilots = {root.pilot for root in group}
        outcomes = {root.outcome for root in group}
        families = {root.selected_family for root in group}
        by_family: dict[str, list[BranchRoot]] = {}
        for root in group:
            by_family.setdefault(root.selected_family, []).append(root)
        family_support = {
            family: FamilySupport(
                games=len({root.game_id or root.episode_id for root in members}),
                pilots=len({root.pilot for root in members}),
                propensity=len({root.game_id or root.episode_id for root in members}) / len(games),
            )
            for family, members in by_family.items()
        }
        clusters[key] = ClusterSupport(
            games=len(games), pilots=len(pilots), outcome_classes=len(outcomes),
            chosen_families=len(families), families=family_support,
        )
    return SupportTable(clusters=clusters, training_folds=allowed)


def aggregate_episode(roots: Iterable[BranchRoot | Mapping[str, Any]]) -> dict[str, Any]:
    values = [value if isinstance(value, BranchRoot) else BranchRoot.from_dict(value) for value in roots]
    if not values:
        raise ValueError("an episode requires at least one root")
    episode_ids = {root.episode_id for root in values}
    if len(episode_ids) != 1:
        raise ValueError("all roots must belong to one episode")
    ordered = sorted(values, key=lambda root: root.chronological_index)
    supported_bs = [root.b for root in ordered if root.supported and root.b is not None and root.error is None]
    first_q_mean = statistics.fmean(float(value) for value in ordered[0].q_values.values()) if ordered[0].q_values else 0.5
    first_probability = min(max(first_q_mean, 1e-12), 1.0 - 1e-12)
    return {
        "episode_id": ordered[0].episode_id,
        "pilot": ordered[0].pilot,
        "B_episode": statistics.fmean(supported_bs) if supported_bs else 0.0,
        "supported_decisions": len(supported_bs),
        "total_decisions": len(ordered),
        "unsupported_mass": 1.0 - len(supported_bs) / len(ordered),
        "initial_state_logit": _logit(first_probability),
        "initial_state_probability": first_probability,
    }


def aggregate_unit(
    episodes: Iterable[Mapping[str, Any]], *, activation: Mapping[str, Any] | bool | None = None
) -> dict[str, Any]:
    values = list(episodes)
    episode_ids = [str(value.get("episode_id", "")) for value in values]
    if len(values) != 8 or len(set(episode_ids)) != 8 or any(not value for value in episode_ids):
        raise ValueError("a branch_bridge_v1 unit requires exactly 8 distinct episodes")
    raw_b = statistics.fmean(float(value.get("B_episode", 0.0)) for value in values)
    activated = bool(activation.get("activated")) if isinstance(activation, Mapping) else bool(activation)
    return {
        "episodes": 8,
        "episode_ids": tuple(episode_ids),
        "B_unit_raw": raw_b,
        "B_unit": raw_b if activated else 0.0,
        "U": statistics.fmean(float(value.get("unsupported_mass", 1.0)) for value in values),
        "supported_decisions": sum(int(value.get("supported_decisions", 0)) for value in values),
        "supported_episodes": sum(int(value.get("supported_decisions", 0)) > 0 for value in values),
        "activated": activated,
    }


@dataclass(frozen=True)
class BranchActivationThresholds:
    overall_support_mass: float = 0.85
    eligible_pilot_support_mass: float = 0.70
    minimum_eligible_overlap_clusters: int = 20
    cluster_positive_slope_fraction: float = 0.70
    residual_spearman: float = 0.30
    pairwise_residual_concordance: float = 0.64
    pilot_macro_logloss_lift: float = 0.015
    positive_fold_fraction: float = 0.80
    bootstrap_probability_positive: float = 0.90
    bootstrap_q10_slope: float = 0.0


def evaluate_activation_metrics(
    rows: Iterable[Mapping[str, Any] | BranchRoot], *,
    thresholds: BranchActivationThresholds = BranchActivationThresholds(),
    bootstrap_samples: int = 2000,
    seed: int = 20260711,
    deterministic_repeat: bool = False,
) -> dict[str, Any]:
    """Evaluate preregistered activation checks from already cross-fitted rows."""
    if bootstrap_samples <= 0:
        raise ValueError("bootstrap_samples must be positive")
    normalized = [_activation_row(value) for value in rows]
    metrics = _activation_statistics(normalized, bootstrap_samples=bootstrap_samples, seed=seed)
    checks = [
        ("overall_support_mass", metrics["overall_support_mass"] >= thresholds.overall_support_mass, metrics["overall_support_mass"], thresholds.overall_support_mass),
        ("eligible_pilot_support_mass", metrics["minimum_eligible_pilot_support_mass"] >= thresholds.eligible_pilot_support_mass, metrics["minimum_eligible_pilot_support_mass"], thresholds.eligible_pilot_support_mass),
        ("eligible_overlap_clusters", metrics["eligible_overlap_cluster_count"] >= thresholds.minimum_eligible_overlap_clusters, metrics["eligible_overlap_cluster_count"], thresholds.minimum_eligible_overlap_clusters),
        ("cluster_positive_slope_fraction", metrics["cluster_positive_slope_fraction"] >= thresholds.cluster_positive_slope_fraction, metrics["cluster_positive_slope_fraction"], thresholds.cluster_positive_slope_fraction),
        ("residual_spearman", metrics["residual_spearman"] >= thresholds.residual_spearman, metrics["residual_spearman"], thresholds.residual_spearman),
        ("pairwise_residual_concordance", metrics["pairwise_residual_concordance"] >= thresholds.pairwise_residual_concordance, metrics["pairwise_residual_concordance"], thresholds.pairwise_residual_concordance),
        ("pilot_macro_logloss_lift", metrics["pilot_macro_logloss_lift"] >= thresholds.pilot_macro_logloss_lift, metrics["pilot_macro_logloss_lift"], thresholds.pilot_macro_logloss_lift),
        ("positive_fold_fraction", metrics["positive_fold_fraction"] >= thresholds.positive_fold_fraction, metrics["positive_fold_fraction"], thresholds.positive_fold_fraction),
        ("bootstrap_probability_positive", metrics["bootstrap_probability_positive"] >= thresholds.bootstrap_probability_positive, metrics["bootstrap_probability_positive"], thresholds.bootstrap_probability_positive),
        ("bootstrap_q10_slope", metrics["bootstrap_q10_slope"] > thresholds.bootstrap_q10_slope, metrics["bootstrap_q10_slope"], f">{thresholds.bootstrap_q10_slope}"),
        ("deterministic_repeat", deterministic_repeat, deterministic_repeat, True),
    ]
    rendered = [{"name": name, "passed": bool(passed), "value": value, "threshold": threshold} for name, passed, value, threshold in checks]
    activated = all(check["passed"] for check in rendered)
    return {
        "schema": "branch_bridge_v1_activation",
        "thresholds": asdict(thresholds),
        "metrics": metrics,
        "checks": rendered,
        "deterministic_repeat": deterministic_repeat,
        "activated": activated,
        "B_multiplier": 1.0 if activated else 0.0,
    }


def effective_branch_value(value: float, activation: Mapping[str, Any] | bool) -> float:
    activated = bool(activation.get("activated")) if isinstance(activation, Mapping) else bool(activation)
    return float(value) if activated else 0.0


def _activation_statistics(rows: list[dict[str, Any]], *, bootstrap_samples: int, seed: int) -> dict[str, Any]:
    support_by_pilot: dict[str, list[bool]] = {}
    for row in rows:
        support_by_pilot.setdefault(row["pilot"], []).append(row["supported"])
    pilot_support = {pilot: sum(values) / len(values) for pilot, values in sorted(support_by_pilot.items()) if values}
    games_by_pilot: dict[str, set[str]] = {}
    for row in rows:
        games_by_pilot.setdefault(row["pilot"], set()).add(row["game_id"] or row["episode_id"])
    eligible = [pilot_support[pilot] for pilot, games in games_by_pilot.items() if len(games) >= 8]
    residual_rows = [
        row for row in rows
        if row["supported"] and row["outcome"] is not None and row["b"] is not None
    ]
    cluster_slopes: list[float] = []
    by_cluster: dict[str, list[dict[str, Any]]] = {}
    for row in residual_rows:
        by_cluster.setdefault(row["cluster_key"], []).append(row)
    for group in by_cluster.values():
        slope = _slope([row["b"] for row in group], [row["outcome"] for row in group])
        if slope is not None:
            cluster_slopes.append(slope)
    residuals = [row["outcome"] - row["m0_prediction"] for row in residual_rows]
    bs = [row["b"] for row in residual_rows]
    spearman = _spearman(bs, residuals)
    pairwise = _pairwise_concordance(residual_rows)
    pilot_lifts: dict[str, float] = {}
    by_pilot: dict[str, list[dict[str, Any]]] = {}
    by_fold: dict[str, list[dict[str, Any]]] = {}
    for row in residual_rows:
        by_pilot.setdefault(row["pilot"], []).append(row)
        by_fold.setdefault(row["fold"], []).append(row)
    for pilot, group in by_pilot.items():
        pilot_lifts[pilot] = _logloss(group, "m0_prediction") - _logloss(group, "m1_prediction")
    fold_lifts = {fold: _logloss(group, "m0_prediction") - _logloss(group, "m1_prediction") for fold, group in by_fold.items()}
    bootstrap = _game_cluster_bootstrap(residual_rows, samples=bootstrap_samples, seed=seed)
    return {
        "rows": len(rows),
        "overall_support_mass": sum(row["supported"] for row in rows) / len(rows) if rows else 0.0,
        "per_pilot_support_mass": pilot_support,
        "minimum_eligible_pilot_support_mass": min(eligible) if eligible else 0.0,
        "eligible_overlap_cluster_count": len(cluster_slopes),
        "cluster_count": len(cluster_slopes),
        "cluster_positive_slope_fraction": sum(slope > 0.0 for slope in cluster_slopes) / len(cluster_slopes) if cluster_slopes else 0.0,
        "residual_spearman": spearman if spearman is not None else 0.0,
        "pairwise_residual_concordance": pairwise,
        "pilot_macro_logloss_lift": statistics.fmean(pilot_lifts.values()) if pilot_lifts else 0.0,
        "per_pilot_logloss_lift": pilot_lifts,
        "positive_fold_fraction": sum(lift > 0.0 for lift in fold_lifts.values()) / len(fold_lifts) if fold_lifts else 0.0,
        "per_fold_logloss_lift": fold_lifts,
        **bootstrap,
    }


def _activation_row(value: Mapping[str, Any] | BranchRoot) -> dict[str, Any]:
    root = value if isinstance(value, BranchRoot) else None
    row = root.as_dict() if root else dict(value)
    q_values = row.get("q_values") or {}
    b = row.get("b")
    if b is None and root is not None:
        b = root.b
    selected_action = row.get("selected_action")
    if b is None and q_values and selected_action in q_values:
        b = float(q_values[selected_action]) - statistics.fmean(float(item) for item in q_values.values())
    return {
        "pilot": str(row.get("pilot", "")), "supported": bool(row.get("supported", False)),
        "cluster_key": _cluster_token(row.get("cluster_key", "")), "game_id": str(row.get("game_id", row.get("episode_id", ""))),
        "episode_id": str(row.get("episode_id", row.get("game_id", ""))),
        "fold": str(row.get("fold", "")), "b": None if b is None else float(b),
        "outcome": None if row.get("outcome") is None else float(row["outcome"]),
        "m0_prediction": _probability(row.get("m0_prediction", row.get("M0", 0.5))),
        "m1_prediction": _probability(row.get("m1_prediction", row.get("M1", 0.5))),
    }


def _game_cluster_bootstrap(rows: list[dict[str, Any]], *, samples: int, seed: int) -> dict[str, float]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["game_id"], row["cluster_key"]), []).append(row)
    units = list(groups.values())
    if not units:
        return {"bootstrap_probability_positive": 0.0, "bootstrap_q10_slope": 0.0}
    rng = Random(seed)
    slopes: list[float] = []
    for _ in range(samples):
        draw = [units[rng.randrange(len(units))] for _ in units]
        flat = [row for group in draw for row in group]
        slope = _slope([row["b"] for row in flat], [row["outcome"] - row["m0_prediction"] for row in flat])
        slopes.append(slope if slope is not None else 0.0)
    return {
        "bootstrap_probability_positive": sum(slope > 0.0 for slope in slopes) / len(slopes),
        "bootstrap_q10_slope": _quantile(slopes, 0.10),
    }


def _side_features(label: str, side: Mapping[str, Any], *, include_hand: bool) -> list[str]:
    active = _active_card(_lookup(side, "active"))
    bench = _as_list(_lookup(side, "bench"))
    discard = _as_list(_lookup(side, "discard"))
    features = [
        f"{label}:bench_count={len(bench)}", f"{label}:discard_count={len(discard)}",
        f"{label}:prize_count={_prize_count(side)}",
        f"{label}:deck_count={_token(_lookup(side, 'deckCount', 'deck_count'))}",
        f"{label}:hand_count={_token(_lookup(side, 'handCount', 'hand_count'))}",
        f"{label}:bench_max={_token(_lookup(side, 'benchMax', 'bench_max'))}",
    ]
    features.extend(_pokemon_features(label, "active", active))
    for index, pokemon in enumerate(bench):
        features.extend(_pokemon_features(label, f"bench{index}", _as_mapping(pokemon)))
    for card_id in sorted(_card_id(card) for card in discard):
        features.append(f"{label}:discard={card_id}")
    statuses = _lookup(side, "status", "statuses")
    for status in sorted(_status_tokens(statuses)):
        features.append(f"{label}:status={status}")
    for key in ("retreated", "energyAttached", "supporterPlayed", "stadiumPlayed"):
        if _lookup(side, key) is not None:
            features.append(f"{label}:status:{key}={_token(_lookup(side, key))}")
    if include_hand:
        for card_id in sorted(_card_id(card) for card in _as_list(_lookup(side, "hand"))):
            features.append(f"own:hand={card_id}")
    return features


def _pokemon_features(side: str, location: str, pokemon: Mapping[str, Any]) -> list[str]:
    if not pokemon:
        return [f"{side}:{location}=EMPTY"]
    values = [
        f"{side}:{location}:card={_card_id(pokemon)}",
        f"{side}:{location}:hp={_token(_lookup(pokemon, 'hp', 'HP'))}",
        f"{side}:{location}:energy={_energy_token(_lookup(pokemon, 'energy', 'energies', 'energyCards'))}",
        f"{side}:{location}:tools={_tool_token(_lookup(pokemon, 'tools', 'tool', 'toolCards'))}",
    ]
    values.extend(f"{side}:{location}:status={status}" for status in _status_tokens(_lookup(pokemon, "status", "statuses")))
    return values


def _state_sides(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = _lookup(state, "sides", "players")
    if isinstance(raw, Mapping):
        return [_as_mapping(raw.get("0", raw.get(0, {}))), _as_mapping(raw.get("1", raw.get(1, {})))]
    values = [_as_mapping(value) for value in _as_list(raw)]
    if values:
        return values
    return [_as_mapping(_lookup(state, "you", "own")), _as_mapping(_lookup(state, "opponent", "opp"))]


def _current_mapping(state: Mapping[str, Any]) -> Mapping[str, Any]:
    current = _as_mapping(_lookup(state, "current"))
    return current if current else state


def _active_card(value: Any) -> Mapping[str, Any]:
    cards = _as_list(value)
    return _as_mapping(cards[0]) if cards else _as_mapping(value)


def _flag(current: Mapping[str, Any], own: Mapping[str, Any], key: str) -> bool:
    value = _lookup(current, key)
    return _as_bool(_lookup(own, key) if value is None else value)


def _lookup(mapping: Mapping[str, Any] | Any, *keys: str) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _action_value(option: Mapping[str, Any], selection: Mapping[str, Any], *keys: str) -> str:
    value = _lookup(selection, *keys)
    if value is None:
        value = _lookup(option, *keys)
    return _token(value)


def _legal_family(value: Mapping[str, Any] | str | tuple[Any, Any]) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, tuple) and len(value) == 2:
        return semantic_action_family(value[0], value[1])
    return semantic_action_family(value)


def _cluster_token(key: OverlapClusterKey | Mapping[str, Any] | Any) -> str:
    if isinstance(key, OverlapClusterKey):
        return key.token()
    if isinstance(key, Mapping):
        return canonical_json(key)
    return str(key)


def _turn_bin(value: int) -> str:
    return _count_bin(value, ((0, 1), (2, 3), (4, 5), (6, 8)), upper="9+")


def _count_bin(value: int, ranges: Sequence[tuple[int, int]], upper: str = "6+") -> str:
    for lower, upper_bound in ranges:
        if lower <= value <= upper_bound:
            return f"{lower}-{upper_bound}"
    return upper


def _prize_count(side: Mapping[str, Any]) -> int:
    value = _lookup(side, "prize_count", "prizeCount", "prizes", "prize")
    return len(value) if isinstance(value, (list, tuple, set)) else _as_int(value, 0)


def _card_id(value: Any) -> str:
    mapping = _as_mapping(value)
    return _token(_lookup(mapping, "card_id", "cardId", "id")) if mapping else _token(value)


def _energy_token(value: Any) -> str:
    return str(len(value)) if isinstance(value, (list, tuple, set)) else _token(value)


def _tool_token(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(_card_id(item) for item in value))
    return _card_id(value)


def _numeric_action_type(value: Any) -> str | None:
    numeric_types = {
        7: "PLAY", 8: "ATTACH", 9: "PLAY", 10: "ABILITY", 12: "RETREAT",
        13: "ATTACK", 14: "END",
    }
    try:
        return numeric_types.get(int(value))
    except (TypeError, ValueError):
        return None


def _status_tokens(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return sorted(_token(key) for key, enabled in value.items() if enabled)
    if isinstance(value, (list, tuple, set)):
        return sorted(_token(item) for item in value)
    return [] if value is None else [_token(value)]


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any) -> bool:
    return bool(value)


def _token(value: Any) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _probability(value: Any) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("prediction must be finite")
    return min(max(result, 1e-12), 1.0 - 1e-12)


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(min(value, 709.0), -709.0)))


def _logit(probability: float) -> float:
    return math.log(probability / (1.0 - probability))


def _slope(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    if len(xs) < 2:
        return None
    mean_x, mean_y = statistics.fmean(xs), statistics.fmean(ys)
    denominator = sum((value - mean_x) ** 2 for value in xs)
    return None if denominator == 0.0 else sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator


def _spearman(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    if len(xs) < 2:
        return None
    ranks_x, ranks_y = _ranks(xs), _ranks(ys)
    mean_x, mean_y = statistics.fmean(ranks_x), statistics.fmean(ranks_y)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(ranks_x, ranks_y))
    denominator = math.sqrt(sum((x - mean_x) ** 2 for x in ranks_x) * sum((y - mean_y) ** 2 for y in ranks_y))
    return None if denominator == 0.0 else numerator / denominator


def _ranks(values: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda pair: pair[1])
    ranks = [0.0] * len(values)
    start = 0
    while start < len(indexed):
        end = start + 1
        while end < len(indexed) and indexed[end][1] == indexed[start][1]:
            end += 1
        rank = (start + 1 + end) / 2.0
        for index, _ in indexed[start:end]:
            ranks[index] = rank
        start = end
    return ranks


def _pairwise_concordance(rows: Sequence[dict[str, Any]]) -> float:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(row["game_id"] or row["episode_id"], []).append(row)
    game_values = [
        (
            statistics.fmean(row["b"] for row in group),
            statistics.fmean(row["outcome"] - row["m0_prediction"] for row in group),
        )
        for group in groups.values()
    ]
    agree = comparable = 0
    for left in range(len(game_values)):
        for right in range(left + 1, len(game_values)):
            delta_b = game_values[left][0] - game_values[right][0]
            delta_residual = game_values[left][1] - game_values[right][1]
            if delta_b == 0.0 or delta_residual == 0.0:
                continue
            comparable += 1
            agree += (delta_b > 0.0) == (delta_residual > 0.0)
    return agree / comparable if comparable else 0.0


def _logloss(rows: Sequence[dict[str, Any]], key: str) -> float:
    if not rows:
        return float("inf")
    return statistics.fmean(
        -(row["outcome"] * math.log(row[key]) + (1.0 - row["outcome"]) * math.log(1.0 - row[key]))
        for row in rows
    )


def _quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower, upper = int(position), min(int(position) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _contains_burned_panel_id(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_burned_panel_id(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_burned_panel_id(item) for item in value)
    return value == BURNED_PANEL_ID


def _json_ready(value: Any) -> Any:
    if is_dataclass(value):
        return _json_ready(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, set):
        return sorted(_json_ready(item) for item in value)
    return value


__all__ = [
    "BURNED_PANEL_ID", "BURNED_PANEL_SHA256", "BURNED_VALIDATION_SHA256", "BranchActivationThresholds",
    "BranchRoot", "ClusterSupport", "FEATURE_BUCKETS", "FamilySupport", "FrozenHashedLogistic",
    "OverlapClusterKey", "SupportTable", "TECHNICAL_DENYLIST_SHA256", "action_family",
    "actor_visible_state_features", "aggregate_episode", "aggregate_unit", "branch_root_dict",
    "branch_root_from_dict", "build_support_table", "canonical_json", "canonical_sha256",
    "effective_branch_value", "evaluate_activation_metrics", "fixed_overlap_cluster_key",
    "hashed_actor_visible_features", "overlap_cluster_key", "reject_burned_artifact", "semantic_action_family",
    "sha1_feature_bucket", "sha256_file", "validate_artifact_not_burned",
    "PANEL_ID", "PANEL_SHA256", "VALIDATION_SHA256", "TECHNICAL_DENYLIST",
]
