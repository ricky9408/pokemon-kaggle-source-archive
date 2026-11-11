"""Engine-independent primitives for conservative paired-world search.

The module deliberately does not know how to clone a game state or advance a
simulation.  An engine adapter supplies legal actions and world values; this
module supplies deterministic bookkeeping and the safeguards around using the
result to override a root policy.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
from math import fsum, isfinite
from statistics import median
from typing import Any, TypeVar


Action = TypeVar("Action")
Actor = TypeVar("Actor")
State = TypeVar("State")
ActionPrior = Callable[[State, Action], float]


@dataclass(frozen=True)
class WorldActionValue:
    """One root-action result from one determinized world.

    ``value`` is always from the root player's point of view: larger is better
    for the root player.  ``world_id`` must identify the same determinization
    across every root action being compared.
    """

    action: Any
    world_id: Any
    value: float


@dataclass(frozen=True)
class ActionWorldAggregate:
    """Order-independent summary of an action's independently evaluated worlds."""

    action: Any
    world_count: int
    mean: float
    median: float
    minimum: float
    maximum: float
    world_values: tuple[tuple[str, float], ...]


@dataclass(frozen=True)
class RootOverride:
    """The root choice and the evidence (or lack of evidence) behind it."""

    action: Any
    overridden: bool
    reason: str
    paired_world_count: int
    margin: float | None
    prior_mean: float | None
    challenger_mean: float | None


def stable_observation_seed(observation: Any, *, namespace: str = "paired-world-v1") -> int:
    """Return a stable 64-bit seed derived only from a public observation.

    Python's built-in ``hash`` is deliberately randomized across processes, so
    it is not suitable for paired worlds.  Canonical JSON means mapping order
    cannot affect this seed.  Unsupported values fail closed instead of falling
    back to an address-dependent representation.
    """

    if not isinstance(namespace, str):
        raise TypeError("namespace must be a string")
    payload = _canonical_json(observation)
    digest = sha256(namespace.encode("utf-8") + b"\0" + payload).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def select_rollout_action(
    state: State,
    legal_actions: Sequence[Action],
    *,
    actor: Actor,
    root_player: Actor,
    root_prior: ActionPrior[State, Action],
    opponent_prior: ActionPrior[State, Action] | None,
) -> Action:
    """Select a deterministic rollout action using the acting player's prior.

    The opponent policy is required on non-root turns.  There is intentionally
    no fallback to ``root_prior``: doing so turns an adversarial rollout into
    cooperative self-play whenever an opponent adapter is missing.
    """

    if not legal_actions:
        raise ValueError("legal_actions must be nonempty")
    if actor == root_player:
        prior = root_prior
    else:
        if opponent_prior is None:
            raise ValueError("opponent_prior is required for non-root turns")
        prior = opponent_prior

    scored: list[tuple[float, str, Action]] = []
    for action in legal_actions:
        score = float(prior(state, action))
        if not isfinite(score):
            raise ValueError("action priors must return finite scores")
        scored.append((score, _canonical_json(action).decode("utf-8"), action))
    # The canonical action key makes ties independent of adapter option order.
    return min(scored, key=lambda item: (-item[0], item[1]))[2]


def aggregate_action_worlds(values: Iterable[WorldActionValue]) -> tuple[ActionWorldAggregate, ...]:
    """Group action values by world, rejecting duplicate action/world samples.

    Duplicates usually mean a retry or an adapter bookkeeping bug.  Averaging
    them would overweight one world and make an apparent paired result depend
    on execution history, so they are rejected.
    """

    grouped: dict[str, tuple[Any, dict[str, float]]] = {}
    for sample in values:
        action_key = _canonical_json(sample.action).decode("utf-8")
        world_key = _canonical_json(sample.world_id).decode("utf-8")
        value = float(sample.value)
        if not isfinite(value):
            raise ValueError("world values must be finite")
        action, world_values = grouped.setdefault(action_key, (sample.action, {}))
        if world_key in world_values:
            raise ValueError("duplicate action/world sample")
        world_values[world_key] = value

    aggregates: list[ActionWorldAggregate] = []
    for action_key in sorted(grouped):
        action, by_world = grouped[action_key]
        ordered = tuple(sorted(by_world.items()))
        outcomes = [value for _, value in ordered]
        aggregates.append(
            ActionWorldAggregate(
                action=action,
                world_count=len(outcomes),
                mean=fsum(outcomes) / len(outcomes),
                median=float(median(outcomes)),
                minimum=min(outcomes),
                maximum=max(outcomes),
                world_values=ordered,
            )
        )
    return tuple(aggregates)


def select_conservative_root_override(
    prior_action: Any,
    values: Iterable[WorldActionValue],
    *,
    min_worlds: int,
    min_margin: float,
) -> RootOverride:
    """Override the root prior only on enough paired worlds and clear margin.

    A challenger is compared exclusively against ``prior_action`` in the
    intersection of their world IDs.  That prevents a partially evaluated
    action from winning by being measured in a friendlier set of worlds.
    """

    if min_worlds <= 0:
        raise ValueError("min_worlds must be positive")
    if not isfinite(min_margin) or min_margin < 0.0:
        raise ValueError("min_margin must be a finite nonnegative number")

    aggregates = aggregate_action_worlds(values)
    by_action = {_canonical_json(item.action).decode("utf-8"): item for item in aggregates}
    prior_key = _canonical_json(prior_action).decode("utf-8")
    prior = by_action.get(prior_key)
    if prior is None:
        return RootOverride(prior_action, False, "prior_action_not_evaluated", 0, None, None, None)

    prior_by_world = dict(prior.world_values)
    candidates: list[tuple[float, str, Any, int, float, float]] = []
    for action_key, candidate in by_action.items():
        if action_key == prior_key:
            continue
        candidate_by_world = dict(candidate.world_values)
        paired_ids = tuple(sorted(prior_by_world.keys() & candidate_by_world.keys()))
        if len(paired_ids) < min_worlds:
            continue
        prior_mean = fsum(prior_by_world[world_id] for world_id in paired_ids) / len(paired_ids)
        candidate_mean = fsum(candidate_by_world[world_id] for world_id in paired_ids) / len(paired_ids)
        margin = candidate_mean - prior_mean
        candidates.append((margin, action_key, candidate.action, len(paired_ids), prior_mean, candidate_mean))

    if not candidates:
        return RootOverride(prior_action, False, "insufficient_paired_worlds", 0, None, None, None)

    margin, _, action, world_count, prior_mean, challenger_mean = min(
        candidates, key=lambda item: (-item[0], item[1])
    )
    if margin < min_margin:
        return RootOverride(
            prior_action,
            False,
            "margin_below_threshold",
            world_count,
            margin,
            prior_mean,
            challenger_mean,
        )
    return RootOverride(action, True, "paired_margin_met", world_count, margin, prior_mean, challenger_mean)


def _canonical_json(value: Any) -> bytes:
    """Encode JSON-shaped values deterministically, including sets and tuples."""

    return json.dumps(
        _canonicalize(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonicalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("canonical values must be finite")
        return value
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return {"__tuple__": [_canonicalize(item) for item in value]}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (frozenset, set)):
        items = [_canonicalize(item) for item in value]
        return {"__set__": sorted(items, key=lambda item: _canonical_json(item))}
    raise TypeError(f"unsupported canonical value type: {type(value).__name__}")
