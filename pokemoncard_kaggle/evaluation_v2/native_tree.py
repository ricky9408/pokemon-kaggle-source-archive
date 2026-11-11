"""Candidate-neutral expectiminimax trees backed by deterministic path replay."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from math import fsum, isfinite
from collections.abc import Callable, Sequence
from typing import Any

from .expectiminimax import ExpectiminimaxNode, ExpectiminimaxResult, expectiminimax
from .native_adapter import (
    PatchedNativeSession,
    derive_world_seed,
    enumerate_legal_selections,
    information_set_hash,
    semantic_selection,
)
from .world_bank import BeliefWorld, WorldBank


@dataclass(frozen=True)
class NativeTreeDecision:
    selection: tuple[int, ...] | None
    semantic_action: str | None
    value: float | None
    resolved: bool
    worlds: int
    native_nodes_built: int
    search: ExpectiminimaxResult | None
    root_action_values: tuple[tuple[str, float], ...] = ()
    margin: float | None = None
    error: str | None = None


def public_leaf_value(observation: dict[str, Any], root_player: int) -> float:
    """Bounded, deck-agnostic public-state utility from the root perspective."""

    current = observation.get("current")
    if not isinstance(current, dict):
        raise ValueError("leaf observation has no current state")
    result = current.get("result", -1)
    if result != -1:
        if result == root_player:
            return 1.0
        if result == 1 - root_player:
            return -1.0
        return 0.0
    players = current.get("players")
    if not isinstance(players, list) or len(players) != 2:
        raise ValueError("leaf state must have two players")
    root = players[root_player]
    opponent = players[1 - root_player]
    if not isinstance(root, dict) or not isinstance(opponent, dict):
        raise ValueError("leaf players must be mappings")

    # Root prizes taken minus opponent prizes taken. Prize arrays contain the
    # cards still owned by that player, so the sign is root_remaining - opp_remaining.
    prize_edge = len(root.get("prize") or []) - len(opponent.get("prize") or [])
    hand_edge = int(root.get("handCount") or 0) - int(opponent.get("handCount") or 0)
    hp_edge = _field_hp(root) - _field_hp(opponent)
    energy_edge = _field_energy(root) - _field_energy(opponent)
    board_edge = _field_count(root) - _field_count(opponent)
    value = 0.18 * prize_edge + 0.012 * hand_edge + 0.00055 * hp_edge + 0.028 * energy_edge + 0.025 * board_edge
    return max(-0.95, min(0.95, value))


class NativeTreeBuilder:
    """Eager bounded tree builder using fresh seeded path replay per node.

    Depth counts complete MAIN decisions, not low-level engine selections. Card
    searches, target choices, and other effect substeps are resolved before a
    leaf is evaluated, avoiding values on half-resolved actions.
    """

    def __init__(
        self,
        api_module: Any,
        observation: dict[str, Any],
        worlds: tuple[BeliefWorld, ...],
        *,
        depth: int,
        max_native_nodes: int = 20_000,
        max_actions: int = 128,
        max_policy_prior: Callable[[dict[str, Any]], Sequence[float]] | None = None,
        leaf_evaluator: Callable[[dict[str, Any], int], float] | None = None,
    ) -> None:
        if depth < 1:
            raise ValueError("depth must be at least one")
        if not worlds:
            raise ValueError("at least one belief world is required")
        current = observation.get("current")
        if not isinstance(current, dict) or current.get("yourIndex") not in (0, 1):
            raise ValueError("root observation has no valid yourIndex")
        self.api = api_module
        self.observation = observation
        self.worlds = worlds
        self.depth = depth
        self.max_native_nodes = max_native_nodes
        self.max_actions = max_actions
        self.max_policy_prior = max_policy_prior
        self.leaf_evaluator = leaf_evaluator
        self.root_player = int(current["yourIndex"])
        self.native_nodes_built = 0
        self._observations: dict[tuple[str, tuple[tuple[int, ...], ...]], dict[str, Any]] = {}

    def build(self) -> tuple[ExpectiminimaxNode, ...]:
        return tuple(self._build_node(world, (), depth=0) for world in self.worlds)

    def _observation_at(self, world: BeliefWorld, path: tuple[tuple[int, ...], ...]) -> dict[str, Any]:
        cache_key = (world.world_id, path)
        cached = self._observations.get(cache_key)
        if cached is not None:
            return cached
        if self.native_nodes_built >= self.max_native_nodes:
            raise RuntimeError("native node budget exhausted")
        self.native_nodes_built += 1
        with PatchedNativeSession(self.api, seed=derive_world_seed(world)) as session:
            state = session.begin(self.observation, world)
            for selection in path:
                state = session.step(state.searchId, selection)
            converted = asdict(state.observation)
        self._observations[cache_key] = converted
        return converted

    def _build_node(
        self,
        world: BeliefWorld,
        path: tuple[tuple[int, ...], ...],
        *,
        depth: int,
    ) -> ExpectiminimaxNode:
        observation = self._observation_at(world, path)
        current = observation.get("current")
        if not isinstance(current, dict):
            raise ValueError("native observation has no current state")
        actor = "max" if current.get("yourIndex") == self.root_player else "min"
        key = information_set_hash(observation) if observation.get("select") else {
            "terminal": current.get("result"),
            "path_depth": depth,
        }
        result = current.get("result", -1)
        if result != -1:
            return ExpectiminimaxNode(
                actor=actor,
                information_set_key=key,
                terminal_value=public_leaf_value(observation, self.root_player),
            )
        select = observation.get("select")
        at_main_boundary = isinstance(select, dict) and select.get("context") == 0
        if (depth >= self.depth and at_main_boundary) or not isinstance(select, dict) or not select.get("option"):
            leaf_value = (
                public_leaf_value(observation, self.root_player)
                if self.leaf_evaluator is None
                else float(self.leaf_evaluator(observation, self.root_player))
            )
            if not isfinite(leaf_value) or not -1.0 <= leaf_value <= 1.0:
                raise ValueError("leaf evaluator returned an invalid value")
            return ExpectiminimaxNode(
                actor=actor,
                information_set_key=key,
                leaf_value=leaf_value,
            )

        actions = enumerate_legal_selections(select, max_actions=self.max_actions)
        action_map: dict[str, tuple[int, ...]] = {}
        for selection in actions:
            semantic = _canonical_action(semantic_selection(select, selection))
            if semantic in action_map:
                raise ValueError("semantic action collision after serial normalization")
            action_map[semantic] = selection
        child_depth = depth + 1 if at_main_boundary else depth
        successors = {
            semantic: self._build_node(world, path + (selection,), depth=child_depth)
            for semantic, selection in sorted(action_map.items())
        }
        action_priors: dict[str, float] = {}
        if actor == "max" and depth == 0 and self.max_policy_prior is not None:
            option_scores = tuple(float(value) for value in self.max_policy_prior(observation))
            if len(option_scores) != len(select.get("option") or ()) or any(not isfinite(value) for value in option_scores):
                raise ValueError("max policy prior returned invalid option scores")
            for semantic, selection in action_map.items():
                action_priors[semantic] = (
                    fsum(option_scores[index] for index in selection) / len(selection)
                    if selection
                    else 0.0
                )
        return ExpectiminimaxNode(
            actor=actor,
            information_set_key=key,
            legal_actions=tuple(sorted(action_map)),
            successors=successors,
            action_priors=action_priors,
        )


def search_native_world_bank(
    api_module: Any,
    observation: dict[str, Any],
    world_bank: WorldBank,
    *,
    depth: int = 2,
    world_limit: int | None = None,
    max_native_nodes: int = 20_000,
    max_actions: int = 128,
    max_policy_prior: Callable[[dict[str, Any]], Sequence[float]] | None = None,
    prior_weight: float = 0.0,
    leaf_evaluator: Callable[[dict[str, Any], int], float] | None = None,
) -> NativeTreeDecision:
    """Run candidate-neutral information-set search or return no action."""

    worlds = (
        world_bank.worlds
        if world_limit is None
        else tuple(sorted(world_bank.worlds, key=lambda world: world.stable_hash)[:world_limit])
    )
    try:
        builder = NativeTreeBuilder(
            api_module,
            observation,
            worlds,
            depth=depth,
            max_native_nodes=max_native_nodes,
            max_actions=max_actions,
            max_policy_prior=max_policy_prior,
            leaf_evaluator=leaf_evaluator,
        )
        roots = builder.build()
        result = expectiminimax(
            roots,
            root_actor="max",
            node_budget=max(max_native_nodes * 4, 10_000),
            depth_budget=None,
            prior_weight=prior_weight,
        )
        if not result.resolved or not isinstance(result.action, str):
            reasons = ",".join(item.reason for item in result.unresolved) or "no selected action"
            return NativeTreeDecision(
                None,
                None,
                None,
                False,
                len(worlds),
                builder.native_nodes_built,
                result,
                (),
                None,
                f"expectiminimax unresolved: {reasons}",
            )
        root_select = observation.get("select")
        if not isinstance(root_select, dict):
            raise ValueError("root select missing")
        root_actions = {
            _canonical_action(semantic_selection(root_select, selection)): selection
            for selection in enumerate_legal_selections(root_select, max_actions=max_actions)
        }
        selection = root_actions.get(result.action)
        if selection is None:
            raise ValueError("selected semantic action is absent from root")
        root_key = json.dumps(roots[0].information_set_key, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        root_values = tuple(
            sorted(
                (str(item.action), float(item.value))
                for item in result.transitions
                if item.information_set_key == root_key and item.actor == "max" and item.value is not None
            )
        )
        selected_value = next((value for action, value in root_values if action == result.action), None)
        alternatives = [value for action, value in root_values if action != result.action]
        margin = selected_value - max(alternatives) if selected_value is not None and alternatives else None
        return NativeTreeDecision(
            selection,
            result.action,
            result.value,
            True,
            len(worlds),
            builder.native_nodes_built,
            result,
            root_values,
            margin,
        )
    except Exception as exc:
        nodes = locals().get("builder")
        return NativeTreeDecision(
            None,
            None,
            None,
            False,
            len(worlds),
            getattr(nodes, "native_nodes_built", 0),
            None,
            (),
            None,
            f"{type(exc).__name__}: {exc}",
        )


def _canonical_action(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _field(player: dict[str, Any]) -> list[dict[str, Any]]:
    cards = list(player.get("active") or []) + list(player.get("bench") or [])
    return [card for card in cards if isinstance(card, dict)]


def _field_hp(player: dict[str, Any]) -> int:
    return sum(int(card.get("hp") or 0) for card in _field(player))


def _field_energy(player: dict[str, Any]) -> int:
    return sum(len(card.get("energyCards") or []) for card in _field(player))


def _field_count(player: dict[str, Any]) -> int:
    return len(_field(player))


__all__ = [
    "NativeTreeBuilder",
    "NativeTreeDecision",
    "public_leaf_value",
    "search_native_world_bank",
]
