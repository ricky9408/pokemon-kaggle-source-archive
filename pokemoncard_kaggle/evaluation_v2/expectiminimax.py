"""Candidate-neutral information-set expectiminimax.

This module is deliberately a data-only search core.  An engine adapter builds
``ExpectiminimaxNode`` values; the search never imports an engine and never
asks a candidate or baseline policy which action to take.

Several determinized worlds may be supplied for one information set.  A
decision is evaluated once per semantic action and that same action is used in
every world in the information set.  This is the important distinction from
running an independent perfect-information search in each world.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
import json
from math import fsum, isfinite
from typing import Any


@dataclass(frozen=True)
class ExpectiminimaxNode:
    """Engine-independent description of one public-information world.

    ``successors`` is a mapping from semantic action to a node or a sequence
    of nodes for decision nodes.  For a ``chance`` node it is a sequence (or a
    mapping whose values are nodes); each child must carry its probability in
    ``chance_probability``.  A ``leaf_value`` is allowed only as a bounded
    fallback at a depth/budget boundary or on a node with no successors.
    """

    actor: Any
    information_set_key: Any
    legal_actions: tuple[Any, ...] = ()
    successors: Any = field(default_factory=dict)
    action_priors: Any = field(default_factory=dict)
    chance_probability: float | None = None
    terminal_value: float | None = None
    leaf_value: float | None = None


@dataclass(frozen=True)
class ChanceSuccessor:
    """Explicit probability wrapper useful when children are not mutable."""

    probability: float
    node: ExpectiminimaxNode


@dataclass(frozen=True)
class TransitionEvidence:
    information_set_key: str
    actor: str
    action: Any | None
    world_count: int
    successor_count: int
    value: float | None
    selected: bool = False


@dataclass(frozen=True)
class UnresolvedEvidence:
    reason: str
    path: tuple[str, ...] = ()
    information_set_key: str | None = None
    actor: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class CoverageEvidence:
    nodes_visited: int
    information_sets: int
    worlds_evaluated: int
    actions_evaluated: int
    transitions_recorded: int
    unresolved_count: int
    node_budget: int | None
    depth_budget: int | None
    budget_exhausted: bool

    @property
    def complete(self) -> bool:
        return self.unresolved_count == 0 and not self.budget_exhausted


@dataclass(frozen=True)
class ExpectiminimaxResult:
    """Search output; unresolved searches intentionally have no value/action."""

    action: Any | None
    value: float | None
    resolved: bool
    coverage: CoverageEvidence
    transitions: tuple[TransitionEvidence, ...]
    unresolved: tuple[UnresolvedEvidence, ...]

    @property
    def complete(self) -> bool:
        return self.resolved

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Short aliases make the contract pleasant to use without hiding its meaning.
Node = ExpectiminimaxNode
SearchResult = ExpectiminimaxResult


class _Search:
    def __init__(
        self,
        *,
        root_actor: Any,
        node_budget: int | None,
        depth_budget: int | None,
        prior_weight: float,
    ) -> None:
        self.root_actor = root_actor
        self.node_budget = node_budget
        self.depth_budget = depth_budget
        self.prior_weight = prior_weight
        self.nodes_visited = 0
        self.information_sets: set[str] = set()
        self.worlds_evaluated = 0
        self.actions_evaluated = 0
        self.transitions: list[TransitionEvidence] = []
        self.unresolved: list[UnresolvedEvidence] = []
        self._budget_reported = False

    def fail(
        self,
        reason: str,
        *,
        path: tuple[str, ...],
        key: str | None = None,
        actor: str | None = None,
        error: str | None = None,
    ) -> None:
        item = UnresolvedEvidence(reason, path, key, actor, error)
        if item not in self.unresolved:
            self.unresolved.append(item)

    def visit(self, *, path: tuple[str, ...]) -> bool:
        if self.node_budget is not None and self.nodes_visited >= self.node_budget:
            if not self._budget_reported:
                self.fail("budget_exhausted", path=path)
                self._budget_reported = True
            return False
        self.nodes_visited += 1
        return True

    def coverage(self) -> CoverageEvidence:
        return CoverageEvidence(
            nodes_visited=self.nodes_visited,
            information_sets=len(self.information_sets),
            worlds_evaluated=self.worlds_evaluated,
            actions_evaluated=self.actions_evaluated,
            transitions_recorded=len(self.transitions),
            unresolved_count=len(self.unresolved),
            node_budget=self.node_budget,
            depth_budget=self.depth_budget,
            budget_exhausted=any(
                item.reason in {"budget_exhausted", "depth_budget_without_leaf_value"} for item in self.unresolved
            ),
        )

    def result(self, action: Any | None = None, value: float | None = None) -> ExpectiminimaxResult:
        resolved = not self.unresolved and value is not None
        return ExpectiminimaxResult(
            action if resolved else None,
            value if resolved else None,
            resolved,
            self.coverage(),
            tuple(self.transitions),
            tuple(self.unresolved),
        )

    def evaluate(self, nodes: tuple[Any, ...], *, depth: int, path: tuple[str, ...]) -> float | None:
        if not nodes:
            self.fail("empty_information_set", path=path)
            return None
        if self.depth_budget is not None and depth > self.depth_budget:
            return self._leaf_only(nodes, path=path, reason="depth_budget")

        parsed: list[tuple[Any, str, str]] = []
        for node in nodes:
            parsed_node = self._parse_node(node, path=path)
            if parsed_node is None:
                return None
            actor, key, actor_label = parsed_node
            parsed.append((node, key, actor_label))
            self.worlds_evaluated += 1
        if len({key for _, key, _ in parsed}) != 1:
            self.fail("information_set_key_mismatch", path=path)
            return None
        if len({label for _, _, label in parsed}) != 1:
            self.fail("actor_mismatch", path=path)
            return None
        key = parsed[0][1]
        actor_label = parsed[0][2]
        self.information_sets.add(key)

        terminal_values: list[float] = []
        for node in nodes:
            value = self._read(node, "terminal_value", path=path)
            if value is None:
                continue
            checked = self._terminal(value, path=path, key=key, actor=actor_label)
            if checked is None:
                return None
            terminal_values.append(checked)
        if terminal_values:
            if len(terminal_values) != len(nodes):
                self.fail("mixed_terminal_and_nonterminal", path=path, key=key, actor=actor_label)
                return None
            return fsum(terminal_values) / len(terminal_values)

        if actor_label == "chance":
            return self._evaluate_chance(nodes, depth=depth, path=path, key=key)

        if all(not self._read(node, "legal_actions", path=path) for node in nodes):
            leaf_values: list[float] = []
            for node in nodes:
                raw_leaf = self._read(node, "leaf_value", path=path)
                if raw_leaf is None:
                    self.fail("nonterminal_without_legal_actions", path=path, key=key, actor=actor_label)
                    return None
                checked_leaf = self._leaf(raw_leaf, path=path)
                if checked_leaf is None:
                    return None
                leaf_values.append(checked_leaf)
            return fsum(leaf_values) / len(leaf_values)

        return self._evaluate_decision(nodes, actor_label=actor_label, depth=depth, path=path, key=key)

    def _evaluate_decision(
        self,
        nodes: tuple[Any, ...],
        *,
        actor_label: str,
        depth: int,
        path: tuple[str, ...],
        key: str,
    ) -> float | None:
        legal_sets: list[dict[str, Any]] = []
        for node in nodes:
            actions = self._actions(node, path=path, key=key, actor=actor_label)
            if actions is None:
                return None
            legal_sets.append(actions)
        common = set(legal_sets[0])
        for actions in legal_sets[1:]:
            common.intersection_update(actions)
        if not common:
            self.fail("no_common_legal_action", path=path, key=key, actor=actor_label)
            return None

        scored: list[tuple[str, Any, float, int, float]] = []
        for action_key in sorted(common):
            action = legal_sets[0][action_key]
            child_nodes: list[Any] = []
            successor_count = 0
            for node in nodes:
                children = self._action_children(node, action_key, path=path, key=key, actor=actor_label)
                if children is None or not children:
                    return None
                successor_count += len(children)
                child_nodes.extend(children)
            # Merge worlds that expose the same next information set before
            # recursing.  Otherwise two hidden worlds could independently
            # choose different actions at an indistinguishable child state.
            child_groups: dict[str, list[Any]] = {}
            for child in child_nodes:
                try:
                    child_key = _canonical_json(self._read_required(child, "information_set_key")).decode("utf-8")
                except Exception as exc:
                    self.fail("successor_error", path=path, key=key, actor=actor_label, error=f"{type(exc).__name__}: {exc}")
                    return None
                child_groups.setdefault(child_key, []).append(child)
            weighted_values: list[float] = []
            for child_key in sorted(child_groups):
                group = tuple(child_groups[child_key])
                child_value = self.evaluate(group, depth=depth + 1, path=path + (f"{action_key}:{child_key}",))
                if child_value is None:
                    return None
                weighted_values.extend([child_value] * len(group))
            self.actions_evaluated += 1
            value = fsum(weighted_values) / len(weighted_values)
            prior = 0.0
            if actor_label == "max" and depth == 0 and self.prior_weight > 0.0:
                prior_value = self._action_prior(nodes, action_key, path=path, key=key, actor=actor_label)
                if prior_value is None:
                    return None
                prior = prior_value
            scored.append((action_key, action, value, successor_count, prior))

        prior_center = fsum(item[4] for item in scored) / len(scored)
        adjusted: list[tuple[str, Any, float, int]] = []
        transition_positions: list[int] = []
        for action_key, action, base_value, successor_count, prior in scored:
            value = base_value + self.prior_weight * (prior - prior_center)
            adjusted.append((action_key, action, value, successor_count))
            transition_positions.append(len(self.transitions))
            self.transitions.append(TransitionEvidence(key, actor_label, action, len(nodes), successor_count, value))

        if actor_label == "max":
            chosen = max(adjusted, key=lambda item: (item[2], _reverse_key(item[0])))
        else:
            chosen = min(adjusted, key=lambda item: (item[2], item[0]))
        chosen_index = transition_positions[adjusted.index(chosen)]
        transition = self.transitions[chosen_index]
        self.transitions[chosen_index] = TransitionEvidence(
            transition.information_set_key,
            transition.actor,
            transition.action,
            transition.world_count,
            transition.successor_count,
            transition.value,
            True,
        )
        return chosen[2]

    def _action_prior(
        self,
        nodes: tuple[Any, ...],
        action_key: str,
        *,
        path: tuple[str, ...],
        key: str,
        actor: str,
    ) -> float | None:
        values: list[float] = []
        try:
            for node in nodes:
                priors = self._read(node, "action_priors", path=path)
                if not isinstance(priors, Mapping):
                    raise ValueError("action_priors must be a mapping when prior_weight is positive")
                matches = [
                    value
                    for action, value in priors.items()
                    if _canonical_json(action).decode("utf-8") == action_key
                ]
                if len(matches) != 1:
                    raise ValueError("action prior missing or duplicated")
                value = float(matches[0])
                if not isfinite(value):
                    raise ValueError("action prior must be finite")
                values.append(value)
            if max(values) - min(values) > 1e-9:
                raise ValueError("action priors differ inside one information set")
            return fsum(values) / len(values)
        except Exception as exc:
            self.fail("action_prior_error", path=path, key=key, actor=actor, error=f"{type(exc).__name__}: {exc}")
            return None

    def _evaluate_chance(
        self, nodes: tuple[Any, ...], *, depth: int, path: tuple[str, ...], key: str
    ) -> float | None:
        if len(nodes) != 1:
            self.fail("chance_information_set_has_multiple_worlds", path=path, key=key, actor="chance")
            return None
        children = self._chance_children(nodes[0], path=path, key=key)
        if children is None or not children:
            return None
        values: list[tuple[float, float]] = []
        for index, (probability, child) in enumerate(children):
            if not self.visit(path=path + (f"chance:{index}",)):
                return None
            child_value = self.evaluate((child,), depth=depth + 1, path=path + (f"chance:{index}",))
            if child_value is None:
                return None
            values.append((probability, child_value))
        total = fsum(probability for probability, _ in values)
        if not isfinite(total) or total <= 0.0 or abs(total - 1.0) > 1e-9:
            self.fail("chance_probabilities_do_not_sum_to_one", path=path, key=key, actor="chance")
            return None
        value = fsum(probability * child_value for probability, child_value in values)
        self.transitions.append(TransitionEvidence(key, "chance", None, 1, len(values), value, True))
        return value

    def _leaf_only(self, nodes: tuple[Any, ...], *, path: tuple[str, ...], reason: str) -> float | None:
        values: list[float] = []
        for node in nodes:
            raw_terminal = self._read(node, "terminal_value", path=path)
            if raw_terminal is not None:
                checked_terminal = self._terminal(raw_terminal, path=path, key="", actor="")
                if checked_terminal is None:
                    return None
                values.append(checked_terminal)
                continue
            raw = self._read(node, "leaf_value", path=path)
            if raw is None:
                self.fail(f"{reason}_without_leaf_value", path=path)
                return None
            checked = self._leaf(raw, path=path)
            if checked is None:
                return None
            values.append(checked)
        return fsum(values) / len(values)

    def _parse_node(self, node: Any, *, path: tuple[str, ...]) -> tuple[Any, str, str] | None:
        try:
            actor = self._read_required(node, "actor")
            raw_key = self._read_required(node, "information_set_key")
            key = _canonical_json(raw_key).decode("utf-8")
            actor_label = self._actor_label(actor)
            if not self.visit(path=path):
                return None
            return actor, key, actor_label
        except Exception as exc:
            self.fail("node_error", path=path, error=f"{type(exc).__name__}: {exc}")
            return None

    @staticmethod
    def _read(node: Any, name: str, *, path: tuple[str, ...]) -> Any:
        try:
            if isinstance(node, Mapping):
                return node.get(name)
            return getattr(node, name)
        except Exception as exc:
            raise ValueError(f"{name} unavailable at {path}") from exc

    def _read_required(self, node: Any, name: str) -> Any:
        value = self._read(node, name, path=())
        if value is None:
            raise ValueError(f"{name} is required")
        return value

    def _actor_label(self, actor: Any) -> str:
        if actor == "chance" or actor is None:
            return "chance"
        if actor == "max" or actor == "root" or actor == self.root_actor:
            return "max"
        if actor in {"min", "opponent"}:
            return "min"
        return "min"

    def _actions(self, node: Any, *, path: tuple[str, ...], key: str, actor: str) -> dict[str, Any] | None:
        try:
            raw_actions = self._read(node, "legal_actions", path=path)
            if raw_actions is None:
                raise ValueError("legal_actions is required")
            result: dict[str, Any] = {}
            for action in raw_actions:
                action_key = _canonical_json(action).decode("utf-8")
                if action_key in result and result[action_key] != action:
                    raise ValueError("semantic action key collision")
                result[action_key] = action
            return result
        except Exception as exc:
            self.fail("legal_actions_error", path=path, key=key, actor=actor, error=f"{type(exc).__name__}: {exc}")
            return None

    def _action_children(
        self, node: Any, action_key: str, *, path: tuple[str, ...], key: str, actor: str
    ) -> tuple[Any, ...] | None:
        try:
            successors = self._read(node, "successors", path=path)
            if not isinstance(successors, Mapping):
                raise ValueError("decision successors must be a mapping")
            match = next((value for action, value in successors.items() if _canonical_json(action).decode("utf-8") == action_key), None)
            if match is None:
                raise ValueError("successor missing for legal action")
            if isinstance(match, (str, bytes)):
                raise ValueError("successor must be a node or sequence of nodes")
            if isinstance(match, Sequence) and not isinstance(match, Mapping):
                return tuple(match)
            return (match,)
        except Exception as exc:
            self.fail("successor_error", path=path, key=key, actor=actor, error=f"{type(exc).__name__}: {exc}")
            return None

    def _chance_children(self, node: Any, *, path: tuple[str, ...], key: str) -> list[tuple[float, Any]] | None:
        try:
            successors = self._read(node, "successors", path=path)
            values = list(successors.values()) if isinstance(successors, Mapping) else list(successors)
            result: list[tuple[float, Any]] = []
            for item in values:
                if isinstance(item, ChanceSuccessor):
                    probability, child = item.probability, item.node
                else:
                    child = item
                    probability = self._read(child, "chance_probability", path=path)
                if probability is None or not isfinite(float(probability)) or float(probability) < 0.0:
                    raise ValueError("chance probability must be finite and nonnegative")
                result.append((float(probability), child))
            return result
        except Exception as exc:
            self.fail("chance_successor_error", path=path, key=key, actor="chance", error=f"{type(exc).__name__}: {exc}")
            return None

    def _terminal(self, value: Any, *, path: tuple[str, ...], key: str, actor: str) -> float | None:
        try:
            value = float(value)
        except (TypeError, ValueError):
            self.fail("invalid_terminal_value", path=path, key=key, actor=actor)
            return None
        if not isfinite(value) or value not in {-1.0, 0.0, 1.0}:
            self.fail("invalid_terminal_value", path=path, key=key, actor=actor)
            return None
        return value

    def _leaf(self, value: Any, *, path: tuple[str, ...]) -> float | None:
        try:
            value = float(value)
        except (TypeError, ValueError):
            self.fail("invalid_leaf_value", path=path)
            return None
        if not isfinite(value) or not -1.0 <= value <= 1.0:
            self.fail("leaf_value_out_of_bounds", path=path)
            return None
        return value


def expectiminimax(
    root: ExpectiminimaxNode | Sequence[ExpectiminimaxNode],
    *,
    root_actor: Any = "max",
    node_budget: int | None = 10_000,
    depth_budget: int | None = 64,
    max_nodes: int | None = None,
    max_depth: int | None = None,
    prior_weight: float = 0.0,
) -> ExpectiminimaxResult:
    """Solve a root information set, failing closed on every uncertainty.

    ``root`` may be one node or a nonempty sequence of indistinguishable
    worlds.  All worlds must expose the same canonical information-set key.
    Budgets count visited nodes and edges; exceeding either budget returns no
    action and no value, together with the partial evidence collected so far.
    """

    if max_nodes is not None:
        node_budget = max_nodes
    if max_depth is not None:
        depth_budget = max_depth
    search = _Search(
        root_actor=root_actor,
        node_budget=node_budget,
        depth_budget=depth_budget,
        prior_weight=prior_weight,
    )
    try:
        if node_budget is not None and (not isinstance(node_budget, int) or node_budget <= 0):
            search.fail("invalid_node_budget", path=())
            return search.result()
        if depth_budget is not None and (not isinstance(depth_budget, int) or depth_budget < 0):
            search.fail("invalid_depth_budget", path=())
            return search.result()
        if not isfinite(float(prior_weight)) or prior_weight < 0.0:
            search.fail("invalid_prior_weight", path=())
            return search.result()
        if isinstance(root, (str, bytes)):
            raise ValueError("root must be a node or sequence of nodes")
        roots = (root,) if not isinstance(root, Sequence) else tuple(root)
        if not roots:
            search.fail("empty_root_information_set", path=())
            return search.result()
        parsed = [search._parse_node(node, path=("root",)) for node in roots]
        if any(item is None for item in parsed):
            return search.result()
        key = parsed[0][1]  # type: ignore[index]
        if any(item[1] != key for item in parsed):  # type: ignore[index]
            search.fail("information_set_key_mismatch", path=("root",))
            return search.result()
        # The root is a decision information set.  evaluate() would also
        # support a chance root, but the public contract requires root=max.
        if parsed[0][2] != "max":  # type: ignore[index]
            search.fail("root_is_not_max_node", path=("root",), key=key)
            return search.result()
        # _parse_node already charged the roots; evaluate the root without
        # charging them a second time.
        search.nodes_visited -= len(roots)
        value = search.evaluate(roots, depth=0, path=("root",))
        if value is None:
            return search.result()
        # Re-evaluate the root action values only through the normal decision
        # routine's recorded selected transition; it is already deterministic.
        chosen = next(
            (
                item.action
                for item in reversed(search.transitions)
                if item.selected and item.information_set_key == key
            ),
            None,
        )
        return search.result(chosen, value)
    except Exception as exc:
        search.fail("search_error", path=("root",), error=f"{type(exc).__name__}: {exc}")
        return search.result()


def solve_expectiminimax(*args: Any, **kwargs: Any) -> ExpectiminimaxResult:
    """Named alias for callers that prefer a verb over the algorithm name."""

    return expectiminimax(*args, **kwargs)


search_expectiminimax = expectiminimax


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_canonicalize(value), ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


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
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return {"__set__": sorted(items, key=lambda item: _canonical_json(item))}
    raise TypeError(f"unsupported canonical value type: {type(value).__name__}")


def _reverse_key(value: str) -> tuple[int, ...]:
    """Make max ties choose the same ascending canonical key as min ties."""

    return tuple(-byte for byte in value.encode("utf-8"))


__all__ = [
    "ChanceSuccessor",
    "CoverageEvidence",
    "ExpectiminimaxNode",
    "ExpectiminimaxResult",
    "Node",
    "SearchResult",
    "TransitionEvidence",
    "UnresolvedEvidence",
    "expectiminimax",
    "search_expectiminimax",
    "solve_expectiminimax",
]
