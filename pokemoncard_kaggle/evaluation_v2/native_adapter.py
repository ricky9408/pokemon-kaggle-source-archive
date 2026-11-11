"""Adapter primitives for the deterministic evaluator-only native engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, is_dataclass
from hashlib import sha256
from itertools import combinations
import ctypes
import json
from math import comb
from typing import Any

from .world_bank import BeliefWorld


NATIVE_ADAPTER_NAMESPACE = "evaluation-v2-native-path-replay-v1"


@dataclass(frozen=True)
class NativePathTrace:
    world_id: str
    seed: int
    path: tuple[tuple[int, ...], ...]
    observation_hashes: tuple[str, ...]
    terminal_result: int | None

    @property
    def stable_hash(self) -> str:
        return sha256(_canonical_json(asdict(self))).hexdigest()


def derive_world_seed(world: BeliefWorld, *, namespace: str = NATIVE_ADAPTER_NAMESPACE) -> int:
    """Derive a stable uint32 engine seed from one immutable world."""

    if not namespace:
        raise ValueError("namespace must be nonempty")
    digest = sha256(namespace.encode("utf-8") + b"\0" + world.stable_hash.encode("ascii")).digest()
    return int.from_bytes(digest[:4], "big")


def enumerate_legal_selections(select: Mapping[str, Any], *, max_actions: int = 256) -> tuple[tuple[int, ...], ...]:
    """Enumerate all legal index selections or fail before truncating them."""

    options = select.get("option")
    if not isinstance(options, Sequence) or isinstance(options, (str, bytes)):
        raise ValueError("select.option must be a sequence")
    minimum = _integer(select.get("minCount"), "select.minCount")
    maximum = _integer(select.get("maxCount"), "select.maxCount")
    if minimum < 0 or maximum < minimum or maximum > len(options):
        raise ValueError("invalid selection bounds")
    if max_actions <= 0:
        raise ValueError("max_actions must be positive")
    action_count = sum(comb(len(options), count) for count in range(minimum, maximum + 1))
    if action_count > max_actions:
        raise ValueError(f"legal action set has {action_count} combinations; cap is {max_actions}")
    return tuple(
        tuple(selection)
        for count in range(minimum, maximum + 1)
        for selection in combinations(range(len(options)), count)
    )


def semantic_selection(select: Mapping[str, Any], selection: Sequence[int]) -> tuple[dict[str, Any], ...]:
    """Map engine-local indices to stable option payloads."""

    options = select.get("option")
    if not isinstance(options, Sequence) or isinstance(options, (str, bytes)):
        raise ValueError("select.option must be a sequence")
    result: list[dict[str, Any]] = []
    for index in selection:
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(options):
            raise ValueError("selection contains an invalid option index")
        option = options[index]
        if not isinstance(option, Mapping):
            raise ValueError("select options must be mappings")
        result.append(
            {
                str(key): _json_value(value)
                for key, value in option.items()
                if value is not None and not str(key).lower().startswith("serial")
            }
        )
    return tuple(result)


def information_set_hash(observation: Mapping[str, Any]) -> str:
    """Hash only the actor-visible state and legal semantic options."""

    return sha256(_canonical_json(information_set_projection(observation))).hexdigest()


def information_set_projection(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Return the normalized actor-visible information-set identity."""

    current = observation.get("current")
    select = observation.get("select")
    if not isinstance(current, Mapping) or not isinstance(select, Mapping):
        raise ValueError("observation must contain current and select mappings")
    options = select.get("option")
    if not isinstance(options, Sequence) or isinstance(options, (str, bytes)):
        raise ValueError("select.option must be a sequence")
    return {
        "current": _public_identity_value(current),
        "select": {
            str(key): _public_identity_value(value)
            for key, value in select.items()
            if key not in {"option"} and value is not None
        },
        "semantic_options": sorted(
            (_public_identity_value(option) for option in options),
            key=lambda value: _canonical_json(value),
        ),
    }


def native_search_arguments(observation: Mapping[str, Any], world: BeliefWorld) -> dict[str, list[int]]:
    """Translate a public-belief world into ``SearchBegin`` hidden-zone args."""

    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("observation.current must be a mapping")
    your_index = _integer(current.get("yourIndex"), "current.yourIndex")
    players = current.get("players")
    if your_index not in (0, 1) or not isinstance(players, Sequence) or len(players) != 2:
        raise ValueError("invalid current player structure")
    opponent = players[1 - your_index]
    if not isinstance(opponent, Mapping):
        raise ValueError("opponent player must be a mapping")
    active = opponent.get("active")
    opponent_active = list(world.opponent.active) if isinstance(active, Sequence) and any(card is None for card in active) else []
    return {
        "your_deck": list(world.own.deck),
        "your_prize": list(world.own.prize),
        "opponent_deck": list(world.opponent.deck),
        "opponent_prize": list(world.opponent.prize),
        "opponent_hand": list(world.opponent.hand),
        "opponent_active": opponent_active,
    }


class PatchedNativeSession(AbstractContextManager["PatchedNativeSession"]):
    """One seeded evaluator engine session.

    The supplied module is the copied ``cg.api`` bundled beside the patched
    evaluator library.  The session deliberately owns and destroys one native
    ``ApiData`` pointer; callers should open a fresh session for every replayed
    search path when maximum isolation matters.
    """

    def __init__(self, api_module: Any, *, seed: int) -> None:
        if not 0 <= seed <= 0xFFFFFFFF:
            raise ValueError("seed must fit uint32")
        self.api = api_module
        self.seed = seed
        self.pointer: int | None = None

    def __enter__(self) -> "PatchedNativeSession":
        lib = self.api.lib
        if not hasattr(lib, "AgentSetSeed"):
            raise RuntimeError("native library lacks evaluator-only AgentSetSeed")
        lib.AgentSetSeed.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        lib.AgentSetSeed.restype = ctypes.c_int
        pointer = lib.AgentStart()
        if not pointer:
            raise RuntimeError("AgentStart failed")
        if lib.AgentSetSeed(pointer, self.seed) != 0:
            lib.BattleFinish(pointer)
            raise RuntimeError("AgentSetSeed failed")
        self.pointer = pointer
        self.api.agent_ptr = pointer
        return self

    def begin(self, observation: Mapping[str, Any], world: BeliefWorld) -> Any:
        if self.pointer is None:
            raise RuntimeError("session is not open")
        converted = self.api.to_observation_class(dict(observation))
        arguments = native_search_arguments(observation, world)
        return self.api.search_begin(converted, **arguments)

    def step(self, search_id: int, selection: Sequence[int]) -> Any:
        if self.pointer is None:
            raise RuntimeError("session is not open")
        return self.api.search_step(search_id, list(selection))

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.pointer is None:
            return None
        try:
            self.api.search_end()
        finally:
            self.api.lib.BattleFinish(self.pointer)
            if getattr(self.api, "agent_ptr", None) == self.pointer:
                delattr(self.api, "agent_ptr")
            self.pointer = None
        return None


def replay_native_path(
    api_module: Any,
    observation: Mapping[str, Any],
    world: BeliefWorld,
    path: Sequence[Sequence[int]],
    *,
    seed: int | None = None,
) -> NativePathTrace:
    """Rebuild a root and replay one complete selection path in isolation."""

    engine_seed = derive_world_seed(world) if seed is None else seed
    hashes: list[str] = []
    terminal: int | None = None
    normalized_path = tuple(tuple(int(index) for index in selection) for selection in path)
    with PatchedNativeSession(api_module, seed=engine_seed) as session:
        state = session.begin(observation, world)
        hashes.append(native_observation_hash(state.observation))
        for selection in normalized_path:
            state = session.step(state.searchId, selection)
            hashes.append(native_observation_hash(state.observation))
        current = getattr(state.observation, "current", None)
        terminal = getattr(current, "result", None) if current is not None else None
    return NativePathTrace(world.world_id, engine_seed, normalized_path, tuple(hashes), terminal)


def native_observation_hash(observation: Any) -> str:
    payload = asdict(observation) if is_dataclass(observation) else observation
    return sha256(_canonical_json(_json_value(payload))).hexdigest()


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if hasattr(value, "value"):
        return _json_value(value.value)
    raise TypeError(f"unsupported native JSON value: {type(value).__name__}")


def _public_identity_value(value: Any) -> Any:
    """Canonicalize a visible value without engine-assigned card serials."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if is_dataclass(value):
        return _public_identity_value(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): _public_identity_value(item)
            for key, item in value.items()
            if not str(key).lower().startswith("serial")
        }
    if isinstance(value, (list, tuple)):
        return [_public_identity_value(item) for item in value]
    if hasattr(value, "value"):
        return _public_identity_value(value.value)
    raise TypeError(f"unsupported public identity value: {type(value).__name__}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = [
    "NATIVE_ADAPTER_NAMESPACE",
    "NativePathTrace",
    "PatchedNativeSession",
    "derive_world_seed",
    "enumerate_legal_selections",
    "information_set_hash",
    "information_set_projection",
    "native_observation_hash",
    "native_search_arguments",
    "replay_native_path",
    "semantic_selection",
]
