"""Legacy offline-only mechanics extraction from caller-described traces.

The caller-receipt path in this module is permanently retired as an
authenticity path by ``V631_CANONICAL_ENGINE_TRACE_ARCHITECTURE``. It remains
only as a pure regression-fixture extractor while canonical engine traces and
independent replay are implemented in ``canonical_trace_replay``. It does not
run an engine, attest a trace, compare an official wrapper, access a holdout,
issue permits, upload, or modify an agent.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import re
from types import MappingProxyType
from typing import Any

try:  # The frozen runtime is gmpy2/MPFR; the fallback is offline-only.
    import gmpy2  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised only on incomplete dev hosts
    gmpy2 = None

from .assignment import ExactRational, FeaturePoint
from .common import canonical_json_bytes, canonical_sha256, freeze, zero_authority


TRACE_SCHEMA = "eval.v6.3.1.replay-verified-trace.v1"
RECEIPT_SCHEMA = "eval.v6.3.1.replay-verification-receipt.v1"
FEATURE_RESULT_SCHEMA = "eval.v6.3.1.offline-trace-feature-result.v1"
CALLER_RECEIPT_AUTHENTICITY_PATH_RETIRED = True
MPFR_PRECISION_BITS = 256
MPFR_ROUNDING = "round_to_nearest_even"
CONTROL_COUNT = 4
SEEDS_PER_CONTROL = 300
ORIENTATIONS = (0, 1)
FEATURE_KEYS = ("F1", "F2", "F3", "F4", "F5", "F6")

ATTACK_ACTION = "DECLARE_ATTACK"
F5_ACTION_WHITELIST = frozenset(
    {
        "PLAY_BASIC_POKEMON",
        "EVOLVE_POKEMON",
        "ATTACH_ENERGY",
        "PLAY_TRAINER",
        "USE_ABILITY",
        "RETREAT",
        "SWITCH_ACTIVE",
        ATTACK_ACTION,
    }
)
NON_STRATEGIC_ACTIONS = frozenset(
    {
        "END_TURN",
        "PASS",
        "CONCEDE",
        "INSPECT",
        "VIEW_INFORMATION",
        "UI_SELECTION_ONLY",
        "REORDER_WITHOUT_RULES_EFFECT",
        "ADMINISTRATIVE_ACTION",
    }
)
KNOWN_ACTIONS = F5_ACTION_WHITELIST | NON_STRATEGIC_ACTIONS
DIRECT_DAMAGE_KIND = "ATTACK_DIRECT_DAMAGE"

_SHA = re.compile(r"^[0-9a-f]{64}$")
_ISSUED: dict[int, bytes] = {}
_TOKEN = object()
_FORBIDDEN_SUMMARY_NAMES = frozenset(
    {
        "feature_values",
        "features",
        "F1",
        "F2",
        "F3",
        "F4",
        "F5",
        "F6",
        "mechanics_x",
        "raw_sufficient_statistics",
        "archive_r",
        "archive_point_rate",
    }
)


class TraceFeatureError(ValueError):
    """Raised when a local trace feature precondition fails closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> TraceFeatureError:
    return TraceFeatureError(code, message)


def _sha(value: Any, label: str, code: str = "LOCAL_TRACE_SCHEMA_INVALID") -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"{label} must be an integer >= {minimum}")
    return value


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"{label} fields must be exact")
    return value


def _no_float_or_summary(value: Any, label: str = "trace") -> None:
    if type(value) is float:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"{label} contains binary64")
    if type(value) is dict:
        overlap = set(value).intersection(_FORBIDDEN_SUMMARY_NAMES)
        if overlap:
            raise _fail("LOCAL_CALLER_SUMMARY_MISMATCH", f"{label} contains caller summary {sorted(overlap)}")
        for key, item in value.items():
            _no_float_or_summary(item, f"{label}.{key}")
    elif type(value) in (list, tuple):
        for index, item in enumerate(value):
            _no_float_or_summary(item, f"{label}[{index}]")


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"{label} must be a nonempty string")
    return value


def _action_digest(action_class: str, actor: str, parameters: Any) -> str:
    return canonical_sha256(
        {"action_class": action_class, "actor_player_id": actor, "canonical_parameters": parameters}
    )


def canonical_legal_action_set_sha256(actions: Sequence[Mapping[str, Any]]) -> str:
    """Return the canonical digest used in a checkpoint's legal-action payload."""
    return canonical_sha256(list(actions))


_HEADER_FIELDS = frozenset(
    {
        "schema_id", "game_id", "candidate_archive_sha256", "control_archive_sha256",
        "candidate_source_tree_sha256", "control_source_tree_sha256", "engine_sha256",
        "ruleset_sha256", "card_catalog_sha256", "candidate_deck_manifest_root",
        "control_deck_manifest_root", "common_seed_id", "common_seed_material_sha256",
        "orientation", "candidate_seat", "control_seat", "starting_player_id",
        "player_roles", "initial_prize_count", "damage_counter_unit_hp", "initial_state_sha256",
        "final_state_sha256",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "schema_id", "game_id", "sequence_number", "record_type", "engine_tick",
        "actor_player_id", "turn_owner_player_id", "regular_turn_ordinal", "phase_id",
        "action_instance_id", "parent_action_instance_id", "state_before_sha256",
        "state_after_sha256", "payload",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_id", "replay_verified", "state_hashes_verified", "rng_transcript_verified",
        "legal_actions_verified", "selected_actions_verified", "attack_costs_verified",
        "canonical_records_verified",
    }
)


def _validate_header(value: Any) -> dict[str, Any]:
    header = _exact(value, _HEADER_FIELDS, "game header")
    if header["schema_id"] != TRACE_SCHEMA:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "unknown trace schema")
    for field in ("game_id", "common_seed_id", "starting_player_id"):
        _text(header[field], field)
    for field in (
        "candidate_archive_sha256", "control_archive_sha256", "candidate_source_tree_sha256",
        "control_source_tree_sha256", "engine_sha256", "ruleset_sha256", "card_catalog_sha256",
        "candidate_deck_manifest_root", "control_deck_manifest_root", "common_seed_material_sha256",
        "initial_state_sha256", "final_state_sha256",
    ):
        _sha(header[field], field)
    if type(header["orientation"]) is not int or header["orientation"] not in ORIENTATIONS:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "orientation must be 0 or 1")
    if header["candidate_seat"] != header["orientation"] or header["control_seat"] != 1 - header["orientation"]:
        raise _fail("LOCAL_SEAT_PAIR_INCOMPLETE", "orientation and semantic seats disagree")
    roles = _exact(header["player_roles"], frozenset({"candidate", "control"}), "player_roles")
    candidate, control = _text(roles["candidate"], "candidate player id"), _text(roles["control"], "control player id")
    if candidate == control:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "candidate and control player IDs must differ")
    _integer(header["initial_prize_count"], "initial_prize_count", minimum=1)
    _integer(header["damage_counter_unit_hp"], "damage_counter_unit_hp", minimum=1)
    return header


def _validate_action(value: Any, *, expected_actor: str) -> dict[str, Any]:
    action = _exact(value, frozenset({"action_class", "actor_player_id", "canonical_parameters", "canonical_action_sha256"}), "legal action")
    action_class = _text(action["action_class"], "action_class")
    if action_class not in KNOWN_ACTIONS:
        raise _fail("LOCAL_ACTION_CLASS_UNRESOLVED", f"unresolved action class {action_class}")
    if action["actor_player_id"] != expected_actor:
        raise _fail("LOCAL_LEGAL_ACTION_SET_MISMATCH", "legal action actor disagrees with checkpoint")
    if type(action["canonical_parameters"]) not in (dict, list, str, int, bool, type(None)):
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "canonical parameters are not JSON")
    if action["canonical_action_sha256"] != _action_digest(action_class, expected_actor, action["canonical_parameters"]):
        raise _fail("LOCAL_LEGAL_ACTION_SET_MISMATCH", "legal action hash is stale")
    return action


def _payload_fields(record_type: str) -> frozenset[str]:
    common = {
        "RNG_CONSUME": {"rng_domain", "rng_stream_id", "rng_draw_index", "raw_random_bytes", "mapping_algorithm_id", "mapped_result"},
        "TURN_START": {"player_id", "regular_turn_ordinal", "turn_kind"},
        "MANDATORY_PROCESSING_COMPLETE": {"player_id", "regular_turn_ordinal", "mandatory_draw_completed", "status_processing_completed"},
        "FIRST_DECISION_CHECKPOINT": {"player_id", "regular_turn_ordinal", "state_sha256", "canonical_legal_action_set_sha256", "canonical_legal_actions", "attack_phase_permitted"},
        "ACTION_CHOSEN": {"player_id", "action_instance_id", "action_class", "action_definition_id", "canonical_parameters", "canonical_action_sha256", "legal_action_set_sha256"},
        "ATTACK_DECLARE": {"player_id", "action_instance_id", "attack_definition_id", "effective_attack_cost_definition_sha256", "effective_required_attack_cost_units", "mandatory_additional_energy_units_consumed_to_declare"},
        "DAMAGE_APPLIED": {"source_action_instance_id", "source_actor_player_id", "damage_kind", "target_object_id", "target_owner_player_id", "raw_damage_hp", "applied_damage_hp", "target_hp_before", "target_hp_after", "weakness_modifier", "resistance_modifier", "prevention_amount"},
        "PRIZE_ZONE_CHANGE": {"player_id", "prize_count_before", "prize_count_after", "reason_code", "source_action_instance_id"},
        "TURN_END": {"player_id", "regular_turn_ordinal", "end_reason"},
        "GAME_END": {"winner_player_id", "terminal_reason", "terminal_sequence_number", "terminal_state_sha256"},
    }
    try:
        return frozenset(common[record_type])
    except KeyError as exc:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"unknown record type {record_type}") from exc


def _validate_record(value: Any, header: Mapping[str, Any], expected_sequence: int, previous_tick: int) -> dict[str, Any]:
    record = _exact(value, _RECORD_FIELDS, f"record {expected_sequence}")
    if record["schema_id"] != TRACE_SCHEMA or record["game_id"] != header["game_id"]:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "record does not bind the game header")
    if record["sequence_number"] != expected_sequence:
        raise _fail("LOCAL_TRACE_SEQUENCE_INVALID", "record sequence must begin at zero and increment by one")
    tick = _integer(record["engine_tick"], "engine_tick")
    if tick < previous_tick:
        raise _fail("LOCAL_TRACE_SEQUENCE_INVALID", "engine ticks must not decrease")
    _text(record["phase_id"], "phase_id")
    for field in ("state_before_sha256", "state_after_sha256"):
        _sha(record[field], field)
    for field in ("actor_player_id", "turn_owner_player_id", "action_instance_id", "parent_action_instance_id"):
        if record[field] is not None:
            _text(record[field], field)
    if record["regular_turn_ordinal"] is not None:
        _integer(record["regular_turn_ordinal"], "regular_turn_ordinal", minimum=1)
    record_type = _text(record["record_type"], "record_type")
    payload = _exact(record["payload"], _payload_fields(record_type), f"{record_type} payload")
    roles = header["player_roles"]
    players = {roles["candidate"], roles["control"]}
    if record["actor_player_id"] is not None and record["actor_player_id"] not in players:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "record actor is not a player")
    if record["turn_owner_player_id"] is not None and record["turn_owner_player_id"] not in players:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "turn owner is not a player")
    if record_type == "FIRST_DECISION_CHECKPOINT":
        actor = payload["player_id"]
        if actor not in players or actor != record["actor_player_id"] or record["regular_turn_ordinal"] != payload["regular_turn_ordinal"]:
            raise _fail("LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", "checkpoint player or ordinal disagrees with envelope")
        _sha(payload["state_sha256"], "checkpoint state")
        _sha(payload["canonical_legal_action_set_sha256"], "checkpoint legal-action root")
        if payload["state_sha256"] != record["state_after_sha256"]:
            raise _fail("LOCAL_STATE_HASH_MISMATCH", "checkpoint state hash disagrees with record")
        if type(payload["canonical_legal_actions"]) is not list or type(payload["attack_phase_permitted"]) is not bool:
            raise _fail("LOCAL_LEGAL_ACTION_SET_MISMATCH", "checkpoint legal actions are malformed")
        actions = [_validate_action(action, expected_actor=actor) for action in payload["canonical_legal_actions"]]
        if canonical_legal_action_set_sha256(actions) != payload["canonical_legal_action_set_sha256"]:
            raise _fail("LOCAL_LEGAL_ACTION_SET_MISMATCH", "checkpoint legal-action root is stale")
    elif record_type in {"TURN_START", "MANDATORY_PROCESSING_COMPLETE", "TURN_END"}:
        if payload["player_id"] not in players or payload["player_id"] != record["actor_player_id"] or payload["regular_turn_ordinal"] != record["regular_turn_ordinal"]:
            raise _fail("LOCAL_TRACE_SCHEMA_INVALID", f"{record_type} player or ordinal disagrees with envelope")
        if record_type == "TURN_START" and payload["turn_kind"] != "REGULAR":
            raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "only regular turn starts belong in this trace schema")
        if record_type == "MANDATORY_PROCESSING_COMPLETE" and (payload["mandatory_draw_completed"] is not True or payload["status_processing_completed"] is not True):
            raise _fail("LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", "mandatory processing is incomplete")
    elif record_type == "ACTION_CHOSEN":
        player = payload["player_id"]
        if player not in players or player != record["actor_player_id"] or payload["action_instance_id"] != record["action_instance_id"]:
            raise _fail("LOCAL_SELECTED_ACTION_NOT_LEGAL", "chosen action identity disagrees with envelope")
        _text(payload["action_definition_id"], "action_definition_id")
        action_class = _text(payload["action_class"], "chosen action class")
        if action_class not in KNOWN_ACTIONS:
            raise _fail("LOCAL_ACTION_CLASS_UNRESOLVED", "chosen action class is unresolved")
        _sha(payload["legal_action_set_sha256"], "chosen action legal root")
        if payload["canonical_action_sha256"] != _action_digest(action_class, player, payload["canonical_parameters"]):
            raise _fail("LOCAL_SELECTED_ACTION_NOT_LEGAL", "chosen action hash is stale")
    elif record_type == "ATTACK_DECLARE":
        if payload["player_id"] not in players or payload["player_id"] != record["actor_player_id"] or payload["action_instance_id"] != record["action_instance_id"]:
            raise _fail("LOCAL_ATTACK_COST_UNRESOLVED", "attack identity disagrees with envelope")
        _text(payload["attack_definition_id"], "attack definition")
        _sha(payload["effective_attack_cost_definition_sha256"], "effective attack cost definition", "LOCAL_ATTACK_COST_UNRESOLVED")
        for field in ("effective_required_attack_cost_units", "mandatory_additional_energy_units_consumed_to_declare"):
            if type(payload[field]) is not int or isinstance(payload[field], bool) or payload[field] < 0:
                raise _fail("LOCAL_ATTACK_COST_UNRESOLVED", f"{field} must be a resolved nonnegative integer")
    elif record_type == "DAMAGE_APPLIED":
        if payload["source_actor_player_id"] not in players or payload["target_owner_player_id"] not in players or payload["source_actor_player_id"] == payload["target_owner_player_id"]:
            raise _fail("LOCAL_DAMAGE_EVENT_UNCLASSIFIED", "damage ownership is unresolved")
        _text(payload["source_action_instance_id"], "damage source action")
        _text(payload["target_object_id"], "damage target")
        _text(payload["damage_kind"], "damage kind")
        for field in ("raw_damage_hp", "applied_damage_hp", "target_hp_before", "target_hp_after", "weakness_modifier", "resistance_modifier", "prevention_amount"):
            _integer(payload[field], field, minimum=0)
        if payload["target_hp_after"] > payload["target_hp_before"] or payload["applied_damage_hp"] > payload["target_hp_before"]:
            raise _fail("LOCAL_DAMAGE_EVENT_UNCLASSIFIED", "damage application is inconsistent")
    elif record_type == "PRIZE_ZONE_CHANGE":
        if payload["player_id"] not in players:
            raise _fail("LOCAL_PRIZE_EVENT_INCONSISTENT", "prize owner is unresolved")
        for field in ("prize_count_before", "prize_count_after"):
            _integer(payload[field], field, minimum=0)
        _text(payload["reason_code"], "prize reason")
        if payload["source_action_instance_id"] is not None:
            _text(payload["source_action_instance_id"], "prize source action")
    elif record_type == "GAME_END":
        if payload["winner_player_id"] is not None and payload["winner_player_id"] not in players:
            raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "winner is not a player")
        _text(payload["terminal_reason"], "terminal reason")
        if payload["terminal_sequence_number"] != expected_sequence or payload["terminal_state_sha256"] != record["state_after_sha256"] or payload["terminal_state_sha256"] != header["final_state_sha256"]:
            raise _fail("LOCAL_STATE_HASH_MISMATCH", "terminal state binding is inconsistent")
    return record


def _validate_receipt(value: Any) -> Mapping[str, Any]:
    receipt = _exact(value, _RECEIPT_FIELDS, "replay verification receipt")
    if receipt["schema_id"] != RECEIPT_SCHEMA:
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "unknown replay receipt schema")
    failure_codes = {
        "replay_verified": "LOCAL_TRACE_REPLAY_MISMATCH",
        "state_hashes_verified": "LOCAL_STATE_HASH_MISMATCH",
        "rng_transcript_verified": "LOCAL_RNG_TRANSCRIPT_MISMATCH",
        "legal_actions_verified": "LOCAL_LEGAL_ACTION_SET_MISMATCH",
        "selected_actions_verified": "LOCAL_SELECTED_ACTION_NOT_LEGAL",
        "attack_costs_verified": "LOCAL_ATTACK_COST_UNRESOLVED",
        "canonical_records_verified": "LOCAL_TRACE_SCHEMA_INVALID",
    }
    for field, code in failure_codes.items():
        if receipt[field] is not True:
            raise _fail(code, f"caller replay-verification receipt lacks {field}")
    return receipt


def _validate_selected_actions(records: Sequence[Mapping[str, Any]]) -> None:
    """Bind chosen actions and attack declarations to their checkpoint action set."""
    active_actions: tuple[str, frozenset[str]] | None = None
    chosen: dict[str, Mapping[str, Any]] = {}
    for record in records:
        kind, payload = record["record_type"], record["payload"]
        if kind == "FIRST_DECISION_CHECKPOINT":
            active_actions = (
                payload["canonical_legal_action_set_sha256"],
                frozenset(action["canonical_action_sha256"] for action in payload["canonical_legal_actions"]),
            )
        elif kind == "ACTION_CHOSEN":
            if active_actions is None or payload["legal_action_set_sha256"] != active_actions[0] or payload["canonical_action_sha256"] not in active_actions[1]:
                raise _fail("LOCAL_SELECTED_ACTION_NOT_LEGAL", "chosen action is absent from the current legal-action set")
            chosen[payload["action_instance_id"]] = payload
        elif kind == "ATTACK_DECLARE":
            selected = chosen.get(payload["action_instance_id"])
            if selected is None or selected["action_class"] != ATTACK_ACTION or selected["player_id"] != payload["player_id"] or selected["action_definition_id"] != payload["attack_definition_id"]:
                raise _fail("LOCAL_SELECTED_ACTION_NOT_LEGAL", "attack declaration lacks its selected legal attack")
        elif kind in {"TURN_END", "GAME_END"}:
            active_actions = None


@dataclass(frozen=True)
class ReplayVerifiedGame:
    """A legacy fixture object, never an authenticity attestation."""

    header: Mapping[str, Any]
    records: tuple[Mapping[str, Any], ...]
    receipt: Mapping[str, Any]
    _token: object

    def __post_init__(self) -> None:
        if self._token is not _TOKEN:
            raise ValueError("ReplayVerifiedGame requires the private constructor token")


def _game_snapshot(value: ReplayVerifiedGame) -> bytes:
    def thaw(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return [thaw(child) for child in item]
        return item

    return canonical_json_bytes(thaw({"header": value.header, "records": value.records, "receipt": value.receipt}))


def make_replay_verified_game(
    header: Mapping[str, Any], records: Sequence[Mapping[str, Any]], receipt: Mapping[str, Any]
) -> ReplayVerifiedGame:
    """Build one legacy regression fixture with permanently zero authority."""
    _no_float_or_summary(header)
    _no_float_or_summary(records)
    checked_header = _validate_header(dict(header))
    if type(records) not in (list, tuple) or not records:
        raise _fail("LOCAL_TRACE_FILE_MISSING", "records must be a nonempty sequence")
    checked: list[dict[str, Any]] = []
    previous_tick = 0
    for sequence, record in enumerate(records):
        checked_record = _validate_record(record, checked_header, sequence, previous_tick)
        previous_tick = checked_record["engine_tick"]
        checked.append(checked_record)
    if checked[-1]["record_type"] != "GAME_END" or sum(row["record_type"] == "GAME_END" for row in checked) != 1:
        raise _fail("LOCAL_TRACE_SEQUENCE_INVALID", "a trace must end with exactly one GAME_END")
    if checked[0]["state_before_sha256"] != checked_header["initial_state_sha256"]:
        raise _fail("LOCAL_STATE_HASH_MISMATCH", "first record does not bind the initial state")
    for left, right in zip(checked, checked[1:]):
        if left["state_after_sha256"] != right["state_before_sha256"]:
            raise _fail("LOCAL_STATE_HASH_MISMATCH", "adjacent record state hashes do not chain")
    _validate_selected_actions(checked)
    issued = ReplayVerifiedGame(freeze(checked_header), tuple(freeze(row) for row in checked), freeze(_validate_receipt(dict(receipt))), _TOKEN)
    _ISSUED[id(issued)] = _game_snapshot(issued)
    return issued


def validate_replay_verified_game(value: Any) -> ReplayVerifiedGame:
    if type(value) is not ReplayVerifiedGame or value._token is not _TOKEN or _ISSUED.get(id(value)) != _game_snapshot(value):
        raise _fail("LOCAL_TRACE_REPLAY_MISMATCH", "an issued, unmodified ReplayVerifiedGame is required")
    return value


def _mp_context() -> Any:
    if gmpy2 is None:
        return None
    context = gmpy2.get_context().copy()
    context.precision = MPFR_PRECISION_BITS
    context.round = gmpy2.RoundToNearest
    return context


def _mp(value: Fraction | int) -> Any:
    """Return the authoritative exact arithmetic value, never an MPFR projection."""
    return Fraction(value)


def _fraction(value: Any) -> Fraction:
    if type(value) is not Fraction:
        raise TypeError("authoritative trace-feature arithmetic must remain Fraction")
    return value


def _exact_mpfr_text(value: Any) -> str:
    fraction = Fraction(value)
    if gmpy2 is not None:
        with gmpy2.context(_mp_context()):
            return format(gmpy2.mpfr(gmpy2.mpq(fraction.numerator, fraction.denominator)), ".64a")
    return f"offline-exact-rational:{fraction.numerator}/{fraction.denominator}"


def _bounded(value: Any, lower: int, upper: int) -> Any:
    if gmpy2 is None:
        lower_value, upper_value, tolerance = Fraction(lower), Fraction(upper), Fraction(1, 10**30)
    else:
        lower_value, upper_value, tolerance = _mp(lower), _mp(upper), _mp(Fraction(1, 10**30))
    if value < lower_value - tolerance or value > upper_value + tolerance:
        raise _fail("LOCAL_FEATURE_NUMERIC_DOMAIN_VIOLATION", "feature is outside its numeric domain")
    return max(lower_value, min(upper_value, value))


@dataclass(frozen=True)
class GameFeatureCounts:
    f1: Fraction
    prizes_taken: tuple[int, int]
    initial_prize_count: int
    f2_success: tuple[int, int]
    f2_count: tuple[int, int]
    f3_damage: tuple[int, int]
    f3_energy: tuple[int, int]
    f4_success: tuple[int, int]
    f4_opportunity: tuple[int, int]
    f5_success: tuple[int, int]
    f5_count: tuple[int, int]
    game_point_numerator: int


@dataclass(frozen=True)
class GameSufficientStatistics:
    """Integer-only raw statistics for one orientation, retained for bootstrap."""

    orientation: int
    candidate_prizes_taken: int
    control_prizes_taken: int
    initial_prize_count: int
    f2_success: tuple[int, int]
    f2_count: tuple[int, int]
    f3_damage: tuple[int, int]
    f3_energy: tuple[int, int]
    f4_success: tuple[int, int]
    f4_opportunity: tuple[int, int]
    f5_success: tuple[int, int]
    f5_count: tuple[int, int]
    game_point_numerator: int


@dataclass(frozen=True)
class SeedPairSufficientStatistics:
    """One complete control/seed block with both orientations preserved."""

    control_archive_sha256: str
    common_seed_id: str
    orientation_zero: GameSufficientStatistics
    orientation_one: GameSufficientStatistics


def _player_index(header: Mapping[str, Any], player: str) -> int:
    return 0 if player == header["player_roles"]["candidate"] else 1


def _turn_records(game: ReplayVerifiedGame) -> dict[tuple[str, int], list[Mapping[str, Any]]]:
    turns: dict[tuple[str, int], list[Mapping[str, Any]]] = defaultdict(list)
    active: tuple[str, int] | None = None
    for record in game.records:
        kind, payload = record["record_type"], record["payload"]
        if kind == "TURN_START":
            active = (payload["player_id"], payload["regular_turn_ordinal"])
        if active is not None:
            turns[active].append(record)
        if kind in {"TURN_END", "GAME_END"}:
            active = None
    return turns


def _checkpoint(turn: Sequence[Mapping[str, Any]], player: str, ordinal: int, *, resource: bool = False) -> Mapping[str, Any] | None:
    checkpoints = [row for row in turn if row["record_type"] == "FIRST_DECISION_CHECKPOINT"]
    if len(checkpoints) != 1:
        raise _fail("LOCAL_RESOURCE_CHECKPOINT_INVALID" if resource else "LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", f"{player} turn {ordinal} lacks one first-decision checkpoint")
    checkpoint = checkpoints[0]
    mandatory = [row for row in turn if row["record_type"] == "MANDATORY_PROCESSING_COMPLETE"]
    if len(mandatory) != 1 or mandatory[0]["sequence_number"] > checkpoint["sequence_number"]:
        raise _fail("LOCAL_RESOURCE_CHECKPOINT_INVALID" if resource else "LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", "checkpoint does not follow mandatory processing")
    if any(row["record_type"] == "ACTION_CHOSEN" and row["sequence_number"] < checkpoint["sequence_number"] for row in turn):
        raise _fail("LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", "voluntary action preceded checkpoint")
    return checkpoint


def _rate(success: int, count: int, *, terminal_neutral: bool) -> Any:
    if count:
        return _mp(Fraction(success, count))
    if not terminal_neutral:
        raise _fail("LOCAL_CHECKPOINT_MISSING_OR_AMBIGUOUS", "zero checkpoints are not proven terminal")
    return _mp(Fraction(1, 2))


def derive_game_feature_counts(game: ReplayVerifiedGame) -> GameFeatureCounts:
    """Derive raw F1-F5 quantities from one already replay-verified game."""
    game = validate_replay_verified_game(game)
    header, records = game.header, game.records
    players = (header["player_roles"]["candidate"], header["player_roles"]["control"])
    turns = _turn_records(game)
    terminal_sequence = records[-1]["sequence_number"]
    complete_round_2 = [row["sequence_number"] for row in records if row["record_type"] == "TURN_END" and row["payload"]["regular_turn_ordinal"] == 2]
    complete_round_4 = [row["sequence_number"] for row in records if row["record_type"] == "TURN_END" and row["payload"]["regular_turn_ordinal"] == 4]
    boundary2 = max(complete_round_2) if len(complete_round_2) == 2 else terminal_sequence
    boundary4 = max(complete_round_4) if len(complete_round_4) == 2 else terminal_sequence
    if len(complete_round_2) not in (0, 1, 2) or len(complete_round_4) not in (0, 1, 2):
        raise _fail("LOCAL_TRACE_SEQUENCE_INVALID", "round barrier is ambiguous")

    prizes = {player: header["initial_prize_count"] for player in players}
    prizes_at_boundary = dict(prizes)
    attacks: dict[str, set[str]] = {player: set() for player in players}
    damage, energy = [0, 0], [0, 0]
    for row in records:
        payload = row["payload"]
        if row["record_type"] == "PRIZE_ZONE_CHANGE":
            player = payload["player_id"]
            if payload["prize_count_before"] != prizes[player] or payload["prize_count_after"] > prizes[player]:
                raise _fail("LOCAL_PRIZE_EVENT_INCONSISTENT", "prize zone transition is inconsistent")
            prizes[player] = payload["prize_count_after"]
        if row["sequence_number"] == boundary2:
            prizes_at_boundary = dict(prizes)
        if row["sequence_number"] <= boundary4 and row["record_type"] == "ATTACK_DECLARE":
            index = _player_index(header, payload["player_id"])
            attacks[payload["player_id"]].add(payload["action_instance_id"])
            energy[index] += payload["effective_required_attack_cost_units"] + payload["mandatory_additional_energy_units_consumed_to_declare"]
        if row["sequence_number"] <= boundary4 and row["record_type"] == "DAMAGE_APPLIED":
            source = payload["source_actor_player_id"]
            if payload["source_action_instance_id"] in attacks[source]:
                if payload["damage_kind"] != DIRECT_DAMAGE_KIND:
                    raise _fail("LOCAL_DAMAGE_EVENT_UNCLASSIFIED", "attack-sourced HP change is not direct attack damage")
                unit = header["damage_counter_unit_hp"]
                if payload["applied_damage_hp"] % unit:
                    raise _fail("LOCAL_DAMAGE_UNIT_MISMATCH", "applied damage is not an exact counter-unit multiple")
                damage[_player_index(header, source)] += payload["applied_damage_hp"] // unit
            elif payload["damage_kind"] == DIRECT_DAMAGE_KIND:
                raise _fail("LOCAL_DAMAGE_EVENT_UNCLASSIFIED", "direct attack damage lacks an included declaration")
    if boundary2 == terminal_sequence and records[-1]["record_type"] == "GAME_END":
        prizes_at_boundary = dict(prizes)
    for player in players:
        if not 0 <= prizes_at_boundary[player] <= header["initial_prize_count"]:
            raise _fail("LOCAL_INITIAL_PRIZE_STATE_INVALID", "prize state lies outside initial-prize range")
    prizes_taken = tuple(header["initial_prize_count"] - prizes_at_boundary[player] for player in players)
    f1 = _bounded(_mp(Fraction(prizes_taken[0] - prizes_taken[1], header["initial_prize_count"])), -1, 1)

    f2_success, f2_count = [0, 0], [0, 0]
    f4_success, f4_opp = [0, 0], [0, 0]
    f5_success, f5_count = [0, 0], [0, 0]
    for player in players:
        index = _player_index(header, player)
        for ordinal in range(1, 5):
            turn = turns.get((player, ordinal))
            if turn is None:
                continue  # GAME_END proves absence terminal because it is unique and final.
            cp = _checkpoint(turn, player, ordinal, resource=True)
            actions = cp["payload"]["canonical_legal_actions"]
            f5_count[index] += 1
            if any(action["action_class"] in F5_ACTION_WHITELIST for action in actions):
                f5_success[index] += 1
            ready = any(action["action_class"] == ATTACK_ACTION for action in actions)
            if ordinal in (2, 4):
                f2_count[index] += 1
                f2_success[index] += int(ready)
            if cp["payload"]["attack_phase_permitted"] and not ready:
                f4_opp[index] += 1
                if any(row["record_type"] == "ATTACK_DECLARE" and row["payload"]["player_id"] == player for row in turn):
                    f4_success[index] += 1
    winner = records[-1]["payload"]["winner_player_id"]
    game_point_numerator = 2 if winner == players[0] else 1 if winner is None else 0
    return GameFeatureCounts(
        f1,
        prizes_taken,
        header["initial_prize_count"],
        tuple(f2_success),
        tuple(f2_count),
        tuple(damage),
        tuple(energy),
        tuple(f4_success),
        tuple(f4_opp),
        tuple(f5_success),
        tuple(f5_count),
        game_point_numerator,
    )


def _efficiency(damage: int, energy: int) -> Any:
    return _mp(0) if damage == energy == 0 else _mp(Fraction(damage, damage + energy))


def _pair_features(left: GameFeatureCounts, right: GameFeatureCounts) -> tuple[Any, Any, Any, Any, Any]:
    f1 = (left.f1 + right.f1) / _mp(2)
    values = [f1]
    for success, count, neutral in (
        (tuple(left.f2_success[i] + right.f2_success[i] for i in range(2)), tuple(left.f2_count[i] + right.f2_count[i] for i in range(2)), True),
        (tuple(left.f3_damage[i] + right.f3_damage[i] for i in range(2)), tuple(left.f3_energy[i] + right.f3_energy[i] for i in range(2)), False),
        (tuple(left.f4_success[i] + right.f4_success[i] for i in range(2)), tuple(left.f4_opportunity[i] + right.f4_opportunity[i] for i in range(2)), True),
        (tuple(left.f5_success[i] + right.f5_success[i] for i in range(2)), tuple(left.f5_count[i] + right.f5_count[i] for i in range(2)), True),
    ):
        if neutral:
            candidate, control = _rate(success[0], count[0], terminal_neutral=True), _rate(success[1], count[1], terminal_neutral=True)
        else:
            candidate, control = _efficiency(success[0], count[0]), _efficiency(success[1], count[1])
        values.append(_bounded(candidate - control, -1, 1))
    return tuple(values)  # type: ignore[return-value]


def _single_features(counts: GameFeatureCounts) -> tuple[Any, Any, Any, Any, Any]:
    return (
        counts.f1,
        _rate(counts.f2_success[0], counts.f2_count[0], terminal_neutral=True) - _rate(counts.f2_success[1], counts.f2_count[1], terminal_neutral=True),
        _efficiency(counts.f3_damage[0], counts.f3_energy[0]) - _efficiency(counts.f3_damage[1], counts.f3_energy[1]),
        _rate(counts.f4_success[0], counts.f4_opportunity[0], terminal_neutral=True) - _rate(counts.f4_success[1], counts.f4_opportunity[1], terminal_neutral=True),
        _rate(counts.f5_success[0], counts.f5_count[0], terminal_neutral=True) - _rate(counts.f5_success[1], counts.f5_count[1], terminal_neutral=True),
    )


def _integer_statistics(game: ReplayVerifiedGame, counts: GameFeatureCounts) -> GameSufficientStatistics:
    return GameSufficientStatistics(
        game.header["orientation"],
        counts.prizes_taken[0],
        counts.prizes_taken[1],
        counts.initial_prize_count,
        counts.f2_success,
        counts.f2_count,
        counts.f3_damage,
        counts.f3_energy,
        counts.f4_success,
        counts.f4_opportunity,
        counts.f5_success,
        counts.f5_count,
        counts.game_point_numerator,
    )


@dataclass(frozen=True)
class OfflineTraceFeatureResult:
    schema_id: str
    exact_rationals: Mapping[str, ExactRational]
    feature_point: FeaturePoint
    features: Mapping[str, str]
    x: str
    r: str
    pre_serialization_mpfr256: Mapping[str, str]
    mpfr256_projection_sha256: str
    seed_pair_sufficient_statistics: tuple[SeedPairSufficientStatistics, ...]
    control_count: int
    seeds_per_control: int
    offline_conformance_only: bool
    trace_authenticity_verified: bool
    official_wrapper_parity_verified: bool
    authority: bool
    calibration_upload_authorized: bool
    production_upload_authorized: bool
    sealed_holdout_access_authorized: bool
    agent_modification_authorized: bool
    permits: tuple[object, ...]
    report: Mapping[str, Any]


def extract_offline_trace_features(games: Sequence[ReplayVerifiedGame]) -> OfflineTraceFeatureResult:
    """Aggregate exactly four controls, 300 common seeds, and both orientations."""
    if type(games) not in (list, tuple):
        raise _fail("LOCAL_TRACE_FILE_MISSING", "games must be an explicit sequence")
    expected = CONTROL_COUNT * SEEDS_PER_CONTROL * len(ORIENTATIONS)
    if len(games) > expected:
        raise _fail("LOCAL_CONTROL_SEED_INCOMPLETE", f"at most {expected} games are allowed")
    checked = [validate_replay_verified_game(game) for game in games]
    candidate_archives = {game.header["candidate_archive_sha256"] for game in checked}
    if len(candidate_archives) != 1 or any(len({game.header[field] for game in checked}) != 1 for field in ("candidate_source_tree_sha256", "engine_sha256", "ruleset_sha256")):
        raise _fail("LOCAL_ENGINE_OR_RULESET_MISMATCH", "candidate or rooted static semantics differ across games")
    if len({game.header["card_catalog_sha256"] for game in checked}) != 1:
        raise _fail("LOCAL_CARD_CATALOG_MISMATCH", "card catalog differs across games")
    if len({game.header["candidate_deck_manifest_root"] for game in checked}) != 1:
        raise _fail("LOCAL_DECK_MANIFEST_MISMATCH", "candidate deck manifest differs across games")
    controls = {game.header["control_archive_sha256"] for game in checked}
    if len(controls) != CONTROL_COUNT:
        raise _fail("LOCAL_CONTROL_SEED_INCOMPLETE", "exactly four controls are required")
    game_ids = [game.header["game_id"] for game in checked]
    if len(set(game_ids)) != len(game_ids):
        raise _fail("LOCAL_TRACE_SCHEMA_INVALID", "game_id values must be unique across the panel")
    for control in controls:
        control_rows = [game for game in checked if game.header["control_archive_sha256"] == control]
        if len({game.header["control_source_tree_sha256"] for game in control_rows}) != 1:
            raise _fail("LOCAL_ENGINE_OR_RULESET_MISMATCH", "a control archive changed source binding across seeds")
        if len({game.header["control_deck_manifest_root"] for game in control_rows}) != 1:
            raise _fail("LOCAL_DECK_MANIFEST_MISMATCH", "a control archive changed deck binding across seeds")
    cells: dict[tuple[str, str, int], ReplayVerifiedGame] = {}
    for game in checked:
        header = game.header
        key = (header["control_archive_sha256"], header["common_seed_id"], header["orientation"])
        if key in cells:
            raise _fail("LOCAL_SEAT_PAIR_INCOMPLETE", "duplicate control/seed/orientation game")
        cells[key] = game
    pair_values: dict[str, list[tuple[Any, Any, Any, Any, Any]]] = defaultdict(list)
    seat_values: dict[int, list[tuple[Any, Any, Any, Any, Any]]] = defaultdict(list)
    paired_points: list[Fraction] = []
    bootstrap_statistics: list[SeedPairSufficientStatistics] = []
    canonical_seed_ids: set[str] | None = None
    seed_material_by_id: dict[str, str] = {}
    for control in sorted(controls):
        seed_rows = [game for game in checked if game.header["control_archive_sha256"] == control]
        seed_ids = {game.header["common_seed_id"] for game in seed_rows}
        if len(seed_ids) != SEEDS_PER_CONTROL:
            raise _fail("LOCAL_CONTROL_SEED_INCOMPLETE", "each control needs exactly 300 seeds")
        if canonical_seed_ids is None:
            canonical_seed_ids = seed_ids
        elif seed_ids != canonical_seed_ids:
            raise _fail("LOCAL_COMMON_SEED_MISMATCH", "controls do not share the same 300 common seed IDs")
        for seed in sorted(seed_ids):
            pair = [cells.get((control, seed, orientation)) for orientation in ORIENTATIONS]
            if any(item is None for item in pair):
                raise _fail("LOCAL_SEAT_PAIR_INCOMPLETE", "seat pair is incomplete")
            left, right = pair  # type: ignore[misc]
            if left.header["common_seed_material_sha256"] != right.header["common_seed_material_sha256"]:
                raise _fail("LOCAL_COMMON_SEED_MISMATCH", "seat pair seed material differs")
            material = left.header["common_seed_material_sha256"]
            prior_material = seed_material_by_id.setdefault(seed, material)
            if material != prior_material:
                raise _fail("LOCAL_COMMON_SEED_MISMATCH", "a common seed ID changed material across controls")
            if left.header["control_source_tree_sha256"] != right.header["control_source_tree_sha256"] or left.header["control_deck_manifest_root"] != right.header["control_deck_manifest_root"]:
                raise _fail("LOCAL_DECK_MANIFEST_MISMATCH", "control bindings differ within a seat pair")
            a, b = derive_game_feature_counts(left), derive_game_feature_counts(right)
            pair_values[control].append(_pair_features(a, b))
            seat_values[0].append(_single_features(a))
            seat_values[1].append(_single_features(b))
            paired_points.extend((_mp(Fraction(a.game_point_numerator, 2)), _mp(Fraction(b.game_point_numerator, 2))))
            bootstrap_statistics.append(
                SeedPairSufficientStatistics(
                    control,
                    seed,
                    _integer_statistics(left, a),
                    _integer_statistics(right, b),
                )
            )
    control_means = []
    for control in sorted(controls):
        rows = pair_values[control]
        control_means.append(tuple(sum((row[index] for row in rows), _mp(0)) / _mp(SEEDS_PER_CONTROL) for index in range(5)))
    f1_to_f5 = tuple(_bounded(sum((row[index] for row in control_means), _mp(0)) / _mp(CONTROL_COUNT), -1, 1) for index in range(5))
    seat_means = []
    for orientation in ORIENTATIONS:
        values = seat_values[orientation]
        seat_means.append(sum((sum(row, _mp(0)) / _mp(5) for row in values), _mp(0)) / _mp(CONTROL_COUNT * SEEDS_PER_CONTROL))
    f6 = _bounded(-abs(seat_means[0] - seat_means[1]) / _mp(2), -1, 0)
    values = (*f1_to_f5, f6)
    x = _bounded(sum(values, _mp(0)) / _mp(6), -1, 1)
    r = _bounded(_mp(2) * (sum(paired_points, _mp(0)) / _mp(expected)) - _mp(1), -1, 1)
    exact_rationals = {
        name: ExactRational.from_fraction(value, label=name)
        for name, value in zip(FEATURE_KEYS, values, strict=True)
    }
    exact_rationals["x"] = ExactRational.from_fraction(x, label="x")
    exact_rationals["R"] = ExactRational.from_fraction(r, label="R")
    feature_point = FeaturePoint.make(
        [exact_rationals[name] for name in FEATURE_KEYS],
        exact_rationals["R"],
    )
    if feature_point.x != exact_rationals["x"]:
        raise _fail("LOCAL_FEATURE_RATIONAL_DIVERGENCE", "trace-derived x disagrees with exact FeaturePoint composition")
    serialized = dict(zip(FEATURE_KEYS, feature_point.display_features, strict=True))
    precursors = {name: _exact_mpfr_text(value) for name, value in zip(FEATURE_KEYS, values, strict=True)}
    precursors["x"] = _exact_mpfr_text(x)
    precursors["R"] = _exact_mpfr_text(r)
    report = zero_authority(
        "OFFLINE_TRACE_FEATURE_CONFORMANCE_ONLY",
        detail="retired caller-receipt fixture accepted for offline regression only; canonical trace authenticity and official-wrapper parity are not claimed",
        extra={
            "offline_conformance_only": True,
            "trace_authenticity_verified": False,
            "official_wrapper_parity_verified": False,
            "replay_receipt_is_caller_supplied": True,
            "control_count": CONTROL_COUNT,
            "seeds_per_control": SEEDS_PER_CONTROL,
            "mpfr_precision_bits": MPFR_PRECISION_BITS,
            "mpfr_rounding": MPFR_ROUNDING,
            "mpfr_backend_available": gmpy2 is not None,
            "authoritative_numeric_layer": "exact_reduced_rationals",
            "mpfr_and_fixed_decimal_are_display_only": True,
            "integer_seed_pair_statistics_retained": True,
        },
    )
    return OfflineTraceFeatureResult(
        FEATURE_RESULT_SCHEMA, MappingProxyType(exact_rationals), feature_point, MappingProxyType(serialized), feature_point.display_x, feature_point.display_r, MappingProxyType(precursors), feature_point.mpfr256_projection_sha256, tuple(bootstrap_statistics), CONTROL_COUNT, SEEDS_PER_CONTROL,
        True, False, False, False, False, False, False, False, (), freeze(report),
    )


__all__ = [
    "ATTACK_ACTION", "CALLER_RECEIPT_AUTHENTICITY_PATH_RETIRED", "CONTROL_COUNT", "DIRECT_DAMAGE_KIND", "FEATURE_KEYS", "FEATURE_RESULT_SCHEMA",
    "F5_ACTION_WHITELIST", "MPFR_PRECISION_BITS", "MPFR_ROUNDING", "NON_STRATEGIC_ACTIONS",
    "ORIENTATIONS", "RECEIPT_SCHEMA", "ReplayVerifiedGame", "SEEDS_PER_CONTROL", "TRACE_SCHEMA",
    "ExactRational", "GameSufficientStatistics", "SeedPairSufficientStatistics", "TraceFeatureError",
    "canonical_legal_action_set_sha256", "derive_game_feature_counts",
    "extract_offline_trace_features", "make_replay_verified_game", "validate_replay_verified_game",
]
