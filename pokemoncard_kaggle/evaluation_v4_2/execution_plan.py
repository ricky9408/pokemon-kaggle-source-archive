"""Pure deterministic full-grid execution planning for v4.2 container arms.

The planner consumes already-sealed v4.2 inputs and emits a complete, immutable
claim set.  It has no execution, Docker, filesystem, clock, network, or
subprocess surface.  A plan is research evidence only; it cannot authorize an
anchor or a production submission.
"""

from __future__ import annotations

import hashlib
import json
import math
from numbers import Real
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .arm_receipt import (
    ATTEMPT_CLAIM_SCHEMA,
    CONTAINER_AUTHORITY,
    build_attempt_claim,
    validate_attempt_claim,
)
from .container_protocol import validate_container_protocol
from .contrast_protocol import validate_contrast_protocol
from .simulation_design import SEATS, validate_simulation_template


EXECUTION_PLAN_SCHEMA = "evaluation_v4_2_container_execution_plan_v1"
DEVELOPMENT_AUTHORITY = CONTAINER_AUTHORITY
STATE_FROZEN = "FROZEN"
MIN_ENGINE_COUNT = 2
MIN_OPPONENT_COUNT = 12
SEED_COUNT = 16
PAIRED_CELL_COUNT = MIN_ENGINE_COUNT * MIN_OPPONENT_COUNT * SEED_COUNT * 2
ARM_COUNT = PAIRED_CELL_COUNT * 2

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_FIELDS = frozenset(
    {"archive_sha256", "policy_content_sha256", "main_sha256", "deck_sha256"}
)
_ENGINE_FIELDS = frozenset({"engine_id", "binary_sha256", "runtime_tree_sha256"})
_OPPONENT_FIELDS = frozenset(
    {
        "opponent_id",
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "family_id",
        "rating_layer",
        "weight",
        "ood_mass",
    }
)
_PLAN_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "template_content_sha256",
        "simulation_template",
        "contrast_protocol_sha256",
        "contrast_protocol",
        "engine_roster",
        "opponent_roster",
        "seeds",
        "candidate_identity",
        "baseline_identity",
        "opponent_main_sha256s",
        "container_protocols",
        "execution_design_sha256",
        "claims",
        "claim_set_sha256",
        "paired_cell_count",
        "arm_count",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
        "state",
    }
)
_PLAN_FIELDS = _PLAN_CONTENT_FIELDS | {"content_sha256"}
_UNIFORM_PROTOCOL_FIELDS = frozenset(
    {
        "oci_image",
        "image_digest_sha256",
        "image_manifest_media_type",
        "image_manifest_raw_sha256",
        "image_config_sha256",
        "image_layer_sha256s",
        "platform",
        "network_mode",
        "read_only_rootfs",
        "cap_drop",
        "no_new_privileges",
        "scratch_tmpfs",
        "cpu_limit_millicores",
        "memory_limit_bytes",
        "pids_limit",
        "max_steps",
        "output_limit_bytes",
        "arm_deadline_seconds",
        "arm_deadline_enforcement",
        "action_deadline_seconds",
        "action_deadline_enforcement",
        "retry_policy",
        "container_scope",
        "runtime_sha256",
        "security_sha256",
        "source_sha256",
        "command",
        "authority",
        "research_only",
        "external_authority",
        "submission_authorized",
        "anchor_allowed",
        "production_submission_authorized",
        "state",
    }
)


class ExecutionPlanError(ValueError):
    """A v4.2 full-grid plan is malformed or not authority-safe."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical JSON representation used by all plan hashes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExecutionPlanError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash a value after canonical JSON serialization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ExecutionPlanError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ExecutionPlanError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExecutionPlanError(f"{label} must be a positive integer")
    return value


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ExecutionPlanError(f"{label} must be a non-empty trimmed string")
    return value


def _identity(value: object, *, label: str) -> dict[str, str]:
    raw = _exact_fields(value, _IDENTITY_FIELDS, label=label)
    return {
        "archive_sha256": _sha256(raw["archive_sha256"], label=f"{label}.archive_sha256"),
        "policy_content_sha256": _sha256(
            raw["policy_content_sha256"], label=f"{label}.policy_content_sha256"
        ),
        "main_sha256": _sha256(raw["main_sha256"], label=f"{label}.main_sha256"),
        "deck_sha256": _sha256(raw["deck_sha256"], label=f"{label}.deck_sha256"),
    }


def _rosters(
    engines_value: object, opponents_value: object
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(engines_value, list) or len(engines_value) < MIN_ENGINE_COUNT:
        raise ExecutionPlanError("plan must contain at least two engines")
    engines: list[dict[str, Any]] = []
    engine_ids: set[str] = set()
    for index, item in enumerate(engines_value):
        raw = _exact_fields(item, _ENGINE_FIELDS, label=f"engine_roster[{index}]")
        engine = {
            "engine_id": _text(raw["engine_id"], label=f"engine_roster[{index}].engine_id"),
            "binary_sha256": _sha256(
                raw["binary_sha256"], label=f"engine_roster[{index}].binary_sha256"
            ),
            "runtime_tree_sha256": _sha256(
                raw["runtime_tree_sha256"], label=f"engine_roster[{index}].runtime_tree_sha256"
            ),
        }
        if engine["engine_id"] in engine_ids:
            raise ExecutionPlanError("duplicate engine_id in plan")
        engine_ids.add(engine["engine_id"])
        engines.append(engine)
    if engines != sorted(engines, key=lambda item: item["engine_id"]):
        raise ExecutionPlanError("engine_roster must be canonically sorted")

    if not isinstance(opponents_value, list) or len(opponents_value) < MIN_OPPONENT_COUNT:
        raise ExecutionPlanError("plan must contain at least twelve opponents")
    opponents: list[dict[str, Any]] = []
    opponent_ids: set[str] = set()
    for index, item in enumerate(opponents_value):
        raw = _exact_fields(item, _OPPONENT_FIELDS, label=f"opponent_roster[{index}]")
        weight = raw["weight"]
        ood_mass = raw["ood_mass"]
        if isinstance(weight, bool) or not isinstance(weight, Real) or not math.isfinite(float(weight)):
            raise ExecutionPlanError(f"opponent_roster[{index}].weight must be finite")
        if isinstance(ood_mass, bool) or not isinstance(ood_mass, Real) or not math.isfinite(float(ood_mass)):
            raise ExecutionPlanError(f"opponent_roster[{index}].ood_mass must be finite")
        opponent = {
            "opponent_id": _text(raw["opponent_id"], label=f"opponent_roster[{index}].opponent_id"),
            "archive_sha256": _sha256(
                raw["archive_sha256"], label=f"opponent_roster[{index}].archive_sha256"
            ),
            "policy_content_sha256": _sha256(
                raw["policy_content_sha256"],
                label=f"opponent_roster[{index}].policy_content_sha256",
            ),
            "deck_sha256": _sha256(
                raw["deck_sha256"], label=f"opponent_roster[{index}].deck_sha256"
            ),
            "family_id": _text(raw["family_id"], label=f"opponent_roster[{index}].family_id"),
            "rating_layer": raw["rating_layer"],
            "weight": float(weight),
            "ood_mass": float(ood_mass),
        }
        if opponent["rating_layer"] not in {"top", "mid", "low"}:
            raise ExecutionPlanError("opponent rating_layer is invalid")
        if opponent["weight"] <= 0.0 or opponent["ood_mass"] not in (0.0, 1.0):
            raise ExecutionPlanError("opponent weight or ood_mass is invalid")
        if opponent["opponent_id"] in opponent_ids:
            raise ExecutionPlanError("duplicate opponent_id in plan")
        opponent_ids.add(opponent["opponent_id"])
        opponents.append(opponent)
    if opponents != sorted(opponents, key=lambda item: item["opponent_id"]):
        raise ExecutionPlanError("opponent_roster must be canonically sorted")
    return engines, opponents


def _opponent_main_hashes(
    value: object, *, opponent_roster: Sequence[Mapping[str, Any]]
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ExecutionPlanError("opponent_main_sha256s must be a mapping")
    expected_ids = {row["opponent_id"] for row in opponent_roster}
    if set(value) != expected_ids:
        raise ExecutionPlanError("opponent_main_sha256s must exactly match opponent IDs")
    return {
        opponent_id: _sha256(value[opponent_id], label=f"opponent_main_sha256s[{opponent_id}]")
        for opponent_id in sorted(expected_ids)
    }


def arm_protocol_id(
    policy_label: str, engine_id: str, opponent_id: str, seed: int, seat: str
) -> str:
    """Return the stable human-readable ID for one protocol grid arm."""

    if policy_label not in {"candidate", "baseline"}:
        raise ExecutionPlanError("policy_label must be candidate or baseline")
    if seat not in SEATS:
        raise ExecutionPlanError("seat must be policy_first or policy_second")
    return f"{policy_label}:{engine_id}:{opponent_id}:{seed}:{seat}"


def _expected_arm_index(
    *,
    engines: Sequence[Mapping[str, Any]],
    opponents: Sequence[Mapping[str, Any]],
    seeds: Sequence[int],
) -> dict[str, tuple[str, str, str, int, str]]:
    expected: dict[str, tuple[str, str, str, int, str]] = {}
    for engine in engines:
        for opponent in opponents:
            for seed in seeds:
                for seat in SEATS:
                    for policy_label in ("candidate", "baseline"):
                        arm_id = arm_protocol_id(
                            policy_label,
                            engine["engine_id"],
                            opponent["opponent_id"],
                            seed,
                            seat,
                        )
                        if arm_id in expected:
                            raise ExecutionPlanError(f"arm protocol ID collision: {arm_id!r}")
                        expected[arm_id] = (
                            policy_label,
                            engine["engine_id"],
                            opponent["opponent_id"],
                            seed,
                            seat,
                        )
    return expected


def _normalize_protocols(
    value: object,
    *,
    engines: Sequence[Mapping[str, Any]],
    opponents: Sequence[Mapping[str, Any]],
    seeds: Sequence[int],
    contrast: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ExecutionPlanError("container_protocols must be a list")
    expected = _expected_arm_index(engines=engines, opponents=opponents, seeds=seeds)
    if len(value) != len(expected):
        raise ExecutionPlanError(
            f"container_protocols must contain exactly {len(expected)} protocols"
        )

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        try:
            protocol = validate_container_protocol(item)
        except ValueError as exc:
            raise ExecutionPlanError(f"container_protocols[{index}] is invalid: {exc}") from exc
        arm_id = protocol["arm_id"]
        if arm_id in seen:
            raise ExecutionPlanError(f"duplicate container protocol arm_id {arm_id!r}")
        seen.add(arm_id)
        if arm_id not in expected:
            raise ExecutionPlanError(f"extra or mismatched container protocol arm_id {arm_id!r}")
        policy_label, _, _, _, _ = expected[arm_id]
        if protocol["arm_kind"] != policy_label:
            raise ExecutionPlanError(
                f"container protocol arm_kind does not match arm_id {arm_id!r}"
            )
        if protocol["arm_deadline_seconds"] != contrast["worker_timeout_seconds"]:
            raise ExecutionPlanError("container arm deadline does not match contrast worker timeout")
        if protocol["action_deadline_seconds"] != contrast["max_action_seconds"]:
            raise ExecutionPlanError("container action deadline does not match contrast max action")
        if protocol["max_steps"] != contrast["max_steps"]:
            raise ExecutionPlanError("container max_steps does not match contrast max_steps")
        normalized.append(protocol)

    missing = set(expected) - seen
    if missing:
        raise ExecutionPlanError(f"missing container protocols: {len(missing)}")

    normalized.sort(key=lambda protocol: protocol["arm_id"])
    baseline = {
        field: normalized[0][field]
        for field in _UNIFORM_PROTOCOL_FIELDS
    }
    for protocol in normalized[1:]:
        actual = {field: protocol[field] for field in _UNIFORM_PROTOCOL_FIELDS}
        if canonical_json_bytes(actual) != canonical_json_bytes(baseline):
            raise ExecutionPlanError(
                "container protocols must have uniform image/runtime/security/source/resource settings"
            )
    return normalized


def _claim_base(
    *,
    execution_design_sha256: str,
    template: Mapping[str, Any],
    contrast: Mapping[str, Any],
    candidate: Mapping[str, str],
    baseline: Mapping[str, str],
    opponent_main_sha256s: Mapping[str, str],
    engine: Mapping[str, Any],
    opponent: Mapping[str, Any],
    seed: int,
    seat: str,
    policy_label: str,
    protocol: Mapping[str, Any],
) -> dict[str, Any]:
    policy = candidate if policy_label == "candidate" else baseline
    return {
        "schema": ATTEMPT_CLAIM_SCHEMA,
        "execution_design_sha256": execution_design_sha256,
        "container_protocol_sha256": protocol["content_sha256"],
        "bundle_manifest_sha256": protocol["bundle_manifest_sha256"],
        "task_spec_sha256": protocol["task_spec_sha256"],
        "template_content_sha256": template["content_sha256"],
        "contrast_protocol_sha256": contrast["content_sha256"],
        "candidate_archive_sha256": candidate["archive_sha256"],
        "baseline_archive_sha256": baseline["archive_sha256"],
        "policy_label": policy_label,
        "policy_archive_sha256": policy["archive_sha256"],
        "opponent_id": opponent["opponent_id"],
        "opponent_archive_sha256": opponent["archive_sha256"],
        "opponent_policy_content_sha256": opponent["policy_content_sha256"],
        "opponent_main_sha256": opponent_main_sha256s[opponent["opponent_id"]],
        "opponent_deck_sha256": opponent["deck_sha256"],
        "engine_id": engine["engine_id"],
        "engine_binary_sha256": engine["binary_sha256"],
        "engine_runtime_tree_sha256": engine["runtime_tree_sha256"],
        "seed": seed,
        "seat": seat,
        "max_steps": protocol["max_steps"],
        "max_attempts": 1,
        "retry_ordinal": 0,
        "authority": CONTAINER_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def _build_claims(
    *,
    execution_design_sha256: str,
    template: Mapping[str, Any],
    contrast: Mapping[str, Any],
    candidate: Mapping[str, str],
    baseline: Mapping[str, str],
    opponent_main_sha256s: Mapping[str, str],
    protocols: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for engine in template["engine_roster"]:
        for opponent in template["opponent_roster"]:
            for seed in template["seeds"]:
                for seat in SEATS:
                    for policy_label in ("candidate", "baseline"):
                        arm_id = arm_protocol_id(
                            policy_label,
                            engine["engine_id"],
                            opponent["opponent_id"],
                            seed,
                            seat,
                        )
                        base = _claim_base(
                            execution_design_sha256=execution_design_sha256,
                            template=template,
                            contrast=contrast,
                            candidate=candidate,
                            baseline=baseline,
                            opponent_main_sha256s=opponent_main_sha256s,
                            engine=engine,
                            opponent=opponent,
                            seed=seed,
                            seat=seat,
                            policy_label=policy_label,
                            protocol=protocols[arm_id],
                        )
                        claims.append(build_attempt_claim(base))
    return claims


def _plan_content(
    *,
    template: Mapping[str, Any],
    contrast: Mapping[str, Any],
    candidate: Mapping[str, str],
    baseline: Mapping[str, str],
    opponent_main_sha256s: Mapping[str, str],
    protocols: list[dict[str, Any]],
) -> dict[str, Any]:
    engines = template["engine_roster"]
    opponents = template["opponent_roster"]
    seeds = template["seeds"]
    design = {
        "schema": EXECUTION_PLAN_SCHEMA,
        "template_content_sha256": template["content_sha256"],
        "simulation_template": template,
        "contrast_protocol_sha256": contrast["content_sha256"],
        "contrast_protocol": contrast,
        "engine_roster": engines,
        "opponent_roster": opponents,
        "seeds": seeds,
        "candidate_identity": candidate,
        "baseline_identity": baseline,
        "opponent_main_sha256s": opponent_main_sha256s,
        "container_protocols": protocols,
        "paired_cell_count": len(engines) * len(opponents) * len(seeds) * len(SEATS),
        "arm_count": len(protocols),
    }
    execution_design_sha256 = canonical_sha256(design)
    protocol_by_id = {protocol["arm_id"]: protocol for protocol in protocols}
    claims = _build_claims(
        execution_design_sha256=execution_design_sha256,
        template=template,
        contrast=contrast,
        candidate=candidate,
        baseline=baseline,
        opponent_main_sha256s=opponent_main_sha256s,
        protocols=protocol_by_id,
    )
    if len(claims) != len(protocols):
        raise ExecutionPlanError("claim count does not equal protocol count")
    return {
        **design,
        "execution_design_sha256": execution_design_sha256,
        "claims": claims,
        "claim_set_sha256": canonical_sha256(claims),
        "authority": CONTAINER_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "state": STATE_FROZEN,
    }


def _validate_plan_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _PLAN_CONTENT_FIELDS, label="execution plan content")
    if raw["schema"] != EXECUTION_PLAN_SCHEMA:
        raise ExecutionPlanError(f"schema must be {EXECUTION_PLAN_SCHEMA!r}")
    template_hash = _sha256(raw["template_content_sha256"], label="template_content_sha256")
    try:
        checked_template = validate_simulation_template(raw["simulation_template"])
    except ValueError as exc:
        raise ExecutionPlanError(f"simulation template in plan is invalid: {exc}") from exc
    if checked_template["content_sha256"] != template_hash:
        raise ExecutionPlanError("template_content_sha256 does not match simulation_template")
    contrast_hash = _sha256(raw["contrast_protocol_sha256"], label="contrast_protocol_sha256")
    try:
        checked_contrast = validate_contrast_protocol(raw["contrast_protocol"])
    except ValueError as exc:
        raise ExecutionPlanError(f"contrast protocol in plan is invalid: {exc}") from exc
    if checked_contrast["content_sha256"] != contrast_hash:
        raise ExecutionPlanError("contrast_protocol_sha256 does not match contrast_protocol")
    candidate = _identity(raw["candidate_identity"], label="candidate_identity")
    baseline = _identity(raw["baseline_identity"], label="baseline_identity")
    if candidate["archive_sha256"] == baseline["archive_sha256"]:
        raise ExecutionPlanError("candidate and baseline archive hashes must differ")
    engines, opponents = _rosters(raw["engine_roster"], raw["opponent_roster"])
    if engines != checked_template["engine_roster"]:
        raise ExecutionPlanError("plan engine roster differs from simulation template")
    if opponents != checked_template["opponent_roster"]:
        raise ExecutionPlanError("plan opponent roster differs from simulation template")
    if len(engines) != checked_contrast["engine_count"]:
        raise ExecutionPlanError("plan engine count does not match contrast protocol")
    if len(opponents) != checked_contrast["opponent_count"]:
        raise ExecutionPlanError("plan opponent count does not match contrast protocol")
    seeds = raw["seeds"]
    if not isinstance(seeds, list) or len(seeds) != SEED_COUNT or len(set(seeds)) != SEED_COUNT:
        raise ExecutionPlanError("plan must contain exactly sixteen unique seeds")
    if any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in seeds):
        raise ExecutionPlanError("plan seeds must be non-negative integers")
    if seeds != checked_template["seeds"]:
        raise ExecutionPlanError("plan seeds differ from simulation template")
    opponent_main = _opponent_main_hashes(opponent_main_sha256s := raw["opponent_main_sha256s"], opponent_roster=opponents)
    protocols = raw["container_protocols"]
    if not isinstance(protocols, list):
        raise ExecutionPlanError("container_protocols must be a list")
    checked_protocols = []
    for index, protocol in enumerate(protocols):
        try:
            checked_protocols.append(validate_container_protocol(protocol))
        except ValueError as exc:
            raise ExecutionPlanError(f"container_protocols[{index}] is invalid: {exc}") from exc
    if checked_protocols != protocols:
        raise ExecutionPlanError("container_protocols must be canonical")
    if checked_protocols != sorted(checked_protocols, key=lambda protocol: protocol["arm_id"]):
        raise ExecutionPlanError("container_protocols must be canonically sorted by arm_id")

    expected = _expected_arm_index(engines=engines, opponents=opponents, seeds=seeds)
    if len(checked_protocols) != len(expected):
        raise ExecutionPlanError("container_protocols count does not match the full grid")
    seen: set[str] = set()
    for protocol in checked_protocols:
        arm_id = protocol["arm_id"]
        if arm_id in seen:
            raise ExecutionPlanError("duplicate container protocol arm_id")
        seen.add(arm_id)
        if arm_id not in expected or protocol["arm_kind"] != expected[arm_id][0]:
            raise ExecutionPlanError("container protocol arm kind/id mismatch")
        if protocol["arm_deadline_seconds"] != checked_contrast["worker_timeout_seconds"]:
            raise ExecutionPlanError("container arm deadline does not match contrast protocol")
        if protocol["action_deadline_seconds"] != checked_contrast["max_action_seconds"]:
            raise ExecutionPlanError("container action deadline does not match contrast protocol")
        if protocol["max_steps"] != checked_contrast["max_steps"]:
            raise ExecutionPlanError("container max_steps does not match contrast protocol")
    if seen != set(expected):
        raise ExecutionPlanError("container protocols are not the exact full grid")
    baseline_protocol = {
        field: checked_protocols[0][field]
        for field in _UNIFORM_PROTOCOL_FIELDS
    }
    for protocol in checked_protocols[1:]:
        if canonical_json_bytes({field: protocol[field] for field in _UNIFORM_PROTOCOL_FIELDS}) != canonical_json_bytes(baseline_protocol):
            raise ExecutionPlanError("container protocol settings are not uniform")

    design = {
        "schema": EXECUTION_PLAN_SCHEMA,
        "template_content_sha256": template_hash,
        "simulation_template": checked_template,
        "contrast_protocol_sha256": contrast_hash,
        "contrast_protocol": checked_contrast,
        "engine_roster": engines,
        "opponent_roster": opponents,
        "seeds": seeds,
        "candidate_identity": candidate,
        "baseline_identity": baseline,
        "opponent_main_sha256s": opponent_main,
        "container_protocols": checked_protocols,
        "paired_cell_count": raw["paired_cell_count"],
        "arm_count": raw["arm_count"],
    }
    execution_design = _sha256(raw["execution_design_sha256"], label="execution_design_sha256")
    if execution_design != canonical_sha256(design):
        raise ExecutionPlanError("execution_design_sha256 mismatch")
    claims = raw["claims"]
    if not isinstance(claims, list) or len(claims) != len(expected):
        raise ExecutionPlanError("claims must contain exactly one claim per arm")
    checked_claims: list[dict[str, Any]] = []
    for index, claim in enumerate(claims):
        try:
            checked_claims.append(validate_attempt_claim(claim))
        except ValueError as exc:
            raise ExecutionPlanError(f"claims[{index}] is invalid: {exc}") from exc
    if checked_claims != claims:
        raise ExecutionPlanError("claims must be canonical")
    if any(claim["execution_design_sha256"] != execution_design for claim in checked_claims):
        raise ExecutionPlanError("every claim must use execution_design_sha256")
    expected_claim_ids = {
        (policy, engine, opponent, seed, seat)
        for policy, engine, opponent, seed, seat in expected.values()
    }
    actual_claim_ids = {
        (claim["policy_label"], claim["engine_id"], claim["opponent_id"], claim["seed"], claim["seat"])
        for claim in checked_claims
    }
    if actual_claim_ids != expected_claim_ids:
        raise ExecutionPlanError("claims are not the exact candidate/baseline full grid")
    engines_by_id = {engine["engine_id"]: engine for engine in engines}
    opponents_by_id = {opponent["opponent_id"]: opponent for opponent in opponents}
    protocols_by_id = {protocol["arm_id"]: protocol for protocol in checked_protocols}
    expected_claims = _build_claims(
        execution_design_sha256=execution_design,
        template=checked_template,
        contrast=checked_contrast,
        candidate=candidate,
        baseline=baseline,
        opponent_main_sha256s=opponent_main,
        protocols=protocols_by_id,
    )
    if checked_claims != expected_claims:
        raise ExecutionPlanError("claims are not in canonical full-grid order")
    for claim in checked_claims:
        engine = engines_by_id[claim["engine_id"]]
        opponent = opponents_by_id[claim["opponent_id"]]
        policy = candidate if claim["policy_label"] == "candidate" else baseline
        if claim["template_content_sha256"] != template_hash:
            raise ExecutionPlanError("claim template hash does not match plan")
        if claim["contrast_protocol_sha256"] != contrast_hash:
            raise ExecutionPlanError("claim contrast hash does not match plan")
        if claim["candidate_archive_sha256"] != candidate["archive_sha256"]:
            raise ExecutionPlanError("claim candidate archive does not match plan identity")
        if claim["baseline_archive_sha256"] != baseline["archive_sha256"]:
            raise ExecutionPlanError("claim baseline archive does not match plan identity")
        if claim["policy_archive_sha256"] != policy["archive_sha256"]:
            raise ExecutionPlanError("claim policy archive does not match plan identity")
        for field, claim_field in (
            ("archive_sha256", "opponent_archive_sha256"),
            ("policy_content_sha256", "opponent_policy_content_sha256"),
            ("deck_sha256", "opponent_deck_sha256"),
        ):
            if claim[claim_field] != opponent[field]:
                raise ExecutionPlanError("claim opponent identity does not match plan roster")
        if claim["opponent_main_sha256"] != opponent_main[claim["opponent_id"]]:
            raise ExecutionPlanError("claim opponent main does not match plan binding")
        if (
            claim["engine_binary_sha256"] != engine["binary_sha256"]
            or claim["engine_runtime_tree_sha256"] != engine["runtime_tree_sha256"]
        ):
            raise ExecutionPlanError("claim engine identity does not match plan roster")
        arm_id = arm_protocol_id(
            claim["policy_label"],
            claim["engine_id"],
            claim["opponent_id"],
            claim["seed"],
            claim["seat"],
        )
        if claim["container_protocol_sha256"] != protocols_by_id[arm_id]["content_sha256"]:
            raise ExecutionPlanError("claim container protocol does not match plan arm")
    if raw["claim_set_sha256"] != canonical_sha256(checked_claims):
        raise ExecutionPlanError("claim_set_sha256 mismatch")
    if raw["paired_cell_count"] != len(engines) * len(opponents) * len(seeds) * len(SEATS):
        raise ExecutionPlanError("paired_cell_count does not match the grid")
    if _positive_integer(raw["paired_cell_count"], label="paired_cell_count") != raw["paired_cell_count"]:
        raise ExecutionPlanError("paired_cell_count does not match the grid")
    if _positive_integer(raw["arm_count"], label="arm_count") != len(expected):
        raise ExecutionPlanError("arm_count does not match the grid")
    if raw["authority"] != CONTAINER_AUTHORITY:
        raise ExecutionPlanError(f"authority must be {CONTAINER_AUTHORITY!r}")
    if raw["anchor_allowed"] is not False or raw["production_submission_authorized"] is not False:
        raise ExecutionPlanError("execution plan cannot grant anchor or production authority")
    if raw["state"] != STATE_FROZEN:
        raise ExecutionPlanError("state must be FROZEN")
    return {
        "schema": EXECUTION_PLAN_SCHEMA,
        "template_content_sha256": template_hash,
        "simulation_template": checked_template,
        "contrast_protocol_sha256": contrast_hash,
        "contrast_protocol": checked_contrast,
        "engine_roster": engines,
        "opponent_roster": opponents,
        "seeds": seeds,
        "candidate_identity": candidate,
        "baseline_identity": baseline,
        "opponent_main_sha256s": opponent_main,
        "container_protocols": checked_protocols,
        "execution_design_sha256": execution_design,
        "claims": checked_claims,
        "claim_set_sha256": raw["claim_set_sha256"],
        "paired_cell_count": raw["paired_cell_count"],
        "arm_count": raw["arm_count"],
        "authority": CONTAINER_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "state": STATE_FROZEN,
    }


def validate_execution_plan(value: object) -> dict[str, Any]:
    """Validate an exact, self-hash-checked full-grid execution plan."""

    raw = _exact_fields(value, _PLAN_FIELDS, label="execution plan")
    content = _validate_plan_content({field: raw[field] for field in _PLAN_CONTENT_FIELDS})
    digest = _sha256(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(content):
        raise ExecutionPlanError("execution plan content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise ExecutionPlanError("execution plan is not canonical")
    return expected


def compile_execution_plan(
    template: object,
    contrast_protocol: object,
    candidate_identity: Mapping[str, Any],
    baseline_identity: Mapping[str, Any],
    opponent_main_sha256s: Mapping[str, str],
    container_protocols: object,
) -> dict[str, Any]:
    """Compile and seal the exact candidate/baseline container full grid."""

    try:
        checked_template = validate_simulation_template(template)
    except ValueError as exc:
        raise ExecutionPlanError(f"simulation template is invalid: {exc}") from exc
    try:
        checked_contrast = validate_contrast_protocol(contrast_protocol)
    except ValueError as exc:
        raise ExecutionPlanError(f"contrast protocol is invalid: {exc}") from exc
    candidate = _identity(candidate_identity, label="candidate_identity")
    baseline = _identity(baseline_identity, label="baseline_identity")
    if candidate["archive_sha256"] == baseline["archive_sha256"]:
        raise ExecutionPlanError("candidate and baseline archive hashes must differ")
    expected_baseline = {
        "archive_sha256": checked_contrast["baseline_archive_sha256"],
        "policy_content_sha256": checked_contrast["baseline_policy_content_sha256"],
        "main_sha256": checked_contrast["baseline_main_sha256"],
        "deck_sha256": checked_contrast["baseline_deck_sha256"],
    }
    if baseline != expected_baseline:
        raise ExecutionPlanError("baseline identity does not match contrast protocol")
    if len(checked_template["engine_roster"]) != checked_contrast["engine_count"]:
        raise ExecutionPlanError("template engine count does not match contrast protocol")
    if len(checked_template["opponent_roster"]) != checked_contrast["opponent_count"]:
        raise ExecutionPlanError("template opponent count does not match contrast protocol")
    if len(checked_template["seeds"]) != checked_contrast["seed_count"]:
        raise ExecutionPlanError("template seed count does not match contrast protocol")
    if checked_contrast["seats"] != list(SEATS):
        raise ExecutionPlanError("contrast seats do not match execution grid")
    mains = _opponent_main_hashes(
        opponent_main_sha256s, opponent_roster=checked_template["opponent_roster"]
    )
    protocols = _normalize_protocols(
        container_protocols,
        engines=checked_template["engine_roster"],
        opponents=checked_template["opponent_roster"],
        seeds=checked_template["seeds"],
        contrast=checked_contrast,
    )
    content = _plan_content(
        template=checked_template,
        contrast=checked_contrast,
        candidate=candidate,
        baseline=baseline,
        opponent_main_sha256s=mains,
        protocols=protocols,
    )
    return validate_execution_plan({**content, "content_sha256": canonical_sha256(content)})


build_execution_plan = compile_execution_plan
build_full_grid_execution_plan = compile_execution_plan
compile_full_grid_execution_plan = compile_execution_plan
validate_full_grid_execution_plan = validate_execution_plan


__all__ = [
    "ARM_COUNT",
    "DEVELOPMENT_AUTHORITY",
    "EXECUTION_PLAN_SCHEMA",
    "ExecutionPlanError",
    "MIN_ENGINE_COUNT",
    "MIN_OPPONENT_COUNT",
    "PAIRED_CELL_COUNT",
    "SEED_COUNT",
    "arm_protocol_id",
    "build_execution_plan",
    "build_full_grid_execution_plan",
    "canonical_json_bytes",
    "canonical_sha256",
    "compile_execution_plan",
    "compile_full_grid_execution_plan",
    "validate_execution_plan",
    "validate_full_grid_execution_plan",
]
