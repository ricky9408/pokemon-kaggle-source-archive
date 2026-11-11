"""Fixed, research-only VOI-P5 outcome evaluator.

This module is intentionally a small endpoint calculator.  It does not infer
families, calibrate probabilities, access a holdout, or authorize anything.
The input is an immutable, hashable record of the five pre-registered pairs.
"""

from __future__ import annotations

from hashlib import sha256
import json
import math
from numbers import Real
import os
from pathlib import Path
import re
from typing import Any, Mapping


INPUT_SCHEMA = "voi_p5_outcomes_v1"
RESULT_SCHEMA = "voi_p5_research_result_v1"
DECISION_RESEARCH_ONLY = "VOI_SIGNAL_RESEARCH_ONLY"
DECISION_CLOSED = "CLOSED"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_INPUT_FIELDS = frozenset(
    {"schema", "protocol_sha256", "pair_assignment_sha256", "waves", "pairs"}
)
_WAVE_FIELDS = frozenset({"wave_id", "pair_ids"})
_PAIR_FIELDS = frozenset(
    {"pair_id", "family_id", "wave_id", "selected_member", "members"}
)
_MEMBER_FIELDS = frozenset({"lineage_id", "family_id", "p0", "p1", "outcomes"})
_PAIR_METRIC_FIELDS = frozenset(
    {
        "pair_id",
        "family_id",
        "wave_id",
        "selected_member",
        "hosted_mean_by_member",
        "selected_minus_other_delta",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "pair_assignment_sha256",
        "outcomes_content_sha256",
        "pair_metrics",
        "positive_delta_count",
        "sign_test_probability",
        "macro_proper_score_lift",
        "integrity_pass",
        "primary_pass",
        "forecast_diagnostic_pass",
        "research_only",
        "decision",
        "production_submission_authorized",
        "sealed_holdout_accessed",
        "content_sha256",
    }
)


class VOIP5Error(ValueError):
    """The complete VOI-P5 input or result is malformed."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the deterministic JSON bytes used by all content hashes."""

    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise VOIP5Error(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise VOIP5Error(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise VOIP5Error(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise VOIP5Error(f"{label} must be a lowercase SHA-256")
    return value


def _finite_real(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise VOIP5Error(f"{label} must be finite")
    return float(value)


def _normalized_member(value: object, *, pair_id: str, member: str) -> dict[str, Any]:
    raw = _exact_fields(value, _MEMBER_FIELDS, label=f"pair {pair_id} member {member}")
    family_id = _identifier(raw["family_id"], label=f"pair {pair_id} member {member} family_id")
    p0 = _finite_real(raw["p0"], label=f"pair {pair_id} member {member} p0")
    p1 = _finite_real(raw["p1"], label=f"pair {pair_id} member {member} p1")
    if not 0.05 <= p0 <= 0.95:
        raise VOIP5Error(f"pair {pair_id} member {member} p0 must be in [0.05, 0.95]")
    if not 0.05 <= p1 <= 0.95:
        raise VOIP5Error(f"pair {pair_id} member {member} p1 must be in [0.05, 0.95]")

    outcomes = raw["outcomes"]
    if not isinstance(outcomes, list) or len(outcomes) != 24:
        raise VOIP5Error(f"pair {pair_id} member {member} must have exactly 24 outcomes")
    normalized_outcomes: list[float] = []
    for index, outcome in enumerate(outcomes):
        number = _finite_real(
            outcome, label=f"pair {pair_id} member {member} outcome {index}"
        )
        if number not in (0.0, 0.5, 1.0):
            raise VOIP5Error(
                f"pair {pair_id} member {member} outcome {index} must be one of 0, 0.5, 1"
            )
        normalized_outcomes.append(number)

    return {
        "lineage_id": _identifier(raw["lineage_id"], label=f"pair {pair_id} member {member} lineage_id"),
        "family_id": family_id,
        "p0": p0,
        "p1": p1,
        "outcomes": normalized_outcomes,
    }


def _normalize_input(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _INPUT_FIELDS, label="VOI-P5 input")
    if raw["schema"] != INPUT_SCHEMA:
        raise VOIP5Error(f"schema must be {INPUT_SCHEMA!r}")
    protocol_sha256 = _sha256(raw["protocol_sha256"], label="protocol_sha256")
    pair_assignment_sha256 = _sha256(
        raw["pair_assignment_sha256"], label="pair_assignment_sha256"
    )

    raw_waves = raw["waves"]
    if not isinstance(raw_waves, list) or len(raw_waves) != 3:
        raise VOIP5Error("waves must contain exactly three waves")
    waves: list[dict[str, Any]] = []
    wave_ids: set[str] = set()
    wave_pair_ids: set[str] = set()
    for raw_wave in raw_waves:
        wave = _exact_fields(raw_wave, _WAVE_FIELDS, label="wave")
        wave_id = _identifier(wave["wave_id"], label="wave_id")
        if wave_id in wave_ids:
            raise VOIP5Error(f"duplicate wave_id {wave_id!r}")
        wave_ids.add(wave_id)
        pair_ids = wave["pair_ids"]
        if not isinstance(pair_ids, list) or not pair_ids:
            raise VOIP5Error(f"wave {wave_id} pair_ids must be a non-empty list")
        normalized_pair_ids = []
        for pair_id in pair_ids:
            normalized_pair_id = _identifier(pair_id, label=f"wave {wave_id} pair_id")
            if normalized_pair_id in wave_pair_ids:
                raise VOIP5Error(f"pair_id {normalized_pair_id!r} occurs in multiple waves")
            wave_pair_ids.add(normalized_pair_id)
            normalized_pair_ids.append(normalized_pair_id)
        waves.append({"wave_id": wave_id, "pair_ids": sorted(normalized_pair_ids)})

    allocations = sorted(len(wave["pair_ids"]) for wave in waves)
    if allocations != [1, 2, 2]:
        raise VOIP5Error("waves must have allocation 2/2/1")

    raw_pairs = raw["pairs"]
    if not isinstance(raw_pairs, list) or len(raw_pairs) != 5:
        raise VOIP5Error("pairs must contain exactly five pair records")
    pairs: list[dict[str, Any]] = []
    pair_ids: set[str] = set()
    lineage_ids: set[str] = set()
    family_ids: set[str] = set()
    for raw_pair in raw_pairs:
        pair = _exact_fields(raw_pair, _PAIR_FIELDS, label="pair")
        pair_id = _identifier(pair["pair_id"], label="pair_id")
        if pair_id in pair_ids:
            raise VOIP5Error(f"duplicate pair_id {pair_id!r}")
        pair_ids.add(pair_id)
        family_id = _identifier(pair["family_id"], label=f"pair {pair_id} family_id")
        family_ids.add(family_id)
        wave_id = _identifier(pair["wave_id"], label=f"pair {pair_id} wave_id")
        if wave_id not in wave_ids:
            raise VOIP5Error(f"pair {pair_id} has an unknown wave_id")
        if pair_id not in wave_pair_ids:
            raise VOIP5Error(f"pair {pair_id} is missing from its wave assignment")
        assigned_wave = next(wave for wave in waves if pair_id in wave["pair_ids"])
        if assigned_wave["wave_id"] != wave_id:
            raise VOIP5Error(f"pair {pair_id} wave assignment mismatch")
        selected_member = pair["selected_member"]
        if selected_member not in {"A", "B"}:
            raise VOIP5Error(f"pair {pair_id} selected_member must be A or B")

        members = _exact_fields(pair["members"], frozenset({"A", "B"}), label=f"pair {pair_id} members")
        normalized_members: dict[str, dict[str, Any]] = {}
        for member_id in ("A", "B"):
            member = _normalized_member(members[member_id], pair_id=pair_id, member=member_id)
            if member["family_id"] != family_id:
                raise VOIP5Error(f"pair {pair_id} members must have the pair family_id")
            lineage_id = member["lineage_id"]
            if lineage_id in lineage_ids:
                raise VOIP5Error(f"duplicate lineage_id {lineage_id!r}")
            lineage_ids.add(lineage_id)
            normalized_members[member_id] = member
        pairs.append(
            {
                "pair_id": pair_id,
                "family_id": family_id,
                "wave_id": wave_id,
                "selected_member": selected_member,
                "members": normalized_members,
            }
        )

    if pair_ids != wave_pair_ids:
        missing = sorted(pair_ids - wave_pair_ids)
        extra = sorted(wave_pair_ids - pair_ids)
        raise VOIP5Error(f"wave roster does not exactly match pairs; missing={missing}, extra={extra}")
    if len(lineage_ids) != 10:
        raise VOIP5Error("there must be exactly ten unique lineages")
    if len(family_ids) != 4:
        raise VOIP5Error("VOI-P5 must cover exactly four families")

    return {
        "schema": INPUT_SCHEMA,
        "protocol_sha256": protocol_sha256,
        "pair_assignment_sha256": pair_assignment_sha256,
        "waves": sorted(waves, key=lambda item: item["wave_id"]),
        "pairs": sorted(pairs, key=lambda item: item["pair_id"]),
    }


def validate_voi_p5_outcomes(value: object) -> dict[str, Any]:
    """Validate and return the canonical, order-independent input."""

    return _normalize_input(value)


def _binary_cross_entropy(probability: float, outcome: float) -> float:
    return -(
        outcome * math.log(probability) + (1.0 - outcome) * math.log(1.0 - probability)
    )


def _member_metrics(member: Mapping[str, Any]) -> tuple[float, float]:
    outcomes = member["outcomes"]
    hosted_mean = sum(outcomes) / 24.0
    p0_loss = sum(_binary_cross_entropy(member["p0"], outcome) for outcome in outcomes) / 24.0
    p1_loss = sum(_binary_cross_entropy(member["p1"], outcome) for outcome in outcomes) / 24.0
    return hosted_mean, p0_loss - p1_loss


def evaluate_voi_p5(value: object) -> dict[str, Any]:
    """Evaluate one complete VOI-P5 batch, or fail on any malformed unit."""

    normalized = _normalize_input(value)
    pair_metrics: list[dict[str, Any]] = []
    lineage_lifts: list[float] = []
    positive_delta_count = 0

    for pair in normalized["pairs"]:
        members = pair["members"]
        means: dict[str, float] = {}
        for member_id in ("A", "B"):
            mean, lift = _member_metrics(members[member_id])
            means[member_id] = mean
            lineage_lifts.append(lift)
        selected_member = pair["selected_member"]
        other_member = "B" if selected_member == "A" else "A"
        delta = means[selected_member] - means[other_member]
        if delta > 0.0:
            positive_delta_count += 1
        pair_metrics.append(
            {
                "pair_id": pair["pair_id"],
                "family_id": pair["family_id"],
                "wave_id": pair["wave_id"],
                "selected_member": selected_member,
                "hosted_mean_by_member": {"A": means["A"], "B": means["B"]},
                "selected_minus_other_delta": delta,
            }
        )

    sign_test_probability = sum(
        math.comb(5, index) for index in range(positive_delta_count, 6)
    ) / 32.0
    macro_proper_score_lift = sum(lineage_lifts) / 10.0
    primary_pass = positive_delta_count == 5
    forecast_diagnostic_pass = macro_proper_score_lift >= 0.015

    content = {
        "schema": RESULT_SCHEMA,
        "protocol_sha256": normalized["protocol_sha256"],
        "pair_assignment_sha256": normalized["pair_assignment_sha256"],
        "outcomes_content_sha256": canonical_sha256(normalized),
        "pair_metrics": pair_metrics,
        "positive_delta_count": positive_delta_count,
        "sign_test_probability": sign_test_probability,
        "macro_proper_score_lift": macro_proper_score_lift,
        "integrity_pass": True,
        "primary_pass": primary_pass,
        "forecast_diagnostic_pass": forecast_diagnostic_pass,
        "research_only": True,
        "decision": DECISION_RESEARCH_ONLY
        if primary_pass and forecast_diagnostic_pass
        else DECISION_CLOSED,
        "production_submission_authorized": False,
        "sealed_holdout_accessed": False,
    }
    result = {**content, "content_sha256": canonical_sha256(content)}
    validate_voi_p5_result(result)
    return result


def validate_voi_p5_result(value: object) -> dict[str, Any]:
    """Validate the strict result envelope and its canonical content hash."""

    raw = _exact_fields(value, _RESULT_FIELDS, label="VOI-P5 result")
    if raw["schema"] != RESULT_SCHEMA:
        raise VOIP5Error(f"result schema must be {RESULT_SCHEMA!r}")
    protocol_sha256 = _sha256(raw["protocol_sha256"], label="result protocol_sha256")
    pair_assignment_sha256 = _sha256(
        raw["pair_assignment_sha256"], label="result pair_assignment_sha256"
    )
    outcomes_content_sha256 = _sha256(
        raw["outcomes_content_sha256"], label="result outcomes_content_sha256"
    )
    pair_metrics = raw["pair_metrics"]
    if not isinstance(pair_metrics, list) or len(pair_metrics) != 5:
        raise VOIP5Error("result pair_metrics must contain exactly five records")
    pair_metric_ids: set[str] = set()
    for metric in pair_metrics:
        metric_value = _exact_fields(metric, _PAIR_METRIC_FIELDS, label="result pair metric")
        pair_id = _identifier(metric_value["pair_id"], label="result pair metric pair_id")
        if pair_id in pair_metric_ids:
            raise VOIP5Error(f"duplicate result pair metric pair_id {pair_id!r}")
        pair_metric_ids.add(pair_id)
        _identifier(metric_value["family_id"], label="result pair metric family_id")
        _identifier(metric_value["wave_id"], label="result pair metric wave_id")
        if metric_value["selected_member"] not in {"A", "B"}:
            raise VOIP5Error("result pair metric selected_member must be A or B")
        means = _exact_fields(
            metric_value["hosted_mean_by_member"],
            frozenset({"A", "B"}),
            label="result hosted_mean_by_member",
        )
        for member_id in ("A", "B"):
            mean = _finite_real(means[member_id], label=f"result hosted_mean_by_member.{member_id}")
            if not 0.0 <= mean <= 1.0:
                raise VOIP5Error("result hosted means must be in [0, 1]")
        delta = _finite_real(
            metric_value["selected_minus_other_delta"],
            label="result selected_minus_other_delta",
        )
        if not -1.0 <= delta <= 1.0:
            raise VOIP5Error("result selected-minus-other deltas must be in [-1, 1]")
    positive_delta_count = raw["positive_delta_count"]
    if (
        isinstance(positive_delta_count, bool)
        or not isinstance(positive_delta_count, int)
        or not 0 <= positive_delta_count <= 5
    ):
        raise VOIP5Error("result positive_delta_count must be an integer in [0, 5]")
    sign_test_probability = _finite_real(
        raw["sign_test_probability"], label="result sign_test_probability"
    )
    expected_sign_probability = sum(
        math.comb(5, index) for index in range(positive_delta_count, 6)
    ) / 32.0
    if sign_test_probability != expected_sign_probability:
        raise VOIP5Error("result sign_test_probability is not the exact five-pair tail")
    macro_lift = _finite_real(
        raw["macro_proper_score_lift"], label="result macro_proper_score_lift"
    )
    if raw["primary_pass"] is not (positive_delta_count == 5):
        raise VOIP5Error("result primary_pass does not match the five strict deltas")
    if raw["forecast_diagnostic_pass"] is not (macro_lift >= 0.015):
        raise VOIP5Error("result forecast_diagnostic_pass does not match the BCE threshold")
    content = {field: raw[field] for field in _RESULT_FIELDS if field != "content_sha256"}
    content_sha256 = _sha256(raw["content_sha256"], label="result content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise VOIP5Error("result content_sha256 mismatch")
    if raw["integrity_pass"] is not True or raw["research_only"] is not True:
        raise VOIP5Error("result must be an integrity-passed research-only result")
    if raw["production_submission_authorized"] is not False:
        raise VOIP5Error("production_submission_authorized must be false")
    if raw["sealed_holdout_accessed"] is not False:
        raise VOIP5Error("sealed_holdout_accessed must be false")
    if raw["decision"] not in {DECISION_RESEARCH_ONLY, DECISION_CLOSED}:
        raise VOIP5Error("result decision is invalid")
    if raw["decision"] == DECISION_RESEARCH_ONLY and not (
        raw["primary_pass"] is True and raw["forecast_diagnostic_pass"] is True
    ):
        raise VOIP5Error("research-only decision requires both diagnostic passes")
    if raw["decision"] == DECISION_CLOSED and (
        raw["primary_pass"] is True and raw["forecast_diagnostic_pass"] is True
    ):
        raise VOIP5Error("a fully passed result cannot be CLOSED")
    return {
        **dict(raw),
        "protocol_sha256": protocol_sha256,
        "pair_assignment_sha256": pair_assignment_sha256,
        "outcomes_content_sha256": outcomes_content_sha256,
        "content_sha256": content_sha256,
    }


def write_voi_p5_result_once(path: str | Path, result: Mapping[str, Any]) -> Path:
    """Persist one canonical result and refuse every later write."""

    validated = validate_voi_p5_result(result)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(validated, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return destination


# Descriptive aliases make the one-shot API convenient without adding another
# protocol or behavior surface.
evaluate_voi_p5_outcomes = evaluate_voi_p5
write_result_create_once = write_voi_p5_result_once


__all__ = [
    "DECISION_CLOSED",
    "DECISION_RESEARCH_ONLY",
    "INPUT_SCHEMA",
    "RESULT_SCHEMA",
    "VOIP5Error",
    "canonical_json_bytes",
    "canonical_sha256",
    "evaluate_voi_p5",
    "evaluate_voi_p5_outcomes",
    "validate_voi_p5_outcomes",
    "validate_voi_p5_result",
    "write_result_create_once",
    "write_voi_p5_result_once",
]
