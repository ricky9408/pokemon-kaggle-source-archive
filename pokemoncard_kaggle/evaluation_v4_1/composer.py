"""Authoritative, research-only VOI-P5 evidence composer.

The composer rebuilds predictions, then obtains detached live Kaggle snapshots
whose horizons were derived from authenticated replay byte buffers. It verifies
external timestamps, enforces pair exposure chronology, and only then calls the
fixed endpoint calculator. It never reopens caller capture paths, cannot
authorize a production agent, and cannot open the sealed holdout.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Mapping

from .authorization import (
    validate_authorization,
    validate_research_permit,
    validate_usage_ledger,
)
from .beacon import validate_beacon_receipt
from .evidence_budget import load_ledger
from .kaggle_evidence import (
    reverify_authenticated_pair_capture_online,
    validate_authenticated_live_pair_snapshot,
)
from .prediction import validate_prediction_bundle
from .protocol import (
    canonical_json_bytes,
    canonical_sha256,
    protocol_core_sha256,
    validate_pair_assignment,
    validate_population_manifest,
    validate_protocol,
)
from .statistics import evaluate_voi_p5
from .timestamping import verify_anchor_chronology, verify_rfc3161_token


COMPOSITION_SCHEMA = "voi_p5_authoritative_research_composition_v4"
DECISION_SIGNAL = "VOI_SIGNAL_RESEARCH_ONLY"
DECISION_CLOSED = "CLOSED"
_ANCHOR_KEYS = frozenset({"data_path", "token_path", "ca_file"})


class CompositionError(ValueError):
    """The complete VOI-P5 packet fails an authoritative integrity check."""


def _utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise CompositionError(f"{label} must be UTC text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CompositionError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise CompositionError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _exact_mapping(value: object, keys: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CompositionError(f"{label} fields must exactly be {sorted(keys)}")
    return value


def _verify_anchor(artifact: object, material: object) -> dict[str, Any]:
    paths = _exact_mapping(material, _ANCHOR_KEYS, label="timestamp material")
    data_path = Path(paths["data_path"])
    expected_bytes = canonical_json_bytes(artifact) + b"\n"
    try:
        actual_bytes = data_path.read_bytes()
    except OSError as exc:
        raise CompositionError(f"cannot read timestamped artifact: {exc}") from exc
    if actual_bytes != expected_bytes:
        raise CompositionError("timestamped data bytes are not the exact canonical artifact")
    return verify_rfc3161_token(
        data_path=data_path,
        token_path=paths["token_path"],
        ca_file=paths["ca_file"],
    )


def _validate_alpha_allocation(
    protocol: Mapping[str, Any],
    evidence_budget_ledger_path: str | Path,
    *,
    population_anchor_time: datetime,
) -> dict[str, Any]:
    state = load_ledger(evidence_budget_ledger_path)
    expected_sha = protocol["evidence_budget_allocation_event_sha256"]
    matches = [event for event in state["events"] if event["event_sha256"] == expected_sha]
    if len(matches) != 1:
        raise CompositionError("protocol allocation event is absent or duplicated in evidence budget ledger")
    event = matches[0]
    if (
        event["event_type"] != "ALLOCATE"
        or event["protocol_context_sha256"] != protocol_core_sha256(protocol)
        or event["alpha_amount"] != protocol["confirmatory_alpha"]
        or event["disposition"] != "ALLOCATED"
    ):
        raise CompositionError("evidence budget allocation does not match frozen protocol core and alpha")
    allocation_time = _utc(event["created_at_utc"], label="allocation created_at_utc")
    protocol_frozen = _utc(protocol["frozen_at_utc"], label="protocol frozen_at_utc")
    if allocation_time < protocol_frozen:
        raise CompositionError("alpha allocation cannot predate the frozen protocol core")
    if allocation_time >= population_anchor_time:
        raise CompositionError("alpha allocation must predate the population timestamp anchor")
    return {"event": event, "ledger_head_sha256": state["head_sha256"]}


def _build_statistics_input(
    *,
    protocol: Mapping[str, Any],
    assignment: Mapping[str, Any],
    predictions: Mapping[str, Any],
    horizons: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    prediction_by_uuid = {record["lineage_uuid"]: record for record in predictions["records"]}
    preference_by_pair = {row["pair_id"]: row for row in predictions["pair_preferences"]}
    pairs = []
    for pair in assignment["pairs"]:
        members = {}
        for member, lineage_uuid in zip(("A", "B"), pair["slot_order"]):
            prediction = prediction_by_uuid[lineage_uuid]
            members[member] = {
                "lineage_id": prediction["lineage_id"],
                "family_id": pair["family_id"],
                "p0": prediction["prediction"]["p0"],
                "p1": prediction["prediction"]["p1"],
                "outcomes": horizons[lineage_uuid]["outcomes"],
            }
        preference = preference_by_pair[pair["pair_id"]]
        pairs.append(
            {
                "pair_id": pair["pair_id"],
                "family_id": pair["family_id"],
                "wave_id": pair["wave_id"],
                "selected_member": preference["selected_member"],
                "members": members,
            }
        )
    return {
        "schema": "voi_p5_outcomes_v1",
        "protocol_sha256": canonical_sha256(protocol),
        "pair_assignment_sha256": assignment["content_sha256"],
        "waves": [
            {
                "wave_id": wave_id,
                "pair_ids": [pair["pair_id"] for pair in assignment["pairs"] if pair["wave_id"] == wave_id],
            }
            for wave_id in protocol["waves"]
        ],
        "pairs": pairs,
    }


def _enforce_pair_chronology(
    assignment: Mapping[str, Any],
    horizons: Mapping[str, Mapping[str, Any]],
    pair_barriers: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    previous_completed: datetime | None = None
    previous_barrier_sha: str | None = None
    for pair in assignment["pairs"]:
        member_horizons = [horizons[lineage_uuid] for lineage_uuid in pair["slot_order"]]
        barrier = pair_barriers[pair["pair_id"]]
        submission_times = [
            _utc(horizon["submission_created_at_utc"], label="submission_created_at_utc")
            for horizon in member_horizons
        ]
        first_games = [
            _utc(horizon["first_game_created_at_utc"], label="first_game_created_at_utc")
            for horizon in member_horizons
        ]
        # Both pair members must occupy latest-two before either literal horizon begins.
        if min(first_games) <= max(submission_times):
            raise CompositionError(f"pair {pair['pair_id']} had games before both members occupied latest-two")
        completed = _utc(barrier["horizon_completed_at_utc"], label="horizon_completed_at_utc")
        if previous_completed is not None and min(submission_times) <= previous_completed:
            raise CompositionError(f"pair {pair['pair_id']} overlaps the preceding pair horizon")
        if barrier["prior_pair_barrier_content_sha256"] != previous_barrier_sha:
            raise CompositionError(f"pair {pair['pair_id']} does not bind the preceding pair barrier")
        modules = {horizon["module_version"] for horizon in member_horizons}
        if len(modules) != 1:
            raise CompositionError(f"pair {pair['pair_id']} crosses hosted module versions")
        previous_completed = completed
        previous_barrier_sha = barrier["content_sha256"]
        metrics.append(
            {
                "pair_id": pair["pair_id"],
                "wave_id": pair["wave_id"],
                "both_submitted_by_utc": max(submission_times).isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "first_game_utc": min(first_games).isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "last_game_utc": previous_completed.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "module_version": next(iter(modules)),
                "pair_completion_barrier_content_sha256": barrier["content_sha256"],
            }
        )
    return metrics


def compose_research_result(
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    beacon_receipt: object,
    predictor_model: object,
    kaggle_runtime_binding: object,
    prediction_bundle: object,
    authorization: object,
    population_timestamp_material: object,
    prediction_timestamp_material: object,
    authorization_timestamp_material: object,
    evidence_budget_ledger_path: str | Path,
    usage_ledger_path: str | Path,
    pair_capture_packages_by_pair_id: object,
    openssl_bin: str = "openssl",
) -> dict[str, Any]:
    """Compose the only valid research result from exact raw upstream evidence."""

    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    beacon = validate_beacon_receipt(beacon_receipt, protocol=frozen, openssl_bin=openssl_bin)
    assignment = validate_pair_assignment(pair_assignment, frozen, population)
    if (
        assignment["external_beacon_sha256"] != beacon["external_beacon_sha256"]
        or assignment["external_beacon_round"] != beacon["external_beacon_round"]
    ):
        raise CompositionError("pair assignment is not derived from the verified beacon receipt")
    predictions = validate_prediction_bundle(
        prediction_bundle,
        protocol=frozen,
        population_manifest=population,
        pair_assignment=assignment,
        predictor_model=predictor_model,
    )
    artifacts = {
        "protocol": frozen,
        "population_manifest": population,
        "pair_assignment": assignment,
        "prediction_bundle": predictions,
        "predictor_model": predictor_model,
        "kaggle_runtime_binding": kaggle_runtime_binding,
    }
    auth = validate_authorization(authorization, **artifacts)

    population_anchor = _verify_anchor(population, population_timestamp_material)
    prediction_anchor = _verify_anchor(predictions, prediction_timestamp_material)
    authorization_anchor = _verify_anchor(auth, authorization_timestamp_material)
    population_grant = _utc(population_anchor["granted_at_utc"], label="population TSA grant")
    prediction_grant = _utc(prediction_anchor["granted_at_utc"], label="prediction TSA grant")
    authorization_grant = _utc(authorization_anchor["granted_at_utc"], label="authorization TSA grant")
    if beacon["anchor_granted_at_utc"] != population_anchor["granted_at_utc"]:
        raise CompositionError("beacon boundary does not use the population TSA grant")
    beacon_time = _utc(beacon["current_pulse"]["timeStamp"], label="beacon pulse time")
    if not population_grant < beacon_time < prediction_grant <= authorization_grant:
        raise CompositionError("population, beacon, prediction, and authorization anchors are misordered")
    prediction_created = _utc(predictions["created_at_utc"], label="prediction created_at_utc")
    authorization_created = _utc(auth["created_at_utc"], label="authorization created_at_utc")
    if not beacon_time < prediction_created <= prediction_grant:
        raise CompositionError("prediction creation must follow the beacon and precede its TSA grant")
    if not prediction_grant <= authorization_created <= authorization_grant:
        raise CompositionError("authorization creation must follow the prediction TSA grant")
    allocation = _validate_alpha_allocation(
        frozen,
        evidence_budget_ledger_path,
        population_anchor_time=population_grant,
    )

    usage_events = validate_usage_ledger(usage_ledger_path, auth, artifacts=artifacts)
    if len(usage_events) != 10:
        raise CompositionError("complete VOI-P5 composition requires exactly ten usage events")
    pair_ids = {pair["pair_id"] for pair in assignment["pairs"]}
    if not isinstance(pair_capture_packages_by_pair_id, Mapping) or set(
        pair_capture_packages_by_pair_id
    ) != pair_ids:
        raise CompositionError("pair captures must exactly cover all five randomized pairs")
    snapshots: dict[str, dict[str, Any]] = {}
    horizons: dict[str, dict[str, Any]] = {}
    permit_by_uuid: dict[str, Mapping[str, Any]] = {}
    for pair_id in sorted(pair_ids):
        try:
            live_snapshot = reverify_authenticated_pair_capture_online(
                pair_capture_packages_by_pair_id[pair_id],
                authorization=auth,
                usage_ledger_path=usage_ledger_path,
                artifacts=artifacts,
            )
            snapshot = validate_authenticated_live_pair_snapshot(
                live_snapshot,
                authorization=auth,
                artifacts=artifacts,
            )
        except Exception as exc:
            raise CompositionError(f"pair {pair_id} authenticated capture is invalid: {exc}") from exc
        if snapshot["pair_id"] != pair_id:
            raise CompositionError("pair capture ID mismatch")
        snapshots[pair_id] = snapshot
        for lineage_uuid, horizon in snapshot["horizons_by_lineage_uuid"].items():
            if lineage_uuid in horizons:
                raise CompositionError("lineage appears in multiple pair captures")
            permit = validate_research_permit(
                snapshot["permits_by_lineage_uuid"][lineage_uuid],
                auth,
                ledger_path=usage_ledger_path,
                artifacts=artifacts,
            )
            receipt = snapshot["submission_receipts_by_lineage_uuid"][lineage_uuid]
            if permit["lineage_uuid"] != lineage_uuid:
                raise CompositionError("unit permit lineage UUID mismatch")
            if (
                horizon["lineage_uuid"] != lineage_uuid
                or horizon["permit_content_sha256"] != permit["content_sha256"]
                or horizon["submission_receipt_content_sha256"] != receipt["content_sha256"]
            ):
                raise CompositionError("online horizon identity binding mismatch")
            if _utc(
                receipt["submission_created_at_utc"],
                label="hosted submission creation",
            ) >= _utc(auth["expires_at_utc"], label="authorization expiry"):
                raise CompositionError("hosted submission was created after authorization expiry")
            verify_anchor_chronology(
                prediction_anchor,
                submission_created_at_utc=horizon["submission_created_at_utc"],
                first_game_created_at_utc=horizon["first_game_created_at_utc"],
            )
            verify_anchor_chronology(
                authorization_anchor,
                submission_created_at_utc=horizon["submission_created_at_utc"],
                first_game_created_at_utc=horizon["first_game_created_at_utc"],
            )
            horizons[lineage_uuid] = horizon
            permit_by_uuid[lineage_uuid] = permit
    if set(horizons) != set(assignment["selected_lineage_uuids"]):
        raise CompositionError("online snapshots do not cover all selected lineage UUIDs")

    for lineage_uuid in assignment["selected_lineage_uuids"]:
        permit = validate_research_permit(
            permit_by_uuid[lineage_uuid],
            auth,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        permit_by_uuid[lineage_uuid] = permit

    # Usage order and permit identity must match the actual hosted creation order.
    ordered_horizons = sorted(
        horizons.values(),
        key=lambda horizon: (
            _utc(horizon["submission_created_at_utc"], label="submission time"),
            horizon["submission_ref"],
        ),
    )
    expected_uuid_order = [event["lineage_uuid"] for event in usage_events]
    if [horizon["lineage_uuid"] for horizon in ordered_horizons] != expected_uuid_order:
        raise CompositionError("hosted submission creation order differs from authorized usage order")
    event_by_uuid = {event["lineage_uuid"]: event for event in usage_events}
    for horizon in ordered_horizons:
        permit = permit_by_uuid[horizon["lineage_uuid"]]
        event = event_by_uuid[horizon["lineage_uuid"]]
        if (
            permit["usage_sequence"] != event["sequence"]
            or permit["usage_event_sha256"] != event["event_sha256"]
            or permit["prior_pair_barrier_content_sha256"]
            != event["prior_pair_barrier_content_sha256"]
        ):
            raise CompositionError("research permit does not bind its exact usage ledger event")
        event_time = _utc(
            event["created_at_utc"],
            label="usage event created_at_utc",
        )
        submission_time = _utc(horizon["submission_created_at_utc"], label="submission time")
        if not authorization_grant <= event_time <= submission_time:
            raise CompositionError("research permit consumption must follow authorization TSA and precede upload")
    pair_barriers = {
        pair_id: snapshot["pair_completion_barrier"]
        for pair_id, snapshot in snapshots.items()
    }
    pair_chronology = _enforce_pair_chronology(assignment, horizons, pair_barriers)
    statistics_input = _build_statistics_input(
        protocol=frozen,
        assignment=assignment,
        predictions=predictions,
        horizons=horizons,
    )
    statistics_result = evaluate_voi_p5(statistics_input)
    passed = statistics_result["decision"] == "VOI_SIGNAL_RESEARCH_ONLY"
    content = {
        "schema": COMPOSITION_SCHEMA,
        "protocol_sha256": canonical_sha256(frozen),
        "population_content_sha256": population["content_sha256"],
        "pair_assignment_content_sha256": assignment["content_sha256"],
        "beacon_receipt_content_sha256": beacon["content_sha256"],
        "prediction_bundle_content_sha256": predictions["content_sha256"],
        "authorization_content_sha256": auth["content_sha256"],
        "kaggle_runtime_binding_content_sha256": auth[
            "kaggle_runtime_binding_content_sha256"
        ],
        "population_timestamp_token_sha256": population_anchor["token_sha256"],
        "prediction_timestamp_token_sha256": prediction_anchor["token_sha256"],
        "authorization_timestamp_token_sha256": authorization_anchor["token_sha256"],
        "evidence_budget_allocation_event_sha256": allocation["event"]["event_sha256"],
        "evidence_budget_ledger_head_sha256": allocation["ledger_head_sha256"],
        "usage_ledger_head_sha256": usage_events[-1]["event_sha256"],
        "horizon_content_sha256_by_lineage_uuid": {
            lineage_uuid: horizons[lineage_uuid]["content_sha256"]
            for lineage_uuid in sorted(horizons)
        },
        "pair_completion_barrier_content_sha256_by_pair_id": {
            pair_id: pair_barriers[pair_id]["content_sha256"]
            for pair_id in sorted(pair_barriers)
        },
        "authenticated_pair_capture_content_sha256_by_pair_id": {
            pair_id: snapshots[pair_id]["capture_content_sha256"]
            for pair_id in sorted(snapshots)
        },
        "authenticated_live_pair_snapshot_content_sha256_by_pair_id": {
            pair_id: snapshots[pair_id]["content_sha256"]
            for pair_id in sorted(snapshots)
        },
        "pair_chronology": pair_chronology,
        "statistics_input_content_sha256": canonical_sha256(statistics_input),
        "statistics_result": statistics_result,
        "integrity_pass": True,
        "decision": DECISION_SIGNAL if passed else DECISION_CLOSED,
        "research_only": True,
        "production_submission_authorized": False,
        "sealed_holdout_accessed": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def write_composition_once(path: str | Path, composition: Mapping[str, Any]) -> Path:
    if composition.get("schema") != COMPOSITION_SCHEMA:
        raise CompositionError("composition schema mismatch")
    if composition.get("production_submission_authorized") is not False:
        raise CompositionError("composition cannot authorize production")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(composition) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"composition already exists: {target}") from None
    return target


__all__ = [
    "COMPOSITION_SCHEMA",
    "DECISION_CLOSED",
    "DECISION_SIGNAL",
    "CompositionError",
    "compose_research_result",
    "write_composition_once",
]
