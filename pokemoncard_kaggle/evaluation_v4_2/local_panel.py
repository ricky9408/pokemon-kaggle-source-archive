"""Compose exact full-grid local Docker evidence from sealed arm receipts.

This module has no row-injection API.  Outcomes are derived only from successful
receipt objects matching every claim in a validated execution plan.  Without
an external append witness and artifact reopening, even those receipts remain
locally forgeable.  The panel is therefore diagnostic inventory, not admissible
mechanics, public-transfer, or submission evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

from .arm_receipt import (
    CONTAINER_AUTHORITY,
    validate_arm_receipt,
)
from .execution_plan import validate_execution_plan


LOCAL_PANEL_SCHEMA = "evaluation_v4_2_local_docker_panel_v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ROW_FIELDS = frozenset(
    {
        "engine_id",
        "opponent_id",
        "seed",
        "seat",
        "candidate_outcome",
        "baseline_outcome",
        "candidate_receipt_sha256",
        "baseline_receipt_sha256",
        "candidate_transcript_sha256",
        "baseline_transcript_sha256",
        "candidate_max_action_seconds",
        "baseline_max_action_seconds",
    }
)
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "execution_plan_content_sha256",
        "receipts",
        "rows",
        "paired_cell_count",
        "arm_count",
        "local_custody_complete",
        "mechanics_outcomes_available",
        "mechanics_outcomes_admissible",
        "external_witness_verified",
        "global_one_shot_verified",
        "receipt_artifacts_reopened",
        "trusted_policy_code_required",
        "cross_policy_isolation_verified",
        "native_platform_verified",
        "latency_metrics_admissible",
        "remote_attestation_verified",
        "scientific_selector_admissible",
        "randomization_allowed",
        "submit_authorized",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_FIELDS = _CONTENT_FIELDS | frozenset({"content_sha256"})


class LocalPanelError(ValueError):
    """Local receipt evidence is incomplete, duplicated, or inconsistent."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LocalPanelError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise LocalPanelError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise LocalPanelError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _row_key(row: Mapping[str, Any]) -> tuple[str, str, int, str]:
    return (
        str(row["engine_id"]),
        str(row["opponent_id"]),
        int(row["seed"]),
        str(row["seat"]),
    )


def _compose_content(
    execution_plan: object, receipt_values: Iterable[object]
) -> dict[str, Any]:
    try:
        plan = validate_execution_plan(execution_plan)
    except ValueError as exc:
        raise LocalPanelError(f"execution plan is invalid: {exc}") from exc
    claims = plan["claims"]
    claims_by_hash = {claim["content_sha256"]: claim for claim in claims}
    protocols_by_hash = {
        protocol["content_sha256"]: protocol
        for protocol in plan["container_protocols"]
    }
    if len(claims_by_hash) != len(claims):
        raise LocalPanelError("execution plan contains duplicate claim hashes")

    raw_receipts = list(receipt_values)
    if len(raw_receipts) != len(claims):
        raise LocalPanelError(
            f"receipt count must equal the exact arm count {len(claims)}; got {len(raw_receipts)}"
        )
    checked: list[dict[str, Any]] = []
    seen_claims: set[str] = set()
    seen_attempts: set[str] = set()
    seen_receipts: set[str] = set()
    for index, raw in enumerate(raw_receipts):
        if not isinstance(raw, Mapping):
            raise LocalPanelError(f"receipts[{index}] must be an object")
        claim_hash = raw.get("claim_content_sha256")
        if claim_hash not in claims_by_hash:
            raise LocalPanelError(f"receipts[{index}] does not bind an expected claim")
        try:
            receipt = validate_arm_receipt(raw, claims_by_hash[claim_hash])
        except ValueError as exc:
            raise LocalPanelError(f"receipts[{index}] is invalid: {exc}") from exc
        if receipt["terminal_status"] != "SUCCESS":
            raise LocalPanelError(
                f"arm {receipt['attempt_id']} is terminal {receipt['terminal_status']}; panel vetoed"
            )
        claim = claims_by_hash[claim_hash]
        protocol = protocols_by_hash.get(claim["container_protocol_sha256"])
        if protocol is None:
            raise LocalPanelError("claim container protocol is absent from execution plan")
        if receipt["image_manifest_sha256"] != protocol["image_digest_sha256"]:
            raise LocalPanelError("receipt image manifest differs from its container protocol")
        if receipt["image_config_sha256"] != protocol["image_config_sha256"]:
            raise LocalPanelError("receipt image config differs from its container protocol")
        if receipt["runtime_bundle_sha256"] != protocol["runtime_sha256"]:
            raise LocalPanelError("receipt runtime bundle differs from its container protocol")
        if receipt["launcher_source_sha256"] != protocol["source_sha256"]:
            raise LocalPanelError("receipt launcher source differs from its container protocol")
        if receipt["external_deadline_seconds"] != protocol["arm_deadline_seconds"]:
            raise LocalPanelError("receipt external deadline differs from its container protocol")
        mounts = protocol["input_mounts"]
        if len(mounts) != 1 or receipt["input_bundle_sha256"] != mounts[0]["source_sha256"]:
            raise LocalPanelError("receipt input bundle differs from its private protocol mount")
        result = receipt["worker_result"]
        if (
            result["max_policy_action_seconds"] > protocol["action_deadline_seconds"]
            or result["max_opponent_action_seconds"] > protocol["action_deadline_seconds"]
        ):
            raise LocalPanelError("receipt reports an action beyond the frozen action deadline")
        if claim_hash in seen_claims:
            raise LocalPanelError("duplicate or replacement receipt for one claim")
        if receipt["attempt_id"] in seen_attempts:
            raise LocalPanelError("duplicate attempt_id across receipts")
        if receipt["content_sha256"] in seen_receipts:
            raise LocalPanelError("duplicate receipt content across arms")
        seen_claims.add(claim_hash)
        seen_attempts.add(receipt["attempt_id"])
        seen_receipts.add(receipt["content_sha256"])
        checked.append(receipt)
    if seen_claims != set(claims_by_hash):
        raise LocalPanelError("receipt set does not exactly cover the execution plan")

    uniform_fields = (
        "image_manifest_sha256",
        "image_config_sha256",
        "docker_daemon_fingerprint_sha256",
        "runtime_bundle_sha256",
        "launcher_source_sha256",
        "remote_attestation_verified",
        "docker_daemon_reports_amd64",
        "native_platform_verified",
        "latency_parity_allowed",
        "authority",
    )
    baseline_uniform = {field: checked[0][field] for field in uniform_fields}
    for receipt in checked[1:]:
        actual = {field: receipt[field] for field in uniform_fields}
        if actual != baseline_uniform:
            raise LocalPanelError("receipts do not share one observed runtime/security posture")

    claim_by_hash = claims_by_hash
    cells: dict[tuple[str, str, int, str], dict[str, tuple[dict[str, Any], dict[str, Any]]]] = {}
    for receipt in checked:
        claim = claim_by_hash[receipt["claim_content_sha256"]]
        key = (
            claim["engine_id"],
            claim["opponent_id"],
            claim["seed"],
            claim["seat"],
        )
        by_label = cells.setdefault(key, {})
        label = claim["policy_label"]
        if label in by_label:
            raise LocalPanelError(f"duplicate {label} arm for cell {key}")
        by_label[label] = (claim, receipt)

    rows: list[dict[str, Any]] = []
    for key in sorted(cells):
        by_label = cells[key]
        if set(by_label) != {"candidate", "baseline"}:
            raise LocalPanelError(f"cell {key} lacks an exact candidate/baseline pair")
        candidate = by_label["candidate"][1]
        baseline = by_label["baseline"][1]
        candidate_result = candidate["worker_result"]
        baseline_result = baseline["worker_result"]
        row = {
            "engine_id": key[0],
            "opponent_id": key[1],
            "seed": key[2],
            "seat": key[3],
            "candidate_outcome": candidate_result["outcome"],
            "baseline_outcome": baseline_result["outcome"],
            "candidate_receipt_sha256": candidate["content_sha256"],
            "baseline_receipt_sha256": baseline["content_sha256"],
            "candidate_transcript_sha256": candidate_result["transcript_sha256"],
            "baseline_transcript_sha256": baseline_result["transcript_sha256"],
            "candidate_max_action_seconds": candidate_result["max_policy_action_seconds"],
            "baseline_max_action_seconds": baseline_result["max_policy_action_seconds"],
        }
        _exact_fields(row, _ROW_FIELDS, label=f"row[{len(rows)}]")
        rows.append(row)
    if len(rows) != plan["paired_cell_count"]:
        raise LocalPanelError("composed row count does not equal paired_cell_count")

    checked.sort(key=lambda receipt: receipt["attempt_id"])
    native = all(receipt["native_platform_verified"] for receipt in checked)
    return {
        "schema": LOCAL_PANEL_SCHEMA,
        "execution_plan_content_sha256": plan["content_sha256"],
        "receipts": checked,
        "rows": rows,
        "paired_cell_count": plan["paired_cell_count"],
        "arm_count": plan["arm_count"],
        "local_custody_complete": False,
        "mechanics_outcomes_available": True,
        "mechanics_outcomes_admissible": False,
        "external_witness_verified": False,
        "global_one_shot_verified": False,
        "receipt_artifacts_reopened": False,
        "trusted_policy_code_required": True,
        "cross_policy_isolation_verified": False,
        "native_platform_verified": native,
        "latency_metrics_admissible": native,
        "remote_attestation_verified": False,
        "scientific_selector_admissible": False,
        "randomization_allowed": False,
        "submit_authorized": False,
        "authority": CONTAINER_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def compose_local_panel(
    execution_plan: object, receipts: Iterable[object]
) -> dict[str, Any]:
    content = _compose_content(execution_plan, receipts)
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_local_panel(value: object, execution_plan: object) -> dict[str, Any]:
    raw = _exact_fields(value, _FIELDS, label="local Docker panel")
    receipts = raw["receipts"]
    if not isinstance(receipts, list):
        raise LocalPanelError("local Docker panel receipts must be a list")
    content = _compose_content(execution_plan, receipts)
    for field in _CONTENT_FIELDS:
        if raw[field] != content[field]:
            raise LocalPanelError(f"local Docker panel derived field changed: {field}")
    digest = _sha256(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(content):
        raise LocalPanelError("local Docker panel content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise LocalPanelError("local Docker panel is not canonical")
    return expected


__all__ = [
    "LOCAL_PANEL_SCHEMA",
    "LocalPanelError",
    "canonical_json_bytes",
    "canonical_sha256",
    "compose_local_panel",
    "validate_local_panel",
]
