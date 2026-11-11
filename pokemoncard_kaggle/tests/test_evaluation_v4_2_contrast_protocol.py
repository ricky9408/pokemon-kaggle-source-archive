from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v4_2.contrast_protocol import (
    ARM_EXECUTION_MODE,
    CONTRAST_PROTOCOL_SCHEMA,
    FAILURE_POLICY,
    REQUIRED_PLATFORM,
    SEATS,
    ContrastProtocolError,
    build_contrast_protocol,
    canonical_sha256,
    load_contrast_protocol,
    validate_contrast_protocol,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _content() -> dict[str, object]:
    return {
        "schema": CONTRAST_PROTOCOL_SCHEMA,
        "baseline_archive_sha256": _sha("archive"),
        "baseline_policy_content_sha256": _sha("policy-content"),
        "baseline_main_sha256": _sha("main"),
        "baseline_deck_sha256": _sha("deck"),
        "max_steps": 600,
        "worker_timeout_seconds": 900.0,
        "max_action_seconds": 9.0,
        "workers": 2,
        "platform": REQUIRED_PLATFORM,
        "arm_execution_mode": ARM_EXECUTION_MODE,
        "failure_policy": FAILURE_POLICY,
        "engine_count": 2,
        "opponent_count": 12,
        "seed_count": 16,
        "seats": list(SEATS),
        "population_readiness_sha256": _sha("population-readiness"),
    }


def test_build_validate_and_load_are_canonical(tmp_path: Path) -> None:
    receipt = build_contrast_protocol(_content())
    assert validate_contrast_protocol(receipt) == receipt
    assert receipt["content_sha256"] == canonical_sha256(
        {key: value for key, value in receipt.items() if key != "content_sha256"}
    )

    path = tmp_path / "contrast-protocol.json"
    path.write_bytes(json.dumps(receipt, sort_keys=True).encode("ascii"))
    assert load_contrast_protocol(path) == receipt


def test_unknown_fields_are_rejected_by_builder_and_validator() -> None:
    with pytest.raises(ContrastProtocolError, match="exactly"):
        build_contrast_protocol({**_content(), "unexpected": True})
    receipt = build_contrast_protocol(_content())
    with pytest.raises(ContrastProtocolError, match="exactly"):
        validate_contrast_protocol({**receipt, "unexpected": True})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_steps", True),
        ("workers", False),
        ("engine_count", 2.0),
        ("opponent_count", True),
        ("seed_count", 16.0),
        ("worker_timeout_seconds", float("nan")),
        ("max_action_seconds", float("inf")),
    ],
)
def test_numeric_contract_rejects_booleans_nonfinite_and_wrong_types(
    field: str, value: object
) -> None:
    with pytest.raises(ContrastProtocolError):
        build_contrast_protocol({**_content(), field: value})


def test_duration_fields_use_canonical_float_json_numbers() -> None:
    with pytest.raises(ContrastProtocolError, match="canonical float"):
        build_contrast_protocol({**_content(), "worker_timeout_seconds": 900})
    with pytest.raises(ContrastProtocolError, match="canonical float"):
        build_contrast_protocol({**_content(), "max_action_seconds": 9})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform", "Darwin/arm64"),
        ("arm_execution_mode", "shared_process"),
        ("failure_policy", "retry"),
        ("engine_count", 3),
        ("opponent_count", 11),
        ("seed_count", 15),
        ("seats", ["policy_first"]),
    ],
)
def test_frozen_values_and_grid_expectations_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ContrastProtocolError):
        build_contrast_protocol({**_content(), field: value})


def test_tampering_is_rejected_even_when_the_receipt_is_reordered() -> None:
    receipt = build_contrast_protocol(_content())
    tampered = copy.deepcopy(receipt)
    tampered["baseline_main_sha256"] = _sha("changed-main")
    with pytest.raises(ContrastProtocolError, match="mismatch"):
        validate_contrast_protocol(tampered)

    reordered = {key: receipt[key] for key in reversed(list(receipt))}
    assert validate_contrast_protocol(reordered) == receipt


def test_builder_does_not_expose_authority_fields() -> None:
    receipt = build_contrast_protocol(_content())
    assert set(receipt) == set(_content()) | {"content_sha256"}
    assert not any("submit" in key or "quota" in key or "anchor" in key for key in receipt)
