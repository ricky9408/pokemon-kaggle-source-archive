from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from evaluation_v5_1.owned_pair_pilot import (
    COMPLETE,
    OwnedPairPilotError,
    add_canonical_root,
    canonical_json,
    validate_design_freeze,
    validate_rehearsal,
)
from evaluation_v5_1.canonical import canonical_sha256


H = lambda digit: digit * 64


def ts(minutes: int) -> str:
    return (datetime(2026, 7, 15, 1, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def make_artifacts() -> tuple[dict, dict, dict, dict]:
    pairs = [
        {
            "pair_id": "owned-a",
            "archive_identity": {"archive_id": "archive-a", "archive_label": "owned active archive A"},
            "submission_ref": "submission-ref-a",
            "submission_id": "submission-id-a",
            "archive_sha256": H("a"),
            "active": True,
        },
        {
            "pair_id": "owned-b",
            "archive_identity": {"archive_id": "archive-b", "archive_label": "owned active archive B"},
            "submission_ref": "submission-ref-b",
            "submission_id": "submission-id-b",
            "archive_sha256": H("b"),
            "active": True,
        },
    ]
    controls = [
        {
            "control_label": "claude_v103",
            "role": "claude",
            "archive_id": "control-claude",
            "archive_sha256": H("1"),
        },
        {
            "control_label": "grok_v123",
            "role": "grok",
            "archive_id": "control-grok",
            "archive_sha256": H("2"),
        },
        {
            "control_label": "top_a",
            "role": "top_tier",
            "archive_id": "control-top-a",
            "archive_sha256": H("3"),
        },
        {
            "control_label": "top_b",
            "role": "top_tier",
            "archive_id": "control-top-b",
            "archive_sha256": H("4"),
        },
    ]
    cells = []
    for pair_index, pair in enumerate(pairs):
        for control_index, control in enumerate(controls):
            for seat in (0, 1):
                seed = 1000
                cells.append(
                    {
                        "cell_id": f"{pair['pair_id']}-{control['control_label']}-{seat}",
                        "pair_id": pair["pair_id"],
                        "control_label": control["control_label"],
                        "control_role": control["role"],
                        "control_archive_sha256": control["archive_sha256"],
                        "seed": seed,
                        "seat": seat,
                    }
                )
    design = {
        "schema": "evaluation_v5_1_owned_pair_design_freeze_v1",
        "protocol_id": "EVALUATION_V5_1_OWNED_PAIR_PILOT_V1",
        "mode": "DEVELOPMENT_ONLY_ZERO_AUTHORITY",
        "design_frozen_at_utc": ts(0),
        "pre_registration_sha256": H("e"),
        "pairs": pairs,
        "controls": controls,
        "deterministic_engine": {"manifest_id": "engine-manifest-1", "manifest_sha256": H("c")},
        "evaluator_runner_sha256": H("d"),
        "schedule": {
            "seed_root_sha256": canonical_sha256(sorted({cell["seed"] for cell in cells})),
            "seats": [0, 1],
            "control_labels": [control["control_label"] for control in controls],
            "cells": cells,
        },
        "metrics": ["steps"],
        "quotas": {"local_cells_per_pair": 8, "hosted_future_episodes_per_pair": 2},
        "forbidden_hosted_fields": [
            "hosted_outcome", "hosted_rank", "hosted_score", "kaggle_rank", "kaggle_score",
            "leaderboard_rank", "leaderboard_score", "public_outcome", "public_rank", "public_score",
        ],
        "production_blockers": {
            "common_ancestry": {"terminal": True, "reason": "common ancestry is unresolved"},
            "external_collector_unavailable": {"terminal": True, "reason": "external collector is unavailable"},
            "only_two_units": {"terminal": True, "reason": "only two owned units are present"},
            "prior_hosted_history": {"terminal": True, "reason": "prior hosted history is not cleared"},
        },
    }
    design = add_canonical_root(design, "design_root_sha256")

    local_rows = []
    for index, cell in enumerate(cells):
        pair = next(item for item in pairs if item["pair_id"] == cell["pair_id"])
        local_rows.append(
            {
                "cell_id": cell["cell_id"],
                "pair_id": pair["pair_id"],
                "submission_ref": pair["submission_ref"],
                "submission_id": pair["submission_id"],
                "archive_sha256": pair["archive_sha256"],
                "control_label": cell["control_label"],
                "control_role": cell["control_role"],
                "control_archive_sha256": cell["control_archive_sha256"],
                "seed": cell["seed"],
                "seat": cell["seat"],
                "started_at_utc": ts(1),
                "completed_at_utc": ts(2 + index),
                "transcript_sha256": H("f"),
                "terminal_outcome": "WIN" if index % 2 else "LOSS",
                "error": None,
                "metrics": {"steps": 10 + index},
            }
        )
    local = add_canonical_root(
        {
            "schema": "evaluation_v5_1_owned_pair_local_result_v1",
            "protocol_id": "EVALUATION_V5_1_OWNED_PAIR_PILOT_V1",
            "mode": "DEVELOPMENT_ONLY_ZERO_AUTHORITY",
            "design_root_sha256": design["design_root_sha256"],
            "local_started_at_utc": ts(1),
            "local_completed_at_utc": ts(30),
            "reproducibility": {
                "primary_panel_sha256": H("5"),
                "repeat_panel_sha256": H("6"),
                "semantic_rows_sha256": H("7"),
                "semantic_reproduction_equal": True,
            },
            "rows": local_rows,
        },
        "local_result_root_sha256",
    )
    activation = add_canonical_root(
        {
            "schema": "evaluation_v5_1_owned_pair_activation_freeze_v1",
            "protocol_id": "EVALUATION_V5_1_OWNED_PAIR_PILOT_V1",
            "mode": "DEVELOPMENT_ONLY_ZERO_AUTHORITY",
            "design_root_sha256": design["design_root_sha256"],
            "local_result_root_sha256": local["local_result_root_sha256"],
            "activation_frozen_at_utc": ts(31),
            "t0_utc": ts(32),
        },
        "activation_root_sha256",
    )
    inventory = []
    for pair_index, pair in enumerate(pairs):
        for episode_index in range(3):
            minute = 33 + pair_index * 10 + episode_index
            inventory.append(
                {
                    "pair_id": pair["pair_id"],
                    "submission_ref": pair["submission_ref"],
                    "submission_id": pair["submission_id"],
                    "archive_sha256": pair["archive_sha256"],
                    "episode_id": f"episode-{pair['pair_id']}-{episode_index}",
                    "created_at_utc": ts(minute),
                    "started_at_utc": ts(minute + 1),
                    "ended_at_utc": ts(minute + 2),
                    "outcome": "WIN" if episode_index % 2 else "LOSS",
                    "seat": 0 if episode_index % 2 else 1,
                    "agent_status": "DONE",
                    "runtime_or_package_failure": False,
                    "source_sha256": H(str(7 + episode_index)),
                }
            )
    rows = [item for item in inventory if item["episode_id"].endswith("-0") or item["episode_id"].endswith("-1")]
    hosted = add_canonical_root(
        {
            "schema": "evaluation_v5_1_owned_pair_hosted_result_v1",
            "protocol_id": "EVALUATION_V5_1_OWNED_PAIR_PILOT_V1",
            "mode": "DEVELOPMENT_ONLY_ZERO_AUTHORITY",
            "design_root_sha256": design["design_root_sha256"],
            "activation_root_sha256": activation["activation_root_sha256"],
            "exhaustive_inventory": inventory,
            "exhaustive_inventory_root_sha256": canonical_sha256(inventory),
            "rows": rows,
        },
        "hosted_result_root_sha256",
    )
    return design, local, activation, hosted


def test_happy_structural_rehearsal_is_complete_but_zero_authority() -> None:
    receipt = validate_rehearsal(*make_artifacts())
    assert receipt["decision"] == COMPLETE
    assert receipt["authority"] is False
    assert receipt["candidate_development_authorized"] is False
    assert receipt["predictive_validity_authorized"] is False
    assert receipt["sealed_holdout_access"] is False
    assert receipt["holdout_access_authorized"] is False
    assert receipt["submission_authorized"] is False
    assert "SUBMIT_AUTHORIZED" not in canonical_json(receipt)


def test_phase_ordering_design_local_activation_t0_is_strict() -> None:
    design, local, activation, hosted = make_artifacts()
    bad_local = deepcopy(local)
    bad_local["local_started_at_utc"] = ts(0)
    bad_local = add_canonical_root(bad_local, "local_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="after design freeze"):
        validate_rehearsal(design, bad_local, activation, hosted)

    bad_activation = deepcopy(activation)
    bad_activation["activation_frozen_at_utc"] = ts(30)
    bad_activation = add_canonical_root(bad_activation, "activation_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="activation freeze"):
        validate_rehearsal(design, local, bad_activation, hosted)


@pytest.mark.parametrize("mutation", ["omit", "duplicate"])
def test_local_schedule_must_close_with_unique_cells(mutation: str) -> None:
    design, local, activation, hosted = make_artifacts()
    changed = deepcopy(local)
    if mutation == "omit":
        changed["rows"] = changed["rows"][:-1]
    else:
        changed["rows"][-1] = deepcopy(changed["rows"][0])
    changed = add_canonical_root(changed, "local_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="schedule|duplicate"):
        validate_rehearsal(design, changed, activation, hosted)


def test_archive_mismatch_is_rejected_in_local_and_hosted_receipts() -> None:
    design, local, activation, hosted = make_artifacts()
    bad_local = deepcopy(local)
    bad_local["rows"][0]["archive_sha256"] = H("9")
    bad_local = add_canonical_root(bad_local, "local_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="exact schedule identity"):
        validate_rehearsal(design, bad_local, activation, hosted)

    bad_hosted = deepcopy(hosted)
    bad_hosted["exhaustive_inventory"][0]["submission_id"] = "wrong-submission"
    bad_hosted["exhaustive_inventory_root_sha256"] = canonical_sha256(bad_hosted["exhaustive_inventory"])
    bad_hosted = add_canonical_root(bad_hosted, "hosted_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="exact archive identity"):
        validate_rehearsal(design, local, activation, bad_hosted)


def test_hosted_requires_literal_earliest_prefix_and_rejects_pre_t0() -> None:
    design, local, activation, hosted = make_artifacts()
    omitted_earliest = deepcopy(hosted)
    omitted_earliest["rows"] = [row for row in omitted_earliest["rows"] if not row["episode_id"].endswith("-0")]
    omitted_earliest = add_canonical_root(omitted_earliest, "hosted_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="earliest chronological prefix"):
        validate_rehearsal(design, local, activation, omitted_earliest)

    pre_t0 = deepcopy(hosted)
    pre_t0["exhaustive_inventory"][0]["created_at_utc"] = ts(30)
    pre_t0["exhaustive_inventory"][0]["started_at_utc"] = ts(31)
    pre_t0["exhaustive_inventory"][0]["ended_at_utc"] = ts(33)
    pre_t0["exhaustive_inventory_root_sha256"] = canonical_sha256(pre_t0["exhaustive_inventory"])
    pre_t0 = add_canonical_root(pre_t0, "hosted_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="pre-T0"):
        validate_rehearsal(design, local, activation, pre_t0)


def test_hosted_prefix_is_ordered_by_end_time_then_episode_id() -> None:
    design, local, activation, hosted = make_artifacts()
    changed = deepcopy(hosted)
    owned_a = [
        row for row in changed["exhaustive_inventory"] if row["pair_id"] == "owned-a"
    ]
    by_suffix = {row["episode_id"].rsplit("-", 1)[-1]: row for row in owned_a}
    by_suffix["0"]["ended_at_utc"] = ts(40)
    by_suffix["1"]["ended_at_utc"] = ts(38)
    by_suffix["2"]["ended_at_utc"] = ts(39)
    changed["exhaustive_inventory"] = sorted(
        changed["exhaustive_inventory"],
        key=lambda row: (row["ended_at_utc"], row["episode_id"]),
    )
    owned_b = [
        row
        for row in changed["exhaustive_inventory"]
        if row["pair_id"] == "owned-b"
    ][:2]
    changed["rows"] = [by_suffix["1"], by_suffix["2"], *owned_b]
    changed["exhaustive_inventory_root_sha256"] = canonical_sha256(
        changed["exhaustive_inventory"]
    )
    changed = add_canonical_root(changed, "hosted_result_root_sha256")
    assert validate_rehearsal(design, local, activation, changed)["decision"] == COMPLETE

    changed["rows"] = [by_suffix["0"], by_suffix["1"], *owned_b]
    changed = add_canonical_root(changed, "hosted_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="earliest chronological prefix"):
        validate_rehearsal(design, local, activation, changed)


def test_hosted_prefix_retains_draws_and_runtime_failures() -> None:
    design, local, activation, hosted = make_artifacts()
    changed = deepcopy(hosted)
    episode_id = changed["rows"][0]["episode_id"]
    for row in changed["exhaustive_inventory"]:
        if row["episode_id"] == episode_id:
            row["outcome"] = "DRAW"
            row["agent_status"] = "ERROR"
            row["runtime_or_package_failure"] = True
    for row in changed["rows"]:
        if row["episode_id"] == episode_id:
            row["outcome"] = "DRAW"
            row["agent_status"] = "ERROR"
            row["runtime_or_package_failure"] = True
    changed["exhaustive_inventory_root_sha256"] = canonical_sha256(
        changed["exhaustive_inventory"]
    )
    changed = add_canonical_root(changed, "hosted_result_root_sha256")

    receipt = validate_rehearsal(design, local, activation, changed)
    assert receipt["decision"] == COMPLETE


def test_design_requires_all_control_roles_and_unique_control_labels() -> None:
    design, _, _, _ = make_artifacts()
    missing_role = deepcopy(design)
    missing_role["controls"] = [
        control for control in missing_role["controls"] if control["role"] != "top_tier"
    ]
    retained = {control["control_label"] for control in missing_role["controls"]}
    missing_role["schedule"]["cells"] = [
        cell
        for cell in missing_role["schedule"]["cells"]
        if cell["control_label"] in retained
    ]
    missing_role["schedule"]["control_labels"] = sorted(retained)
    missing_role["schedule"]["seed_root_sha256"] = canonical_sha256(
        sorted({cell["seed"] for cell in missing_role["schedule"]["cells"]})
    )
    missing_role["quotas"]["local_cells_per_pair"] = 4
    missing_role = add_canonical_root(missing_role, "design_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="Claude, Grok, and top-tier"):
        validate_design_freeze(missing_role)

    duplicate_label = deepcopy(design)
    duplicate_label["controls"][1]["control_label"] = duplicate_label["controls"][0][
        "control_label"
    ]
    duplicate_label = add_canonical_root(duplicate_label, "design_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="sorted and unique"):
        validate_design_freeze(duplicate_label)


def test_design_requires_exact_preregistration_binding() -> None:
    design, _, _, _ = make_artifacts()
    missing = deepcopy(design)
    del missing["pre_registration_sha256"]
    missing = add_canonical_root(missing, "design_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="fields are not exact"):
        validate_design_freeze(missing)

    malformed = deepcopy(design)
    malformed["pre_registration_sha256"] = "ABC"
    malformed = add_canonical_root(malformed, "design_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="lowercase SHA-256"):
        validate_design_freeze(malformed)


@pytest.mark.parametrize("field", ["public_score", "public_rank", "hosted_score", "leaderboard_rank"])
def test_forbidden_public_fields_are_rejected(field: str) -> None:
    design, local, activation, hosted = make_artifacts()
    bad = deepcopy(hosted)
    bad[field] = "0"
    with pytest.raises(OwnedPairPilotError, match="forbidden public/hosted"):
        validate_rehearsal(design, local, activation, bad)


def test_sealed_holdout_reference_is_rejected() -> None:
    design, local, activation, hosted = make_artifacts()
    bad = deepcopy(hosted)
    bad["exhaustive_inventory"][0]["episode_id"] = "sealed-holdout-episode"
    with pytest.raises(OwnedPairPilotError, match="sealed/holdout"):
        validate_rehearsal(design, local, activation, bad)


def test_authority_is_non_bypassable_even_when_inputs_are_rehashed() -> None:
    design, local, activation, hosted = make_artifacts()
    bad_design = deepcopy(design)
    bad_design["mode"] = "SUBMIT_AUTHORIZED"
    bad_design = add_canonical_root(bad_design, "design_root_sha256")
    with pytest.raises(OwnedPairPilotError):
        validate_rehearsal(bad_design, local, activation, hosted)

    receipt = validate_rehearsal(design, local, activation, hosted)
    for key, value in receipt.items():
        if any(token in key for token in ("authority", "candidate", "holdout", "submission")):
            assert value is False


def test_no_floats_in_protocol_receipts() -> None:
    design, local, activation, hosted = make_artifacts()
    bad = deepcopy(local)
    bad["rows"][0]["metrics"]["runtime_ms"] = 1.5
    bad = add_canonical_root(bad, "local_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="float"):
        validate_rehearsal(design, bad, activation, hosted)


def test_local_requires_bound_exact_semantic_reproduction() -> None:
    design, local, activation, hosted = make_artifacts()
    bad = deepcopy(local)
    bad["reproducibility"]["semantic_reproduction_equal"] = False
    bad = add_canonical_root(bad, "local_result_root_sha256")
    with pytest.raises(OwnedPairPilotError, match="exact semantic reproduction"):
        validate_rehearsal(design, bad, activation, hosted)


def test_cli_json_round_trip_is_canonical(tmp_path, capsys) -> None:
    design, local, activation, hosted = make_artifacts()
    paths = {}
    for name, artifact in zip(("design", "local", "activation", "hosted"), (design, local, activation, hosted)):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        paths[name] = path
    from evaluation_v5_1.owned_pair_pilot import main

    assert main(["rehearsal", str(paths["design"]), "--local", str(paths["local"]), "--activation", str(paths["activation"]), "--hosted", str(paths["hosted"])]) == 0
    output = capsys.readouterr().out.strip()
    assert output == canonical_json(validate_rehearsal(design, local, activation, hosted))
