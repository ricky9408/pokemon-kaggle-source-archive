from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from evaluation_v4.design import (
    DesignError,
    SEED_COUNT,
    SEED_DERIVATION_ALGORITHM,
    build_design_manifest,
    canonical_sha256,
    derive_seeds,
    validate_design_manifest,
    write_design_manifest_once,
)


def _digest(index: int) -> str:
    return f"{index:064x}"


def _design() -> dict[str, object]:
    opponents = []
    layers = ("top", "mid", "low")
    families = ("control", "tempo", "spread", "toolbox")
    for index in range(12):
        opponents.append(
            {
                "opponent_id": f"opponent-{index:02d}",
                "content_sha256": _digest(index + 20),
                "family_id": families[index % len(families)],
                "rating_layer": layers[index % len(layers)],
                "weight": 1.0 / 12.0,
            }
        )
    return {
        "schema": "whole_policy_simulation_design_v1",
        "protocol_sha256": _digest(1),
        "compiler_code_sha256": _digest(2),
        "runner_code_sha256": _digest(3),
        "dependency_lock_sha256": _digest(4),
        "candidate_archive_sha256": _digest(5),
        "baseline_archive_sha256": _digest(6),
        "seed_beacon_sha256": _digest(7),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "engine_roster": [
            {"engine_id": "released", "binary_sha256": _digest(8)},
            {"engine_id": "source", "binary_sha256": _digest(9)},
        ],
        "opponent_roster": opponents,
        "state": "FROZEN",
    }


def test_frozen_outcome_free_design_has_exact_deterministic_seeds() -> None:
    manifest = build_design_manifest(_design())

    assert manifest["schema"] == "whole_policy_simulation_design_v1"
    assert manifest["seeds"] == derive_seeds(_digest(7))
    assert len(manifest["seeds"]) == SEED_COUNT
    assert all(isinstance(seed, int) and 0 <= seed < 2**63 for seed in manifest["seeds"])
    assert "outcome" not in manifest and "prediction" not in manifest
    assert "certification" not in manifest and "authorization" not in manifest
    assert validate_design_manifest(manifest) == manifest


def test_seed_derivation_matches_the_bound_algorithm() -> None:
    beacon = _digest(7)
    expected = [
        int.from_bytes(hashlib.sha256(f"{beacon}:{counter}".encode("ascii")).digest()[:8], "big")
        & ((1 << 63) - 1)
        for counter in range(16)
    ]
    assert derive_seeds(beacon) == expected


def test_arbitrary_supplied_seeds_and_unknown_fields_are_rejected() -> None:
    design = _design()
    design["seeds"] = [123]
    with pytest.raises(DesignError, match="fields must exactly"):
        build_design_manifest(design)

    design = _design()
    design["prediction"] = 1.0
    with pytest.raises(DesignError, match="fields must exactly"):
        build_design_manifest(design)

    manifest = build_design_manifest(_design())
    manifest["seeds"][0] = 123
    with pytest.raises(DesignError, match="exact deterministic"):
        validate_design_manifest(manifest)


def test_duplicate_hash_aliases_are_rejected() -> None:
    design = _design()
    design["engine_roster"][1]["binary_sha256"] = design["engine_roster"][0]["binary_sha256"]
    with pytest.raises(DesignError, match="duplicate engine binary"):
        build_design_manifest(design)

    design = _design()
    design["opponent_roster"][1]["content_sha256"] = design["opponent_roster"][0]["content_sha256"]
    with pytest.raises(DesignError, match="duplicate opponent content"):
        build_design_manifest(design)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda design: [row.__setitem__("family_id", "control") for row in design["opponent_roster"]], "four families"),
        (lambda design: [row.__setitem__("rating_layer", "top") for row in design["opponent_roster"]], "rating layer"),
        (lambda design: design["opponent_roster"][0].__setitem__("weight", 0.0), "positive number"),
        (lambda design: design["opponent_roster"][0].__setitem__("weight", float("nan")), "finite positive"),
        (lambda design: design["opponent_roster"][0].__setitem__("weight", 0.2), "sum to one"),
    ],
)
def test_missing_family_or_layer_support_and_malformed_weights_are_rejected(mutate: object, message: str) -> None:
    design = _design()
    mutate(design)  # type: ignore[operator]
    with pytest.raises(DesignError, match=message):
        build_design_manifest(design)


def test_candidate_and_baseline_must_differ() -> None:
    design = _design()
    design["baseline_archive_sha256"] = design["candidate_archive_sha256"]
    with pytest.raises(DesignError, match="must differ"):
        build_design_manifest(design)


def test_manifest_is_input_order_invariant_and_input_is_not_mutated() -> None:
    design = _design()
    before = deepcopy(design)
    reversed_design = deepcopy(design)
    reversed_design["engine_roster"].reverse()
    reversed_design["opponent_roster"].reverse()

    assert build_design_manifest(design) == build_design_manifest(reversed_design)
    assert design == before


def test_mutated_or_noncanonical_manifest_is_rejected_even_if_rehashed() -> None:
    manifest = build_design_manifest(_design())
    mutated = deepcopy(manifest)
    mutated["opponent_roster"][0]["family_id"] = "mutated"
    with pytest.raises(DesignError, match="content_sha256 mismatch"):
        validate_design_manifest(mutated)

    reordered = deepcopy(manifest)
    reordered["opponent_roster"].reverse()
    content = {key: value for key, value in reordered.items() if key != "content_sha256"}
    reordered["content_sha256"] = canonical_sha256(content)
    with pytest.raises(DesignError, match="canonically sorted"):
        validate_design_manifest(reordered)


def test_write_once_persists_canonical_manifest(tmp_path: object) -> None:
    manifest = build_design_manifest(_design())
    path = tmp_path / "nested" / "simulation-design.json"  # type: ignore[operator]

    assert write_design_manifest_once(path, manifest) == path
    assert json.loads(path.read_text(encoding="ascii")) == manifest
    with pytest.raises(FileExistsError):
        write_design_manifest_once(path, manifest)
