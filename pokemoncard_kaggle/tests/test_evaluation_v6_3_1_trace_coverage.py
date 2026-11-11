from __future__ import annotations

import copy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.trace_coverage import (
    IPC_SITE_MANIFEST,
    MUTATION_SITE_MANIFEST,
    REQUIRED_MANIFEST_FAMILIES,
    RNG_SITE_MANIFEST,
    SEMANTIC_FIELD_MANIFEST,
    SELECTION_SITE_MANIFEST,
    TERMINAL_SITE_MANIFEST,
    TRACE_HOOK_MANIFEST,
    TraceCoverageError,
    build_coverage_manifest,
    validate_coverage_manifest,
)


SOURCE_ROOT = sha256(b"fixture-source-root").hexdigest()
REVIEWER_A = "audit-a"
REVIEWER_B = "audit-b"


def _row(
    path: str,
    stable_id: str,
    family: str,
    classification: str,
    hook: str,
    primitive: str,
) -> dict[str, str]:
    return {
        "source_root_sha256": SOURCE_ROOT,
        "canonical_relative_path": path,
        "stable_site_id": stable_id,
        "family": family,
        "classification": classification,
        "authorized_primitive_id": primitive,
        "trace_hook_id": hook,
        "classification_a": classification,
        "classification_b": classification,
        "reviewer_a_id": REVIEWER_A,
        "reviewer_b_id": REVIEWER_B,
    }


def _fixture_rows() -> dict[str, list[dict[str, str]]]:
    return {
        SEMANTIC_FIELD_MANIFEST: [
            _row("engine/State.h", "field.hp", "STATE_FIELD", "SEMANTIC_SERIALIZED", "hook.semantic", "V631_CANONICAL_FIELD_SERIALIZER"),
            _row("engine/State.h", "field.zone", "STATE_FIELD", "SEMANTIC_SERIALIZED", "hook.semantic", "V631_CANONICAL_FIELD_SERIALIZER"),
        ],
        MUTATION_SITE_MANIFEST: [
            _row("engine/HP.cpp", "mutation.hp", "HP", "AUTHORITATIVE_MUTATION", "hook.mutation", "V631_MUTATE_HP"),
            _row("engine/Zone.cpp", "mutation.zone", "ZONE", "AUTHORITATIVE_MUTATION", "hook.mutation", "V631_MUTATE_ZONE"),
        ],
        RNG_SITE_MANIFEST: [
            _row("engine/Rng.cpp", "rng.draw", "RNG_DRAW", "RECORDED_DRAW", "hook.rng", "V631_RECORDED_RNG_DRAW"),
            _row("engine/Rng.cpp", "rng.permutation", "RNG_PERMUTATION", "RECORDED_PERMUTATION", "hook.rng", "V631_RECORDED_RNG_PERMUTATION"),
        ],
        SELECTION_SITE_MANIFEST: [
            _row("engine/Select.cpp", "selection.choice", "SELECTION_CHOICE", "SELECTION_CHOICE", "hook.selection", "V631_SELECTION_CHOICE"),
            _row("engine/Select.cpp", "selection.options", "LEGAL_OPTIONS", "LEGAL_OPTION_SET", "hook.selection", "V631_LEGAL_OPTION_SET"),
        ],
        IPC_SITE_MANIFEST: [
            _row("engine/Api.cpp", "ipc.request", "AGENT_REQUEST", "AGENT_IPC", "hook.ipc", "V631_AGENT_IPC_REQUEST"),
            _row("engine/Api.cpp", "ipc.response", "AGENT_RESPONSE", "AGENT_IPC", "hook.ipc", "V631_AGENT_IPC_RESPONSE"),
        ],
        TERMINAL_SITE_MANIFEST: [
            _row("engine/Terminal.cpp", "terminal.result", "TERMINAL_RESULT", "TERMINAL_TRANSITION", "hook.terminal", "V631_TERMINAL_RESULT"),
            _row("engine/Terminal.cpp", "terminal.state", "TERMINAL_STATE", "TERMINAL_TRANSITION", "hook.terminal", "V631_TERMINAL_STATE"),
        ],
        TRACE_HOOK_MANIFEST: [
            _row("trace/Hooks.cpp", "hook.ipc-site", "IPC", "IPC_HOOK", "hook.ipc", "V631_TRACE_HOOK"),
            _row("trace/Hooks.cpp", "hook.mutation-site", "MUTATION", "MUTATION_HOOK", "hook.mutation", "V631_TRACE_HOOK"),
            _row("trace/Hooks.cpp", "hook.rng-site", "RNG", "RNG_HOOK", "hook.rng", "V631_TRACE_HOOK"),
            _row("trace/Hooks.cpp", "hook.selection-site", "SELECTION", "SELECTION_HOOK", "hook.selection", "V631_TRACE_HOOK"),
            _row("trace/Hooks.cpp", "hook.semantic-site", "CHECKPOINT", "CHECKPOINT_HOOK", "hook.semantic", "V631_TRACE_HOOK"),
            _row("trace/Hooks.cpp", "hook.terminal-site", "TERMINAL", "TERMINAL_HOOK", "hook.terminal", "V631_TRACE_HOOK"),
        ],
    }


def _manifest() -> dict[str, object]:
    result = build_coverage_manifest(SOURCE_ROOT, _fixture_rows())
    return result.as_dict()


def _rehash(wire: dict[str, object]) -> dict[str, object]:
    payload = {key: wire[key] for key in ("schema", "mode", "source_root_sha256", "required_site_ids", "manifests", "authority")}
    wire["coverage_manifest_root_sha256"] = canonical_sha256(payload)
    return wire


def test_positive_fixture_is_rooted_sorted_and_zero_authority() -> None:
    wire = _manifest()
    checked = validate_coverage_manifest(wire, expected_source_root_sha256=SOURCE_ROOT)

    assert checked.root_sha256 == wire["coverage_manifest_root_sha256"]
    assert tuple(checked.manifests) == REQUIRED_MANIFEST_FAMILIES
    assert checked.zero_authority_report()["authority"] is False
    assert checked.zero_authority_report()["upload_authorized"] is False
    assert checked.zero_authority_report()["holdout_access_authorized"] is False
    assert checked.zero_authority_report()["campaign_authorized"] is False
    assert checked.zero_authority_report()["agent_modification_authorized"] is False
    assert checked.zero_authority_report()["permits"] == []


def test_manifest_root_is_deterministic_and_round_trips() -> None:
    first = _manifest()
    second = _manifest()
    assert first == second
    assert validate_coverage_manifest(first).as_dict() == first


def test_inventory_id_order_is_independent_from_canonical_source_order() -> None:
    rows = _fixture_rows()
    rows[SEMANTIC_FIELD_MANIFEST] = [
        _row("engine/AState.h", "field.zeta", "STATE_FIELD", "SEMANTIC_SERIALIZED", "hook.semantic", "V631_CANONICAL_FIELD_SERIALIZER"),
        _row("engine/ZState.h", "field.alpha", "STATE_FIELD", "SEMANTIC_SERIALIZED", "hook.semantic", "V631_CANONICAL_FIELD_SERIALIZER"),
    ]
    required = {
        family: sorted(row["stable_site_id"] for row in family_rows)
        for family, family_rows in rows.items()
    }

    checked = build_coverage_manifest(
        SOURCE_ROOT,
        rows,
        required_site_ids=required,
    )

    assert tuple(entry.stable_site_id for entry in checked.manifests[SEMANTIC_FIELD_MANIFEST]) == (
        "field.zeta",
        "field.alpha",
    )
    assert checked.required_site_ids[SEMANTIC_FIELD_MANIFEST] == (
        "field.alpha",
        "field.zeta",
    )


@pytest.mark.parametrize(
    ("manifest_family", "stable_site_id"),
    (
        (MUTATION_SITE_MANIFEST, "mutation.hp"),
        (MUTATION_SITE_MANIFEST, "mutation.zone"),
        (RNG_SITE_MANIFEST, "rng.draw"),
        (SELECTION_SITE_MANIFEST, "selection.choice"),
        (IPC_SITE_MANIFEST, "ipc.request"),
        (TERMINAL_SITE_MANIFEST, "terminal.result"),
    ),
)
def test_deliberate_unhooked_source_site_fails_closed(manifest_family: str, stable_site_id: str) -> None:
    wire = _manifest()
    rows = wire["manifests"][manifest_family]
    assert isinstance(rows, list)
    wire["manifests"][manifest_family] = [row for row in rows if row["stable_site_id"] != stable_site_id]
    _rehash(wire)

    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire)
    assert caught.value.code in {"TRACE_COVERAGE_UNCOVERED_SITE", "TRACE_COVERAGE_MANIFEST_FAMILY_MISSING"}


def test_missing_manifest_family_is_rejected() -> None:
    wire = _manifest()
    del wire["manifests"][RNG_SITE_MANIFEST]
    _rehash(wire)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire)
    assert caught.value.code == "TRACE_COVERAGE_MANIFEST_FAMILY_MISSING"


def test_unknown_semantic_field_and_entropy_classifications_are_rejected() -> None:
    for family, stable_id, classification in (
        (SEMANTIC_FIELD_MANIFEST, "field.hp", "UNKNOWN"),
        (RNG_SITE_MANIFEST, "rng.draw", "UNCLASSIFIED"),
    ):
        wire = _manifest()
        row = next(row for row in wire["manifests"][family] if row["stable_site_id"] == stable_id)
        row["classification"] = classification
        row["classification_a"] = classification
        row["classification_b"] = classification
        _rehash(wire)
        with pytest.raises(TraceCoverageError) as caught:
            validate_coverage_manifest(wire)
        assert caught.value.code == "TRACE_COVERAGE_UNCLASSIFIED"


@pytest.mark.parametrize("classification", ["RAW_MEMORY", "POINTER_VALUE", "LOCALE_DEPENDENT", "UNORDERED_SERIALIZATION"])
def test_prohibited_serialization_classification_is_rejected(classification: str) -> None:
    wire = _manifest()
    row = wire["manifests"][SEMANTIC_FIELD_MANIFEST][0]
    row["classification"] = classification
    row["classification_a"] = classification
    row["classification_b"] = classification
    _rehash(wire)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire)
    assert caught.value.code in {"TRACE_COVERAGE_UNCLASSIFIED", "TRACE_COVERAGE_PROHIBITED_SERIALIZATION"}


def test_rejected_hazard_can_be_named_without_authorizing_it() -> None:
    rows = _fixture_rows()
    rows[RNG_SITE_MANIFEST].append(
        _row(
            "engine/Game.cpp",
            "entropy.wall_clock",
            "RNG_ENTROPY",
            "REJECTED_ENTROPY",
            "hook.rng",
            "V631_NO_WALL_CLOCK_ENTROPY",
        )
    )
    rows[RNG_SITE_MANIFEST].sort(key=lambda row: (row["canonical_relative_path"], row["stable_site_id"]))
    required = {
        family: sorted(row["stable_site_id"] for row in family_rows)
        for family, family_rows in rows.items()
    }

    checked = build_coverage_manifest(SOURCE_ROOT, rows, required_site_ids=required)

    assert "entropy.wall_clock" in checked.required_site_ids[RNG_SITE_MANIFEST]


def test_duplicate_site_and_noncanonical_order_are_rejected() -> None:
    duplicate = _manifest()
    duplicate["manifests"][SEMANTIC_FIELD_MANIFEST][1]["stable_site_id"] = "field.hp"
    duplicate["required_site_ids"][SEMANTIC_FIELD_MANIFEST][1] = "field.hp"
    _rehash(duplicate)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(duplicate)
    assert caught.value.code in {"TRACE_COVERAGE_DUPLICATE", "TRACE_COVERAGE_ORDER_INVALID"}

    unordered = _manifest()
    unordered["manifests"][TRACE_HOOK_MANIFEST].reverse()
    _rehash(unordered)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(unordered)
    assert caught.value.code == "TRACE_COVERAGE_ORDER_INVALID"


def test_stale_source_or_content_root_is_rejected() -> None:
    wire = _manifest()
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire, expected_source_root_sha256=sha256(b"different-source").hexdigest())
    assert caught.value.code == "TRACE_COVERAGE_ROOT_STALE"

    changed = _manifest()
    changed["manifests"][IPC_SITE_MANIFEST][0]["authorized_primitive_id"] = "V631_AGENT_IPC_REQUEST_CHANGED"
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(changed)
    assert caught.value.code == "TRACE_COVERAGE_ROOT_STALE"


def test_caller_authority_claim_is_rejected_even_with_recomputed_root() -> None:
    wire = _manifest()
    wire["authority"]["upload_authorized"] = True
    _rehash(wire)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire)
    assert caught.value.code == "TRACE_COVERAGE_AUTHORITY_CLAIM"


def test_unhooked_reference_and_noncanonical_path_are_rejected() -> None:
    unhooked = _manifest()
    unhooked["manifests"][MUTATION_SITE_MANIFEST][0]["trace_hook_id"] = "hook.missing"
    _rehash(unhooked)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(unhooked)
    assert caught.value.code == "TRACE_COVERAGE_UNHOOKED_SITE"

    bad_path = _manifest()
    bad_path["manifests"][TERMINAL_SITE_MANIFEST][0]["canonical_relative_path"] = "../Terminal.cpp"
    _rehash(bad_path)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(bad_path)
    assert caught.value.code == "TRACE_COVERAGE_ENTRY_INVALID"


@pytest.mark.parametrize("field", ["authorized_primitive_id", "trace_hook_id"])
def test_unknown_primitive_or_hook_binding_is_rejected(field: str) -> None:
    wire = _manifest()
    wire["manifests"][MUTATION_SITE_MANIFEST][0][field] = "UNKNOWN"
    _rehash(wire)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(wire)
    assert caught.value.code == "TRACE_COVERAGE_UNCLASSIFIED"


def test_reviewer_disagreement_and_shared_reviewer_are_rejected() -> None:
    disagreement = _manifest()
    disagreement["manifests"][SELECTION_SITE_MANIFEST][0]["classification_b"] = "LEGAL_OPTION_SET"
    _rehash(disagreement)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(disagreement)
    assert caught.value.code == "TRACE_COVERAGE_REVIEW_DISAGREEMENT"

    shared = _manifest()
    shared["manifests"][IPC_SITE_MANIFEST][0]["reviewer_b_id"] = REVIEWER_A
    _rehash(shared)
    with pytest.raises(TraceCoverageError) as caught:
        validate_coverage_manifest(shared)
    assert caught.value.code == "TRACE_COVERAGE_REVIEW_NOT_INDEPENDENT"


def test_validation_does_not_mutate_caller_fixture() -> None:
    wire = _manifest()
    original = copy.deepcopy(wire)
    validate_coverage_manifest(wire)
    assert wire == original
