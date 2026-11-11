from __future__ import annotations

from dataclasses import replace

import pytest

import evaluation_v6_3_1.assignment as assignment


def _root(tag: str) -> str:
    return __import__("hashlib").sha256(tag.encode("ascii")).hexdigest()


def _units() -> tuple[assignment.IndexedUnit, ...]:
    interventions = ("i0", "i1", "i2", "i0", "i1", "i2", "i0", "i3", "i4", "i0", "i1", "i2", "i3", "i4", "i0", "i1")
    zero = assignment.ExactRational("0", "1")
    return tuple(
        assignment.IndexedUnit(
            index,
            assignment.UNIT_IDS[index],
            assignment.OfflineUnitCandidate(
                _root(f"archive-{index}"), f"source-{index}", f"lineage-{index}", f"development-{index}", interventions[index], assignment.FeaturePoint.make([zero] * 6, zero),
            ),
        )
        for index in range(16)
    )


def _record() -> assignment.FeasibleAssignmentRecord:
    return assignment.FeasibleAssignmentRecord(sum(1 << index for index in range(7)), 6, 15)


def _roots() -> dict[str, str]:
    return {name: _root(name) for name in ("population_root", "local_panel_root", "support_artifact_root", "assignment_protocol_root")}


def test_exact_partition_scenarios_and_intervention_constraints() -> None:
    record = _record()
    assert record.dev_indices == (0, 1, 2, 3, 4, 5)
    assert record.confirm_indices == tuple(range(7, 15))
    assert assignment.assignment_structurally_eligible(_units(), record)

    broken = list(_units())
    candidate = broken[7].candidate
    broken[7] = replace(broken[7], candidate=replace(candidate, source_component_id="source-0"))
    assert not assignment.assignment_structurally_eligible(tuple(broken), record)


def test_canonical_binary_order_length_duplicate_rejection_and_root_substitution() -> None:
    roots = _roots()
    first = _record()
    second = assignment.FeasibleAssignmentRecord(first.dev_pool_mask, 5, 15)
    ordered = tuple(sorted((first, second), key=lambda item: (item.dev_pool_mask, item.dev_reserve_index, item.confirm_reserve_index)))
    artifact = assignment.serialize_test_only_feasible_assignment_list_fixture(ordered, **roots)
    assert len(artifact.binary) == assignment.FAS_HEADER_BYTES + 2 * assignment.FAS_RECORD_BYTES
    assert assignment.parse_feasible_assignment_list(artifact.binary, **roots) == ordered
    with pytest.raises(assignment.AssignmentSupportError, match="canonical"):
        assignment.serialize_test_only_feasible_assignment_list_fixture((first, first), **roots)
    changed = dict(roots)
    changed["population_root"] = _root("other-population")
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.parse_feasible_assignment_list(artifact.binary, **changed)
    assert error.value.code == "FEASIBLE_LIST_ROOT_MISMATCH"


def test_no_feasible_assignment_and_live_composer_are_fail_closed() -> None:
    artifact = assignment.serialize_test_only_feasible_assignment_list_fixture((), **_roots())
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.select_offline_drand_assignment(artifact, future_round_commitment_root=_root("commit"), drand_chain_hash=_root("chain"), round_number=1, randomness=b"r", drand_signature=b"s")
    assert error.value.code == "FEASIBLE_LIST_CANONICALIZATION_FAILURE"
    with pytest.raises(ValueError, match="intentionally absent"):
        assignment.AuthenticatedAssignmentComposer()


def test_drand_selection_uses_canonical_record_and_independent_fisher_yates_orders() -> None:
    artifact = assignment.serialize_test_only_feasible_assignment_list_fixture((_record(),), **_roots())
    kwargs = {"future_round_commitment_root": _root("commit"), "drand_chain_hash": _root("chain"), "round_number": 7, "randomness": b"randomness", "drand_signature": b"signature"}
    first = assignment.select_test_only_drand_assignment_fixture(artifact, **kwargs)
    second = assignment.select_test_only_drand_assignment_fixture(artifact, **kwargs)
    assert first == second
    assert first.selected_index == 0
    assert sorted(first.dev_order) == list(assignment.UNIT_IDS[:6])
    assert sorted(first.confirm_order) == list(assignment.UNIT_IDS[7:15])
    assert first.dev_reserve == "U07"
    assert first.confirm_reserve == "U16"
    assert first.report["calibration_upload_authorized"] is False
    with pytest.raises(assignment.AssignmentSupportError):
        assignment.select_test_only_drand_assignment_fixture(replace(artifact), **kwargs)

    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.select_offline_drand_assignment(artifact, **kwargs)
    assert error.value.code == "FEASIBLE_LIST_CANONICALIZATION_FAILURE"

    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.select_test_only_drand_assignment_fixture(
            artifact,
            **{**kwargs, "round_number": 2**64},
        )
    assert error.value.code == "DRAND_RESULT_INVALID"


def test_feature_quantization_epsilon_and_support_threshold_boundaries() -> None:
    value = assignment.ExactRational("-9876543121", "80000000000")
    point = assignment.FeaturePoint.make([value] * 6, assignment.ExactRational("1", "1"))
    assert point.features[0] == assignment.ExactRational("-9876543121", "80000000000")
    assert point.display_features[0] == "-0.123456789012"
    assert point.x == point.features[0]
    assert point.canonical()["exact"]["F1"] == {
        "numerator": "-9876543121",
        "denominator": "80000000000",
    }
    assert assignment.EPSILON == __import__("decimal").Decimal("0.000000000001")
    assert assignment.EPSILON_RATIONAL == assignment.ExactRational("1", "1000000000000")
    relation = assignment.SupportRelation((0, 1, 2, 3, 4, 5), 6, True, 9499)
    assert not relation.passed
    assert replace(relation, bootstrap_pass_count=9500).passed
    assert not replace(relation, point_supported=False, bootstrap_pass_count=10_000).passed


def test_display_rounding_never_collapses_exact_support_operands() -> None:
    zero = assignment.ExactRational("0", "1")
    left = assignment.FeaturePoint.make([zero] * 6, zero)
    tiny = assignment.ExactRational("1", "2500000000000")
    right = assignment.FeaturePoint.make([tiny] * 5 + [zero], zero)
    assert left.display_features == right.display_features
    assert left.features != right.features
    assert left.canonical()["exact"] != right.canonical()["exact"]
    assert assignment._distance("F", left, right) > 0
    assert left.mpfr256_projection_sha256 != right.mpfr256_projection_sha256


def test_noncanonical_or_inexact_rational_inputs_fail_closed() -> None:
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.ExactRational("0", "2")
    assert error.value.code == "LOCAL_FEATURE_RATIONAL_NONCANONICAL"
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.FeaturePoint.make(["0"] * 6, "0")
    assert error.value.code == "LOCAL_FEATURE_EXACT_VALUE_MISSING"
    assert assignment.ExactRational.make(
        {"numerator": "-1", "denominator": "3"}
    ) == assignment.ExactRational("-1", "3")
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.ExactRational.make(__import__("decimal").Decimal("0.5"))
    assert error.value.code == "LOCAL_FEATURE_EXACT_VALUE_MISSING"


def test_assignment_feature_point_rejects_positive_f6() -> None:
    zero = assignment.ExactRational("0", "1")
    positive = assignment.ExactRational("1", "10")
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.FeaturePoint.make([zero] * 5 + [positive], zero)
    assert error.value.code == "LOCAL_FEATURE_BOOTSTRAP_INVALID"


def test_mpq_projection_rounds_once_for_greater_than_256_bit_operands() -> None:
    numerator = "3436863917022567287875100637396155292604864197398225685802962159534473738654662744643661375"
    denominator = "7575769280874492212550641729429623347156622092293734346785482562413024730144995151192805243"
    value = assignment.ExactRational(numerator, denominator)
    projected = assignment._project_mpfr(value)
    context = assignment.gmpy2.get_context().copy()
    context.precision = assignment.MPFR_PRECISION_BITS
    context.round = assignment.gmpy2.RoundToNearest
    with assignment.gmpy2.context(context):
        expected = assignment.gmpy2.mpfr(
            assignment.gmpy2.mpq(int(numerator), int(denominator))
        )
        double_rounded = assignment.gmpy2.mpfr(numerator) / assignment.gmpy2.mpfr(denominator)
    assert projected == expected
    assert projected != double_rounded


def test_bootstrap_rejection_and_determinism_contract() -> None:
    # 8-bit modulus 3 rejects 255 (limit 255), then accepts 5 -> 2.
    assert assignment.bounded_rejection_from_draws((255, 5), modulus=3, width=1) == (2, 1)
    with pytest.raises(assignment.AssignmentSupportError, match="ended"):
        assignment.bounded_rejection_from_draws((255,), modulus=3, width=1)
    first = assignment.generate_bootstrap_index_matrix(model_root=_root("model"), population_root=_root("population"), local_panel_root=_root("panel"))
    second = assignment.generate_bootstrap_index_matrix(model_root=_root("model"), population_root=_root("population"), local_panel_root=_root("panel"))
    assert first.packed == second.packed
    assert len(first.packed) == 10_000 * 4 * 300 * 2
    assert all(0 <= index < 300 for index in first.indices(0, 0))


def test_tensor_issuance_rejects_replace_and_object_mutation() -> None:
    candidates = tuple(item.candidate for item in _units())
    rows = {candidate.archive_sha256: tuple(candidate.point for _ in range(10_000)) for candidate in candidates}
    tensor = assignment.make_test_only_offline_feature_tensor_fixture(candidates, rows, model_root=_root("model"), population_root=_root("population"), local_panel_root=_root("panel"))
    assert assignment.validate_offline_feature_tensor(tensor) is tensor
    with pytest.raises(assignment.AssignmentSupportError):
        assignment.validate_offline_feature_tensor(replace(tensor))
    object.__setattr__(tensor, "bootstrap_root", _root("mutated"))
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.validate_offline_feature_tensor(tensor)
    assert error.value.code == "LOCAL_FEATURE_ROOT_INVALID"


def test_caller_supplied_components_and_bootstrap_cannot_build_feasible_list() -> None:
    candidates = tuple(item.candidate for item in _units())
    rows = {
        candidate.archive_sha256: tuple(candidate.point for _ in range(10_000))
        for candidate in candidates
    }
    tensor = assignment.make_test_only_offline_feature_tensor_fixture(
        candidates,
        rows,
        model_root=_root("model"),
        population_root=_root("population"),
        local_panel_root=_root("panel"),
    )
    assert tensor.component_derivation_state == assignment.TEST_ONLY_COMPONENT_PROVENANCE
    assert tensor.bootstrap_derivation_state == assignment.TEST_ONLY_BOOTSTRAP_DERIVATION
    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.build_offline_feasible_assignment_list(
            tensor,
            None,  # type: ignore[arg-type]
            assignment_protocol_root=_root("assignment-protocol"),
        )
    assert error.value.code == "POPULATION_COMPONENT_CONSTRAINT_FAILURE"

    with pytest.raises(assignment.AssignmentSupportError) as error:
        assignment.make_offline_feature_tensor(  # type: ignore[attr-defined]
            candidates,
            rows,
            model_root=_root("model"),
            population_root=_root("population"),
            local_panel_root=_root("panel"),
        )
    assert error.value.code == "LOCAL_FEATURE_BOOTSTRAP_INVALID"


def test_support_lookup_root_mutation_is_rejected() -> None:
    candidates = tuple(item.candidate for item in _units())
    rows = {
        candidate.archive_sha256: tuple(candidate.point for _ in range(10_000))
        for candidate in candidates
    }
    tensor = assignment.make_test_only_offline_feature_tensor_fixture(
        candidates,
        rows,
        model_root=_root("model"),
        population_root=_root("population"),
        local_panel_root=_root("panel"),
    )
    lookup = assignment.precompute_support_lookup(tensor, ((0, 1, 2, 3, 4, 5),))
    object.__setattr__(lookup, "root", _root("substituted-support-root"))
    with pytest.raises(assignment.AssignmentSupportError) as error:
        lookup.relation((0, 1, 2, 3, 4, 5), 6)
    assert error.value.code == "SUPPORT_RECOMPUTATION_DIVERGENCE"


def test_every_public_result_is_explicitly_offline_and_zero_authority() -> None:
    report = assignment.offline_assignment_result(state="Support", detail="fixture")
    assert report["state"] == "OfflineSupportCandidate"
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == []
    assert report["calibration_slots_remaining"] == 16
    assert report["production_slots_remaining"] == 1
