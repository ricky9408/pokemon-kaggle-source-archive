from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import secrets

import pytest

from evaluation_v5_1.recruitment import (
    AncestryError,
    IntakeError,
    LotteryError,
    PlanError,
    append_intake_entry,
    build_ancestry_dag,
    build_intake_ledger,
    build_recruitment_plan,
    close_intake,
    commit_recruitment_seed,
    derive_ancestry_families,
    derive_commit_reveal_seed,
    replay_roster_lottery,
    validate_ancestry_dag,
    validate_intake_ledger,
    validate_recruitment_plan,
    validate_roster_replay,
    verify_recruitment,
)


def _hash(value: object) -> str:
    return hashlib.sha256(str(value).encode("ascii")).hexdigest()


def _node(node_type: str, value: object, *, complete: bool = True) -> dict[str, object]:
    return {
        "node_type": node_type,
        "content_sha256": _hash(f"{node_type}:{value}"),
        "complete": complete,
        "derivation_evidence_sha256s": [_hash(f"evidence:{node_type}:{value}")],
    }


def _id(node: dict[str, object]) -> str:
    return f"{node['node_type']}:{node['content_sha256']}"


def _timestamp(stratum: int, offset: int) -> str:
    base = datetime(2026, 7, 15, tzinfo=timezone.utc)
    return (base + timedelta(days=stratum * 30 + offset + 1)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _dag_and_candidates(*, families: int = 20, archives_per_family: int = 2, merge_families: tuple[int, int] | None = None, incomplete: bool = False) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]], str, str]:
    dev_seed = secrets.token_hex(32)
    registrar_seed = secrets.token_hex(32)
    plan = build_recruitment_plan(
        dev_seed_commitment_sha256=commit_recruitment_seed(dev_seed),
        registrar_seed_commitment_sha256=commit_recruitment_seed(registrar_seed),
    )
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, str]] = []
    roots: list[str] = []
    terminals: list[str] = []
    source_by_family: dict[int, dict[str, object]] = {}
    candidates: list[dict[str, object]] = []
    for family in range(families):
        source = source_by_family.setdefault(family, _node("SOURCE_TREE", f"family-{family}"))
        derivation = _node("DERIVATION_EVIDENCE", f"family-{family}")
        nodes.extend([source, derivation])
        terminals.extend([_id(source), _id(derivation)])
        for member in range(archives_per_family):
            index = family * archives_per_family + member
            archive = _node("ARCHIVE", f"archive-{index}")
            policy = _node("POLICY", f"policy-{index}")
            nodes.extend([archive, policy])
            roots.append(archive["content_sha256"])  # type: ignore[arg-type]
            edges.append({"edge_type": "DERIVATION", "source": _id(archive), "target": _id(policy)})
            edges.extend(
                [
                    {"edge_type": "SOURCE_TREE", "source": _id(policy), "target": _id(source)},
                    {"edge_type": "DERIVATION", "source": _id(policy), "target": _id(derivation)},
                ]
            )
            if merge_families and family == merge_families[1]:
                other_source = source_by_family.setdefault(merge_families[0], _node("SOURCE_TREE", f"family-{merge_families[0]}"))
                edges.append({"edge_type": "SOURCE_TREE", "source": _id(policy), "target": _id(other_source)})
            candidates.append(
                {
                    "archive_sha256": archive["content_sha256"],
                    "deck_sha256": _hash(f"deck-{index}"),
                    "policy_sha256": policy["content_sha256"],
                    "intake_timestamp_utc": _timestamp(family // 5, family % 5 * 2 + member),
                }
            )
    if incomplete:
        # One reachable non-terminal node is incomplete, so UNKNOWN_FAMILY can
        # preserve it conservatively while EXCLUDE rejects it at intake.
        for node in nodes:
            if node["node_type"] == "POLICY":
                node["complete"] = False
                break
    dag = build_ancestry_dag(
        nodes=nodes,
        edges=sorted(edges, key=lambda edge: (edge["source"], edge["edge_type"], edge["target"])),
        cohort_archive_roots=roots,
        declared_terminal_roots=sorted(set(terminals)),
    )
    return plan, dag, candidates, dev_seed, registrar_seed


def test_plan_freezes_sol_population_strata_seed_and_exact_fields() -> None:
    dev_seed = secrets.token_hex(32)
    registrar_seed = secrets.token_hex(32)
    plan = build_recruitment_plan(
        dev_seed_commitment_sha256=commit_recruitment_seed(dev_seed),
        registrar_seed_commitment_sha256=commit_recruitment_seed(registrar_seed),
    )
    assert plan["protocol_id"] == "MCI_FAMILY_TRANSFER_V2"
    assert plan["target_population"] == {
        "selected_families": 20,
        "selected_archives": 20,
        "strata": 4,
        "families_per_stratum": 5,
        "archives_per_selected_family": 1,
        "activation_blocks": 4,
        "archives_per_activation_block": 5,
    }
    assert plan["allowed_eligibility_fields"] == sorted({"archive_sha256", "deck_sha256", "policy_sha256", "intake_timestamp_utc"})
    assert plan["strata"] == [{"stratum_id": f"stratum-{index}", "family_count_target": 5} for index in range(1, 5)]
    assert validate_recruitment_plan(plan) == plan
    changed = deepcopy(plan)
    changed["protocol_id"] = "MCI_TRANSFER_V1"
    changed["content_sha256"] = _hash("tampered")
    with pytest.raises(PlanError):
        validate_recruitment_plan(changed)
    with pytest.raises(TypeError):
        build_recruitment_plan()  # type: ignore[call-arg]
    assert inspect.signature(replay_roster_lottery).parameters["dev_seed"].default is inspect.Parameter.empty
    assert inspect.signature(replay_roster_lottery).parameters["registrar_seed"].default is inspect.Parameter.empty
    assert inspect.signature(validate_roster_replay).parameters["dev_seed"].default is inspect.Parameter.empty
    assert inspect.signature(validate_roster_replay).parameters["registrar_seed"].default is inspect.Parameter.empty


def test_global_dag_requires_terminal_closure_and_full_transitive_edges() -> None:
    plan, dag, candidates, _, _ = _dag_and_candidates(families=1, archives_per_family=1)
    assert validate_ancestry_dag(dag)["schema"] == "evaluation_v5_1_transitive_ancestry_dag_v1"

    parent = _node("POLICY", "unselected-parent")
    archive = _node("ARCHIVE", "direct-only-archive")
    source = _node("SOURCE_TREE", "direct-only-source")
    derivation = _node("DERIVATION_EVIDENCE", "direct-only-derivation")
    bad_edges = [
        {"edge_type": "DERIVATION", "source": _id(archive), "target": _id(parent)},
        {"edge_type": "SOURCE_TREE", "source": _id(archive), "target": _id(source)},
        {"edge_type": "DERIVATION", "source": _id(archive), "target": _id(derivation)},
    ]
    with pytest.raises(AncestryError, match="terminal|path|typed"):
        build_ancestry_dag(
            nodes=[archive, parent, source, derivation],
            edges=sorted(bad_edges, key=lambda edge: (edge["source"], edge["edge_type"], edge["target"])),
            cohort_archive_roots=[archive["content_sha256"]],
            declared_terminal_roots=[_id(source), _id(derivation)],
        )


def test_two_cohort_policies_merge_through_unselected_parent_and_grandparent() -> None:
    archive_a, policy_a = _node("ARCHIVE", "a"), _node("POLICY", "a-policy")
    archive_b, policy_b = _node("ARCHIVE", "b"), _node("POLICY", "b-policy")
    parent_a, parent_b = _node("POLICY", "parent-a"), _node("POLICY", "parent-b")
    grandparent = _node("POLICY", "shared-grandparent")
    source, derivation = _node("SOURCE_TREE", "shared-source"), _node("DERIVATION_EVIDENCE", "shared-derivation")
    nodes = [archive_a, policy_a, archive_b, policy_b, parent_a, parent_b, grandparent, source, derivation]
    edges = [
        {"edge_type": "DERIVATION", "source": _id(archive_a), "target": _id(policy_a)},
        {"edge_type": "DERIVATION", "source": _id(archive_b), "target": _id(policy_b)},
        {"edge_type": "PARENT", "source": _id(policy_a), "target": _id(parent_a)},
        {"edge_type": "PARENT", "source": _id(policy_b), "target": _id(parent_b)},
        {"edge_type": "PARENT", "source": _id(parent_a), "target": _id(grandparent)},
        {"edge_type": "PARENT", "source": _id(parent_b), "target": _id(grandparent)},
    ]
    for policy in (policy_a, policy_b, parent_a, parent_b, grandparent):
        edges.extend(
            [
                {"edge_type": "SOURCE_TREE", "source": _id(policy), "target": _id(source)},
                {"edge_type": "DERIVATION", "source": _id(policy), "target": _id(derivation)},
            ]
        )
    dag = build_ancestry_dag(
        nodes=nodes,
        edges=sorted(edges, key=lambda edge: (edge["source"], edge["edge_type"], edge["target"])),
        cohort_archive_roots=[archive_a["content_sha256"], archive_b["content_sha256"]],  # type: ignore[list-item]
        declared_terminal_roots=[_id(source), _id(derivation)],
    )
    entries = [
        {"decision": "ACCEPTED", "archive_sha256": archive_a["content_sha256"]},
        {"decision": "ACCEPTED", "archive_sha256": archive_b["content_sha256"]},
    ]
    report = derive_ancestry_families(entries, dag)
    assert len(set(report["archive_to_family"].values())) == 1


def test_cycle_and_changed_dag_fail_closed() -> None:
    a, b, archive, source, derivation = (_node("POLICY", "cycle-a"), _node("POLICY", "cycle-b"), _node("ARCHIVE", "cycle-archive"), _node("SOURCE_TREE", "cycle-source"), _node("DERIVATION_EVIDENCE", "cycle-derivation"))
    edges = [
        {"edge_type": "DERIVATION", "source": _id(archive), "target": _id(a)},
        {"edge_type": "PARENT", "source": _id(a), "target": _id(b)},
        {"edge_type": "PARENT", "source": _id(b), "target": _id(a)},
        {"edge_type": "SOURCE_TREE", "source": _id(a), "target": _id(source)},
        {"edge_type": "DERIVATION", "source": _id(a), "target": _id(derivation)},
        {"edge_type": "SOURCE_TREE", "source": _id(b), "target": _id(source)},
        {"edge_type": "DERIVATION", "source": _id(b), "target": _id(derivation)},
    ]
    with pytest.raises(AncestryError, match="cycle"):
        build_ancestry_dag(nodes=[a, b, archive, source, derivation], edges=sorted(edges, key=lambda edge: (edge["source"], edge["edge_type"], edge["target"])), cohort_archive_roots=[archive["content_sha256"]], declared_terminal_roots=[_id(source), _id(derivation)])  # type: ignore[list-item]


def test_intake_chronology_duplicates_outcome_fields_and_external_authority() -> None:
    plan, dag, candidates, _, _ = _dag_and_candidates()
    ledger = build_intake_ledger(plan, candidates, dag)
    closed = close_intake(plan, ledger, dag)
    assert closed["externally_exhaustive"] is False
    assert closed["external_registry_authority"] is False
    assert verify_recruitment(plan, closed, dag)["authority"] is False
    omitted = deepcopy(closed)
    omitted["entries"].pop(4)
    with pytest.raises(IntakeError, match="missing|hash chain|content"):
        validate_intake_ledger(plan, omitted, dag)

    duplicate = deepcopy(candidates[0])
    duplicate["intake_timestamp_utc"] = _timestamp(3, 29)
    rejected = append_intake_entry(plan, ledger, duplicate, dag)
    assert rejected["entries"][-1]["exclusion_code"] == "DUPLICATE_ARCHIVE"
    poisoned = deepcopy(candidates[0])
    poisoned["outcome"] = 1
    with pytest.raises(IntakeError, match="fields|forbidden"):
        build_intake_ledger(plan, [poisoned], dag)


def test_incomplete_ancestry_is_excluded_or_unknown_but_still_structurally_closed() -> None:
    plan, dag, candidates, dev_seed, registrar_seed = _dag_and_candidates(families=20, archives_per_family=1, incomplete=True)
    excluded_plan = build_recruitment_plan(
        incomplete_ancestry_policy="EXCLUDE",
        dev_seed_commitment_sha256=commit_recruitment_seed(dev_seed),
        registrar_seed_commitment_sha256=commit_recruitment_seed(registrar_seed),
    )
    excluded = build_intake_ledger(excluded_plan, candidates, dag)
    assert all(entry["exclusion_code"] == "INCOMPLETE_ANCESTRY" for entry in excluded["entries"])
    unknown = build_intake_ledger(plan, candidates, dag)
    report = derive_ancestry_families(unknown["entries"], dag)
    first_family = report["archive_to_family"][candidates[0]["archive_sha256"]]
    assert report["family_descriptors"][first_family]["kind"] == "UNKNOWN_INCOMPLETE_ANCESTRY"


def test_later_ancestry_merge_reduces_effective_n_below_twenty() -> None:
    plan, dag, candidates, _, _ = _dag_and_candidates(families=20, archives_per_family=1, merge_families=(0, 5))
    closed = close_intake(plan, build_intake_ledger(plan, candidates, dag), dag)
    with pytest.raises(IntakeError, match="fewer than 20"):
        verify_recruitment(plan, closed, dag)


def test_commit_reveal_and_exact_one_archive_per_family_four_by_five_activation() -> None:
    plan, dag, candidates, dev_seed, registrar_seed = _dag_and_candidates(families=20, archives_per_family=2)
    closed = close_intake(plan, build_intake_ledger(plan, candidates, dag), dag)
    assert commit_recruitment_seed(dev_seed) == plan["dev_seed_commitment_sha256"]
    assert len(derive_commit_reveal_seed(plan, dev_seed=dev_seed, registrar_seed=registrar_seed, future_beacon_sha256=_hash("beacon"))) == 64
    replay = replay_roster_lottery(plan, closed, dag, _hash("beacon"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    with pytest.raises(TypeError):
        replay_roster_lottery(plan, closed, dag, _hash("beacon"))  # type: ignore[call-arg]
    assert len(replay["selected_family_ids"]) == 20
    assert len(replay["selected_archive_sha256s"]) == 20
    assert len(set(replay["selected_archive_sha256s"])) == 20
    assert [len(block["archive_sha256s"]) for block in replay["activation_blocks"]] == [5, 5, 5, 5]
    assert [len(stratum["family_ids"]) for stratum in replay["ordered_strata"]] == [5, 5, 5, 5]
    assert [family for stratum in replay["ordered_strata"] for family in stratum["family_ids"]] == replay["ordered_family_ids"]
    assert validate_roster_replay(plan, closed, dag, replay, dev_seed=dev_seed, registrar_seed=registrar_seed) == replay
    with pytest.raises(TypeError):
        validate_roster_replay(plan, closed, dag, replay)  # type: ignore[call-arg]
    with pytest.raises(LotteryError, match="seed"):
        replay_roster_lottery(plan, closed, dag, _hash("beacon"), dev_seed="wrong", registrar_seed=registrar_seed)


def test_changed_beacon_and_beacon_round_change_replay() -> None:
    plan, dag, candidates, dev_seed, registrar_seed = _dag_and_candidates(families=20, archives_per_family=2)
    closed = close_intake(plan, build_intake_ledger(plan, candidates, dag), dag)
    first = replay_roster_lottery(plan, closed, dag, _hash("beacon-a"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    second = replay_roster_lottery(plan, closed, dag, _hash("beacon-b"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    assert first["content_sha256"] != second["content_sha256"]
    with pytest.raises(LotteryError, match="round or identity"):
        replay_roster_lottery(plan, closed, dag, _hash("beacon-a"), dev_seed=dev_seed, registrar_seed=registrar_seed, future_beacon_round="wrong")


def test_sparse_calendar_clustered_intake_uses_balanced_contiguous_family_strata() -> None:
    plan, dag, candidates, dev_seed, registrar_seed = _dag_and_candidates(families=20, archives_per_family=1)
    clustered = deepcopy(candidates)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    for index, candidate in enumerate(clustered, start=1):
        candidate["intake_timestamp_utc"] = (base + timedelta(microseconds=index)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    closed = close_intake(plan, build_intake_ledger(plan, clustered, dag), dag)
    result = verify_recruitment(plan, closed, dag)
    ordered = result["ordered_family_ids"]
    assert [len(stratum["family_ids"]) for stratum in result["ordered_strata"]] == [5, 5, 5, 5]
    assert [family for stratum in result["ordered_strata"] for family in stratum["family_ids"]] == ordered
    assert [result["family_earliest_registration_utc"][family] for family in ordered] == sorted(result["family_earliest_registration_utc"].values())
    replay = replay_roster_lottery(plan, closed, dag, _hash("clustered-beacon"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    assert replay["ordered_strata"] == result["ordered_strata"]


def test_changing_earliest_registration_rebinds_ordered_strata_and_replay() -> None:
    plan, dag, candidates, dev_seed, registrar_seed = _dag_and_candidates(families=20, archives_per_family=1)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    ordered_candidates = deepcopy(candidates)
    for index, candidate in enumerate(ordered_candidates, start=1):
        candidate["intake_timestamp_utc"] = (base + timedelta(days=index)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    first_closed = close_intake(plan, build_intake_ledger(plan, ordered_candidates, dag), dag)
    first = verify_recruitment(plan, first_closed, dag)

    changed_candidates = deepcopy(ordered_candidates)
    changed_candidates[0]["intake_timestamp_utc"] = (base + timedelta(days=40)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    changed_candidates.sort(key=lambda candidate: candidate["intake_timestamp_utc"])
    changed_closed = close_intake(plan, build_intake_ledger(plan, changed_candidates, dag), dag)
    changed = verify_recruitment(plan, changed_closed, dag)
    assert first["ordered_family_ids"] != changed["ordered_family_ids"]
    assert first["ordered_strata"] != changed["ordered_strata"]
    first_replay = replay_roster_lottery(plan, first_closed, dag, _hash("same-beacon"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    changed_replay = replay_roster_lottery(plan, changed_closed, dag, _hash("same-beacon"), dev_seed=dev_seed, registrar_seed=registrar_seed)
    assert first_replay["ordered_strata"] != changed_replay["ordered_strata"]
    assert first_replay["content_sha256"] != changed_replay["content_sha256"]
