from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from evaluation_v6_3_1.engine_patch import tree_sha256
from evaluation_v6_3_1.trace_source_inventory import (
    FAMILY_CARD_ZONE,
    FAMILY_HP_DAMAGE,
    FAMILY_RAW_MEMORY,
    FAMILY_RESULT,
    FAMILY_RNG,
    INVENTORY_FAMILIES,
    PINNED_OPENED_SOURCE_TREE_SHA256,
    TraceSourceInventoryError,
    _mask_cpp,
    _site_id,
    build_trace_source_inventory,
    validate_trace_source_inventory,
)


OPENED_ENGINE = Path(__file__).resolve().parents[1] / "references" / "ptcg_engine_20260701"


def _copy_opened_engine(tmp_path: Path) -> Path:
    destination = tmp_path / "opened-engine"
    shutil.copytree(OPENED_ENGINE, destination)
    return destination


def _inventory_wire() -> dict[str, object]:
    return build_trace_source_inventory(OPENED_ENGINE).canonical()


def _remove_site(wire: dict[str, object], predicate) -> None:
    sites = wire["sites"]
    assert isinstance(sites, list)
    original = len(sites)
    matching = [site for site in sites if predicate(site)]
    assert matching
    target_site_id = sorted(site["stable_site_id"] for site in matching)[0]
    wire["sites"] = [site for site in sites if site["stable_site_id"] != target_site_id]
    assert sum(site["stable_site_id"] == target_site_id for site in sites) == 1
    assert len(wire["sites"]) == original - 1


def test_pinned_inventory_is_deterministic_complete_by_family_and_zero_authority() -> None:
    first = build_trace_source_inventory(OPENED_ENGINE)
    second = build_trace_source_inventory(OPENED_ENGINE)

    assert tree_sha256(OPENED_ENGINE) == PINNED_OPENED_SOURCE_TREE_SHA256
    assert first.canonical() == second.canonical()
    assert {site.family for site in first.sites} == set(INVENTORY_FAMILIES)
    report = first.zero_authority_report()
    assert report["authority"] is False
    assert report["upload_authorized"] is False
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["holdout_access_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == []
    assert report["lexical_source_inventory_sufficient"] is False
    assert report["trace_completeness_claimed"] is False


def test_inventory_covers_the_requested_high_risk_source_sites() -> None:
    inventory = build_trace_source_inventory(OPENED_ENGINE)
    sites = inventory.sites

    assert any(site.family == FAMILY_HP_DAMAGE and "card.damage += damage" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_CARD_ZONE and "MoveListCard(" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_CARD_ZONE and "MoveListCardFront(" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_RESULT and "setResult(" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_RNG and "random_device" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_RNG and "shuffle(" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_RAW_MEMORY and "std::memset" in site.source_region_text for site in sites)
    assert any(site.family == FAMILY_RAW_MEMORY and "serialize(" in site.source_region_text for site in sites)


def test_stable_site_identity_is_bound_to_the_canonical_source_path() -> None:
    region = b"void f() { state.turn += 1; }"
    first, region_first = _site_id("State.cpp", "SEMANTIC_FIELD_DIRECT_WRITE", region)
    second, region_second = _site_id("copy/State.cpp", "SEMANTIC_FIELD_DIRECT_WRITE", region)

    assert first != second
    assert region_first == region_second


def test_cpp_masker_closes_only_the_matching_literal_delimiter() -> None:
    source = 'const char *s = "apostrophe \' // not a comment"; state.turn += 1;\n'
    masked = _mask_cpp(source)

    assert "not a comment" not in masked
    assert "state.turn += 1" in masked


@pytest.mark.parametrize(
    "predicate",
    (
        lambda site: site["family"] == FAMILY_HP_DAMAGE and "card.damage += damage" in site["source_region_text"],
        lambda site: site["family"] == FAMILY_CARD_ZONE and "MoveListCard(" in site["source_region_text"],
        lambda site: site["family"] == FAMILY_RESULT and "setResult(" in site["source_region_text"],
    ),
)
def test_omitted_direct_hp_move_list_or_terminal_site_fails_closed(predicate) -> None:
    wire = _inventory_wire()
    _remove_site(wire, predicate)

    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(wire, OPENED_ENGINE)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_UNCOVERED_SITE"


def test_added_random_device_is_rejected_as_pinned_source_drift(tmp_path: Path) -> None:
    source = _copy_opened_engine(tmp_path)
    api = source / "Api.h"
    api.write_text(api.read_text(encoding="utf-8-sig") + "\nstd::random_device added_entropy;\n", encoding="utf-8")

    with pytest.raises(TraceSourceInventoryError) as caught:
        build_trace_source_inventory(source)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_SOURCE_ROOT_DRIFT"


def test_raw_state_serialize_is_a_hazard_and_never_accepted_as_trace_authority() -> None:
    inventory = build_trace_source_inventory(OPENED_ENGINE)
    raw_sites = [site for site in inventory.sites if site.family == FAMILY_RAW_MEMORY]
    assert any("serialize(" in site.source_region_text for site in raw_sites)
    assert any("std::memset" in site.source_region_text for site in raw_sites)
    with pytest.raises(TraceSourceInventoryError) as caught:
        inventory.to_trace_coverage()
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_NOT_TRACE_COVERAGE"


def test_source_root_drift_is_rejected_even_when_the_caller_recomputes_a_root(tmp_path: Path) -> None:
    source = _copy_opened_engine(tmp_path)
    state = source / "State.h"
    state.write_text(state.read_text(encoding="utf-8-sig") + "\n// drift\n", encoding="utf-8")
    assert tree_sha256(source) != PINNED_OPENED_SOURCE_TREE_SHA256

    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(_inventory_wire(), source)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_SOURCE_ROOT_DRIFT"


def test_caller_authority_claim_is_rejected_even_with_a_recomputed_inventory_root() -> None:
    wire = _inventory_wire()
    authority = wire["authority"]
    assert isinstance(authority, dict)
    authority["upload_authorized"] = True

    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(wire, OPENED_ENGINE)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_AUTHORITY_CLAIM"


def test_duplicate_or_unclassified_rows_are_rejected() -> None:
    wire = _inventory_wire()
    sites = wire["sites"]
    assert isinstance(sites, list)
    sites.append(dict(sites[0]))
    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(wire, OPENED_ENGINE)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_DUPLICATE_SITE"

    wire = _inventory_wire()
    wire["sites"][0]["family"] = "UNCLASSIFIED"
    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(wire, OPENED_ENGINE)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE"


@pytest.mark.parametrize("malformed", (None, [], True, 17))
def test_malformed_site_identity_fails_closed_without_type_errors(malformed) -> None:
    wire = _inventory_wire()
    wire["sites"][0]["stable_site_id"] = malformed

    with pytest.raises(TraceSourceInventoryError) as caught:
        validate_trace_source_inventory(wire, OPENED_ENGINE)
    assert caught.value.code == "TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE"
