from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import math

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.ancestry import ANCESTRY_MANIFEST_SCHEMA, ANCESTRY_PROTOCOL_ID, audit_external_confirmatory_ancestry, canonical_unsigned_manifest_bytes
from evaluation_v5.binding import binding_sha256
from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.charter import FEATURE_NAMES, build_charter, charter_sha256
from evaluation_v5.cohort import OBSERVATION_LOG_SCHEMA, append_registration, build_archive_registration, build_outcome_observation, new_registry, validate_observation_log
from evaluation_v5.engine_capabilities import CAPABILITY_NAMES, ENGINE_CAPABILITY_MANIFEST_SCHEMA, HASH_NAMES, REQUIRED_BACKENDS, build_engine_capability_manifest
from evaluation_v5.firewall import ArchiveRecord, EXTERNAL_CONFIRMATORY, build_firewall
from evaluation_v5.gates import PREDECLARED_MIN_TESTED_CALLS, build_campaign, build_model_input_record, build_operational_safety_evidence, prevalidation_gate
from evaluation_v5.model import MODEL_SCHEMA, build_prediction_manifest, build_prediction_rows

ROOT = Path(__file__).parents[1]
BINDING = json.loads((ROOT / "strategy/evaluation_v5_architecture_binding_20260713.json").read_text())
BASE = datetime(2026, 7, 14, tzinfo=timezone.utc)


def _utc(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _gate_hash() -> str:
    return hashlib.sha256((ROOT / "evaluation_v5/gates.py").read_bytes()).hexdigest()


def _manifest(kind: str, created: str, *, epsilon: float = 0.001, comparator_nonnull: bool = False):
    common = {
        "schema": MODEL_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "feature_names": list(FEATURE_NAMES),
        "standardization_means": {name: 0.5 for name in FEATURE_NAMES},
        "standardization_scales": {name: 1.0 for name in FEATURE_NAMES},
        "intercept": math.log((0.85 if kind == "MCI" else 0.55) / (0.15 if kind == "MCI" else 0.45)),
        "mci_slope": 0.1 if kind == "MCI" else 0.0,
        "era_effects": {"post_freeze": 0.0},
        "seat_effects": {"0": 0.0, "1": 0.0},
        "opponent_rating_knots": [0.0, 3000.0],
        "opponent_rating_values": [0.0, 0.0],
        "rating_interpolation": "piecewise_linear_clamp",
        "probability_epsilon": epsilon,
        "model_kind": kind,
        "development_evidence_sha256": "a" * 64,
        "executable_sha256": "b" * 64,
        "created_at_utc": created,
    }
    if kind == "MCI":
        common.update({"feature_weights": {name: 1 / 6 for name in FEATURE_NAMES}, "comparator_identity": None, "comparator_input_key": None, "comparator_input_mean": None, "comparator_input_scale": None, "comparator_slope": None, "comparator_null_value": None, "comparator_missing_behavior": "NOT_APPLICABLE"})
    elif comparator_nonnull:
        common.update({"feature_weights": {name: 0.0 for name in FEATURE_NAMES}, "comparator_identity": "raw local win-rate model", "comparator_input_key": "raw_local_win_rate", "comparator_input_mean": 0.5, "comparator_input_scale": 1.0, "comparator_slope": 0.1, "comparator_null_value": 0.5, "comparator_missing_behavior": "USE_FROZEN_NULL_VALUE"})
    else:
        common.update({"feature_weights": {name: 0.0 for name in FEATURE_NAMES}, "comparator_identity": "nuisance-only null model", "comparator_input_key": None, "comparator_input_mean": None, "comparator_input_scale": None, "comparator_slope": None, "comparator_null_value": None, "comparator_missing_behavior": "NUISANCE_ONLY"})
    return build_prediction_manifest(common)


def _engine_manifest(*, feasible: bool = True, salt: int = 0):
    backends = {}
    for backend_index, backend_name in enumerate(REQUIRED_BACKENDS):
        fields = {name: f"{backend_index + index + 1 + salt:064x}" for index, name in enumerate(HASH_NAMES)}
        fields.update({name: feasible for name in CAPABILITY_NAMES})
        fields["capability_evidence_sha256"] = {name: f"{backend_index + index + 100 + salt:064x}" for index, name in enumerate(CAPABILITY_NAMES)} if feasible else {}
        backends[backend_name] = fields
    return build_engine_capability_manifest({"schema": ENGINE_CAPABILITY_MANIFEST_SCHEMA, "protocol_id": "MCI_TRANSFER_V1", "backends": backends})


def _ancestry(archive_count: int, family_count: int) -> tuple[dict[str, object], str, dict[str, object]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
    public_key_hex = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    records = []
    for archive_index in range(archive_count):
        family_index = archive_index % family_count if archive_index < 30 else family_count + archive_index - 30
        records.append({"archive_sha256": f"{archive_index + 1:064x}", "policy_sha256": f"{archive_index + 201:064x}", "source_tree_sha256": f"{family_index + 1001:064x}", "direct_parent_policy_sha256s": [], "teacher_checkpoint_sha256s": [], "declared_provenance_evidence_sha256s": [f"{family_index + 2001:064x}"], "ancestry_complete": True, "review_timestamp_utc": _utc(-100)})
    unsigned = {"schema": ANCESTRY_MANIFEST_SCHEMA, "protocol_id": ANCESTRY_PROTOCOL_ID, "records": records}
    manifest = {**unsigned, "auditor_signature_ed25519": private_key.sign(canonical_unsigned_manifest_bytes(unsigned)).hex()}
    audit = audit_external_confirmatory_ancestry(manifest, pinned_public_key_hex=public_key_hex)
    return manifest, public_key_hex, audit


def _evidence(*, complete_archives: int = 30, archive_count: int = 30, family_count: int = 15, post_deadline: bool = False, input_minutes: int = 10, registration_minutes: int = 100, comparator_nonnull: bool = False, epsilon: float = 0.001, comparator_epsilon: float | None = None, mci_minutes: int = -20, comparator_minutes: int = -19) -> dict[str, object]:
    mci = _manifest("MCI", _utc(mci_minutes), epsilon=epsilon)
    comparator = _manifest("FROZEN_COMPARATOR", _utc(comparator_minutes), epsilon=epsilon if comparator_epsilon is None else comparator_epsilon, comparator_nonnull=comparator_nonnull)
    engine = _engine_manifest()
    ancestry_manifest, ancestry_key, ancestry_audit = _ancestry(archive_count, family_count)
    campaign = build_campaign(
        campaign_id="campaign-v5",
        registration_opened_at_utc=_utc(0),
        charter_sha256=charter_sha256(build_charter()),
        architecture_binding_sha256=binding_sha256(BINDING),
        analysis_executable_sha256=_gate_hash(),
        ancestry_auditor_public_key_sha256=ancestry_audit["auditor_public_key_sha256"],
        ancestry_manifest_sha256=ancestry_audit["manifest_sha256"],
        engine_capability_manifest_sha256=engine.manifest_sha256,
        engine_evidence_manifest_sha256="8" * 64,
        engine_evidence_signer_public_key_sha256="9" * 64,
        host_evidence_signer_public_key_sha256="c" * 64,
        safety_evidence_signer_public_key_sha256="d" * 64,
        provenance_evidence_signer_public_key_sha256="e" * 64,
        trust_roots_snapshot_sha256="f" * 64,
        implementation_binding_sha256="a" * 64,
        custody_ca_file_sha256="b" * 64,
        custody_tsa_policy_oid="1.2.3.4",
        mci_manifest_sha256=mci.manifest_sha256,
        comparator_manifest_sha256=comparator.manifest_sha256,
    )
    registry = new_registry()
    observation_records: list[dict[str, object]] = []
    observation_chain_hashes: list[str] = []
    model_inputs: list[dict[str, object]] = []
    firewall_records: list[ArchiveRecord] = []
    archive_hashes: list[str] = []
    for archive_index in range(archive_count):
        archive = f"{archive_index + 1:064x}"
        archive_hashes.append(archive)
        comparator_inputs = {"raw_local_win_rate": 0.9} if comparator_nonnull else {}
        if comparator_nonnull and archive_index == 0:
            comparator_inputs = {"raw_local_win_rate": None}
        model_input = build_model_input_record(archive_sha256=archive, campaign_sha256=campaign["campaign_sha256"], mci_manifest_sha256=mci.manifest_sha256, comparator_manifest_sha256=comparator.manifest_sha256, engine_capability_manifest_sha256=engine.manifest_sha256, features={name: 0.5 for name in FEATURE_NAMES}, comparator_inputs=comparator_inputs, era="post_freeze", created_at_utc=_utc(input_minutes))
        model_inputs.append(model_input)
        registration = build_archive_registration(archive_sha256=archive, deck_sha256=f"{archive_index + 101:064x}", policy_sha256=f"{archive_index + 201:064x}", model_input_sha256=model_input["model_input_sha256"], family_provenance_sha256=ancestry_audit["archive_to_family"][archive], team_pseudonym=f"team-{archive_index:02d}", submission_slot_id=f"slot-{archive_index:02d}", intended_window_start_utc=_utc(1900), intended_window_end_utc=_utc(200000), consent_sha256=f"{archive_index + 401:064x}", registered_at_utc=_utc(registration_minutes + archive_index))
        registry = append_registration(registry, registration)
        firewall_records.append(ArchiveRecord(archive_id=archive, partition=EXTERNAL_CONFIRMATORY, archive_sha256=archive, deck_sha256=registration["deck_sha256"], policy_sha256=registration["policy_sha256"], family_provenance_sha256=registration["family_provenance_sha256"], model_input_sha256=registration["model_input_sha256"], registered_at_utc=registration["registered_at_utc"]))
        if archive_index < complete_archives:
            game_start = 180000 if post_deadline else 2200 + archive_index * 100
            maturity = game_start + 100
            for game_index in range(48):
                observation = build_outcome_observation(archive_sha256=archive, game_id=f"game-{archive_index:02d}-{game_index:02d}", created_at_utc=_utc(game_start + game_index), completion_observed_at_utc=_utc(game_start - 120), completion_evidence_sha256=f"{archive_index + 501:064x}", seat=game_index % 2, opponent_rating=1500, outcome="win")
                observation_records.append(observation)
                previous = observation_chain_hashes[-1] if observation_chain_hashes else "0" * 64
                observation_chain_hashes.append(canonical_sha256({"previous_chain_hash": previous, "record": observation}))
    observation_log = validate_observation_log({"schema": OBSERVATION_LOG_SCHEMA, "records": observation_records, "chain_hashes": observation_chain_hashes})
    safety = build_operational_safety_evidence(campaign_sha256=campaign["campaign_sha256"], archive_sha256s=archive_hashes, tested_calls=PREDECLARED_MIN_TESTED_CALLS)
    return {"campaign": campaign, "mci_manifest": mci, "comparator_manifest": comparator, "model_inputs": model_inputs, "engine_capability_manifest": engine, "ancestry_manifest": ancestry_manifest, "ancestry_auditor_public_key_hex": ancestry_key, "safety_evidence": safety, "registry": registry, "observation_log": observation_log, "firewall": build_firewall(firewall_records), "as_of_utc": _utc(200000)}


_BASE_EVIDENCE = _evidence()


def _copy_evidence() -> dict[str, object]:
    copied = dict(_BASE_EVIDENCE)
    for key in ("campaign", "ancestry_manifest", "safety_evidence", "registry", "observation_log"):
        copied[key] = deepcopy(_BASE_EVIDENCE[key])
    copied["model_inputs"] = [
        {**item, "features": dict(item["features"]), "comparator_inputs": dict(item["comparator_inputs"])}
        for item in _BASE_EVIDENCE["model_inputs"]  # type: ignore[index]
    ]
    return copied


def _run(**changes: object) -> dict[str, object]:
    args: dict[str, object] = {"repo_root": ROOT, "binding": BINDING, "charter": build_charter(), **_copy_evidence()}
    args.update(changes)
    return prevalidation_gate(**args)  # type: ignore[arg-type]


def test_valid_transfer_is_research_only_and_authority_is_closed() -> None:
    result = _run()
    assert result["decision"] == "TRANSFER_VALIDATED_RESEARCH_ONLY"
    assert result["submission_authorized"] is False
    assert result["sealed_holdout_access"] is False
    assert result["authority"] == {"sealed_holdout_access": False, "submission_authorized": False}
    assert all(gate["passed"] for gate in result["gates"][:5])


def test_29_archives_do_not_open_analysis_and_30_open_once() -> None:
    before = _run(**_evidence(complete_archives=29))
    assert before["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert before["gates"][4]["reasons"] == ["analysis_not_open"]
    assert "transfer_sha256" not in before["evidence"]
    after = _run()
    assert after["gates"][4]["passed"] is True
    assert "transfer_sha256" in after["evidence"]


def test_model_manifests_must_be_frozen_before_campaign_opening() -> None:
    result = _run(**_evidence(mci_minutes=1, comparator_minutes=2))
    assert result["gates"][2]["passed"] is False
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert "transfer_sha256" not in result["evidence"]


def test_overregistered_population_never_opens_analysis() -> None:
    result = _run(**_evidence(complete_archives=31, archive_count=31, family_count=14))
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert result["gates"][4]["reasons"] == ["analysis_not_open"]
    assert "transfer_sha256" not in result["evidence"]

    diverse = _run(
        **_evidence(complete_archives=31, archive_count=31, family_count=16)
    )
    assert diverse["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert diverse["gates"][4]["reasons"] == ["analysis_not_open"]
    assert "transfer_sha256" not in diverse["evidence"]


def test_incomplete_registered_archive_cannot_be_silently_skipped() -> None:
    result = _run(
        **_evidence(complete_archives=30, archive_count=31, family_count=16)
    )
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert result["gates"][4]["reasons"] == ["analysis_not_open"]
    assert "transfer_sha256" not in result["evidence"]


def test_missing_or_infeasible_engine_capability_closes_g4() -> None:
    assert _run(engine_capability_manifest=None)["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert _run(engine_capability_manifest=_engine_manifest(feasible=False))["decision"] == "NO_SUBMIT_IDENTIFIABILITY"


def test_engine_hash_swap_closes_before_reconstruction() -> None:
    result = _run(engine_capability_manifest=_engine_manifest(salt=1))
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert "transfer_sha256" not in result["evidence"]


def test_unrelated_firewall_cannot_satisfy_g1() -> None:
    result = _run(firewall=build_firewall([]))
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert result["gates"][1]["passed"] is False
    assert "transfer_sha256" not in result["evidence"]


def test_outcome_derived_probabilities_are_not_an_api() -> None:
    with pytest.raises(TypeError):
        _run(prediction_rows=[])  # type: ignore[call-arg]
    inputs = deepcopy(_evidence()["model_inputs"])
    inputs[0]["mci_probability"] = 0.999  # type: ignore[index]
    result = _run(model_inputs=inputs)
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert "transfer_sha256" not in result["evidence"]


def test_nonnull_comparator_input_is_bound_and_recomputed() -> None:
    evidence = _evidence(comparator_nonnull=True)
    result = _run(**evidence)
    assert result["decision"] == "TRANSFER_VALIDATED_RESEARCH_ONLY"
    comparator = evidence["comparator_manifest"]
    game = {"features": {name: 0.5 for name in FEATURE_NAMES}, "era": "post_freeze", "seat": 0, "opponent_rating": 1500, "comparator_inputs": {"raw_local_win_rate": 0.9}}
    null_game = {**game, "comparator_inputs": {"raw_local_win_rate": None}}
    rows = build_prediction_rows(evidence["mci_manifest"], comparator, [{**game, "game_id": "a", "hosted_at_utc": _utc(300), "outcome": 1}], archive_id="a" * 64, family_id="b" * 64, registered_package_hash="c" * 64, registration_at_utc=_utc(100))
    null_rows = build_prediction_rows(evidence["mci_manifest"], comparator, [{**null_game, "game_id": "b", "hosted_at_utc": _utc(300), "outcome": 1}], archive_id="d" * 64, family_id="e" * 64, registered_package_hash="f" * 64, registration_at_utc=_utc(100))
    assert rows[0]["baseline_probability"] != null_rows[0]["baseline_probability"]


def test_model_input_hash_tamper_duplicate_and_zero_safety_fail_closed() -> None:
    evidence = _evidence()
    inputs = deepcopy(evidence["model_inputs"])
    inputs[0]["features"][FEATURE_NAMES[0]] = 0.9  # type: ignore[index]
    assert _run(model_inputs=inputs)["decision"] == "NO_SUBMIT_INTEGRITY"
    duplicate = list(evidence["model_inputs"]) + [evidence["model_inputs"][0]]
    result = _run(model_inputs=duplicate)
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    safety = deepcopy(evidence["safety_evidence"])
    safety["tested_calls"] = 0  # type: ignore[index]
    assert _run(safety_evidence=safety)["decision"] == "NO_SUBMIT_INTEGRITY"


def test_input_must_precede_registration_and_epsilon_must_match() -> None:
    assert _run(**_evidence(input_minutes=100)) ["decision"] == "NO_SUBMIT_INTEGRITY"
    assert _run(**_evidence(comparator_epsilon=0.002)) ["decision"] == "NO_SUBMIT_INTEGRITY"


def test_post_deadline_games_are_not_eligible() -> None:
    result = _run(**_evidence(post_deadline=True))
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert result["gates"][4]["reasons"] == ["analysis_not_open"]
    assert "transfer_sha256" not in result["evidence"]


def test_campaign_window_and_deadline_are_exact() -> None:
    evidence = _evidence(complete_archives=29)
    deadline = evidence["campaign"]["deadline_at_utc"]
    assert deadline == (BASE + timedelta(days=120)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    result = _run(**{**evidence, "as_of_utc": deadline})
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert "transfer_sha256" not in result["evidence"]


@pytest.mark.parametrize("which", [0, 1, 3])
def test_invalid_prior_gate_suppresses_confirmatory_output(which: int) -> None:
    evidence = _evidence()
    if which == 0:
        bad_binding = deepcopy(BINDING)
        bad_binding["authority"]["submission"] = True
        evidence["binding"] = bad_binding
    elif which == 1:
        evidence["firewall"] = build_firewall([])
    else:
        bad_safety = deepcopy(evidence["safety_evidence"])
        bad_safety["tested_calls"] = 0
        evidence["safety_evidence"] = bad_safety
    result = _run(**evidence)
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert "transfer_sha256" not in result["evidence"]
    assert not any("metrics" in value for value in result["evidence"].values() if isinstance(value, dict))


def test_missing_cohort_is_identifiability_closed() -> None:
    evidence = _evidence()
    result = _run(registry=None, observation_log=None, as_of_utc=None)
    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert "transfer_sha256" not in result["evidence"]


def test_result_is_order_deterministic() -> None:
    first = _run()
    evidence = _evidence()
    second = _run(**{**evidence, "model_inputs": list(reversed(evidence["model_inputs"]))})
    assert first == second
    assert [gate["name"] for gate in first["gates"]] == ["G0", "G1", "G2", "G3", "G4", "G5"]
