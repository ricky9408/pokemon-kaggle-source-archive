from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.exact_gate_v2 import _decode_ed25519_point, _ed25519_add
from evaluation_v5_1.production_release import (
    AMBIGUOUS,
    AUTHORIZED_UNUSED,
    CONFIRMED,
    CONFLICTED,
    CONSUMED_PENDING,
    G14_AUDIT_SCHEMA,
    G15_BASELINE_SCHEMA,
    G15_DESCRIPTOR_SCHEMA,
    G15_RELEASE_EVIDENCE_SCHEMA,
    G15_SCAN_SCHEMA,
    HOLDOUT_CONSUMED_COMPLETE,
    HOLDOUT_CONSUMED_RUNNING,
    PREFLIGHT_LOCKED,
    ProductionReleaseError,
    ResearchOnlyReleaseLedger,
    SyntheticReleaseStateMachine,
    derive_authorization_id,
    derive_authorization_marker,
    validate_g14_opaque_holdout_audit,
    validate_g15_history_baseline,
    validate_g15_release_evidence,
    validate_g15_request_descriptor,
    verify_production_release_exact_v2,
)


def _hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("ascii")).hexdigest()


ARCHIVE_BYTES = b"archive-bytes-000"
MULTIPART_BODY = b"multipart-prefix:" + ARCHIVE_BYTES + b":multipart-suffix"


def _bytes_hash(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


FROZEN_CAPTURE_START_NS = 10
PREFLIGHT_CAPTURE_START_NS = 1_100_000_000_000
POST_CAPTURE_START_NS = 1_400_000_000_000


def _record(
    submission_id: str,
    *,
    description: str | None = None,
    server_created_at_ns: int = 1,
) -> dict[str, object]:
    return {
        "submission_id": submission_id,
        "competition_id": "competition-1",
        "team_id": "team-1",
        "server_created_at_ns": server_created_at_ns,
        "submission_description": description if description is not None else f"historical-{submission_id}",
    }


def _scan(
    collector: str,
    number: int,
    records: list[dict[str, object]],
    *,
    capture_start_ns: int,
) -> dict[str, object]:
    # The second scan begins exactly 60 seconds after the first scan ends.
    started = capture_start_ns if number == 1 else capture_start_ns + 60_000_000_000
    value: dict[str, object] = {
        "schema_version": G15_SCAN_SCHEMA,
        "collector_id": collector,
        "principal_id": f"principal-{collector}",
        "credential_key_id": f"credential-{collector}",
        "host_id": f"host-{collector}",
        "network_id": f"network-{collector}",
        "scan_number": number,
        "started_at_ns": started,
        "ended_at_ns": started,
        "cursor_chain": ["FIRST", f"cursor-{collector}-{number}", "TERMINAL"],
        "reported_total": len(records),
        "records": copy.deepcopy(records),
        "raw_response_hashes": [_hash(f"list:{collector}:{number}"), _hash(f"detail:{collector}:{number}")],
    }
    value["scan_root"] = canonical_sha256(value)
    return value


def _baseline(
    records: list[dict[str, object]] | None = None,
    *,
    capture_start_ns: int = FROZEN_CAPTURE_START_NS,
) -> dict[str, object]:
    rows = sorted(
        records or [_record("submission-0")],
        key=lambda row: (row["server_created_at_ns"], row["submission_id"]),
    )
    value: dict[str, object] = {
        "schema_version": G15_BASELINE_SCHEMA,
        "campaign_root": _hash("campaign"),
        "evaluation_id": "evaluation-1",
        "evaluation_nonce": _hash("evaluation-nonce"),
        "competition_id": "competition-1",
        "team_id": "team-1",
        "registration_ns": 0,
        "review_not_before_ns": 1_000_000_000_000,
        "post_capture_deadline_ns": 3_000_000_000_000,
        "scans": [
            _scan("a", 1, rows, capture_start_ns=capture_start_ns),
            _scan("a", 2, rows, capture_start_ns=capture_start_ns),
            _scan("b", 1, rows, capture_start_ns=capture_start_ns),
            _scan("b", 2, rows, capture_start_ns=capture_start_ns),
        ],
        "baseline_count": len(rows),
    }
    value["baseline_root"] = canonical_sha256(value)
    return value


def _live_baseline(
    records: list[dict[str, object]] | None = None,
    *,
    capture_start_ns: int = PREFLIGHT_CAPTURE_START_NS,
) -> dict[str, object]:
    return _baseline(records, capture_start_ns=capture_start_ns)


def _rehash_baseline(baseline: dict[str, object]) -> None:
    for scan in baseline["scans"]:  # type: ignore[index]
        scan["scan_root"] = canonical_sha256(  # type: ignore[index]
            {key: scan[key] for key in scan if key != "scan_root"}  # type: ignore[union-attr]
        )
    baseline["baseline_root"] = canonical_sha256(
        {key: baseline[key] for key in baseline if key != "baseline_root"}
    )


def _release(baseline: dict[str, object] | None = None, *, nonce: str = "submission-nonce") -> dict[str, object]:
    baseline = baseline or _baseline()
    baseline_validation = validate_g15_history_baseline(baseline)
    submission_nonce = _hash(nonce)
    marker = derive_authorization_marker(
        campaign_root=baseline["campaign_root"], evaluation_id=baseline["evaluation_id"],
        evaluation_nonce=baseline["evaluation_nonce"], submission_nonce=submission_nonce,
    )
    value: dict[str, object] = {
        "schema_version": G15_RELEASE_EVIDENCE_SCHEMA,
        "campaign_root": baseline["campaign_root"],
        "evaluation_id": baseline["evaluation_id"],
        "evaluation_nonce": baseline["evaluation_nonce"],
        "archive_sha256": _bytes_hash(ARCHIVE_BYTES),
        "archive_length": len(ARCHIVE_BYTES),
        "g13_bundle_sha256": _hash("g13"),
        "g14_bundle_sha256": _hash("g14"),
        "g14_tested_archive_sha256": _bytes_hash(ARCHIVE_BYTES),
        "g14_tested_archive_length": len(ARCHIVE_BYTES),
        "g15_input_root": _hash("g15-input"),
        "competition_id": baseline["competition_id"],
        "team_id": baseline["team_id"],
        "submission_nonce": submission_nonce,
        "baseline_root": baseline["baseline_root"],
        "baseline_registration_sha256": baseline_validation["baseline_registration_sha256"],
        "baseline_identity_root": baseline_validation["identity_root"],
        "baseline_count": baseline["baseline_count"],
        "release_intent_sha256": _hash("intent"),
        "marker": marker,
        "endpoint_origin": "https://www.kaggle.com",
        "endpoint_path": "/api/v1/competitions/submissions/submit/pokemon-tcg-ai-battle",
        "tls_policy_sha256": _hash("tls-policy"),
    }
    value["authorization_id"] = derive_authorization_id(**{key: value[key] for key in (
        "campaign_root", "evaluation_id", "evaluation_nonce", "submission_nonce", "competition_id", "team_id",
        "archive_sha256", "archive_length", "g13_bundle_sha256", "g14_bundle_sha256",
        "g15_input_root", "release_intent_sha256", "baseline_registration_sha256",
        "baseline_identity_root", "baseline_count", "marker",
    )})  # type: ignore[arg-type]
    return value


def _descriptor(release: dict[str, object]) -> dict[str, object]:
    value = {key: release[key] for key in (
        "campaign_root", "evaluation_id", "evaluation_nonce", "authorization_id", "competition_id", "team_id",
        "archive_sha256", "archive_length", "g13_bundle_sha256", "g14_bundle_sha256", "g15_input_root",
        "baseline_root", "baseline_registration_sha256", "baseline_identity_root",
        "baseline_count", "marker",
    )}
    value.update({
        "schema_version": G15_DESCRIPTOR_SCHEMA,
        "method": "POST",
        "redirect_policy": "error",
        "automatic_retry": False,
        "request_descriptor_sha256": "",
        "multipart_body_sha256": _bytes_hash(MULTIPART_BODY),
        "endpoint_origin": release["endpoint_origin"],
        "endpoint_path": release["endpoint_path"],
        "tls_policy_sha256": release["tls_policy_sha256"],
        "request_body_media_type": "multipart/form-data",
        "executor_digest": _hash("executor"),
        "runtime_digest": _hash("runtime"),
    })
    value["request_descriptor_sha256"] = canonical_sha256(
        {key: value[key] for key in value if key != "request_descriptor_sha256"}
    )
    return value


def _g14() -> dict[str, object]:
    return {
        "schema_version": G14_AUDIT_SCHEMA, "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "campaign_root": _hash("campaign"), "evaluation_id": "evaluation-1",
        "evaluation_nonce": _hash("evaluation-nonce"), "gate_id": "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT",
        "attempt": 0, "archive_sha256": _bytes_hash(ARCHIVE_BYTES), "archive_length": len(ARCHIVE_BYTES),
        "g12_bundle_sha256": _hash("g12"), "g13_bundle_sha256": _hash("g13"), "g13_selected_archive_sha256": _bytes_hash(ARCHIVE_BYTES),
        "g13_selected_archive_length": len(ARCHIVE_BYTES), "g14_input_root": _hash("g14-input"),
        "runtime_digest": _hash("runtime"), "holdout_ciphertext_sha256": _hash("sealed"),
        "holdout_commitment_root": _hash("commitment"),
        "phase1_audit": {"scheduled_calls": 50_000, "executed_calls": 50_000, "unique_calls": 50_000, "process_starts": 1, "restarts": 0, "crashes": 0, "timeouts": 0, "ooms": 0, "schema_errors": 0, "forbidden_io": 0, "network_egress": 0, "nondeterminism": 0, "resource_violations": 0},
        "holdout_summary": {"expected_records": 50, "completed_records": 50, "unique_records": 50, "excluded_records": 0, "retries": 0, "score_statistics_root": _hash("scores")},
    }


def test_g14_uses_opaque_counters_and_irreversibly_consumes_audit_slot(tmp_path) -> None:
    evidence = _g14()
    assert "records" not in evidence
    receipt = validate_g14_opaque_holdout_audit(evidence)
    assert receipt["structural_validation_complete"] is True
    assert receipt["holdout_accessed"] is False
    assert all(value is False for key, value in receipt.items() if key.endswith("authorized") or key == "authority")
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    assert ledger.begin_g14_holdout_audit(evidence) == HOLDOUT_CONSUMED_RUNNING
    assert ledger.finish_g14_holdout_audit(evidence, completed=True) == HOLDOUT_CONSUMED_COMPLETE
    with pytest.raises(ProductionReleaseError, match="G14_HOLDOUT_ALREADY_CONSUMED"):
        ledger.begin_g14_holdout_audit(evidence)
    ledger.close()


def test_production_shaped_ledger_cannot_mutate_without_trusted_services(tmp_path) -> None:
    ledger = ResearchOnlyReleaseLedger(str(tmp_path / "hard-closed.sqlite"))
    with pytest.raises(ProductionReleaseError) as g14_error:
        ledger.begin_g14_holdout_audit(_g14())
    assert g14_error.value.code == "G14_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"
    with pytest.raises(ProductionReleaseError) as g15_error:
        ledger.register_authorization(_release())
    assert g15_error.value.code == "G15_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"
    assert ledger._connection.execute("SELECT COUNT(*) FROM production_release_state").fetchone()[0] == 0
    ledger.close()


@pytest.mark.parametrize("mutation", ["partial", "latest_two", "stale", "duplicate"])
def test_dual_capture_rejects_partial_stale_and_noncanonical_history(mutation: str) -> None:
    baseline = _baseline([_record("submission-0"), _record("submission-1"), _record("submission-2")])
    broken = copy.deepcopy(baseline)
    if mutation == "partial":
        broken["scans"][0]["reported_total"] = 99  # type: ignore[index]
    elif mutation == "latest_two":
        scan = broken["scans"][0]  # type: ignore[index]
        scan["records"] = scan["records"][-2:]
        scan["reported_total"] = 2
        scan["scan_root"] = canonical_sha256({key: scan[key] for key in scan if key != "scan_root"})
    elif mutation == "stale":
        broken["scans"][1]["started_at_ns"] += 121_000_000_000  # type: ignore[index]
        broken["scans"][1]["ended_at_ns"] += 121_000_000_000  # type: ignore[index]
        scan = broken["scans"][1]  # type: ignore[index]
        scan["scan_root"] = canonical_sha256({key: scan[key] for key in scan if key != "scan_root"})
    else:
        broken["scans"][0]["records"].append(copy.deepcopy(broken["scans"][0]["records"][0]))  # type: ignore[index]
        broken["scans"][0]["reported_total"] += 1  # type: ignore[index]
        scan = broken["scans"][0]  # type: ignore[index]
        scan["scan_root"] = canonical_sha256({key: scan[key] for key in scan if key != "scan_root"})
    broken["baseline_root"] = canonical_sha256({key: broken[key] for key in broken if key != "baseline_root"})
    with pytest.raises(ProductionReleaseError):
        validate_g15_history_baseline(broken)


@pytest.mark.parametrize("field", ["principal_id", "credential_key_id", "host_id", "network_id"])
def test_collectors_must_be_separate_on_every_identity_axis(field: str) -> None:
    baseline = _baseline()
    scans = baseline["scans"]  # type: ignore[index]
    shared = scans[0][field]
    for scan in scans[2:]:
        scan[field] = shared
    _rehash_baseline(baseline)
    with pytest.raises(ProductionReleaseError) as error:
        validate_g15_history_baseline(baseline)
    assert error.value.code == "G15_BASELINE_COLLECTOR_SEPARATION_INVALID"


def test_each_collector_identity_is_stable_across_its_two_scans() -> None:
    baseline = _baseline()
    baseline["scans"][1]["host_id"] = "changed-host"  # type: ignore[index]
    _rehash_baseline(baseline)
    with pytest.raises(ProductionReleaseError) as error:
        validate_g15_history_baseline(baseline)
    assert error.value.code == "G15_BASELINE_COLLECTOR_SEPARATION_INVALID"


def test_history_projection_uses_server_identity_fields_and_exact_target() -> None:
    baseline = _baseline()
    result = validate_g15_history_baseline(baseline)
    assert result["source_authenticated"] is False
    assert set(result["projection"][0]) == {
        "submission_id",
        "competition_id",
        "team_id",
        "server_created_at_ns",
        "submission_description",
    }
    broken = copy.deepcopy(baseline)
    for scan in broken["scans"]:  # type: ignore[index]
        scan["records"][0]["team_id"] = "other-team"
    _rehash_baseline(broken)
    with pytest.raises(ProductionReleaseError, match="outside the frozen target"):
        validate_g15_history_baseline(broken)


def test_preflight_accepts_a_fresh_capture_with_same_history_but_different_capture_root(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    current = _live_baseline()
    assert baseline["baseline_root"] != current["baseline_root"]
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    evidence = release | {"baseline": baseline}
    ledger.register_authorization(release)
    assert ledger.lock_preflight(evidence, current_baseline=current) == PREFLIGHT_LOCKED
    ledger.close()


def test_post_capture_must_be_newer_than_preflight_and_can_confirm_exact_marker(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    evidence = release | {"baseline": baseline}
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    ledger.register_authorization(release)
    ledger.lock_preflight(evidence, current_baseline=_live_baseline())
    ledger.consume_before_network(evidence, _descriptor(release), archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY)
    ledger.record_request_outcome(evidence, outcome="sent")
    post = _live_baseline(
        [
            _record("submission-0"),
            _record(
                "submission-new",
                description=release["marker"],  # type: ignore[arg-type]
                server_created_at_ns=POST_CAPTURE_START_NS,
            ),
        ],
        capture_start_ns=POST_CAPTURE_START_NS,
    )
    assert ledger.confirm_post_capture(
        evidence,
        post_baseline=post,
        response_submission_id="submission-new",
    ) == CONFIRMED
    ledger.close()


def test_replayed_preflight_capture_cannot_confirm_a_request(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    evidence = release | {"baseline": baseline}
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    ledger.register_authorization(release)
    ledger.lock_preflight(evidence, current_baseline=_live_baseline())
    ledger.consume_before_network(evidence, _descriptor(release), archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY)
    ledger.record_request_outcome(evidence, outcome="sent")
    replayed = _live_baseline(
        [
            _record("submission-0"),
            _record("submission-new", description=release["marker"]),  # type: ignore[arg-type]
        ]
    )
    assert ledger.confirm_post_capture(
        evidence,
        post_baseline=replayed,
        response_submission_id="submission-new",
    ) == AMBIGUOUS
    ledger.close()


def test_authorization_marker_is_exact_prefixed_description() -> None:
    release = _release()
    assert release["marker"].startswith("PTCGv5.1-")  # type: ignore[union-attr]
    assert len(release["marker"]) == len("PTCGv5.1-") + 64  # type: ignore[arg-type]


def test_strict_shared_envelope_rejects_forgery_and_mixed_order_key() -> None:
    release = _release()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope = build_envelope(artifact_schema=G15_RELEASE_EVIDENCE_SCHEMA, payload=release, signer_public_key_bytes=public, signature=private.sign(signing_payload(G15_RELEASE_EVIDENCE_SCHEMA, canonical_sha256(release))))
    forged = copy.deepcopy(envelope)
    forged["signature_ed25519_base64"] = "A" * 88
    assert validate_g15_release_evidence(release, pinned_public_key_bytes=public, envelope=forged)["failure_codes"] == ["G15_ENVELOPE_INVALID"]
    point = _decode_ed25519_point(public, label="valid", reject_small_order=True)
    torsion = _decode_ed25519_point(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), label="torsion", reject_small_order=False)
    x, y = _ed25519_add(point, torsion)
    mixed = (y | ((x & 1) << 255)).to_bytes(32, "little")
    assert validate_g15_release_evidence(release, pinned_public_key_bytes=mixed, envelope=envelope)["failure_codes"] == ["G15_ENVELOPE_INVALID"]


def test_descriptor_is_checked_before_consumption_and_redirect_retry_are_forbidden(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    ledger.register_authorization(release)
    evidence = release | {"baseline": baseline}
    assert ledger.lock_preflight(evidence, current_baseline=_live_baseline()) == PREFLIGHT_LOCKED
    descriptor = _descriptor(release)
    descriptor["automatic_retry"] = True
    with pytest.raises(ProductionReleaseError) as error:
        ledger.consume_before_network(evidence, descriptor, archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY)
    assert error.value.code == "G15_REDIRECT_OR_RETRY_FORBIDDEN"
    assert ledger.consume_before_network(evidence, _descriptor(release), archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY) == CONSUMED_PENDING
    assert ledger.record_request_outcome(evidence, outcome="timeout") == AMBIGUOUS
    with pytest.raises(ProductionReleaseError):
        ledger.record_request_outcome(evidence, outcome="sent")
    ledger.close()


@pytest.mark.parametrize("mutation", ["archive", "body", "endpoint", "descriptor_hash"])
def test_descriptor_recomputes_exact_bytes_and_target(mutation: str) -> None:
    release = _release()
    descriptor = _descriptor(release)
    archive = ARCHIVE_BYTES
    body = MULTIPART_BODY
    if mutation == "archive":
        archive = b"different-archive"
    elif mutation == "body":
        body = b"different-body"
    elif mutation == "endpoint":
        descriptor["endpoint_path"] = "/api/v1/wrong-target"
        descriptor["request_descriptor_sha256"] = canonical_sha256(
            {key: descriptor[key] for key in descriptor if key != "request_descriptor_sha256"}
        )
    else:
        descriptor["request_descriptor_sha256"] = _hash("wrong-descriptor")
    with pytest.raises(ProductionReleaseError) as error:
        validate_g15_request_descriptor(
            descriptor,
            release_evidence=release,
            archive_bytes=archive,
            multipart_body=body,
        )
    assert error.value.code == "G15_DESCRIPTOR_INVALID"


def test_registered_release_bytes_cannot_be_substituted_during_preflight(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    ledger.register_authorization(release)
    substituted = copy.deepcopy(release)
    substituted["endpoint_path"] = "/api/v1/other-valid-looking-path"
    with pytest.raises(ProductionReleaseError) as error:
        ledger.lock_preflight(
            substituted | {"baseline": baseline},
            current_baseline=_live_baseline(),
        )
    assert error.value.code == "G15_AUTHORIZATION_BINDING_INVALID"
    ledger.close()


def test_changed_manual_history_second_authorization_and_invalid_transitions_are_terminal(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    assert ledger.register_authorization(release) == AUTHORIZED_UNUSED
    other = _release(baseline, nonce="different")
    with pytest.raises(ProductionReleaseError) as error:
        ledger.register_authorization(other)
    assert error.value.code == "G15_SECOND_AUTHORIZATION_CONFLICT"
    with pytest.raises(ProductionReleaseError, match="G15_INVALID_STATE_TRANSITION"):
        ledger.lock_preflight(release | {"baseline": baseline}, current_baseline=_live_baseline())
    ledger.close()


@pytest.mark.parametrize("failure", ["marker", "response"])
def test_post_capture_wrong_marker_or_response_id_conflicts_without_retry(tmp_path, failure: str) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    evidence = release | {"baseline": baseline}
    ledger.register_authorization(release)
    ledger.lock_preflight(evidence, current_baseline=_live_baseline())
    ledger.consume_before_network(evidence, _descriptor(release), archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY)
    ledger.record_request_outcome(evidence, outcome="sent")
    marker = release["marker"] if failure == "response" else "PTCGv5.1-" + _hash("wrong-marker")
    post = _live_baseline(
        [
            _record("submission-0"),
            _record("submission-new", description=marker, server_created_at_ns=POST_CAPTURE_START_NS),
        ],
        capture_start_ns=POST_CAPTURE_START_NS,
    )
    response_id = "submission-new" if failure == "marker" else "wrong-id"
    assert ledger.confirm_post_capture(evidence, post_baseline=post, response_submission_id=response_id) == CONFLICTED
    ledger.close()


def test_concurrent_manual_submission_invalidates_preflight_and_exact_v2_stays_closed(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    ledger.register_authorization(release)
    changed = _live_baseline([_record("submission-0"), _record("manual")])
    with pytest.raises(ProductionReleaseError, match="G15_CONCURRENT_SUBMISSION_CONFLICT"):
        ledger.lock_preflight(release | {"baseline": baseline}, current_baseline=changed)
    wrapper = verify_production_release_exact_v2(gate_id="G15_RELEASE_CUSTODY", final_bundle={})
    assert wrapper["decision"] == "REJECTED_INVALID_ENVELOPE"
    assert all(value is False for key, value in wrapper.items() if key.endswith("authorized") or key == "authority")
    ledger.close()


def test_missing_post_history_after_a_sent_request_is_ambiguous(tmp_path) -> None:
    baseline, release = _baseline(), _release()
    ledger = SyntheticReleaseStateMachine(str(tmp_path / "ledger.sqlite"))
    evidence = release | {"baseline": baseline}
    ledger.register_authorization(release)
    ledger.lock_preflight(evidence, current_baseline=_live_baseline())
    ledger.consume_before_network(evidence, _descriptor(release), archive_bytes=ARCHIVE_BYTES, multipart_body=MULTIPART_BODY)
    ledger.record_request_outcome(evidence, outcome="sent")
    assert ledger.confirm_post_capture(
        evidence,
        post_baseline=_live_baseline(capture_start_ns=POST_CAPTURE_START_NS),
        response_submission_id="submission-new",
    ) == AMBIGUOUS
    ledger.close()


def test_circular_g15_bundle_binding_and_byte_mutation_fail_closed() -> None:
    release = _release()
    circular = copy.deepcopy(release)
    circular["authorization_id"] = _hash("g15-bundle-hash-in-preimage")
    receipt = validate_g15_release_evidence(circular)
    assert receipt["failure_codes"] == ["G15_AUTHORIZATION_BINDING_INVALID"]
    mutated = _g14()
    mutated["archive_sha256"] = _hash("mutated archive")
    assert validate_g14_opaque_holdout_audit(mutated)["failure_codes"] == ["G14_ARCHIVE_BINDING_MISMATCH"]
    # The G15 descriptor pinning rejects the same byte-identifying mutation.
    with pytest.raises(ProductionReleaseError, match="descriptor archive_sha256"):
        descriptor = _descriptor(release)
        descriptor["archive_sha256"] = _hash("mutated archive")
        validate_g15_request_descriptor(
            descriptor,
            release_evidence=release,
            archive_bytes=ARCHIVE_BYTES,
            multipart_body=MULTIPART_BODY,
        )
