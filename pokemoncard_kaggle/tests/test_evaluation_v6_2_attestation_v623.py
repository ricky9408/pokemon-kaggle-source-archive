from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evaluation_v6_2.attestation_v623 import (
    BUNDLE_SCHEMA,
    CAMPAIGN_SCHEMA,
    CONTRIBUTOR_SCHEMA,
    DOMAIN_CONTRIBUTOR,
    DOMAIN_LINEAGE,
    DOMAIN_POPULATION,
    DOMAIN_REGISTRY,
    DOMAIN_REVOCATION,
    DOMAIN_TECHNICAL,
    ENVELOPE_SCHEMA,
    EXTERNAL_CHECK_ENVELOPE_SCHEMA,
    EXTERNAL_CHECK_SCHEMA,
    LINEAGE_SCHEMA,
    POPULATION_DECISION_SCHEMA,
    POPULATION_GRAPH_SCHEMA,
    PinnedExternalVerifier,
    PinnedRegistryAdmin,
    REGISTRY_SCHEMA,
    REVOCATION_SCHEMA,
    ROLE_ADJUDICATOR,
    ROLE_CONTRIBUTOR,
    ROLE_LINEAGE,
    ROLE_TECHNICAL,
    TECHNICAL_SCHEMA,
    VERDICT_SCHEMA,
    AttestationV623Error,
    assess_population_trust_bundle,
    external_check_signing_message,
    signing_message,
    verify_population_trust_bundle,
)
from evaluation_v6_2.integration_v622 import SLOTS, canonical_sha256


_SIGNED_AT = "2026-07-16T00:00:00Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _container(label: str) -> str:
    return "sha256:" + _digest(label)


def _key(label: str) -> Ed25519PrivateKey:
    # Fixed seed material gives a reproducible generated Ed25519 keypair.
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key_id(private: Ed25519PrivateKey) -> str:
    return "ed25519-sha256:" + hashlib.sha256(_public(private)).hexdigest()


def _envelope(
    payload: dict[str, object],
    *,
    artifact_schema: str,
    domain: bytes,
    private: Ed25519PrivateKey,
    label: str,
    timestamp_token: str | None = None,
) -> dict[str, object]:
    message = signing_message(domain, payload)
    return {
        "schema": ENVELOPE_SCHEMA,
        "artifact_schema": artifact_schema,
        "key_id": _key_id(private),
        "payload_sha256": canonical_sha256(payload),
        "signed_at_utc": _SIGNED_AT,
        "signature_ed25519_base64": base64.b64encode(private.sign(message)).decode("ascii"),
        "timestamp_token_sha256": timestamp_token or _digest("timestamp:" + label),
    }


@dataclass
class _Fixture:
    bundle: dict[str, object]
    admins: dict[str, PinnedRegistryAdmin]
    verifier: "_FakeExternalVerifier"
    pinned_verifier: PinnedExternalVerifier
    private_by_key_id: dict[str, Ed25519PrivateKey]


class _FakeExternalVerifier:
    def __init__(
        self,
        campaign: dict[str, object],
        private: Ed25519PrivateKey,
        *,
        trusted_time_utc: str = _SIGNED_AT,
        unsigned: bool = False,
    ) -> None:
        self._private = private
        self._trusted_time_utc = trusted_time_utc
        self._unsigned = unsigned
        self.calls = 0
        self.pinned = PinnedExternalVerifier(
            entity_id="external-verifier-entity",
            public_key=_public(private),
            verifier_id="fake-independent-verifier",
            verifier_build_sha256=campaign["semantic_verifier_build_sha256"],
            trust_policy_sha256=campaign["trust_policy_sha256"],
            timestamp_policy_sha256=campaign["timestamp_policy_sha256"],
            external_identity_receipt_sha256=_digest("external-verifier-identity"),
        )

    def _check(self, kind: str, subject: str, label: str) -> dict[str, object]:
        self.calls += 1
        build = self.pinned.verifier_build_sha256
        policy = self.pinned.trust_policy_sha256
        receipt = {
            "schema": EXTERNAL_CHECK_SCHEMA,
            "kind": kind,
            "subject_sha256": subject,
            "verifier_id": self.pinned.verifier_id,
            "verifier_build_sha256": build,
            "trust_policy_sha256": policy,
            "timestamp_policy_sha256": self.pinned.timestamp_policy_sha256,
            "trusted_time_utc": self._trusted_time_utc if kind == "TIMESTAMP" else None,
            "evidence_root_sha256": _digest("external:" + label),
            "verified": True,
        }
        if self._unsigned:
            return receipt
        return {
            "schema": EXTERNAL_CHECK_ENVELOPE_SCHEMA,
            "key_id": self.pinned.key_id,
            "receipt": receipt,
            "receipt_sha256": canonical_sha256(receipt),
            "signature_ed25519_base64": base64.b64encode(
                self._private.sign(external_check_signing_message(receipt))
            ).decode("ascii"),
        }

    def verify_identity(self, key_record: dict[str, object]) -> dict[str, object]:
        return self._check("IDENTITY", canonical_sha256(key_record), "identity:" + key_record["key_id"])

    def verify_timestamp(self, timestamp_subject_bytes: bytes, envelope: dict[str, object]) -> dict[str, object]:
        return self._check(
            "TIMESTAMP",
            hashlib.sha256(timestamp_subject_bytes).hexdigest(),
            "timestamp:" + envelope["key_id"] + ":" + envelope["timestamp_token_sha256"],
        )

    def verify_technical(self, receipt: dict[str, object], contributor: dict[str, object]) -> dict[str, object]:
        return self._check("TECHNICAL_SEMANTICS", canonical_sha256(receipt), "technical:" + receipt["slot_id"])

    def verify_lineage(self, receipt: dict[str, object], contributor: dict[str, object]) -> dict[str, object]:
        return self._check("LINEAGE_SEMANTICS", canonical_sha256(receipt), "lineage:" + receipt["slot_id"])


def _campaign() -> dict[str, object]:
    return {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": "campaign-v623-test",
        "campaign_nonce": "a1" * 16,
        "protocol_sha256": _digest("protocol"),
        "slot_schedule_sha256": _digest("slot-schedule"),
        "semantic_verifier_build_sha256": _digest("semantic-verifier-build"),
        "trust_policy_sha256": _digest("trust-policy"),
        "timestamp_policy_sha256": _digest("timestamp-policy"),
        "engine_sha256": _digest("engine"),
        "ruleset_sha256": _digest("ruleset"),
        "build_container_digest": _container("build-container"),
        "safety_policy_sha256": _digest("safety-policy"),
        "dudunsparce_harness_sha256": _digest("dudunsparce-harness"),
    }


def _make_fixture(
    *,
    technical_indices: list[int] | None = None,
    contributor_indices: list[int] | None = None,
    duplicate_artifact: str | None = None,
    duplicate_audit_session: bool = False,
    overlap: str | None = None,
    revoked: bool = False,
    trusted_time_utc: str = _SIGNED_AT,
    unsigned_external: bool = False,
) -> _Fixture:
    campaign = _campaign()
    private_by_key_id: dict[str, Ed25519PrivateKey] = {}
    registry_records: list[dict[str, object]] = []
    role_key_ids: dict[str, list[str]] = {
        ROLE_CONTRIBUTOR: [],
        ROLE_TECHNICAL: [],
        ROLE_LINEAGE: [],
        ROLE_ADJUDICATOR: [],
    }

    def add_key(role: str, entity: str, label: str) -> str:
        private = _key(label)
        key_id = _key_id(private)
        private_by_key_id[key_id] = private
        role_key_ids[role].append(key_id)
        registry_records.append(
            {
                "key_id": key_id,
                "public_key_ed25519_base64": base64.b64encode(_public(private)).decode("ascii"),
                "role": role,
                "entity_id": entity,
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_to_utc": "2027-01-01T00:00:00Z",
                "status": "ACTIVE",
                "external_identity_receipt_sha256": _digest("identity:" + entity),
            }
        )
        return key_id

    contributor_keys = [add_key(ROLE_CONTRIBUTOR, f"contributor-{i:02d}", f"contributor-{i:02d}") for i in range(16)]
    technical_keys = [add_key(ROLE_TECHNICAL, f"technical-{i:02d}", f"technical-{i:02d}") for i in range(4)]
    lineage_keys = [add_key(ROLE_LINEAGE, f"lineage-{i:02d}", f"lineage-{i:02d}") for i in range(4)]
    adjudicator_keys = [add_key(ROLE_ADJUDICATOR, f"adjudicator-{i:02d}", f"adjudicator-{i:02d}") for i in range(3)]

    admin_private = [_key(f"admin-{i}") for i in range(3)]
    admins = {
        _key_id(private): PinnedRegistryAdmin(
            entity_id=f"registry-admin-{i:02d}",
            public_key=_public(private),
            external_identity_receipt_sha256=_digest(f"admin-identity-{i}"),
        )
        for i, private in enumerate(admin_private)
    }

    by_key_id = {record["key_id"]: record for record in registry_records}
    if revoked:
        revoked_key_id = contributor_keys[0]
    else:
        revoked_key_id = None
    registry_records.sort(key=lambda record: (record["role"], record["key_id"]))
    registry = {
        "schema": REGISTRY_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "campaign_nonce": campaign["campaign_nonce"],
        "registry_epoch": 1,
        "keys": registry_records,
    }
    revocation_entries = []
    if revoked_key_id is not None:
        revocation_entries.append(
            {
                "key_id": revoked_key_id,
                "state": "REVOKED",
                "revoked_at_utc": _SIGNED_AT,
                "reason": "fixture revocation",
            }
        )
    revocation_log = {
        "schema": REVOCATION_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "campaign_nonce": campaign["campaign_nonce"],
        "registry_epoch": 1,
        "entries": revocation_entries,
    }

    def admin_approvals(payload: dict[str, object], schema: str, domain: bytes, label: str) -> list[dict[str, object]]:
        return [
            _envelope(
                payload,
                artifact_schema=schema,
                domain=domain,
                private=admin_private[i],
                label=f"{label}:{i}",
            )
            for i in (0, 1)
        ]

    technical_indices = technical_indices or [i % 4 for i in range(16)]
    contributor_indices = contributor_indices or list(range(16))
    lineage_indices = [(i // 4) % 4 for i in range(16)]
    units: list[dict[str, object]] = []
    for index, slot in enumerate(SLOTS):
        source_hash = _digest(f"source:{index}")
        archive_hash = _digest(f"archive:{index}")
        if duplicate_artifact in {"archive", "both"} and index == 1:
            archive_hash = _digest("archive:0")
        if duplicate_artifact in {"source", "both"} and index == 1:
            source_hash = _digest("source:0")
        contributor_key_id = contributor_keys[contributor_indices[index]]
        contributor_entity = by_key_id[contributor_key_id]["entity_id"]
        contributor = {
            "schema": CONTRIBUTOR_SCHEMA,
            "campaign_id": campaign["campaign_id"],
            "campaign_nonce": campaign["campaign_nonce"],
            "unit_nonce": f"{index + 1:032x}",
            "slot_id": slot,
            "contributor": {"key_id": contributor_key_id, "entity_id": contributor_entity},
            "source": {
                "source_tree_sha256": source_hash,
                "vcs_bundle_sha256": _digest(f"vcs:{index}"),
                "commit_head": f"commit-{index:02d}",
                "history_root_sha256": _digest(f"history:{index}"),
                "license": "Apache-2.0",
            },
            "archive": {
                "archive_sha256": archive_hash,
                "package_sha256": _digest(f"package:{index}"),
                "file_manifest_root_sha256": _digest(f"manifest:{index}"),
            },
            "build": {
                "build_recipe_sha256": _digest(f"recipe:{index}"),
                "build_container_digest": campaign["build_container_digest"],
                "toolchain_lock_sha256": _digest(f"toolchain:{index}"),
                "expected_archive_sha256": archive_hash,
            },
            "engine": {
                "engine_version": "engine-v623",
                "engine_sha256": campaign["engine_sha256"],
                "ruleset_sha256": campaign["ruleset_sha256"],
            },
            "authorship_ancestry": {
                "authors": [f"author-{index:02d}"],
                "prior_sources": [],
                "forks_or_derivations": [],
                "codegen_tools": [],
                "independence_declaration": "independent fixture unit",
                "development_window_utc": ["2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"],
                "exposure_declaration": "no shared development exposure",
            },
        }
        technical_key_id = technical_keys[technical_indices[index]]
        lineage_key_id = lineage_keys[lineage_indices[index]]
        technical_entity = by_key_id[technical_key_id]["entity_id"]
        lineage_entity = by_key_id[lineage_key_id]["entity_id"]
        if overlap == "role-alias" and index == 0:
            technical_key_id = contributor_key_id
            technical_entity = contributor["contributor"]["entity_id"]
        elif overlap == "entity-overlap" and index == 0:
            technical_entity = contributor["contributor"]["entity_id"]
        technical = {
            "schema": TECHNICAL_SCHEMA,
            "campaign_id": campaign["campaign_id"],
            "campaign_nonce": campaign["campaign_nonce"],
            "unit_nonce": contributor["unit_nonce"],
            "slot_id": slot,
            "audit_session_id": f"{index + 0x100:032x}" if not (duplicate_audit_session and index == 1) else f"{0x100:032x}",
            "contributor_manifest_sha256": canonical_sha256(contributor),
            "auditor": {"key_id": technical_key_id, "entity_id": technical_entity},
            "source_checkout_sha256": source_hash,
            "build_recipe_sha256": contributor["build"]["build_recipe_sha256"],
            "build_container_digest": campaign["build_container_digest"],
            "toolchain_lock_sha256": contributor["build"]["toolchain_lock_sha256"],
            "commands_manifest_sha256": _digest(f"commands:{index}"),
            "expected_archive_sha256": archive_hash,
            "produced_archive_sha256": archive_hash,
            "engine_sha256": campaign["engine_sha256"],
            "ruleset_sha256": campaign["ruleset_sha256"],
            "linux": {
                "arch": "linux/amd64",
                "container_digest": campaign["build_container_digest"],
                "startup_log_sha256": _digest(f"startup:{index}"),
                "run_log_sha256": _digest(f"run:{index}"),
                "deterministic_handshake_sha256": _digest(f"handshake:{index}"),
                "crash_count": 0,
                "timeout_count": 0,
            },
            "safety": {
                "policy_sha256": campaign["safety_policy_sha256"],
                "evidence_root_sha256": _digest(f"safety:{index}"),
                "dudunsparce_audit_sha256": campaign["dudunsparce_harness_sha256"],
                "disallowed_syscall_count": 0,
                "network_violation_count": 0,
                "filesystem_violation_count": 0,
                "process_violation_count": 0,
            },
            "evidence_roots": {
                "repro_evidence_root_sha256": _digest(f"repro:{index}"),
                "linux_evidence_root_sha256": _digest(f"linux:{index}"),
                "safety_evidence_root_sha256": _digest(f"safety:{index}"),
            },
        }
        lineage = {
            "schema": LINEAGE_SCHEMA,
            "campaign_id": campaign["campaign_id"],
            "campaign_nonce": campaign["campaign_nonce"],
            "unit_nonce": contributor["unit_nonce"],
            "slot_id": slot,
            "audit_session_id": f"{index + 0x200:032x}" if not (duplicate_audit_session and index == 1) else f"{0x200:032x}",
            "contributor_manifest_sha256": canonical_sha256(contributor),
            "auditor": {"key_id": lineage_key_id, "entity_id": lineage_entity},
            "vcs_bundle_sha256": contributor["source"]["vcs_bundle_sha256"],
            "commit_graph_sha256": _digest(f"commit-graph:{index}"),
            "authorship_evidence_sha256": _digest(f"authorship:{index}"),
            "public_references_root_sha256": _digest(f"references:{index}"),
            "similarity_report_root_sha256": _digest(f"similarity:{index}"),
            "provenance_evidence_root_sha256": _digest(f"provenance:{index}"),
            "findings": [
                {
                    "other_slot_id": other,
                    "relation": "INDEPENDENT",
                    "evidence_root_sha256": _digest(f"finding:{index}:{other}"),
                }
                for other in SLOTS
                if other != slot
            ],
        }
        contributor_private = private_by_key_id[contributor_key_id]
        technical_private = private_by_key_id.get(technical_key_id, _key("unregistered-role-alias"))
        lineage_private = private_by_key_id[lineage_key_id]
        units.append(
            {
                "slot_id": slot,
                "contributor_manifest": contributor,
                "contributor_signature": _envelope(
                    contributor,
                    artifact_schema=CONTRIBUTOR_SCHEMA,
                    domain=DOMAIN_CONTRIBUTOR,
                    private=contributor_private,
                    label=f"contributor:{index}",
                ),
                "technical_receipt": technical,
                "technical_signature": _envelope(
                    technical,
                    artifact_schema=TECHNICAL_SCHEMA,
                    domain=DOMAIN_TECHNICAL,
                    private=technical_private,
                    label=f"technical:{index}",
                ),
                "lineage_receipt": lineage,
                "lineage_signature": _envelope(
                    lineage,
                    artifact_schema=LINEAGE_SCHEMA,
                    domain=DOMAIN_LINEAGE,
                    private=lineage_private,
                    label=f"lineage:{index}",
                ),
            }
        )

    graph = {
        "schema": POPULATION_GRAPH_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "campaign_nonce": campaign["campaign_nonce"],
        "nodes": [
            {
                "slot_id": unit["slot_id"],
                "source_tree_sha256": unit["contributor_manifest"]["source"]["source_tree_sha256"],
                "contributor_manifest_sha256": canonical_sha256(unit["contributor_manifest"]),
                "technical_receipt_sha256": canonical_sha256(unit["technical_receipt"]),
                "lineage_receipt_sha256": canonical_sha256(unit["lineage_receipt"]),
            }
            for unit in units
        ],
        "edges": [
            {
                "left_slot_id": SLOTS[left],
                "right_slot_id": SLOTS[right],
                "relation": "INDEPENDENT",
                "evidence_root_sha256": _digest(f"edge:{left}:{right}"),
            }
            for left in range(len(SLOTS))
            for right in range(left + 1, len(SLOTS))
        ],
    }
    assignments = []
    for index, slot in enumerate(SLOTS):
        family_root = _digest(f"family-root:{index}")
        lineage_root = _digest(f"lineage-root:{index}")
        source_tree = units[index]["contributor_manifest"]["source"]["source_tree_sha256"]
        assignments.append(
            {
                "slot_id": slot,
                "source_family_id": "sf-" + canonical_sha256({"members": [source_tree], "evidence_root": family_root})[:24],
                "lineage_time_block_id": "lt-" + canonical_sha256({"component": [slot], "evidence_root": lineage_root})[:24],
                "intervention_family_id": f"intervention-{index % 5}",
                "family_evidence_root_sha256": family_root,
                "lineage_evidence_root_sha256": lineage_root,
            }
        )
    population_decision = {
        "schema": POPULATION_DECISION_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "campaign_nonce": campaign["campaign_nonce"],
        "population_graph_sha256": canonical_sha256(graph),
        "assignments": assignments,
    }
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "campaign": campaign,
        "registry": registry,
        "registry_approvals": admin_approvals(registry, REGISTRY_SCHEMA, DOMAIN_REGISTRY, "registry"),
        "revocation_log": revocation_log,
        "revocation_approvals": admin_approvals(revocation_log, REVOCATION_SCHEMA, DOMAIN_REVOCATION, "revocation"),
        "units": units,
        "population_graph": graph,
        "population_decision": population_decision,
        "population_decision_approvals": [
            _envelope(
                population_decision,
                artifact_schema=POPULATION_DECISION_SCHEMA,
                domain=DOMAIN_POPULATION,
                private=private_by_key_id[key_id],
                label=f"adjudicator:{index}",
            )
            for index, key_id in enumerate(adjudicator_keys[:2])
        ],
    }
    verifier = _FakeExternalVerifier(
        campaign,
        _key("external-verifier"),
        trusted_time_utc=trusted_time_utc,
        unsigned=unsigned_external,
    )
    return _Fixture(bundle, admins, verifier, verifier.pinned, private_by_key_id)


def _assert_no_authority(verdict: dict[str, object]) -> None:
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []
    assert verdict["sealed_holdout_accessed"] is False


def test_valid_bundle_without_external_verifier_is_structural_only() -> None:
    fixture = _make_fixture()
    verdict = verify_population_trust_bundle(fixture.bundle, pinned_registry_admins=fixture.admins)
    assert verdict["state"] == "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER"
    assert verdict["cryptographic_bundle_valid"] is True
    assert verdict["external_authentication_verified"] is False
    assert verdict["semantic_artifact_verification_complete"] is False
    assert verdict["population_feasible"] is False
    assert verdict["checks"]["timestamps_valid"] is False
    assert verdict["checks"]["technical_audits_verified_16"] is False
    assert verdict["checks"]["lineage_audits_verified_16"] is False
    _assert_no_authority(verdict)


@pytest.mark.parametrize(
    ("supply_callback", "supply_pin"),
    [(True, False), (False, True), (True, True)],
)
def test_retired_external_verification_inputs_are_population_infeasible(
    supply_callback: bool, supply_pin: bool
) -> None:
    fixture = _make_fixture()
    verdict = assess_population_trust_bundle(
        fixture.bundle,
        pinned_registry_admins=fixture.admins,
        external_verifier=fixture.verifier if supply_callback else None,
        pinned_external_verifier=fixture.pinned_verifier if supply_pin else None,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    assert "callback-based external verification route is retired" in verdict["failure"]
    assert verdict["cryptographic_bundle_valid"] is False
    assert verdict["external_authentication_verified"] is False
    assert verdict["semantic_artifact_verification_complete"] is False
    assert verdict["population_feasible"] is False
    assert verdict["checks"] == {}
    assert fixture.verifier.calls == 0
    _assert_no_authority(verdict)


def test_unsigned_caller_authored_external_pass_cannot_open_retired_gate() -> None:
    fixture = _make_fixture(unsigned_external=True)
    verdict = assess_population_trust_bundle(
        fixture.bundle,
        pinned_registry_admins=fixture.admins,
        external_verifier=fixture.verifier,
        pinned_external_verifier=fixture.pinned_verifier,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    assert "callback-based external verification route is retired" in verdict["failure"]
    assert verdict["checks"] == {}
    assert fixture.verifier.calls == 0
    _assert_no_authority(verdict)


def test_mismatched_trusted_timestamp_cannot_open_retired_gate() -> None:
    fixture = _make_fixture(trusted_time_utc="2026-07-16T00:10:01Z")
    verdict = assess_population_trust_bundle(
        fixture.bundle,
        pinned_registry_admins=fixture.admins,
        external_verifier=fixture.verifier,
        pinned_external_verifier=fixture.pinned_verifier,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    assert "callback-based external verification route is retired" in verdict["failure"]
    assert verdict["checks"] == {}
    assert fixture.verifier.calls == 0
    _assert_no_authority(verdict)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("missing-admin", "registry governance requires at least two"),
        ("tampered-payload", "payload_sha256"),
        ("tampered-signature", "signature verification failed"),
        ("duplicate-nonce", "unit_nonce values must be globally unique"),
        ("role-alias", "requires registry role TECH_AUDITOR"),
        ("entity-overlap", "technical auditor entity does not match"),
        ("contributor-cap", "contributors require"),
        ("technical-cap", "technical auditors require"),
        ("revoked", "revoked or compromised keys"),
        ("unknown-edge", "unknown, shared, derived, or conflicting lineage"),
        ("wrong-family-id", "source_family_id is not auditor-derived"),
        ("wrong-lineage-id", "lineage_time_block_id is not auditor-derived"),
        ("duplicate-adjudicator", "population adjudicator is unknown or duplicated"),
        ("duplicate-audit-session", "audit_session_id is replayed"),
        ("duplicate-timestamp-token", "timestamp token digest is replayed"),
        ("duplicate-archive", "all 16 archive_sha256 values"),
        ("duplicate-source", "all 16 source_tree_sha256 values"),
    ],
)
def test_invalid_bundle_mutations_fail_closed(mutation: str, expected: str) -> None:
    options: dict[str, object] = {}
    if mutation == "contributor-cap":
        options["contributor_indices"] = [0, 0, 0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    if mutation == "technical-cap":
        options["technical_indices"] = [0] * 5 + [1] * 3 + [2] * 4 + [3] * 4
    if mutation == "revoked":
        options["revoked"] = True
    if mutation == "duplicate-audit-session":
        options["duplicate_audit_session"] = True
    if mutation in {"role-alias", "entity-overlap"}:
        options["overlap"] = mutation
    if mutation == "duplicate-archive":
        options["duplicate_artifact"] = "archive"
    if mutation == "duplicate-source":
        options["duplicate_artifact"] = "source"
    fixture = _make_fixture(**options)
    bundle = fixture.bundle
    if mutation == "missing-admin":
        bundle["registry_approvals"] = bundle["registry_approvals"][:1]
    elif mutation == "tampered-payload":
        bundle["units"][0]["contributor_manifest"]["source"]["commit_head"] = "tampered-commit"
    elif mutation == "tampered-signature":
        bundle["units"][0]["contributor_signature"]["signature_ed25519_base64"] = (
            bundle["units"][1]["contributor_signature"]["signature_ed25519_base64"]
        )
    elif mutation == "duplicate-nonce":
        bundle["units"][1]["contributor_manifest"]["unit_nonce"] = bundle["units"][0]["contributor_manifest"]["unit_nonce"]
    elif mutation == "unknown-edge":
        bundle["population_graph"]["edges"][0]["relation"] = "UNKNOWN"
    elif mutation == "wrong-family-id":
        bundle["population_decision"]["assignments"][0]["source_family_id"] = "sf-" + "0" * 24
    elif mutation == "wrong-lineage-id":
        bundle["population_decision"]["assignments"][0]["lineage_time_block_id"] = "lt-" + "0" * 24
    elif mutation == "duplicate-adjudicator":
        bundle["population_decision_approvals"][1] = deepcopy(bundle["population_decision_approvals"][0])
    elif mutation == "duplicate-timestamp-token":
        bundle["units"][1]["contributor_signature"]["timestamp_token_sha256"] = bundle["units"][0]["contributor_signature"]["timestamp_token_sha256"]
    with pytest.raises(AttestationV623Error, match=expected):
        verify_population_trust_bundle(bundle, pinned_registry_admins=fixture.admins)


def test_assess_population_trust_bundle_is_stably_population_infeasible() -> None:
    fixture = _make_fixture()
    malformed = {"schema": BUNDLE_SCHEMA}
    first = assess_population_trust_bundle(malformed, pinned_registry_admins=fixture.admins)
    second = assess_population_trust_bundle(malformed, pinned_registry_admins=fixture.admins)
    assert first == second
    assert first == {
        "schema": VERDICT_SCHEMA,
        "state": "POPULATION_INFEASIBLE",
        "failure": "population trust bundle fields must exactly be ['campaign', 'population_decision', 'population_decision_approvals', 'population_graph', 'registry', 'registry_approvals', 'revocation_approvals', 'revocation_log', 'schema', 'units']",
        "cryptographic_bundle_valid": False,
        "external_authentication_verified": False,
        "semantic_artifact_verification_complete": False,
        "population_feasible": False,
        "checks": {},
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }
