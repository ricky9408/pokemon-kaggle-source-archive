from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from evaluation_v5_1.blind_activation import (
    G09_ACCESS_EVENT_SCHEMA,
    G09_ACTIVATION_RULE_SCHEMA,
    G09_ACTIVATION_TRIGGER_SCHEMA,
    G09_LOG_CLOSE_SCHEMA,
    G09_LOG_GENESIS_SCHEMA,
    G09_LOG_RECEIPT_SCHEMA,
    G09_NONCE_COMMITMENT_SCHEMA,
    G09_NONCE_REVEAL_SCHEMA,
    G09_PACKAGE_COMMITMENT_SCHEMA,
    G09_REGISTRY_SCHEMA,
    G09_ROSTER_COMMITMENT_SCHEMA,
    G09_ROSTER_SCHEMA,
    G09_RECIPIENT_KEY_REVEAL_SCHEMA,
    G09_SHARE_RELEASE_SCHEMA,
    G09_THRESHOLD_POLICY_SCHEMA,
    G09_V2_DEPENDENCIES_SCHEMA,
    G09_WORM_PUBLICATION_MEDIA_TYPE,
    G09_WORM_PROVIDER_RECEIPT_SCHEMA,
    THRESHOLD_SCHEME,
    BlindActivationError,
    derive_blind_commitment_set_root,
    derive_blind_activation_audit,
    derive_blind_activation_gate_payload,
    derive_activation_trigger_commitment,
    derive_log_close_root,
    derive_log_event_hashes_root,
    derive_log_genesis_root,
    derive_log_worm_root,
    derive_nonce_commitment,
    derive_package_aad,
    derive_package_commitment,
    derive_roster_commitment,
    derive_recipient_private_key_reveal_commitment,
    derive_share_commitment,
    derive_share_seal_aad,
    derive_threshold_shares,
    reconstruct_threshold_secret,
    seal_threshold_share,
    verify_blind_activation_evidence,
)
from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload


CAMPAIGN = "1" * 64
SPEC = "2" * 64
G08 = "3" * 64
EVALUATION = "g09-test-campaign"
ACTIVATION = "2026-08-01T12:00:00.000000Z"
OBSERVED = "2026-08-01T12:05:00.000000Z"
PRE = "2026-08-01T11:58:00.000000Z"
POST = "2026-08-01T12:01:00.000000Z"


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _signed(schema: str, payload: dict[str, object], key: tuple[Ed25519PrivateKey, bytes]) -> dict[str, object]:
    private, public = key
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _blob(raw: bytes, media_type: str = "application/octet-stream") -> dict[str, object]:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def _json(value: object) -> dict[str, object]:
    return _blob(canonical_json_bytes(value), "application/json")


def _decode_json(value: dict[str, object]) -> object:
    return json.loads(base64.b64decode(value["base64"]))


def _binding(registry_hash: str) -> dict[str, str]:
    return {
        "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "campaign_root": CAMPAIGN,
        "evaluation_id": EVALUATION,
        "frozen_spec_hash": SPEC,
        "campaign_registry_hash": registry_hash,
        "g08_result_root": G08,
    }


def _content(payload: dict[str, object]) -> dict[str, object]:
    return {**payload, "content_sha256": canonical_sha256(payload)}


def _fixture(*, stale: bool = False, revoked: bool = False) -> dict[str, object]:
    keys = {
        "registrar": _key(11),
        "activation_service": _key(12),
        "evidence_custodian": _key(13),
        "custodian_1": _key(14),
        "custodian_2": _key(15),
        "custodian_3": _key(16),
        "worm_publication_service": _key(17),
    }
    roles = []
    for role in sorted(keys):
        not_after = "2026-08-02T00:00:00.000000Z"
        revoked_at: str | None = None
        if role == "custodian_1" and stale:
            not_after = "2026-08-01T12:00:00.000000Z"
        if role == "custodian_1" and revoked:
            revoked_at = ACTIVATION
        roles.append(
            {
                "role": role,
                "principal_id": f"{role}-principal",
                "key_id": f"{role}-key-1",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(keys[role][1]).decode("ascii"),
                "not_before_utc": "2026-07-01T00:00:00.000000Z",
                "not_after_utc": not_after,
                "revoked_at_utc": revoked_at,
                "compromised_at_utc": None,
            }
        )
    registry = _content(
        {
            "schema": G09_REGISTRY_SCHEMA,
            "protocol_id": "MCI_FAMILY_TRANSFER_V2",
            "campaign_root": CAMPAIGN,
            "evaluation_id": EVALUATION,
            "frozen_spec_hash": SPEC,
            "roles": roles,
        }
    )
    registry_evidence = _json(registry)
    registry_hash = registry_evidence["sha256"]
    assert isinstance(registry_hash, str)
    binding = _binding(registry_hash)

    packages = [b"blind package one", b"blind package two"]
    archives = sorted(hashlib.sha256(package).hexdigest() for package in packages)
    package_by_archive = {hashlib.sha256(package).hexdigest(): package for package in packages}
    roster = _content(
        {
            "schema": G09_ROSTER_SCHEMA,
            **binding,
            "selected_archives": [
                {"family_id": f"family-{index + 1}", "archive_sha256": archive}
                for index, archive in enumerate(archives)
            ],
        }
    )
    roster_evidence = _json(roster)
    dependencies = _content(
        {
            "schema": G09_V2_DEPENDENCIES_SCHEMA,
            "protocol_id": "MCI_FAMILY_TRANSFER_V2",
            "campaign_root": CAMPAIGN,
            "evaluation_id": EVALUATION,
            "frozen_spec_hash": SPEC,
            "campaign_registry_hash": registry_hash,
            "g08_result_root": G08,
            "g08_roster_sha256": roster_evidence["sha256"],
            "direct_dependencies": [
                {
                    "gate_id": "G00_TRUST_ROOTS",
                    "bundle_sha256": "4" * 64,
                    "authority_payload_sha256": "5" * 64,
                    "decision": "PASS_RESEARCH_ONLY",
                },
                {
                    "gate_id": "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION",
                    "bundle_sha256": G08,
                    "authority_payload_sha256": G08,
                    "decision": "PASS_RESEARCH_ONLY",
                },
            ],
        }
    )
    dependencies_evidence = _json(dependencies)
    dependencies_sha = dependencies_evidence["sha256"]
    assert isinstance(dependencies_sha, str)

    activation_private = bytes(range(1, 33))
    activation_public = X25519PrivateKey.from_private_bytes(activation_private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    recipient_commitment = derive_recipient_private_key_reveal_commitment(
        **binding,
        policy_id="activation-key-1",
        activation_recipient_private_key=activation_private,
    )
    data_key = bytes(range(32, 64))
    shares = derive_threshold_shares(
        data_key, threshold=2, share_count=3, coefficient_material=b"fixture-coefficients"
    )
    share_commitments = []
    for index, share in shares:
        role = f"custodian_{index}"
        share_commitments.append(
            {
                "custodian_role": role,
                "share_index": index,
                "share_commitment_sha256": derive_share_commitment(
                    **binding,
                    policy_id="activation-key-1",
                    custodian_role=role,
                    share_index=index,
                    share=share,
                ),
            }
        )
    policy = _content(
        {
            "schema": G09_THRESHOLD_POLICY_SCHEMA,
            **binding,
            "activation_time_utc": ACTIVATION,
            "policy_id": "activation-key-1",
            "scheme": THRESHOLD_SCHEME,
            "threshold": 2,
            "activation_recipient_public_key_base64": base64.b64encode(activation_public).decode("ascii"),
            "activation_recipient_private_key_reveal_commitment_sha256": recipient_commitment,
            "share_commitments": share_commitments,
            "issued_at_utc": PRE,
            "role": "registrar",
            "key_id": "registrar-key-1",
        }
    )
    policy_evidence = _json(_signed(G09_THRESHOLD_POLICY_SCHEMA, policy, keys["registrar"]))
    policy_sha = canonical_sha256(policy)

    roster_envelopes: list[dict[str, object]] = []
    nonce_envelopes: list[dict[str, object]] = []
    package_envelopes: list[dict[str, object]] = []
    reveal_envelopes: list[dict[str, object]] = []
    for index, archive in enumerate(archives):
        family = f"family-{index + 1}"
        package = package_by_archive[archive]
        nonce = bytes([index + 1]) * 12
        nonce_commitment = derive_nonce_commitment(
            **binding,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
            nonce=nonce,
        )
        aad = derive_package_aad(
            **binding,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
            nonce_commitment_sha256=nonce_commitment,
        )
        ciphertext = AESGCM(data_key).encrypt(nonce, package, aad)
        common = {
            **binding,
            "family_id": family,
            "archive_sha256": archive,
            "package_sha256": archive,
        }
        roster_envelopes.append(
            _signed(
                G09_ROSTER_COMMITMENT_SCHEMA,
                {
                    **common,
                    "roster_commitment_sha256": derive_roster_commitment(**common),
                    "committed_at_utc": PRE,
                    "role": "registrar",
                    "key_id": "registrar-key-1",
                },
                keys["registrar"],
            )
        )
        nonce_envelopes.append(
            _signed(
                G09_NONCE_COMMITMENT_SCHEMA,
                {
                    **common,
                    "nonce_commitment_sha256": nonce_commitment,
                    "committed_at_utc": PRE,
                    "role": "registrar",
                    "key_id": "registrar-key-1",
                },
                keys["registrar"],
            )
        )
        package_envelopes.append(
            _signed(
                G09_PACKAGE_COMMITMENT_SCHEMA,
                {
                    **common,
                    "nonce_commitment_sha256": nonce_commitment,
                    "ciphertext": _blob(ciphertext),
                    "aad": _blob(aad, "application/json"),
                    "package_commitment_sha256": derive_package_commitment(
                        **common,
                        nonce_commitment_sha256=nonce_commitment,
                        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
                        aad_sha256=hashlib.sha256(aad).hexdigest(),
                    ),
                    "committed_at_utc": PRE,
                    "role": "registrar",
                    "key_id": "registrar-key-1",
                },
                keys["registrar"],
            )
        )
        reveal_envelopes.append(
            _signed(
                G09_NONCE_REVEAL_SCHEMA,
                {
                    **common,
                    "nonce": _blob(nonce),
                    "revealed_at_utc": POST,
                    "role": "registrar",
                    "key_id": "registrar-key-1",
                },
                keys["registrar"],
            )
        )

    roster_commitments_evidence = _json(roster_envelopes)
    nonce_commitments_evidence = _json(nonce_envelopes)
    package_commitments_evidence = _json(package_envelopes)
    blind_commitment_set_root = derive_blind_commitment_set_root(
        expected=binding,
        common_v2_dependencies_sha256=dependencies_sha,
        expected_g08_roster_sha256=roster_evidence["sha256"],  # type: ignore[arg-type]
        threshold_policy_evidence_sha256=policy_evidence["sha256"],  # type: ignore[arg-type]
        roster_commitments_evidence_sha256=roster_commitments_evidence["sha256"],  # type: ignore[arg-type]
        nonce_commitments_evidence_sha256=nonce_commitments_evidence["sha256"],  # type: ignore[arg-type]
        package_commitments_evidence_sha256=package_commitments_evidence["sha256"],  # type: ignore[arg-type]
    )
    log_id = "blind-activation-log-1"

    def publication_receipt(
        *,
        phase: str,
        generation: int,
        prior_publication_receipt_sha256: str,
        causal_predecessor_root_sha256: str,
        activation_trigger_envelope_sha256: str,
        event_hashes: list[str],
        published_at_utc: str,
    ) -> dict[str, object]:
        count = len(event_hashes)
        payload = {
            **binding,
            "provider": "test-worm-provider",
            "immutable_object_id": "g09-log-object-1",
            "retention_mode": "COMPLIANCE_WORM",
            "generation": generation,
            "prior_publication_receipt_sha256": prior_publication_receipt_sha256,
            "log_id": log_id,
            "phase": phase,
            "first_sequence": 0,
            "next_sequence": count,
            "cursor_start": "cursor-0",
            "cursor_end": f"cursor-{count}",
            "range_start_sequence": 0,
            "range_end_sequence_exclusive": count,
            "event_count": count,
            "last_event_envelope_sha256": event_hashes[-1] if event_hashes else "0" * 64,
            "event_hashes_root_sha256": derive_log_event_hashes_root(event_hashes),
            "worm_object_root_sha256": derive_log_worm_root(
                log_id=log_id,
                causal_predecessor_root_sha256=causal_predecessor_root_sha256,
                event_hashes=event_hashes,
            ),
            "causal_predecessor_root_sha256": causal_predecessor_root_sha256,
            "activation_trigger_envelope_sha256": activation_trigger_envelope_sha256,
            "blind_commitment_set_root_sha256": blind_commitment_set_root,
            "published_at_utc": published_at_utc,
            "role": "worm_publication_service",
            "key_id": "worm_publication_service-key-1",
        }
        return _blob(
            canonical_json_bytes(
                _signed(
                    G09_WORM_PROVIDER_RECEIPT_SCHEMA,
                    payload,
                    keys["worm_publication_service"],
                )
            ),
            G09_WORM_PUBLICATION_MEDIA_TYPE,
        )

    genesis_publication = publication_receipt(
        phase="GENESIS",
        generation=0,
        prior_publication_receipt_sha256="0" * 64,
        causal_predecessor_root_sha256="0" * 64,
        activation_trigger_envelope_sha256="0" * 64,
        event_hashes=[],
        published_at_utc=PRE,
    )
    genesis_receipt_payload = {
        **binding,
        "log_id": log_id,
        "phase": "GENESIS",
        "prior_receipt_envelope_sha256": "0" * 64,
        "causal_predecessor_root_sha256": "0" * 64,
        "activation_trigger_envelope_sha256": "0" * 64,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "first_sequence": 0,
        "next_sequence": 0,
        "cursor_start": "cursor-0",
        "cursor_end": "cursor-0",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": 0,
        "event_count": 0,
        "last_event_envelope_sha256": "0" * 64,
        "event_hashes_root_sha256": derive_log_event_hashes_root([]),
        "worm_object_root_sha256": derive_log_worm_root(
            log_id=log_id,
            causal_predecessor_root_sha256="0" * 64,
            event_hashes=[],
        ),
        "publication_receipt": genesis_publication,
        "published_at_utc": PRE,
        "role": "evidence_custodian",
        "key_id": "evidence_custodian-key-1",
    }
    genesis_receipt = _signed(
        G09_LOG_RECEIPT_SCHEMA, genesis_receipt_payload, keys["evidence_custodian"]
    )
    genesis_receipt_hash = canonical_sha256(genesis_receipt)
    genesis_committed_at = "2026-08-01T11:59:00.000000Z"
    genesis_root = derive_log_genesis_root(
        expected=binding,
        common_v2_dependencies_sha256=dependencies_sha,
        threshold_policy_sha256=policy_sha,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        activation_time_utc=ACTIVATION,
        log_id=log_id,
        first_sequence=0,
        cursor_start="cursor-0",
        range_start_sequence=0,
        previous_event_sha256="0" * 64,
        genesis_receipt_envelope_sha256=genesis_receipt_hash,
        recipient_private_key_reveal_commitment_sha256=recipient_commitment,
        committed_at_utc=genesis_committed_at,
    )

    def dual(schema: str, core: dict[str, object]) -> list[dict[str, object]]:
        return [
            _signed(
                schema,
                {**core, "role": role, "key_id": f"{role}-key-1"},
                keys[role],
            )
            for role in ("activation_service", "evidence_custodian")
        ]

    genesis_core = {
        **binding,
        "common_v2_dependencies_sha256": dependencies_sha,
        "threshold_policy_sha256": policy_sha,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "activation_time_utc": ACTIVATION,
        "log_id": log_id,
        "first_sequence": 0,
        "cursor_start": "cursor-0",
        "range_start_sequence": 0,
        "previous_event_sha256": "0" * 64,
        "genesis_receipt_envelope_sha256": genesis_receipt_hash,
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
        "genesis_root_sha256": genesis_root,
        "committed_at_utc": genesis_committed_at,
    }
    genesis_signatures = dual(G09_LOG_GENESIS_SCHEMA, genesis_core)
    trigger_nonce = b"signed-trigger-release-nonce-001"[:32].ljust(32, b"0")
    trigger_commitment = derive_activation_trigger_commitment(
        expected=binding,
        common_v2_dependencies_sha256=dependencies_sha,
        threshold_policy_sha256=policy_sha,
        log_genesis_root_sha256=genesis_root,
        recipient_private_key_reveal_commitment_sha256=recipient_commitment,
        trigger_id="activation-trigger-1",
        trigger_release_nonce=trigger_nonce,
        triggered_at_utc=ACTIVATION,
    )
    activation_rule = _content(
        {
            "schema": G09_ACTIVATION_RULE_SCHEMA,
            **binding,
            "activation_time_utc": ACTIVATION,
            "rule_id": "G09_BLIND_ACTIVATION_TIME_V1",
            "common_v2_dependencies_sha256": dependencies_sha,
            "threshold_policy_sha256": policy_sha,
            "blind_commitment_set_root_sha256": blind_commitment_set_root,
            "log_genesis_root_sha256": genesis_root,
            "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
            "activation_trigger_commitment_sha256": trigger_commitment,
            "require_no_pre_activation_quorum": True,
            "require_no_pre_activation_plaintext_or_access": True,
            "issued_at_utc": genesis_committed_at,
            "role": "registrar",
            "key_id": "registrar-key-1",
        }
    )
    activation_rule_envelope = _signed(
        G09_ACTIVATION_RULE_SCHEMA, activation_rule, keys["registrar"]
    )
    activation_rule_evidence = _json(activation_rule_envelope)
    trigger_payload = {
        **binding,
        "activation_rule_sha256": activation_rule_evidence["sha256"],
        "common_v2_dependencies_sha256": dependencies_sha,
        "threshold_policy_sha256": policy_sha,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "log_genesis_root_sha256": genesis_root,
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
        "trigger_id": "activation-trigger-1",
        "trigger_release_nonce": _blob(trigger_nonce),
        "activation_trigger_commitment_sha256": trigger_commitment,
        "triggered_at_utc": ACTIVATION,
        "role": "activation_service",
        "key_id": "activation_service-key-1",
    }
    trigger_envelope = _signed(
        G09_ACTIVATION_TRIGGER_SCHEMA, trigger_payload, keys["activation_service"]
    )
    trigger_hash = canonical_sha256(trigger_envelope)
    empty_event_root = derive_log_event_hashes_root([])
    preactivation_publication = publication_receipt(
        phase="PREACTIVATION",
        generation=1,
        prior_publication_receipt_sha256=genesis_publication["sha256"],  # type: ignore[arg-type]
        causal_predecessor_root_sha256=genesis_root,
        activation_trigger_envelope_sha256=trigger_hash,
        event_hashes=[],
        published_at_utc=ACTIVATION,
    )
    preactivation_receipt_payload = {
        **binding,
        "log_id": log_id,
        "phase": "PREACTIVATION",
        "prior_receipt_envelope_sha256": genesis_receipt_hash,
        "causal_predecessor_root_sha256": genesis_root,
        "activation_trigger_envelope_sha256": trigger_hash,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "first_sequence": 0,
        "next_sequence": 0,
        "cursor_start": "cursor-0",
        "cursor_end": "cursor-0",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": 0,
        "event_count": 0,
        "last_event_envelope_sha256": "0" * 64,
        "event_hashes_root_sha256": empty_event_root,
        "worm_object_root_sha256": derive_log_worm_root(
            log_id=log_id,
            causal_predecessor_root_sha256=genesis_root,
            event_hashes=[],
        ),
        "publication_receipt": preactivation_publication,
        "published_at_utc": ACTIVATION,
        "role": "evidence_custodian",
        "key_id": "evidence_custodian-key-1",
    }
    preactivation_receipt = _signed(
        G09_LOG_RECEIPT_SCHEMA,
        preactivation_receipt_payload,
        keys["evidence_custodian"],
    )
    preactivation_receipt_hash = canonical_sha256(preactivation_receipt)
    preclose_core = {
        **binding,
        "close_kind": "PREACTIVATION_ZERO_ACCESS",
        "log_id": log_id,
        "log_genesis_root_sha256": genesis_root,
        "activation_trigger_envelope_sha256": trigger_hash,
        "predecessor_close_root_sha256": genesis_root,
        "worm_receipt_envelope_sha256": preactivation_receipt_hash,
        "first_sequence": 0,
        "next_sequence": 0,
        "cursor_start": "cursor-0",
        "cursor_end": "cursor-0",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": 0,
        "event_count": 0,
        "last_event_envelope_sha256": "0" * 64,
        "event_hashes_root_sha256": empty_event_root,
        "closed_at_utc": ACTIVATION,
    }
    preclose_core["close_root_sha256"] = derive_log_close_root(
        expected=binding,
        **{
            key: value
            for key, value in preclose_core.items()
            if key not in binding
        },
    )
    preclose_signatures = dual(G09_LOG_CLOSE_SCHEMA, preclose_core)
    preclose_root = preclose_core["close_root_sha256"]
    assert isinstance(preclose_root, str)
    recipient_reveal_payload = {
        **binding,
        "threshold_policy_sha256": policy_sha,
        "activation_trigger_envelope_sha256": trigger_hash,
        "preactivation_close_root_sha256": preclose_root,
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
        "activation_recipient_private_key": _blob(activation_private),
        "revealed_at_utc": POST,
        "role": "activation_service",
        "key_id": "activation_service-key-1",
    }
    recipient_reveal_envelope = _signed(
        G09_RECIPIENT_KEY_REVEAL_SCHEMA,
        recipient_reveal_payload,
        keys["activation_service"],
    )
    recipient_reveal_hash = canonical_sha256(recipient_reveal_envelope)

    release_envelopes = []
    for index, share in shares:
        role = f"custodian_{index}"
        commitment = share_commitments[index - 1]["share_commitment_sha256"]
        assert isinstance(commitment, str)
        share_aad = derive_share_seal_aad(
            **binding,
            threshold_policy_sha256=policy_sha,
            custodian_role=role,
            share_index=index,
            share_commitment_sha256=commitment,
        )
        seal = seal_threshold_share(
            share,
            activation_recipient_public_key=activation_public,
            ephemeral_private_key=bytes([90 + index]) * 32,
            nonce=bytes([70 + index]) * 12,
            aad=share_aad,
        )
        release_envelopes.append(
            _signed(
                G09_SHARE_RELEASE_SCHEMA,
                {
                    **binding,
                    "threshold_policy_sha256": policy_sha,
                    "custodian_role": role,
                    "share_index": index,
                    "share_commitment_sha256": commitment,
                    **seal,
                    "released_at_utc": POST,
                    "role": role,
                    "key_id": f"{role}-key-1",
                },
                keys[role],
            )
        )

    events: list[dict[str, object]] = []
    previous = preclose_root

    def event(event_type: str, role: str, details: dict[str, object]) -> None:
        nonlocal previous
        sequence = len(events)
        payload = {
            **binding,
            "threshold_policy_sha256": policy_sha,
            "blind_commitment_set_root_sha256": blind_commitment_set_root,
            "log_id": log_id,
            "log_genesis_root_sha256": genesis_root,
            "preactivation_close_root_sha256": preclose_root,
            "activation_trigger_envelope_sha256": trigger_hash,
            "sequence": sequence,
            "cursor": f"cursor-{sequence + 1}",
            "previous_cursor": f"cursor-{sequence}",
            "event_id": f"event-{sequence}",
            "previous_envelope_sha256": previous,
            "event_type": event_type,
            "occurred_at_utc": POST,
            "role": role,
            "key_id": f"{role}-key-1",
            "details": details,
        }
        signed = _signed(G09_ACCESS_EVENT_SCHEMA, payload, keys[role])
        events.append(signed)
        previous = canonical_sha256(signed)

    event(
        "RECIPIENT_KEY_REVEAL",
        "activation_service",
        {
            "recipient_key_reveal_envelope_sha256": recipient_reveal_hash,
            "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
        },
    )
    for nonce_reveal in reveal_envelopes:
        payload = nonce_reveal["payload"]
        assert isinstance(payload, dict)
        event(
            "NONCE_REVEAL",
            "registrar",
            {
                "nonce_reveal_envelope_sha256": canonical_sha256(nonce_reveal),
                "family_id": payload["family_id"],
                "archive_sha256": payload["archive_sha256"],
                "package_sha256": payload["package_sha256"],
            },
        )
    for release in release_envelopes:
        payload = release["payload"]
        assert isinstance(payload, dict)
        event(
            "SHARE_RELEASE",
            payload["role"],  # type: ignore[arg-type]
            {
                "release_envelope_sha256": canonical_sha256(release),
                "share_index": payload["share_index"],
            },
        )
    for release in release_envelopes:
        payload = release["payload"]
        assert isinstance(payload, dict)
        event(
            "SHARE_DECRYPT",
            "activation_service",
            {
                "release_envelope_sha256": canonical_sha256(release),
                "share_index": payload["share_index"],
            },
        )
    for index, archive in enumerate(archives):
        details = {
            "family_id": f"family-{index + 1}",
            "archive_sha256": archive,
            "package_sha256": archive,
        }
        event("PACKAGE_DECRYPT", "activation_service", details)
        event("PACKAGE_ACCESS", "evidence_custodian", details)

    event_hashes = [canonical_sha256(value) for value in events]
    terminal_publication = publication_receipt(
        phase="TERMINAL",
        generation=2,
        prior_publication_receipt_sha256=preactivation_publication["sha256"],  # type: ignore[arg-type]
        causal_predecessor_root_sha256=preclose_root,
        activation_trigger_envelope_sha256=trigger_hash,
        event_hashes=event_hashes,
        published_at_utc=POST,
    )
    terminal_receipt_payload = {
        **binding,
        "log_id": log_id,
        "phase": "TERMINAL",
        "prior_receipt_envelope_sha256": preactivation_receipt_hash,
        "causal_predecessor_root_sha256": preclose_root,
        "activation_trigger_envelope_sha256": trigger_hash,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "first_sequence": 0,
        "next_sequence": len(events),
        "cursor_start": "cursor-0",
        "cursor_end": f"cursor-{len(events)}",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": len(events),
        "event_count": len(events),
        "last_event_envelope_sha256": event_hashes[-1],
        "event_hashes_root_sha256": derive_log_event_hashes_root(event_hashes),
        "worm_object_root_sha256": derive_log_worm_root(
            log_id=log_id,
            causal_predecessor_root_sha256=preclose_root,
            event_hashes=event_hashes,
        ),
        "publication_receipt": terminal_publication,
        "published_at_utc": POST,
        "role": "evidence_custodian",
        "key_id": "evidence_custodian-key-1",
    }
    terminal_receipt = _signed(
        G09_LOG_RECEIPT_SCHEMA, terminal_receipt_payload, keys["evidence_custodian"]
    )
    terminal_receipt_hash = canonical_sha256(terminal_receipt)
    terminal_time = "2026-08-01T12:02:00.000000Z"
    terminal_core = {
        **binding,
        "close_kind": "POSTACTIVATION_TERMINAL",
        "log_id": log_id,
        "log_genesis_root_sha256": genesis_root,
        "activation_trigger_envelope_sha256": trigger_hash,
        "predecessor_close_root_sha256": preclose_root,
        "worm_receipt_envelope_sha256": terminal_receipt_hash,
        "first_sequence": 0,
        "next_sequence": len(events),
        "cursor_start": "cursor-0",
        "cursor_end": f"cursor-{len(events)}",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": len(events),
        "event_count": len(events),
        "last_event_envelope_sha256": event_hashes[-1],
        "event_hashes_root_sha256": derive_log_event_hashes_root(event_hashes),
        "closed_at_utc": terminal_time,
    }
    terminal_core["close_root_sha256"] = derive_log_close_root(
        expected=binding,
        **{
            key: value
            for key, value in terminal_core.items()
            if key not in binding
        },
    )
    terminal_signatures = dual(G09_LOG_CLOSE_SCHEMA, terminal_core)

    evidence: dict[str, object] = {
        "common_v2_dependencies": dependencies_evidence,
        "campaign_registry": registry_evidence,
        "expected_g08_roster": roster_evidence,
        "activation_rule": activation_rule_evidence,
        "threshold_public_key_policy": policy_evidence,
        "worm_publication_receipts": _json(
            [genesis_receipt, preactivation_receipt, terminal_receipt]
        ),
        "log_genesis_signatures": _json(genesis_signatures),
        "activation_trigger": _json(trigger_envelope),
        "preactivation_close_signatures": _json(preclose_signatures),
        "recipient_key_reveal": _json(recipient_reveal_envelope),
        "roster_commitments": roster_commitments_evidence,
        "blinded_package_commitments": package_commitments_evidence,
        "nonce_commitments": nonce_commitments_evidence,
        "nonce_reveals": _json(reveal_envelopes),
        "key_share_releases": _json(release_envelopes),
        "access_log": _json(events),
        "terminal_close_signatures": _json(terminal_signatures),
        "package_bytes": {archive: _blob(package) for archive, package in package_by_archive.items()},
        "observed_at_utc": OBSERVED,
    }
    return {
        "keys": keys,
        "binding": binding,
        "archives": archives,
        "evidence": evidence,
        "policy_sha": policy_sha,
        "log_id": log_id,
    }


def _audit(bundle: dict[str, object], **changes: object) -> dict[str, object]:
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    evidence.update(changes)
    return derive_blind_activation_audit(**bundle["binding"], **evidence)  # type: ignore[arg-type]


def _replace_json(evidence: dict[str, object], field: str, value: object) -> None:
    evidence[field] = _json(value)


def _resign_log(evidence: dict[str, object], keys: dict[str, tuple[Ed25519PrivateKey, bytes]]) -> None:
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    closes = _decode_json(evidence["preactivation_close_signatures"])  # type: ignore[arg-type]
    assert isinstance(events, list)
    assert isinstance(closes, list)
    previous = closes[0]["payload"]["close_root_sha256"]
    rebuilt = []
    for sequence, envelope in enumerate(events):
        payload = envelope["payload"]
        payload["sequence"] = sequence
        payload["previous_cursor"] = f"cursor-{sequence}"
        payload["cursor"] = f"cursor-{sequence + 1}"
        payload["previous_envelope_sha256"] = previous
        payload["event_id"] = f"event-{sequence}"
        signed = _signed(G09_ACCESS_EVENT_SCHEMA, payload, keys[payload["role"]])
        rebuilt.append(signed)
        previous = canonical_sha256(signed)
    _replace_json(evidence, "access_log", rebuilt)


def _reclose_terminal(
    evidence: dict[str, object],
    keys: dict[str, tuple[Ed25519PrivateKey, bytes]],
) -> None:
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    receipts = _decode_json(evidence["worm_publication_receipts"])  # type: ignore[arg-type]
    closes = _decode_json(evidence["terminal_close_signatures"])  # type: ignore[arg-type]
    assert isinstance(events, list)
    assert isinstance(receipts, list)
    assert isinstance(closes, list)
    event_hashes = [canonical_sha256(event) for event in events]
    terminal_index = next(
        index
        for index, envelope in enumerate(receipts)
        if envelope["payload"]["phase"] == "TERMINAL"
    )
    payload = receipts[terminal_index]["payload"]
    count = len(event_hashes)
    updates = {
        "next_sequence": count,
        "cursor_end": f"cursor-{count}",
        "range_end_sequence_exclusive": count,
        "event_count": count,
        "last_event_envelope_sha256": event_hashes[-1] if event_hashes else "0" * 64,
        "event_hashes_root_sha256": derive_log_event_hashes_root(event_hashes),
        "worm_object_root_sha256": derive_log_worm_root(
            log_id=payload["log_id"],
            causal_predecessor_root_sha256=payload[
                "causal_predecessor_root_sha256"
            ],
            event_hashes=event_hashes,
        ),
    }
    payload.update(updates)
    publication_envelope = _decode_json(payload["publication_receipt"])
    assert isinstance(publication_envelope, dict)
    publication = publication_envelope["payload"]
    publication.update(updates)
    payload["publication_receipt"] = _blob(
        canonical_json_bytes(
            _signed(
                G09_WORM_PROVIDER_RECEIPT_SCHEMA,
                publication,
                keys["worm_publication_service"],
            )
        ),
        G09_WORM_PUBLICATION_MEDIA_TYPE,
    )
    terminal_receipt = _signed(
        G09_LOG_RECEIPT_SCHEMA, payload, keys["evidence_custodian"]
    )
    receipts[terminal_index] = terminal_receipt
    _replace_json(evidence, "worm_publication_receipts", receipts)

    close_payload = closes[0]["payload"]
    close_payload.update(
        {key: value for key, value in updates.items() if key != "worm_object_root_sha256"}
    )
    close_payload["worm_receipt_envelope_sha256"] = canonical_sha256(
        terminal_receipt
    )
    binding = {
        field: close_payload[field]
        for field in (
            "protocol_id",
            "campaign_root",
            "evaluation_id",
            "frozen_spec_hash",
            "campaign_registry_hash",
            "g08_result_root",
        )
    }
    close_core = {
        key: value
        for key, value in close_payload.items()
        if key not in {"role", "key_id", "close_root_sha256"}
    }
    close_args = {
        key: value for key, value in close_core.items() if key not in binding
    }
    close_core["close_root_sha256"] = derive_log_close_root(
        expected=binding, **close_args
    )
    terminal_signatures = [
        _signed(
            G09_LOG_CLOSE_SCHEMA,
            {**close_core, "role": role, "key_id": f"{role}-key-1"},
            keys[role],
        )
        for role in ("activation_service", "evidence_custodian")
    ]
    _replace_json(evidence, "terminal_close_signatures", terminal_signatures)


def test_honest_activation_recomputes_exact_evidence_only() -> None:
    bundle = _fixture()
    audit = _audit(bundle)
    assert audit["ciphertext_package_set_equals_g08_roster"] is True
    assert audit["decrypted_package_set_equals_g08_roster"] is True
    assert audit["submission_authorized"] is False
    assert audit["released_share_indices"] == [1, 2, 3]
    assert audit["zero_access_close_dual_signed"] is True
    assert audit["terminal_log_range_closed"] is True
    assert audit["recipient_private_key_reveal_verified"] is True
    assert audit["common_v2_gate_allowlisted"] is False
    assert audit["raw_evidence_recomputed"] is True
    assert audit["aggregate_authority"] is False

    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    audit = verify_blind_activation_evidence(
        **bundle["binding"],
        expected_evidence_manifest_root=audit["evidence_manifest_root"],
        **evidence,
    )
    assert audit["evidence_manifest_root"]


def test_threshold_reconstruction_rejects_an_inconsistent_extra_share() -> None:
    shares = derive_threshold_shares(
        bytes(range(32)),
        threshold=2,
        share_count=3,
        coefficient_material=b"threshold-consistency-test",
    )
    corrupted = [*shares[:2], (shares[2][0], bytes([shares[2][1][0] ^ 1]) + shares[2][1][1:])]
    with pytest.raises(BlindActivationError) as raised:
        reconstruct_threshold_secret(corrupted, threshold=2)
    assert raised.value.code == "INCONSISTENT_THRESHOLD_SHARES"


def test_observed_time_is_inert_diagnostic_metadata() -> None:
    bundle = _fixture()
    early = _audit(bundle, observed_at_utc="2026-08-01T11:59:59.000000Z")
    late = _audit(bundle, observed_at_utc="2099-01-01T00:00:00.000000Z")
    assert early == late


def test_forged_later_observed_time_cannot_replace_signed_trigger() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    trigger = _decode_json(evidence["activation_trigger"])  # type: ignore[arg-type]
    payload = trigger["payload"]
    payload["triggered_at_utc"] = PRE
    _replace_json(
        evidence,
        "activation_trigger",
        _signed(
            G09_ACTIVATION_TRIGGER_SCHEMA,
            payload,
            bundle["keys"]["activation_service"],
        ),
    )
    evidence["observed_at_utc"] = "2099-01-01T00:00:00.000000Z"
    with pytest.raises(BlindActivationError) as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "ACTIVATION_TIME_MISMATCH"


@pytest.mark.parametrize("mode", ["noncanonical", "duplicate", "unknown"])
def test_canonical_json_and_exact_fields_fail_closed(mode: str) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    if mode == "noncanonical":
        raw = base64.b64decode(evidence["activation_rule"]["base64"])
        evidence["activation_rule"] = _blob(raw + b"\n", "application/json")
    elif mode == "duplicate":
        evidence["activation_rule"] = _blob(
            b'{"schema":"first","schema":"second"}', "application/json"
        )
    else:
        rule = _decode_json(evidence["activation_rule"])  # type: ignore[arg-type]
        payload = rule["payload"]
        payload["unexpected"] = False
        core = {key: value for key, value in payload.items() if key != "content_sha256"}
        payload["content_sha256"] = canonical_sha256(core)
        _replace_json(
            evidence,
            "activation_rule",
            _signed(G09_ACTIVATION_RULE_SCHEMA, payload, bundle["keys"]["registrar"]),
        )
    with pytest.raises(BlindActivationError) as raised:
        _audit(bundle, **evidence)
    assert raised.value.code in {
        "NONCANONICAL_JSON",
        "INVALID_ACTIVATION_RULE",
        "INVALID_SOURCE_RECORD",
    }


def test_pre_activation_share_quorum_fails() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    releases = _decode_json(evidence["key_share_releases"])  # type: ignore[arg-type]
    payload = releases[0]["payload"]
    payload["released_at_utc"] = PRE
    releases[0] = _signed(G09_SHARE_RELEASE_SCHEMA, payload, bundle["keys"][payload["role"]])
    _replace_json(evidence, "key_share_releases", releases)
    with pytest.raises(BlindActivationError, match="predates activation") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "EARLY_SHARE_RELEASE"


def test_early_recipient_private_key_reveal_fails() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    reveal = _decode_json(evidence["recipient_key_reveal"])  # type: ignore[arg-type]
    payload = reveal["payload"]
    payload["revealed_at_utc"] = PRE
    _replace_json(
        evidence,
        "recipient_key_reveal",
        _signed(
            G09_RECIPIENT_KEY_REVEAL_SCHEMA,
            payload,
            bundle["keys"]["activation_service"],
        ),
    )
    with pytest.raises(BlindActivationError, match="predates activation") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "EARLY_RECIPIENT_KEY_REVEAL"


def test_early_plaintext_or_access_event_fails() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    target = next(item for item in events if item["payload"]["event_type"] == "PACKAGE_ACCESS")
    target["payload"]["occurred_at_utc"] = PRE
    _replace_json(evidence, "access_log", events)
    _resign_log(evidence, bundle["keys"])
    with pytest.raises(BlindActivationError, match="predates activation") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "EARLY_ACCESS"


@pytest.mark.parametrize("mode", ["missing", "extra", "alias"])
def test_package_set_requires_exact_no_alias_roster(mode: str) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    packages = evidence["package_bytes"]
    assert isinstance(packages, dict)
    if mode == "missing":
        packages.pop(bundle["archives"][0])
    elif mode == "extra":
        packages["f" * 64] = next(iter(packages.values()))
    else:
        roster = _decode_json(evidence["expected_g08_roster"])  # type: ignore[arg-type]
        roster["selected_archives"][1]["archive_sha256"] = roster["selected_archives"][0]["archive_sha256"]
        core = {key: value for key, value in roster.items() if key != "content_sha256"}
        roster["content_sha256"] = canonical_sha256(core)
        _replace_json(evidence, "expected_g08_roster", roster)
    with pytest.raises(BlindActivationError, match="archive|roster"):
        _audit(bundle, **evidence)


@pytest.mark.parametrize("mode", ["family", "package"])
def test_swapped_family_or_package_fails(mode: str) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    packages = _decode_json(evidence["blinded_package_commitments"])  # type: ignore[arg-type]
    payload = packages[0]["payload"]
    if mode == "family":
        payload["family_id"] = "family-2"
    else:
        payload["package_sha256"] = bundle["archives"][1]
    packages[0] = _signed(G09_PACKAGE_COMMITMENT_SCHEMA, payload, bundle["keys"]["registrar"])
    _replace_json(evidence, "blinded_package_commitments", packages)
    with pytest.raises(BlindActivationError, match="commitment evidence|extra, omitted, or aliased"):
        _audit(bundle, **evidence)


def test_bad_nonce_reveal_fails() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    reveals = _decode_json(evidence["nonce_reveals"])  # type: ignore[arg-type]
    payload = reveals[0]["payload"]
    payload["nonce"] = _blob(b"x" * 12)
    reveals[0] = _signed(G09_NONCE_REVEAL_SCHEMA, payload, bundle["keys"]["registrar"])
    _replace_json(evidence, "nonce_reveals", reveals)
    with pytest.raises(BlindActivationError, match="does not satisfy"):
        _audit(bundle, **evidence)


@pytest.mark.parametrize("field", ["aad", "ciphertext"])
def test_aad_or_ciphertext_mutation_fails(field: str) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    records = _decode_json(evidence["blinded_package_commitments"])  # type: ignore[arg-type]
    payload = records[0]["payload"]
    wrapped = payload[field]
    raw = base64.b64decode(wrapped["base64"])
    if field == "aad":
        raw = raw.replace(b"family-1", b"family-X")
        payload[field] = _blob(raw, "application/json")
    else:
        payload[field] = _blob(raw[:-1] + bytes([raw[-1] ^ 1]))
    records[0] = _signed(G09_PACKAGE_COMMITMENT_SCHEMA, payload, bundle["keys"]["registrar"])
    _replace_json(evidence, "blinded_package_commitments", records)
    with pytest.raises(BlindActivationError, match="AAD|commitment"):
        _audit(bundle, **evidence)


def test_exact_package_bytes_must_match_decryption() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    archive = bundle["archives"][0]
    evidence["package_bytes"][archive] = _blob(b"replacement package")
    with pytest.raises(BlindActivationError, match="hash to selected archive"):
        _audit(bundle, **evidence)


def test_broken_access_log_chain_fails() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    events[0]["payload"]["previous_envelope_sha256"] = "9" * 64
    events[0] = _signed(
        G09_ACCESS_EVENT_SCHEMA,
        events[0]["payload"],
        bundle["keys"]["activation_service"],
    )
    _replace_json(evidence, "access_log", events)
    with pytest.raises(BlindActivationError, match="hash chain"):
        _audit(bundle, **evidence)


def test_signed_log_events_must_follow_causal_release_order() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    assert isinstance(events, list)
    decrypt_index = next(
        index
        for index, event in enumerate(events)
        if event["payload"]["event_type"] == "SHARE_DECRYPT"
    )
    events.insert(1, events.pop(decrypt_index))
    _replace_json(evidence, "access_log", events)
    _resign_log(evidence, bundle["keys"])
    _reclose_terminal(evidence, bundle["keys"])
    with pytest.raises(BlindActivationError, match="precedes") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "ACCESS_LOG_CAUSALITY"


@pytest.mark.parametrize("mode", ["omitted_prefix", "log_reset"])
def test_omitted_prefix_or_log_reset_fails_even_after_reclosing(mode: str) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    assert isinstance(events, list)
    if mode == "omitted_prefix":
        events.pop(0)
    else:
        for event in events:
            event["payload"]["preactivation_close_root_sha256"] = "9" * 64
    _replace_json(evidence, "access_log", events)
    _resign_log(evidence, bundle["keys"])
    _reclose_terminal(evidence, bundle["keys"])
    with pytest.raises(BlindActivationError) as raised:
        _audit(bundle, **evidence)
    assert raised.value.code in {
        "MISSING_RECIPIENT_KEY_REVEAL_EVENT",
        "LOG_RESET_OR_PREFIX_OMISSION",
    }


def test_missing_terminal_close_fails_before_any_decryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    decrypt_called = False

    def forbidden_decrypt(*args: object, **kwargs: object) -> bytes:
        nonlocal decrypt_called
        decrypt_called = True
        raise AssertionError("decryption ran before terminal log closure")

    monkeypatch.setattr(AESGCM, "decrypt", forbidden_decrypt)
    _replace_json(evidence, "terminal_close_signatures", [])
    with pytest.raises(BlindActivationError, match="exactly two") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "MISSING_DUAL_CLOSE"
    assert decrypt_called is False


def test_regenerated_but_incomplete_log_fails_exact_event_set_closure() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    events = _decode_json(evidence["access_log"])  # type: ignore[arg-type]
    assert isinstance(events, list)
    omitted = next(
        index
        for index, event in enumerate(events)
        if event["payload"]["event_type"] == "PACKAGE_ACCESS"
    )
    events.pop(omitted)
    _replace_json(evidence, "access_log", events)
    _resign_log(evidence, bundle["keys"])
    _reclose_terminal(evidence, bundle["keys"])
    with pytest.raises(BlindActivationError, match="every exact package") as raised:
        _audit(bundle, **evidence)
    assert raised.value.code == "ACCESS_LOG_MISMATCH"


def test_wrong_role_fails_even_when_signature_is_valid() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    releases = _decode_json(evidence["key_share_releases"])  # type: ignore[arg-type]
    payload = releases[0]["payload"]
    payload["role"] = "registrar"
    payload["key_id"] = "registrar-key-1"
    releases[0] = _signed(G09_SHARE_RELEASE_SCHEMA, payload, bundle["keys"]["registrar"])
    _replace_json(evidence, "key_share_releases", releases)
    with pytest.raises(BlindActivationError, match="required role"):
        _audit(bundle, **evidence)


@pytest.mark.parametrize(("stale", "revoked", "code"), [(True, False, "STALE_KEY"), (False, True, "REVOKED_KEY")])
def test_stale_or_revoked_custodian_key_fails(stale: bool, revoked: bool, code: str) -> None:
    bundle = _fixture(stale=stale, revoked=revoked)
    with pytest.raises(BlindActivationError) as raised:
        _audit(bundle)
    assert raised.value.code == code


def test_signature_replay_and_signed_false_commitment_fail() -> None:
    bundle = _fixture()
    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    reveals = _decode_json(evidence["nonce_reveals"])  # type: ignore[arg-type]
    reveals[1] = deepcopy(reveals[0])
    _replace_json(evidence, "nonce_reveals", reveals)
    with pytest.raises(BlindActivationError, match="exact selected archive set"):
        _audit(bundle, **evidence)

    evidence = deepcopy(bundle["evidence"])
    assert isinstance(evidence, dict)
    records = _decode_json(evidence["blinded_package_commitments"])  # type: ignore[arg-type]
    payload = records[0]["payload"]
    payload["package_commitment_sha256"] = "0" * 64
    records[0] = _signed(G09_PACKAGE_COMMITMENT_SCHEMA, payload, bundle["keys"]["registrar"])
    _replace_json(evidence, "blinded_package_commitments", records)
    with pytest.raises(BlindActivationError, match="commitment evidence|package commitment"):
        _audit(bundle, **evidence)


def test_retired_v1_common_gate_wrapper_cannot_turn_g09_into_a_pass() -> None:
    bundle = _fixture()
    with pytest.raises(BlindActivationError, match="unallowlisted") as raised:
        derive_blind_activation_gate_payload(
            **bundle["binding"],
            verifier_module_digest="4" * 64,
            evidence_manifest_root="5" * 64,
            **bundle["evidence"],
        )
    assert raised.value.code == "COMMON_GATE_WRAPPER_RETIRED"
