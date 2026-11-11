from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.cohort import append_registration, build_archive_registration, build_outcome_observation, new_registry
from evaluation_v5.host_evidence import (
    GENESIS_CHAIN_HASH,
    audit_host_evidence,
    host_evidence_signing_payload,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _observation(index: int, *, replay_digest: str) -> dict[str, object]:
    created = f"2026-07-14T01:{index:02d}:00.000000Z"
    return build_outcome_observation(
        archive_sha256="a" * 64,
        game_id=str(85174000 + index),
        created_at_utc=created,
        completion_observed_at_utc="2026-07-13T00:00:00.000000Z",
        completion_evidence_sha256="b" * 64,
        seat=index % 2,
        opponent_rating=1500,
        outcome="win",
        replay_content_sha256=replay_digest,
    )


def _log(observations: list[dict[str, object]]) -> dict[str, object]:
    chains: list[str] = []
    previous = GENESIS_CHAIN_HASH
    for observation in observations:
        previous = canonical_sha256({"previous_chain_hash": previous, "record": observation})
        chains.append(previous)
    return {
        "schema": "evaluation_v5_hosted_observation_log_v4",
        "records": observations,
        "chain_hashes": chains,
    }


def _fixture(
    tmp_path: Path, count: int = 2
) -> tuple[
    Path, dict[str, object], dict[str, object], bytes, dict[str, object], Ed25519PrivateKey
]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    registry = append_registration(
        new_registry(),
        build_archive_registration(
            archive_sha256="a" * 64,
            deck_sha256="c" * 64,
            policy_sha256="d" * 64,
            model_input_sha256="e" * 64,
            family_provenance_sha256="f" * 64,
            team_pseudonym="team-a",
            submission_slot_id="slot-a",
            intended_window_start_utc="2026-07-14T00:00:00.000000Z",
            intended_window_end_utc="2026-07-15T00:00:00.000000Z",
            consent_sha256="1" * 64,
            registered_at_utc="2026-07-13T00:00:00.000000Z",
        ),
    )
    observations: list[dict[str, object]] = []
    raw_by_index: list[bytes] = []
    for index in range(count):
        episode_id = str(85174000 + index)
        target_seat = index % 2
        raw = {
            "configuration": {"actTimeout": 0, "episodeSteps": 10000000},
            "info": {
                "Agents": [{"Name": "team-a"}, {"Name": "opponent"}],
                "EpisodeId": int(episode_id),
                "TeamNames": ["team-a", "opponent"]
                if target_seat == 0
                else ["opponent", "team-a"],
            },
            "rewards": [1, -1] if target_seat == 0 else [-1, 1],
            "statuses": ["DONE", "DONE"],
            "steps": [],
        }
        raw_bytes = json.dumps(raw, separators=(",", ":"), sort_keys=True).encode("ascii")
        raw_by_index.append(raw_bytes)
        observations.append(_observation(index, replay_digest=_sha256(raw_bytes)))
    log = _log(observations)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    receipts: list[dict[str, object]] = []
    for index, observation in enumerate(observations):
        raw_path = root / f"responses/game-{index}.json"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_bytes = raw_by_index[index]
        raw_path.write_bytes(raw_bytes)
        receipts.append(
            {
                "archive_sha256": observation["archive_sha256"],
                "game_id": observation["game_id"],
                "hosted_created_at_utc": observation["created_at_utc"],
                "completion_evidence_sha256": observation["completion_evidence_sha256"],
                "source_episode_reference_id": observation["game_id"],
                "fetched_at_utc": f"2026-07-14T02:{index:02d}:00.000000Z",
                "raw_response_path": f"responses/game-{index}.json",
                "raw_response_sha256": _sha256(raw_bytes),
            }
        )
    census_games = [
        {
            "archive_sha256": receipt["archive_sha256"],
            "game_id": receipt["game_id"],
            "source_episode_reference_id": receipt["source_episode_reference_id"],
            "created_at_utc": receipt["hosted_created_at_utc"],
        }
        for receipt in receipts
    ]
    registry_sha256 = canonical_sha256(registry)
    registry_chain_head = registry["chain_hashes"][-1]
    commitment = canonical_sha256(
        {
            "registry_sha256": registry_sha256,
            "registry_chain_head": registry_chain_head,
            "exhaustive": True,
            "games": census_games,
        }
    )
    census_receipt = {
        "schema": "evaluation_v5_hosted_census_receipt_v1",
        "registry_sha256": registry_sha256,
        "registry_chain_head": registry_chain_head,
        "exhaustive": True,
        "games": census_games,
        "commitment_sha256": commitment,
    }
    census_bytes = json.dumps(census_receipt, separators=(",", ":"), sort_keys=True).encode("ascii")
    (root / "census.json").write_bytes(census_bytes)
    manifest: dict[str, object] = {
        "schema": "evaluation_v5_host_evidence_manifest_v1",
        "protocol_id": "MCI_TRANSFER_V1",
        "reviewed_at": "2026-07-14T03:00:00.000000Z",
        "observation_log_sha256": canonical_sha256(log),
        "observation_chain_head": chains[-1] if (chains := log["chain_hashes"]) else GENESIS_CHAIN_HASH,
        "registry_sha256": registry_sha256,
        "registry_chain_head": registry_chain_head,
        "census": {
            "receipt_path": "census.json",
            "receipt_sha256": _sha256(census_bytes),
            "commitment_sha256": commitment,
            "exhaustive": True,
            "games": census_games,
        },
        "signer_public_key_fingerprint_sha256": _sha256(public_key),
        "receipts": receipts,
        "signature_ed25519_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
    }
    manifest["signature_ed25519_base64"] = base64.b64encode(
        private_key.sign(host_evidence_signing_payload(manifest))
    ).decode("ascii")
    return root, log, manifest, public_key, registry, private_key


def _resign_after_replay_change(
    root: Path,
    log: dict[str, object],
    manifest: dict[str, object],
    private_key: Ed25519PrivateKey,
    index: int,
    raw_bytes: bytes,
) -> None:
    path = root / f"responses/game-{index}.json"
    path.write_bytes(raw_bytes)
    manifest["receipts"][index]["raw_response_sha256"] = _sha256(raw_bytes)
    log["records"][index]["replay_content_sha256"] = _sha256(raw_bytes)
    previous = GENESIS_CHAIN_HASH
    chains: list[str] = []
    for observation in log["records"]:
        previous = canonical_sha256({"previous_chain_hash": previous, "record": observation})
        chains.append(previous)
    log["chain_hashes"] = chains
    manifest["observation_log_sha256"] = canonical_sha256(log)
    manifest["observation_chain_head"] = chains[-1]
    manifest["signature_ed25519_base64"] = base64.b64encode(
        private_key.sign(host_evidence_signing_payload(manifest))
    ).decode("ascii")


def test_complete_signed_evidence_binds_log_and_raw_bytes(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)

    audit = audit_host_evidence(
        log, manifest, root, pinned_public_key=public_key, registry=registry
    )

    assert audit["evidence_complete"] is True
    assert audit["signer_public_key_fingerprint_sha256"] == _sha256(public_key)
    assert audit["observation_log_sha256"] == canonical_sha256(log)
    assert len(audit["receipts"]) == 2
    assert audit["authority"] is False
    assert audit["holdout_access_authorized"] is False
    assert audit["submission_authorized"] is False


def test_signature_and_pinned_key_tampering_fail_closed(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    tampered = deepcopy(manifest)
    tampered["signature_ed25519_base64"] = base64.b64encode(b"\0" * 64).decode("ascii")
    failed = audit_host_evidence(log, tampered, root, pinned_public_key=public_key, registry=registry)
    assert failed["evidence_complete"] is False
    assert failed["authority"] is False
    assert failed["submission_authorized"] is False
    assert failed["holdout_access_authorized"] is False

    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    wrong = audit_host_evidence(log, manifest, root, pinned_public_key=wrong_key, registry=registry)
    assert wrong["evidence_complete"] is False
    assert wrong["signer_public_key_fingerprint_sha256"] is None


@pytest.mark.parametrize(
    "change",
    [
        lambda manifest: manifest["receipts"].pop(),
        lambda manifest: manifest["receipts"].append(deepcopy(manifest["receipts"][-1])),
        lambda manifest: manifest["receipts"].reverse(),
    ],
)
def test_receipt_coverage_and_order_are_exact(tmp_path: Path, change) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    changed = deepcopy(manifest)
    change(changed)
    changed["signature_ed25519_base64"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(b"\x11" * 32).sign(b"wrong")
    ).decode("ascii")
    # Re-sign with the fixture key is intentionally unavailable here: malformed
    # receipts must be rejected before any filesystem evidence is trusted.
    audit = audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)
    assert audit["evidence_complete"] is False


def test_observation_substitution_and_log_head_tampering_fail(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    changed = deepcopy(manifest)
    changed["receipts"][0]["completion_evidence_sha256"] = "c" * 64
    assert not audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]

    changed = deepcopy(manifest)
    changed["observation_chain_head"] = "d" * 64
    assert not audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("fetched_at_utc", "2026-07-14T00:00:00.000000Z"),
        ("fetched_at_utc", "2026-07-14T04:00:00.000000Z"),
        ("hosted_created_at_utc", "2026-07-14T01:00:00Z"),
    ],
)
def test_receipt_timestamps_are_canonical_and_ordered(tmp_path: Path, field: str, value: str) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    changed = deepcopy(manifest)
    changed["receipts"][0][field] = value
    assert not audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]


def test_traversal_symlink_and_mutation_fail_closed(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    changed = deepcopy(manifest)
    changed["receipts"][0]["raw_response_path"] = "../outside.json"
    assert not audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]

    root, log, manifest, public_key, registry, _ = _fixture(tmp_path / "symlink")
    link = root / "responses/link.json"
    link.symlink_to(root / "responses/game-0.json")
    changed = deepcopy(manifest)
    changed["receipts"][0]["raw_response_path"] = "responses/link.json"
    changed["receipts"][0]["raw_response_sha256"] = manifest["receipts"][0]["raw_response_sha256"]
    assert not audit_host_evidence(log, changed, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]

    root, log, manifest, public_key, registry, _ = _fixture(tmp_path / "mutation")
    (root / "responses/game-0.json").write_bytes(b"changed")
    assert not audit_host_evidence(log, manifest, root, pinned_public_key=public_key, registry=registry)["evidence_complete"]


def test_registry_and_exhaustive_census_are_required(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, _ = _fixture(tmp_path)
    without_registry = audit_host_evidence(log, manifest, root, pinned_public_key=public_key)
    assert without_registry["evidence_complete"] is False

    missing_census = deepcopy(manifest)
    missing_census.pop("census")
    failed = audit_host_evidence(
        log, missing_census, root, pinned_public_key=public_key, registry=registry
    )
    assert failed["evidence_complete"] is False


@pytest.mark.parametrize(
    "variant",
    [
        "duplicate_episode_id",
        "episode_id_mismatch",
        "team_seat_mismatch",
        "outcome_mismatch",
    ],
)
def test_replay_semantic_binding_is_fail_closed(
    tmp_path: Path, variant: str
) -> None:
    root, log, manifest, public_key, registry, private_key = _fixture(tmp_path / variant)
    if variant == "duplicate_episode_id":
        raw = (
            b'{"info":{"EpisodeId":85174000,"EpisodeId":85174000,'
            b'"TeamNames":["team-a","opponent"]},"rewards":[1,-1],'
            b'"statuses":["DONE","DONE"]}'
        )
    else:
        raw_payload = {
            "info": {
                "EpisodeId": 85174099 if variant == "episode_id_mismatch" else 85174000,
                "TeamNames": ["opponent", "team-a"]
                if variant == "team_seat_mismatch"
                else ["team-a", "opponent"],
            },
            "rewards": [-1, 1] if variant == "outcome_mismatch" else [1, -1],
            "statuses": ["DONE", "DONE"],
        }
        raw = json.dumps(raw_payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    _resign_after_replay_change(root, log, manifest, private_key, 0, raw)
    audit = audit_host_evidence(
        log, manifest, root, pinned_public_key=public_key, registry=registry
    )
    assert audit["evidence_complete"] is False


def test_status_derived_runtime_failure_is_bound_to_observation(tmp_path: Path) -> None:
    root, log, manifest, public_key, registry, private_key = _fixture(tmp_path)
    log["records"][0]["outcome"] = "runtime_failure"
    raw = json.dumps(
        {
            "info": {
                "EpisodeId": 85174000,
                "TeamNames": ["team-a", "opponent"],
            },
            "rewards": [1, -1],
            "statuses": ["TIMEOUT", "DONE"],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    _resign_after_replay_change(root, log, manifest, private_key, 0, raw)
    audit = audit_host_evidence(
        log, manifest, root, pinned_public_key=public_key, registry=registry
    )
    assert audit["evidence_complete"] is True
    assert audit["receipts"][0]["outcome"] == "runtime_failure"
