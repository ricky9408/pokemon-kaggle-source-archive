from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import io
import tarfile
from types import MappingProxyType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3_1 import policy, population as g2
from evaluation_v6_3_1.common import SIGNATURE_SCHEMA, V63Error, canonical_json_bytes, key_id_for_public_key, signing_message
from tests.test_evaluation_v6_3_1_policy import _profile_with_keys


def _add(store: dict[str, bytes], payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    store[digest] = payload
    return digest


def _add_json(store: dict[str, bytes], value: dict[str, Any] | list[Any]) -> str:
    return _add(store, canonical_json_bytes(value))


def _artifacts(store: dict[str, bytes]) -> list[dict[str, str]]:
    return [
        {"schema": g2.ARTIFACT_SCHEMA, "content_sha256": digest, "payload_base64": base64.b64encode(payload).decode("ascii")}
        for digest, payload in sorted(store.items())
    ]


def _signatures(core: dict[str, Any], domain: bytes, keys: dict[str, Ed25519PrivateKey], parties: tuple[str, ...] = ("A", "B")) -> list[dict[str, str]]:
    return [
        {
            "schema": SIGNATURE_SCHEMA,
            "party_id": party,
            "key_id": key_id_for_public_key(keys[party].public_key().public_bytes_raw()),
            "signature_base64": base64.b64encode(keys[party].sign(signing_message(domain, core))).decode("ascii"),
        }
        for party in sorted(parties)
    ]


def _signature(core: dict[str, Any], domain: bytes, key: Ed25519PrivateKey, party: str) -> dict[str, str]:
    return _signatures(core, domain, {party: key}, (party,))[0]


def _tar(candidate_id: str, variant: str = "valid") -> tuple[bytes, list[dict[str, str]]]:
    files: list[tuple[str, bytes, int]] = [
        ("agent.py", f"CANDIDATE = {candidate_id!r}\n\ndef choose_action():\n    return 0\n".encode("ascii"), 0o644),
        ("deck.csv", b"card_id,count\n1,60\n", 0o644),
    ]
    archive_format = tarfile.USTAR_FORMAT
    symlink = False
    if variant == "gnu":
        archive_format = tarfile.GNU_FORMAT
    elif variant == "pax":
        archive_format = tarfile.PAX_FORMAT
        files = [("segment-" * 20 + "agent.py", files[0][1], 0o644), files[1]]
    elif variant == "prefix_collision":
        files = [("pkg", b"file", 0o644), ("pkg/module.py", b"module", 0o644)]
    elif variant == "duplicate":
        files = [("agent.py", b"first", 0o644), ("agent.py", b"second", 0o644)]
    elif variant == "nfd":
        files = [("cafe\u0301.py", b"nfd", 0o644), files[1]]
    elif variant == "traversal":
        files = [("../escape.py", b"escape", 0o644), files[1]]
    elif variant == "too_many":
        files = [(f"file-{index:03d}.txt", b"x", 0o644) for index in range(g2.MAX_ARCHIVE_ENTRIES + 1)]
    elif variant == "symlink":
        symlink = True

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=archive_format, encoding="utf-8") as archive:
        for path, data, mode in files:
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo("agent-link.py")
            info.type = tarfile.SYMTYPE
            info.linkname = "agent.py"
            info.mode = 0o777
            info.mtime = 0
            archive.addfile(info)
        if variant == "sparse":
            info = tarfile.TarInfo("sparse.bin")
            info.type = tarfile.GNUTYPE_SPARSE
            info.size = 0
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info)

    entries = [
        {"path": path, "mode": str(mode), "byte_length": str(len(data)), "sha256": hashlib.sha256(data).hexdigest()}
        for path, data, mode in sorted(files)
    ]
    if variant in {"duplicate", "prefix_collision"}:
        entries = entries[:1]
    elif variant == "nfd":
        entries[0] = {**entries[0], "path": "caf\u00e9.py"}
    elif variant == "traversal":
        entries[0] = {**entries[0], "path": "escape.py"}
    elif variant == "too_many":
        entries = entries[: g2.MAX_ARCHIVE_ENTRIES]
    archive_bytes = output.getvalue()
    if variant == "concatenated_gzip":
        archive_bytes += archive_bytes
    elif variant == "trailing_data":
        archive_bytes += b"trailing"
    return archive_bytes, entries


def _candidate_records(store: dict[str, bytes], schema: str, candidate_id: str, *record_ids: str) -> str:
    return _add_json(store, {"schema": schema, "candidate_id": candidate_id, "record_ids": sorted(record_ids)})


def _unit(
    candidate_id: str,
    store: dict[str, bytes],
    validated_policy: policy.ValidatedV631Policy,
    keys: dict[str, Ed25519PrivateKey],
    *,
    archive_variant: str = "valid",
    manifest_tamper: str | None = None,
    receipt_os: str = "linux",
    receipt_output_tamper: bool = False,
    safety_finding: bool = False,
    opaque_evidence: str | None = None,
    archive_fixture: tuple[bytes, list[dict[str, str]]] | None = None,
) -> dict[str, Any]:
    policy_sha256 = validated_policy["sha256"]
    archive_bytes, entries = archive_fixture if archive_fixture is not None else _tar(candidate_id, archive_variant)
    entries = [dict(entry) for entry in entries]
    if manifest_tamper == "mode":
        entries[0] = {**entries[0], "mode": "493"}
    elif manifest_tamper == "size":
        entries[0] = {**entries[0], "byte_length": str(int(entries[0]["byte_length"]) + 1)}
    elif manifest_tamper == "hash":
        entries[0] = {**entries[0], "sha256": "0" * 64}
    elif manifest_tamper == "path":
        entries[0] = {**entries[0], "path": "renamed.py"}
    entries.sort(key=lambda entry: entry["path"])
    archive_sha256 = _add(store, archive_bytes)
    manifest_sha256 = _add_json(store, {"schema": g2.ARCHIVE_ENTRY_MANIFEST_SCHEMA, "entries": entries})
    archive = {"schema": g2.ARCHIVE_EVIDENCE_SCHEMA, "archive_filename": f"candidate-{candidate_id.lower()}.tar.gz", "archive_byte_length": str(len(archive_bytes)), "archive_sha256": archive_sha256, "archive_entry_manifest_sha256": manifest_sha256}
    archive["evidence_root_sha256"] = _add_json(store, archive)

    source_tree = {"schema": g2.SOURCE_TREE_SCHEMA, "candidate_id": candidate_id, "entries": entries}
    source_tree_sha256 = _add_json(store, source_tree)
    command_argv = ["python3", "-m", "build_submission"]
    recipe = {"schema": g2.BUILD_RECIPE_SCHEMA, "candidate_id": candidate_id, "operating_system": "linux", "architecture": "amd64", "command_argv": command_argv, "output_archive_format": "ustar+single-gzip-member"}
    recipe_sha256 = _add_json(store, recipe)
    package = {"schema": g2.PACKAGE_EVIDENCE_SCHEMA, "archive_sha256": archive_sha256, "archive_byte_length": archive["archive_byte_length"], "archive_entry_manifest_sha256": manifest_sha256, "source_tree_sha256": source_tree_sha256, "build_recipe_sha256": recipe_sha256}
    package["package_root_sha256"] = _add_json(store, package)

    history_payload: bytes
    if opaque_evidence == "source_history":
        history_payload = b"opaque source history"
    else:
        history_payload = canonical_json_bytes({"schema": g2.SOURCE_HISTORY_SCHEMA, "candidate_id": candidate_id, "source_tree_sha256": source_tree_sha256, "parent_source_tree_sha256s": []})
    source_core = {
        "schema": g2.SOURCE_EVIDENCE_SCHEMA,
        "policy_sha256": policy_sha256,
        "source_mode": "PRIVATE_DUAL_AUDITOR_ESCROW",
        "source_tree_sha256": source_tree_sha256,
        "source_history_root_sha256": _add(store, history_payload),
        "auditor_a_plaintext_root_sha256": source_tree_sha256,
        "auditor_b_plaintext_root_sha256": source_tree_sha256,
    }
    source = {**source_core, "evidence_root_sha256": _add_json(store, source_core), "signatures": _signatures(source_core, g2.DOMAIN_SOURCE_EVIDENCE, keys)}

    toolchain_payload: bytes
    if opaque_evidence == "toolchain":
        toolchain_payload = b"opaque toolchain"
    else:
        toolchain_payload = canonical_json_bytes({"schema": g2.TOOLCHAIN_LOCK_SCHEMA, "operating_system": "linux", "architecture": "amd64", "packages": [{"name": "python", "version": "3.11.15", "artifact_sha256": hashlib.sha256(b"python-amd64").hexdigest()}]})
    build_roots = {
        "package_root_sha256": package["package_root_sha256"],
        "source_evidence_root_sha256": source["evidence_root_sha256"],
        "build_recipe_sha256": recipe_sha256,
        "toolchain_lock_sha256": _add(store, toolchain_payload),
        "container_image_sha256": _add_json(store, {"schema": g2.CONTAINER_PROFILE_SCHEMA, "operating_system": "linux", "architecture": "amd64", "image_reference": "registry.example/eval@sha256", "image_digest_sha256": hashlib.sha256(f"container:{candidate_id}".encode("ascii")).hexdigest()}),
        "engine_sha256": _add_json(store, {"schema": g2.ENGINE_PROFILE_SCHEMA, "name": "ptcg-engine", "version": "1", "content_sha256": hashlib.sha256(b"engine").hexdigest()}),
        "ruleset_sha256": _add_json(store, {"schema": g2.RULESET_PROFILE_SCHEMA, "name": "competition-rules", "version": "1", "content_sha256": hashlib.sha256(b"ruleset").hexdigest()}),
    }
    receipts = []
    for auditor in ("A", "B"):
        findings = ["runtime-safety-finding"] if safety_finding and auditor == "A" else []
        checks = [
            {"check_id": check_id, "finding_ids": findings if check_id == "runtime_safety_audit" else []}
            for check_id in g2.REQUIRED_SAFETY_CHECK_IDS
        ]
        safety_root = _add_json(store, {"schema": g2.SAFETY_AUDIT_SCHEMA, "candidate_id": candidate_id, "auditor_id": auditor, "checks": checks})
        receipt_core = {
            "schema": g2.REBUILD_RECEIPT_SCHEMA,
            "policy_sha256": policy_sha256,
            "auditor_id": auditor,
            "operating_system": receipt_os if auditor == "A" else "linux",
            "architecture": "amd64",
            "rebuild_command_argv": command_argv,
            "build_recipe_sha256": recipe_sha256,
            "source_tree_sha256": source_tree_sha256,
            "toolchain_lock_sha256": build_roots["toolchain_lock_sha256"],
            "container_image_sha256": build_roots["container_image_sha256"],
            "engine_sha256": build_roots["engine_sha256"],
            "ruleset_sha256": build_roots["ruleset_sha256"],
            "output_archive_sha256": _add(store, b"wrong rebuild output") if receipt_output_tamper and auditor == "A" else archive_sha256,
            "output_archive_byte_length": archive["archive_byte_length"],
            "output_archive_entry_manifest_sha256": manifest_sha256,
            "safety_audit_root_sha256": safety_root,
        }
        receipts.append({**receipt_core, "signature": _signature(receipt_core, g2.DOMAIN_REBUILD_RECEIPT, keys[auditor], auditor)})
    build_core = {"schema": g2.BUILD_EVIDENCE_SCHEMA, "policy_sha256": policy_sha256, **build_roots, "rebuild_receipts": receipts}
    build = {**build_core, "evidence_root_sha256": _add_json(store, build_core), "signatures": _signatures(build_core, g2.DOMAIN_BUILD_EVIDENCE, keys)}

    principals = [f"principal-{candidate_id.lower()}"]
    control_root = _add(store, b"opaque control evidence") if opaque_evidence == "control" else _candidate_records(store, g2.CONTROL_EVIDENCE_SCHEMA, candidate_id, f"control-{candidate_id.lower()}")
    disclosure_core = {
        "schema": g2.SEMANTIC_DISCLOSURE_SCHEMA,
        "policy_sha256": policy_sha256,
        "declared_principal_ids": principals,
        "control_evidence_root_sha256": control_root,
        "ancestry_root_sha256": _candidate_records(store, g2.ANCESTRY_EVIDENCE_SCHEMA, candidate_id, f"ancestry-{candidate_id.lower()}"),
        "forks_root_sha256": _candidate_records(store, g2.FORKS_EVIDENCE_SCHEMA, candidate_id),
        "third_party_inputs_root_sha256": _candidate_records(store, g2.THIRD_PARTY_INPUTS_SCHEMA, candidate_id),
        "intervention_evidence_root_sha256": _candidate_records(store, g2.INTERVENTION_EVIDENCE_SCHEMA, candidate_id, f"intervention-{candidate_id.lower()}"),
        "escrow_receipt_root_sha256": _add_json(store, {"schema": g2.ESCROW_RECEIPT_SCHEMA, "candidate_id": candidate_id, "auditor_ids": ["A", "B"], "source_tree_sha256": source_tree_sha256}),
        "contributor_challenge_precommit_sha256": _add_json(store, {"schema": g2.CONTRIBUTOR_CHALLENGE_PRECOMMIT_SCHEMA, "candidate_id": candidate_id, "declared_principal_ids": principals}),
    }
    disclosure = {**disclosure_core, "evidence_root_sha256": _add_json(store, disclosure_core), "signatures": _signatures(disclosure_core, g2.DOMAIN_SEMANTIC_DISCLOSURE, keys)}
    unit_core = {"schema": g2.UNIT_SCHEMA, "candidate_id": candidate_id, "archive_evidence_root_sha256": archive["evidence_root_sha256"], "package_root_sha256": package["package_root_sha256"], "source_evidence_root_sha256": source["evidence_root_sha256"], "build_evidence_root_sha256": build["evidence_root_sha256"], "semantic_disclosure_evidence_root_sha256": disclosure["evidence_root_sha256"]}
    return {"schema": g2.UNIT_SCHEMA, "candidate_id": candidate_id, "archive": archive, "package": package, "source": source, "build": build, "semantic_disclosure": disclosure, "evidence_root_sha256": _add_json(store, unit_core)}


def _pair(left: str, right: str, store: dict[str, bytes], validated_policy: policy.ValidatedV631Policy, keys: dict[str, Ed25519PrivateKey]) -> dict[str, Any]:
    classifications = []
    review_specs = (
        ("source_review_root_sha256", "source"),
        ("lineage_control_review_root_sha256", "lineage_control"),
        ("development_control_review_root_sha256", "development_control"),
        ("intervention_review_root_sha256", "intervention"),
    )
    for auditor in ("A", "B"):
        reviews = {
            field: _add_json(store, {"schema": g2.PAIR_REVIEW_EVIDENCE_SCHEMA, "auditor_id": auditor, "left_candidate_id": left, "right_candidate_id": right, "review_kind": kind, "observation_ids": [f"{kind}-reviewed"]})
            for field, kind in review_specs
        }
        evidence_root = _add_json(store, {"schema": g2.PAIR_ANALYSIS_EVIDENCE_SCHEMA, "auditor_id": auditor, "left_candidate_id": left, "right_candidate_id": right, **reviews})
        analysis = {"schema": g2.PAIR_ANALYSIS_SCHEMA, "auditor_id": auditor, "left_candidate_id": left, "right_candidate_id": right, "source_state": "INDEPENDENT", "lineage_control_state": "INDEPENDENT", "development_control_state": "INDEPENDENT", "intervention_state": "DISTINCT", "analysis_evidence_root_sha256": evidence_root}
        classifications.append({"schema": g2.AUDITOR_CLASSIFICATION_SCHEMA, "auditor_id": auditor, "source_state": "INDEPENDENT", "lineage_control_state": "INDEPENDENT", "development_control_state": "INDEPENDENT", "intervention_state": "DISTINCT", **reviews, "analysis_evidence_root_sha256": evidence_root, "analysis_root_sha256": _add_json(store, analysis)})
    core = {"schema": g2.PAIR_CLASSIFICATION_SCHEMA, "policy_sha256": validated_policy["sha256"], "left_candidate_id": left, "right_candidate_id": right, "classifications": classifications}
    return {**core, "signatures": _signatures(core, g2.DOMAIN_PAIR_CLASSIFICATION, keys)}


def _population(
    *,
    archive_permutation: tuple[int, ...] | None = None,
    **unit_options: Any,
) -> tuple[dict[str, Any], policy.ValidatedV631Policy, dict[str, Ed25519PrivateKey]]:
    raw_policy, keys = _profile_with_keys()
    digest = lambda label: hashlib.sha256(label.encode("ascii")).hexdigest()
    for identity in raw_policy["audit_branches"] + raw_policy["time_authorities"]:
        is_time = identity["role"] == "RFC3161_TIME_AUTHORITY"
        party = identity["party_id"]
        identity.setdefault("tsa_signer_spki_sha256", digest(f"tsa-spki-{party}") if is_time else None)
        identity.setdefault("revocation_issuer_spki_sha256", digest(f"revocation-spki-{party}") if is_time else None)
        identity.setdefault("identity_evidence_root_sha256", digest(f"identity-evidence-{party}") if is_time else None)
    raw_policy["drand"].setdefault("group_hash", digest("drand-group"))
    raw_policy["drand"].setdefault("scheme_id", "pedersen-bls-chained")
    raw_policy["drand"].setdefault("beacon_id", "default")
    raw_policy.setdefault(
        "crypto_runtime",
        {
            "schema": policy.CRYPTO_RUNTIME_POLICY_SCHEMA,
            "openssl_executable_path": "/usr/bin/openssl",
            "openssl_executable_sha256": digest("openssl-executable"),
            "node_executable_path": "/usr/bin/node",
            "node_executable_sha256": digest("node-executable"),
            "rfc3161_imprint_oid": "2.16.840.1.101.3.4.2.1",
        },
    )
    validated_policy = policy.validate_candidate_policy(raw_policy)
    store: dict[str, bytes] = {}
    archive_variant = unit_options.pop("archive_variant", "valid")
    archive_fixtures = [_tar(f"archive-content-{index:02d}", archive_variant if index == 0 else "valid") for index in range(len(g2.CANDIDATE_IDS))]
    archive_fixtures.sort(key=lambda fixture: hashlib.sha256(fixture[0]).hexdigest())
    permutation = archive_permutation or tuple(range(len(g2.CANDIDATE_IDS)))
    assert sorted(permutation) == list(range(len(g2.CANDIDATE_IDS)))
    units = [
        _unit(
            candidate,
            store,
            validated_policy,
            keys,
            archive_fixture=archive_fixtures[permutation[index]],
            **(unit_options if candidate == "U01" else {}),
        )
        for index, candidate in enumerate(g2.CANDIDATE_IDS)
    ]
    pairs = [_pair(left, right, store, validated_policy, keys) for index, left in enumerate(g2.CANDIDATE_IDS) for right in g2.CANDIDATE_IDS[index + 1 :]]
    pair_root = _add_json(store, pairs)
    evidence_root = _add_json(store, {"schema": "eval.v6.3.1.g2-candidate-population-evidence", "policy_sha256": validated_policy["sha256"], "unit_evidence_root_sha256s": [unit["evidence_root_sha256"] for unit in units], "pair_classifications_root_sha256": pair_root})
    value = {"schema": g2.POPULATION_SCHEMA, "artifacts": _artifacts(store), "units": units, "pair_classifications": pairs, "pair_classifications_root_sha256": pair_root, "evidence_root_sha256": evidence_root}
    return value, validated_policy, keys


def _store(value: dict[str, Any]) -> dict[str, bytes]:
    return {item["content_sha256"]: base64.b64decode(item["payload_base64"]) for item in value["artifacts"]}


def _rebind_population_roots(value: dict[str, Any], store: dict[str, bytes], validated_policy: policy.ValidatedV631Policy) -> None:
    pair_root = _add_json(store, value["pair_classifications"])
    value["pair_classifications_root_sha256"] = pair_root
    value["evidence_root_sha256"] = _add_json(store, {"schema": "eval.v6.3.1.g2-candidate-population-evidence", "policy_sha256": validated_policy["sha256"], "unit_evidence_root_sha256s": [unit["evidence_root_sha256"] for unit in value["units"]], "pair_classifications_root_sha256": pair_root})
    value["artifacts"] = _artifacts(store)


def test_g2_is_neutral_content_conformance_without_semantic_projection() -> None:
    value, validated_policy, _ = _population()
    validated = g2.validate_candidate_population(value, policy=validated_policy)
    assert tuple(validated["archive_hashes_by_candidate_id"]) == g2.CANDIDATE_IDS
    archive_hashes = tuple(validated["archive_hashes_by_candidate_id"].values())
    assert archive_hashes == tuple(sorted(archive_hashes))
    assert set(validated["candidate_pair_classification_attachment"]) == {"root_sha256", "pair_count", "candidate_policy_signatures_structurally_verified", "semantic_interpretation_performed", "externally_authenticated"}
    assert validated["candidate_pair_classification_attachment"]["pair_count"] == 120
    assert validated["candidate_pair_classification_attachment"]["semantic_interpretation_performed"] is False
    assert validated["candidate_pair_classification_attachment"]["externally_authenticated"] is False
    assert "components" not in validated
    assert not any(key.endswith("_component_count") for key in validated)
    assert validated["schema_conformant_only"] is True
    assert validated["semantic_population_closed"] is False
    assert validated["semantic_population_validated"] is False
    assert isinstance(validated["units"], MappingProxyType)
    assert all(unit["linux_amd64_rebuild_receipt_auditor_ids"] == ("A", "B") for unit in validated["units"].values())
    verdict = g2.offline_population_verdict(validated)
    assert verdict["population_semantically_closed"] is False
    assert verdict["semantic_population_closed"] is False
    assert verdict["semantic_population_validated"] is False
    assert verdict["permits"] == ()
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False


@pytest.mark.parametrize(
    "archive_permutation",
    (
        (1, 0, *range(2, 16)),
        tuple(reversed(range(16))),
    ),
)
def test_rejects_contributor_selected_unit_labels_with_fully_recomputed_evidence(archive_permutation: tuple[int, ...]) -> None:
    value, validated_policy, _ = _population(archive_permutation=archive_permutation)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "CANDIDATE_ARCHIVE_ORDER_INVALID"


def test_dataclasses_replace_cannot_copy_or_forge_verifier_issuance() -> None:
    value, validated_policy, _ = _population()
    validated = g2.validate_candidate_population(value, policy=validated_policy)

    copied = replace(validated)
    with pytest.raises(V63Error) as exc_info:
        g2.offline_population_verdict(copied)
    assert exc_info.value.code == "POPULATION_OBJECT_NOT_ISSUED"

    forged_data = dict(validated._data)
    forged_data["population_evidence_root_sha256"] = "0" * 64
    forged = replace(validated, _data=MappingProxyType(forged_data))
    with pytest.raises(V63Error) as exc_info:
        g2.offline_population_verdict(forged)
    assert exc_info.value.code == "POPULATION_OBJECT_NOT_ISSUED"


@pytest.mark.parametrize(
    "mutation",
    (
        "population_root",
        "archive_hashes",
        "units",
        "pair_attachment",
        "semantic_flags",
        "authority_claims",
    ),
)
def test_low_level_data_mutation_cannot_produce_a_verdict(mutation: str) -> None:
    value, validated_policy, _ = _population()
    validated = g2.validate_candidate_population(value, policy=validated_policy)
    forged_data = dict(validated._data)
    if mutation == "population_root":
        forged_data["population_evidence_root_sha256"] = "0" * 64
    elif mutation == "archive_hashes":
        archive_hashes = dict(forged_data["archive_hashes_by_candidate_id"])
        archive_hashes["U01"] = "0" * 64
        forged_data["archive_hashes_by_candidate_id"] = archive_hashes
    elif mutation == "units":
        forged_data["units"] = {}
    elif mutation == "pair_attachment":
        attachment = dict(forged_data["candidate_pair_classification_attachment"])
        attachment["root_sha256"] = "0" * 64
        attachment["semantic_interpretation_performed"] = True
        forged_data["candidate_pair_classification_attachment"] = attachment
    elif mutation == "semantic_flags":
        forged_data["semantic_population_closed"] = True
        forged_data["semantic_population_validated"] = True
    else:
        forged_data["calibration_upload_authorized"] = True
        forged_data["production_upload_authorized"] = True
        forged_data["permits"] = [{"forged": True}]
    object.__setattr__(validated, "_data", MappingProxyType(forged_data))

    with pytest.raises(V63Error) as exc_info:
        g2.offline_population_verdict(validated)
    assert exc_info.value.code == "POPULATION_OBJECT_TAMPERED"


def test_low_level_construction_token_mutation_cannot_produce_a_verdict() -> None:
    value, validated_policy, _ = _population()
    validated = g2.validate_candidate_population(value, policy=validated_policy)
    object.__setattr__(validated, "_construction_token", object())
    with pytest.raises(V63Error) as exc_info:
        g2.offline_population_verdict(validated)
    assert exc_info.value.code == "POPULATION_OBJECT_TAMPERED"


def test_candidate_pair_labels_are_verified_but_not_projected_or_enforced() -> None:
    value, validated_policy, keys = _population()
    pair = value["pair_classifications"][0]
    classification = pair["classifications"][1]
    classification.update({"source_state": "CONFLICT", "lineage_control_state": "UNKNOWN", "development_control_state": "SHARED", "intervention_state": "OVERLAP"})
    analysis = {"schema": g2.PAIR_ANALYSIS_SCHEMA, "auditor_id": "B", "left_candidate_id": "U01", "right_candidate_id": "U02", "source_state": "CONFLICT", "lineage_control_state": "UNKNOWN", "development_control_state": "SHARED", "intervention_state": "OVERLAP", "analysis_evidence_root_sha256": classification["analysis_evidence_root_sha256"]}
    store = _store(value)
    classification["analysis_root_sha256"] = _add_json(store, analysis)
    core = {key: pair[key] for key in pair if key != "signatures"}
    pair["signatures"] = _signatures(core, g2.DOMAIN_PAIR_CLASSIFICATION, keys)
    _rebind_population_roots(value, store, validated_policy)
    validated = g2.validate_candidate_population(value, policy=validated_policy)
    assert "components" not in validated
    assert validated["candidate_pair_classification_attachment"]["semantic_interpretation_performed"] is False


def test_rejects_unsigned_and_self_authored_candidate_evidence() -> None:
    value, validated_policy, _ = _population()
    value["units"][0]["source"]["signatures"] = []
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "POPULATION_SIGNATURE_INVALID"

    value, validated_policy, _ = _population()
    attacker = Ed25519PrivateKey.generate()
    pair = value["pair_classifications"][0]
    core = {key: pair[key] for key in pair if key != "signatures"}
    pair["signatures"][0] = _signature(core, g2.DOMAIN_PAIR_CLASSIFICATION, attacker, "A")
    store = _store(value)
    _rebind_population_roots(value, store, validated_policy)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "POPULATION_SIGNATURE_INVALID"


def test_rebuild_receipts_have_no_caller_verdict_and_reject_pass_injection() -> None:
    value, validated_policy, keys = _population()
    assert all("verdict" not in receipt for receipt in value["units"][0]["build"]["rebuild_receipts"])
    build = value["units"][0]["build"]
    build["rebuild_receipts"][0]["verdict"] = "PASS"
    build_core = {key: build[key] for key in build if key not in {"evidence_root_sha256", "signatures"}}
    build["signatures"] = _signatures(build_core, g2.DOMAIN_BUILD_EVIDENCE, keys)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "REBUILD_RECEIPT_INVALID"


@pytest.mark.parametrize(
    ("options", "expected_code"),
    (
        ({"receipt_os": "darwin"}, "REBUILD_RECEIPT_INVALID"),
        ({"receipt_output_tamper": True}, "REBUILD_RECEIPT_INVALID"),
        ({"safety_finding": True}, "SAFETY_AUDIT_FAILED"),
    ),
)
def test_rebuild_receipt_result_is_derived_from_exact_bindings_and_safety(options: dict[str, Any], expected_code: str) -> None:
    value, validated_policy, _ = _population(**options)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == expected_code


@pytest.mark.parametrize("opaque_evidence", ("source_history", "toolchain", "control"))
def test_rejects_opaque_evidence_where_typed_canonical_json_is_required(opaque_evidence: str) -> None:
    value, validated_policy, _ = _population(opaque_evidence=opaque_evidence)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code in {"SOURCE_EVIDENCE_INVALID", "BUILD_EVIDENCE_INVALID", "SEMANTIC_DISCLOSURE_INVALID"}


@pytest.mark.parametrize(
    ("archive_variant", "expected_code"),
    (
        ("concatenated_gzip", "ARCHIVE_PROFILE_INVALID"),
        ("trailing_data", "ARCHIVE_PROFILE_INVALID"),
        ("gnu", "ARCHIVE_PROFILE_INVALID"),
        ("pax", "ARCHIVE_PROFILE_INVALID"),
        ("symlink", "ARCHIVE_PROFILE_INVALID"),
        ("duplicate", "ARCHIVE_PROFILE_INVALID"),
        ("prefix_collision", "ARCHIVE_PROFILE_INVALID"),
        ("nfd", "ARCHIVE_PROFILE_INVALID"),
        ("traversal", "ARCHIVE_PROFILE_INVALID"),
        ("sparse", "ARCHIVE_PROFILE_INVALID"),
        ("too_many", "ARCHIVE_RESOURCE_LIMIT"),
    ),
)
def test_rejects_noncanonical_or_unbounded_archive_profiles(archive_variant: str, expected_code: str) -> None:
    value, validated_policy, _ = _population(archive_variant=archive_variant)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == expected_code


@pytest.mark.parametrize("manifest_tamper", ("path", "mode", "size", "hash"))
def test_manifest_binds_file_mode_size_hash_and_path(manifest_tamper: str) -> None:
    value, validated_policy, _ = _population(manifest_tamper=manifest_tamper)
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "ARCHIVE_MANIFEST_MISMATCH"


def test_rejects_missing_candidate_disclosure_or_pair_analysis_payload() -> None:
    value, validated_policy, _ = _population()
    root = value["units"][0]["semantic_disclosure"]["control_evidence_root_sha256"]
    value["artifacts"] = [artifact for artifact in value["artifacts"] if artifact["content_sha256"] != root]
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "ARTIFACT_PAYLOAD_MISSING"

    value, validated_policy, _ = _population()
    root = value["pair_classifications"][0]["classifications"][0]["analysis_evidence_root_sha256"]
    value["artifacts"] = [artifact for artifact in value["artifacts"] if artifact["content_sha256"] != root]
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "ARTIFACT_PAYLOAD_MISSING"


def test_rejects_role_ids_and_caller_component_labels() -> None:
    value, validated_policy, _ = _population()
    value["units"][0]["candidate_id"] = "D01"
    with pytest.raises(V63Error) as exc_info:
        g2.validate_candidate_population(value, policy=validated_policy)
    assert exc_info.value.code == "CANDIDATE_ID_INVALID"

    value, validated_policy, _ = _population()
    value["units"][0]["semantic_disclosure"]["development_control_group_id"] = "forged"
    with pytest.raises(V63Error, match="fields must exactly"):
        g2.validate_candidate_population(value, policy=validated_policy)
