from __future__ import annotations

import base64
from copy import deepcopy
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.exact_gate_v2 import (
    _decode_ed25519_point,
    _ed25519_add,
    validate_ed25519_public_key,
)
from evaluation_v5_1.rebuild_custody import (
    EXECUTION_POLICY_SCHEMA,
    HOST_RECEIPT_SCHEMA,
    INPUT_NAMES,
    OUTPUT_NAMES,
    PLATFORM_INVENTORY_SCHEMA,
    PROTOCOL_ID,
    RebuildCustodyError,
    UPSTREAM_DEPENDENCY_BUNDLE_MEDIA_TYPE,
    UPSTREAM_DEPENDENCY_BUNDLE_SCHEMA,
    VALIDATION_COUNTERSIGNATURE_SCHEMA,
    WORKSPACE_INVENTORY_SCHEMA,
    derive_rebuild_custody_audit,
    derive_validation_countersignature_payload,
    encode_byte_evidence,
    verify_rebuild_custody,
)


_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_TORSION_GENERATOR = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0"
    "d5dfac05d3c63339b13802886d53fc05"
)


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _signed(
    schema: str,
    payload: dict[str, object],
    private: Ed25519PrivateKey,
    public: bytes,
) -> dict[str, object]:
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _wrapped(label: str, *, media_type: str = "application/octet-stream") -> dict[str, object]:
    return encode_byte_evidence(label.encode("ascii"), media_type=media_type)


def _artifact_inventory(
    names: tuple[str, ...], wrappers: dict[str, dict[str, object]], root: str
) -> list[dict[str, object]]:
    return [
        {
            "artifact_id": name,
            "path": f"{root}/{name}",
            "sha256": wrappers[name]["sha256"],
            "decoded_length": wrappers[name]["decoded_length"],
            "media_type": wrappers[name]["media_type"],
        }
        for name in names
    ]


def _upstream_payload(inputs: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "schema": UPSTREAM_DEPENDENCY_BUNDLE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": "G06_DEV_BYTE_REBUILD",
        "evaluation_id": "dev-2026-07-14",
        "inputs": inputs,
        "execution_policy": {
            "schema": EXECUTION_POLICY_SCHEMA,
            "argv": ["/opt/g06/bin/rebuild", "--fit", "/g06/input/fit_spec"],
            "env_allowlist": [
                {"name": "LC_ALL", "allowed_values": ["C.UTF-8"]},
                {"name": "PYTHONHASHSEED", "allowed_values": ["0"]},
                {"name": "TZ", "allowed_values": ["UTC"]},
            ],
            "max_duration_us": 5_000_000,
        },
    }


def _upstream_wrapper(payload: dict[str, object]) -> dict[str, object]:
    return encode_byte_evidence(
        canonical_json_bytes(payload), media_type=UPSTREAM_DEPENDENCY_BUNDLE_MEDIA_TYPE
    )


def _receipt(
    *,
    public: bytes,
    principal: str,
    custodian: str,
    instance: str,
    nonce: str,
    inputs: dict[str, dict[str, object]],
    outputs: dict[str, dict[str, object]],
) -> dict[str, object]:
    input_inventory = _artifact_inventory(INPUT_NAMES, inputs, "/g06/input")
    output_inventory = _artifact_inventory(OUTPUT_NAMES, outputs, "/g06/output")
    return {
        "schema": HOST_RECEIPT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": "G06_DEV_BYTE_REBUILD",
        "evaluation_id": "dev-2026-07-14",
        "attestor_key_id": validate_ed25519_public_key(public),
        "custody": {
            "principal_id": principal,
            "custodian_id": custodian,
            "host_instance_id": instance,
            "execution_nonce": nonce,
        },
        "platform_inventory": {
            "schema": PLATFORM_INVENTORY_SCHEMA,
            "os": "linux",
            "arch": "amd64",
            "container_image_sha256": inputs["container"]["sha256"],
            "runtime_sha256": inputs["runtime"]["sha256"],
            "toolchain_sha256": inputs["toolchain"]["sha256"],
            "executable_sha256": inputs["executable"]["sha256"],
            "network_mode": "none",
            "rootfs_read_only": True,
        },
        "binary_inventory": [
            {
                "binary_id": name,
                "path": {
                    "runtime": "/opt/g06/bin/runtime",
                    "toolchain": "/opt/g06/bin/toolchain",
                    "executable": "/opt/g06/bin/rebuild",
                }[name],
                "sha256": inputs[name]["sha256"],
                "decoded_length": inputs[name]["decoded_length"],
                "mode": "0555",
            }
            for name in ("runtime", "toolchain", "executable")
        ],
        "invocation": {
            "binary_path": "/opt/g06/bin/rebuild",
            "argv": ["/opt/g06/bin/rebuild", "--fit", "/g06/input/fit_spec"],
            "env": [
                {"name": "LC_ALL", "value": "C.UTF-8"},
                {"name": "PYTHONHASHSEED", "value": "0"},
                {"name": "TZ", "value": "UTC"},
            ],
        },
        "chronology": {
            "started_at_utc": "2026-07-14T01:00:00.000000Z",
            "ended_at_utc": "2026-07-14T01:00:01.000000Z",
        },
        "workspace_pre_inventory": {"schema": WORKSPACE_INVENTORY_SCHEMA, "entries": []},
        "workspace_post_inventory": {
            "schema": WORKSPACE_INVENTORY_SCHEMA,
            "entries": output_inventory,
        },
        "execution": {
            "attempt_index": 0,
            "retry_count": 0,
            "intervention_count": 0,
            "exit_code": 0,
        },
        "inputs": inputs,
        "input_inventory": input_inventory,
        "outputs": outputs,
        "output_inventory": output_inventory,
    }


def _fixture() -> dict[str, object]:
    host_a_private, host_a_public = _key(1)
    host_b_private, host_b_public = _key(2)
    validator_private, validator_public = _key(3)
    inputs = {name: _wrapped(f"frozen-{name}") for name in INPUT_NAMES}
    outputs = {
        name: _wrapped(
            f"exact-{name}",
            media_type="text/plain" if name in {"stdout", "stderr"} else "application/json",
        )
        for name in OUTPUT_NAMES
    }
    upstream_payload = _upstream_payload(inputs)
    payloads = [
        _receipt(
            public=host_a_public,
            principal="principal-a",
            custodian="custodian-a",
            instance="instance-a",
            nonce="nonce-a",
            inputs=deepcopy(inputs),
            outputs=deepcopy(outputs),
        ),
        _receipt(
            public=host_b_public,
            principal="principal-b",
            custodian="custodian-b",
            instance="instance-b",
            nonce="nonce-b",
            inputs=deepcopy(inputs),
            outputs=deepcopy(outputs),
        ),
    ]

    def finalize(
        receipts: list[dict[str, object]] | None = None,
        upstream: dict[str, object] | None = None,
    ) -> dict[str, object]:
        items = deepcopy(payloads if receipts is None else receipts)
        upstream_evidence = _upstream_wrapper(
            deepcopy(upstream_payload if upstream is None else upstream)
        )
        host_envelopes = [
            _signed(HOST_RECEIPT_SCHEMA, items[0], host_a_private, host_a_public),
            _signed(HOST_RECEIPT_SCHEMA, items[1], host_b_private, host_b_public),
        ]
        audit = derive_rebuild_custody_audit(
            host_receipt_envelopes=host_envelopes,
            host_attestor_public_keys=[host_a_public, host_b_public],
            upstream_dependency_bundle=upstream_evidence,
        )
        validator_payload = derive_validation_countersignature_payload(
            audit, validation_authority_public_key=validator_public
        )
        return {
            "host_receipt_envelopes": host_envelopes,
            "host_attestor_public_keys": [host_a_public, host_b_public],
            "upstream_dependency_bundle": upstream_evidence,
            "validation_authority_envelope": _signed(
                VALIDATION_COUNTERSIGNATURE_SCHEMA,
                validator_payload,
                validator_private,
                validator_public,
            ),
            "validation_authority_public_key": validator_public,
        }

    return {
        "kwargs": finalize(),
        "finalize": finalize,
        "payloads": payloads,
        "upstream_payload": upstream_payload,
        "host_publics": [host_a_public, host_b_public],
        "validator_private": validator_private,
        "validator_public": validator_public,
    }


def _payloads(fixture: dict[str, object]) -> list[dict[str, object]]:
    return deepcopy(fixture["payloads"])  # type: ignore[return-value]


def _finalize(fixture: dict[str, object], payloads: list[dict[str, object]]) -> dict[str, object]:
    return fixture["finalize"](payloads)  # type: ignore[operator,no-any-return]


def _mutate_signature(envelope: dict[str, object], defect: str) -> None:
    signature = bytearray(base64.b64decode(envelope["signature_ed25519_base64"]))
    if defect == "noncanonical_r":
        signature[:32] = _ED25519_P.to_bytes(32, "little")
    elif defect == "small_order_r":
        signature[:32] = b"\x01" + bytes(31)
    elif defect == "mixed_order_r":
        signature[:32] = _mixed_order(bytes(signature[:32]))
    else:
        assert defect == "s_gte_l"
        signature[32:] = _ED25519_L.to_bytes(32, "little")
    envelope["signature_ed25519_base64"] = base64.b64encode(signature).decode("ascii")


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _mixed_order(valid_encoding: bytes) -> bytes:
    valid = _decode_ed25519_point(valid_encoding, label="valid fixture", reject_small_order=True)
    torsion = _decode_ed25519_point(
        _TORSION_GENERATOR, label="torsion fixture", reject_small_order=False
    )
    return _encode_point(_ed25519_add(valid, torsion))


def test_exact_dual_host_case_is_research_only_and_roots_come_from_bundle_bytes() -> None:
    fixture = _fixture()
    audit = verify_rebuild_custody(**fixture["kwargs"])  # type: ignore[arg-type]
    upstream_raw = canonical_json_bytes(fixture["upstream_payload"])
    assert audit["upstream_dependency_bundle_sha256"] == hashlib.sha256(upstream_raw).hexdigest()
    assert audit["input_roots"] == {
        name: fixture["upstream_payload"]["inputs"][name]["sha256"]  # type: ignore[index]
        for name in INPUT_NAMES
    }
    assert audit["decision"] == "G06_BYTE_REBUILD_VERIFIED_RESEARCH_ONLY"
    assert audit["authority"] is False
    assert audit["candidate_development_authorized"] is False
    assert audit["sealed_holdout_access_authorized"] is False
    assert audit["release_authorized"] is False
    assert audit["submission_authorized"] is False


def test_upstream_bundle_bytes_not_caller_roots_control_expected_inputs() -> None:
    fixture = _fixture()
    changed_upstream = deepcopy(fixture["upstream_payload"])
    changed_upstream["inputs"]["fit_spec"] = _wrapped("changed-fit-spec")  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="upstream dependency bytes"):
        fixture["finalize"](upstream=changed_upstream)  # type: ignore[operator]

    malformed = deepcopy(fixture["kwargs"])
    malformed["upstream_dependency_bundle"]["sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="sha256 mismatch"):
        verify_rebuild_custody(**malformed)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path,replacement,match",
    [
        (("platform_inventory", "os"), "darwin", "Linux/amd64"),
        (("platform_inventory", "arch"), "arm64", "Linux/amd64"),
        (("platform_inventory", "network_mode"), "bridge", "Linux/amd64"),
        (("binary_inventory", 2, "mode"), "0777", "binary inventory"),
        (("invocation", "binary_path"), "/tmp/rebuild", "frozen argv"),
        (("input_inventory", 0, "path"), "/tmp/campaign", "exact bytes"),
        (("output_inventory", 0, "path"), "/tmp/result", "exact bytes"),
    ],
)
def test_typed_platform_binary_invocation_and_io_inventories_are_exact(
    path: tuple[object, ...], replacement: object, match: str
) -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    target: object = payloads[0]
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    target[path[-1]] = replacement  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match=match):
        _finalize(fixture, payloads)


@pytest.mark.parametrize(
    "field",
    ["principal_id", "custodian_id", "host_instance_id", "execution_nonce"],
)
def test_independence_is_derived_from_distinct_custody_identities(field: str) -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    payloads[1]["custody"][field] = payloads[0]["custody"][field]  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match=f"distinct {field}"):
        _finalize(fixture, payloads)


def test_principal_custodian_alias_and_caller_key_id_are_rejected() -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    payloads[1]["custody"]["custodian_id"] = payloads[0]["custody"]["principal_id"]  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="must not alias"):
        _finalize(fixture, payloads)

    payloads = _payloads(fixture)
    payloads[0]["attestor_key_id"] = "caller-picked-key-id"
    with pytest.raises(RebuildCustodyError, match="derived pinned host key id"):
        _finalize(fixture, payloads)

    kwargs = deepcopy(fixture["kwargs"])
    kwargs["host_attestor_public_keys"][1] = kwargs["host_attestor_public_keys"][0]
    with pytest.raises(RebuildCustodyError, match="public keys must be distinct"):
        verify_rebuild_custody(**kwargs)  # type: ignore[arg-type]


def test_independently_valid_but_different_environment_inventories_fail() -> None:
    fixture = _fixture()
    upstream = deepcopy(fixture["upstream_payload"])
    upstream["execution_policy"]["env_allowlist"][0]["allowed_values"] = [  # type: ignore[index]
        "C.UTF-8",
        "C",
    ]
    # Canonical allowlists are sorted, and both values are individually allowed.
    upstream["execution_policy"]["env_allowlist"][0]["allowed_values"].sort()  # type: ignore[index]
    payloads = _payloads(fixture)
    payloads[0]["invocation"]["env"][0]["value"] = "C"  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="different invocations"):
        fixture["finalize"](payloads, upstream)  # type: ignore[operator]


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_index", True),
        ("retry_count", True),
        ("intervention_count", 1),
        ("exit_code", 1),
    ],
)
def test_zero_execution_counts_reject_bool_retry_intervention_and_failure(
    field: str, value: object
) -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    payloads[0]["execution"][field] = value  # type: ignore[index]
    with pytest.raises(RebuildCustodyError):
        _finalize(fixture, payloads)


def test_bool_is_rejected_for_byte_and_inventory_lengths() -> None:
    fixture = _fixture()
    bad_upstream = deepcopy(fixture["upstream_payload"])
    bad_upstream["inputs"]["campaign_root"]["decoded_length"] = True  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="decoded_length is invalid"):
        fixture["finalize"](upstream=bad_upstream)  # type: ignore[operator]

    payloads = _payloads(fixture)
    payloads[0]["input_inventory"][0]["decoded_length"] = True  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="non-negative integer"):
        _finalize(fixture, payloads)


def test_unclean_workspace_env_chronology_and_authority_claim_fail() -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    payloads[0]["workspace_pre_inventory"]["entries"] = [payloads[0]["input_inventory"][0]]  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="clean workspace custody"):
        _finalize(fixture, payloads)

    payloads = _payloads(fixture)
    payloads[0]["invocation"]["env"][0]["value"] = "en_US.UTF-8"  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="outside the frozen allowlist"):
        _finalize(fixture, payloads)

    payloads = _payloads(fixture)
    payloads[0]["chronology"]["ended_at_utc"] = payloads[0]["chronology"]["started_at_utc"]  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="chronology"):
        _finalize(fixture, payloads)

    payloads = _payloads(fixture)
    payloads[0]["submission_authorized"] = True
    with pytest.raises(RebuildCustodyError):
        _finalize(fixture, payloads)


def test_fake_inventory_hash_changed_bytes_output_mismatch_and_missing_transcript_fail() -> None:
    fixture = _fixture()
    payloads = _payloads(fixture)
    payloads[0]["output_inventory"][0]["sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="exact bytes"):
        _finalize(fixture, payloads)

    payloads = _payloads(fixture)
    replacement = _wrapped("changed-result", media_type="application/json")
    payloads[0]["outputs"]["result_core"] = replacement  # type: ignore[index]
    payloads[0]["output_inventory"][0].update(  # type: ignore[index]
        sha256=replacement["sha256"], decoded_length=replacement["decoded_length"]
    )
    payloads[0]["workspace_post_inventory"]["entries"] = deepcopy(payloads[0]["output_inventory"])  # type: ignore[index]
    with pytest.raises(RebuildCustodyError, match="byte-identical outputs"):
        _finalize(fixture, payloads)

    for missing in ("comparator_manifest", "prediction_transcript"):
        payloads = _payloads(fixture)
        del payloads[0]["outputs"][missing]  # type: ignore[index]
        with pytest.raises(RebuildCustodyError, match="every exact byte artifact"):
            _finalize(fixture, payloads)


@pytest.mark.parametrize("defect", ["noncanonical_r", "small_order_r", "mixed_order_r", "s_gte_l"])
@pytest.mark.parametrize("target", ["host", "validator"])
def test_noncanonical_torsion_mixed_order_r_and_s_gte_l_fail_before_signature_check(
    defect: str, target: str
) -> None:
    fixture = _fixture()
    kwargs = deepcopy(fixture["kwargs"])
    envelope = (
        kwargs["host_receipt_envelopes"][0]
        if target == "host"
        else kwargs["validation_authority_envelope"]
    )
    _mutate_signature(envelope, defect)
    with pytest.raises(RebuildCustodyError, match="signature encoding is invalid"):
        verify_rebuild_custody(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("defect", ["noncanonical", "small_order", "mixed_order"])
@pytest.mark.parametrize("target", ["host", "validator"])
def test_noncanonical_small_order_and_mixed_order_public_a_are_rejected(
    defect: str, target: str
) -> None:
    fixture = _fixture()
    kwargs = deepcopy(fixture["kwargs"])
    valid = (
        kwargs["host_attestor_public_keys"][0]
        if target == "host"
        else kwargs["validation_authority_public_key"]
    )
    if defect == "noncanonical":
        invalid = _ED25519_P.to_bytes(32, "little")
    elif defect == "small_order":
        invalid = b"\x01" + bytes(31)
    else:
        invalid = _mixed_order(valid)
    if target == "host":
        kwargs["host_attestor_public_keys"][0] = invalid
    else:
        kwargs["validation_authority_public_key"] = invalid
    with pytest.raises(RebuildCustodyError, match="strict Ed25519 public key"):
        verify_rebuild_custody(**kwargs)  # type: ignore[arg-type]


def test_validation_envelope_must_countersign_exact_pair_without_authority() -> None:
    fixture = _fixture()
    kwargs = deepcopy(fixture["kwargs"])
    validator_payload = deepcopy(kwargs["validation_authority_envelope"]["payload"])
    validator_payload["submission_authorized"] = True
    kwargs["validation_authority_envelope"] = _signed(
        VALIDATION_COUNTERSIGNATURE_SCHEMA,
        validator_payload,
        fixture["validator_private"],
        fixture["validator_public"],
    )
    with pytest.raises(RebuildCustodyError, match="exact G06 pair audit"):
        verify_rebuild_custody(**kwargs)  # type: ignore[arg-type]


def test_validation_payload_builder_rejects_bool_pair_length() -> None:
    fixture = _fixture()
    kwargs = fixture["kwargs"]
    audit = derive_rebuild_custody_audit(
        host_receipt_envelopes=kwargs["host_receipt_envelopes"],  # type: ignore[index]
        host_attestor_public_keys=kwargs["host_attestor_public_keys"],  # type: ignore[index]
        upstream_dependency_bundle=kwargs["upstream_dependency_bundle"],  # type: ignore[index]
    )
    audit["upstream_dependency_bundle_decoded_length"] = True
    with pytest.raises(RebuildCustodyError, match="non-negative integer"):
        derive_validation_countersignature_payload(
            audit,
            validation_authority_public_key=fixture["validator_public"],  # type: ignore[arg-type]
        )
