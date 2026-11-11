from __future__ import annotations

import copy
import hashlib

import pytest

from evaluation_v4_2.container_protocol import (
    CONTAINER_PROTOCOL_SCHEMA,
    DEVELOPMENT_AUTHORITY,
    REQUIRED_ACTION_DEADLINE_ENFORCEMENT,
    REQUIRED_ARM_DEADLINE_ENFORCEMENT,
    REQUIRED_CONTAINER_SCOPE,
    REQUIRED_COMMAND,
    REQUIRED_NETWORK_MODE,
    REQUIRED_PLATFORM,
    REQUIRED_RETRY_POLICY,
    STATE_FROZEN,
    ContainerProtocolError,
    build_container_protocol,
    canonical_sha256,
    validate_container_protocol,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _content() -> dict[str, object]:
    image_digest = _sha("oci-image")
    return {
        "schema": CONTAINER_PROTOCOL_SCHEMA,
        "arm_id": "candidate-arm-001",
        "arm_kind": "candidate",
        "bundle_manifest_sha256": _sha("bundle-manifest"),
        "task_spec_sha256": _sha("task-spec"),
        "oci_image": f"ghcr.io/example/evaluator@sha256:{image_digest}",
        "image_digest_sha256": image_digest,
        "image_manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "image_manifest_raw_sha256": image_digest,
        "image_config_sha256": _sha("image-config"),
        "image_layer_sha256s": [_sha("layer-1"), _sha("layer-2")],
        "platform": REQUIRED_PLATFORM,
        "network_mode": REQUIRED_NETWORK_MODE,
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "input_mounts": [
            {
                "source_id": "sealed-inputs",
                "source_sha256": _sha("inputs"),
                "target": "/inputs",
                "read_only": True,
                "private": True,
            }
        ],
        "scratch_tmpfs": {
            "target": "/tmp",
            "size_bytes": 64 * 1024 * 1024,
            "read_only": False,
            "private": True,
        },
        "cpu_limit_millicores": 1000,
        "memory_limit_bytes": 512 * 1024 * 1024,
        "pids_limit": 128,
        "max_steps": 600,
        "output_limit_bytes": 1024 * 1024,
        "arm_deadline_seconds": 30.0,
        "arm_deadline_enforcement": REQUIRED_ARM_DEADLINE_ENFORCEMENT,
        "action_deadline_seconds": 1.0,
        "action_deadline_enforcement": REQUIRED_ACTION_DEADLINE_ENFORCEMENT,
        "retry_policy": REQUIRED_RETRY_POLICY,
        "container_scope": REQUIRED_CONTAINER_SCOPE,
        "runtime_sha256": _sha("runtime"),
        "security_sha256": _sha("security"),
        "source_sha256": _sha("source"),
        "command": list(REQUIRED_COMMAND),
        "authority": DEVELOPMENT_AUTHORITY,
        "research_only": True,
        "external_authority": False,
        "submission_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "state": STATE_FROZEN,
    }


def test_build_validate_and_self_hash_are_canonical() -> None:
    protocol = build_container_protocol(_content())

    assert validate_container_protocol(protocol) == protocol
    assert protocol["content_sha256"] == canonical_sha256(
        {key: value for key, value in protocol.items() if key != "content_sha256"}
    )


def test_unknown_fields_and_presealed_builder_input_are_rejected() -> None:
    with pytest.raises(ContainerProtocolError, match="exactly"):
        build_container_protocol({**_content(), "unexpected": True})

    protocol = build_container_protocol(_content())
    with pytest.raises(ContainerProtocolError, match="exactly"):
        validate_container_protocol({**protocol, "unexpected": True})
    with pytest.raises(ContainerProtocolError, match="hash-free"):
        build_container_protocol(protocol)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("oci_image", "ghcr.io/example/evaluator:latest"),
        ("platform", "linux/arm64"),
        ("network_mode", "bridge"),
        ("read_only_rootfs", False),
        ("cap_drop", ["NET_ADMIN"]),
        ("no_new_privileges", False),
        ("arm_deadline_enforcement", "in_container"),
        ("action_deadline_enforcement", "best_effort"),
        ("retry_policy", "one_retry"),
        ("container_scope", "shared_container"),
        ("command", ["python", "-c", "print('forged result')"]),
        ("authority", "SUBMIT_AUTHORIZED"),
        ("research_only", False),
        ("production_submission_authorized", True),
    ],
)
def test_security_deadline_and_authority_escalations_are_rejected(
    field: str, value: object
) -> None:
    with pytest.raises(ContainerProtocolError):
        build_container_protocol({**_content(), field: value})


def test_digest_and_immutable_hash_bindings_are_checked() -> None:
    content = _content()
    content["image_digest_sha256"] = _sha("different-image")
    with pytest.raises(ContainerProtocolError, match="match"):
        build_container_protocol(content)

    protocol = build_container_protocol(_content())
    for field in ("runtime_sha256", "security_sha256", "source_sha256"):
        tampered = copy.deepcopy(protocol)
        tampered[field] = _sha(f"changed-{field}")
        with pytest.raises(ContainerProtocolError, match="mismatch"):
            validate_container_protocol(tampered)


def test_mounts_tmpfs_and_resource_limits_are_fail_closed() -> None:
    cases = [
        ("input_mounts", [{**_content()["input_mounts"][0], "private": False}]),  # type: ignore[index]
        (
            "scratch_tmpfs",
            {**_content()["scratch_tmpfs"], "read_only": True},  # type: ignore[arg-type]
        ),
        ("cpu_limit_millicores", 0),
        ("memory_limit_bytes", True),
        ("pids_limit", -1),
        ("arm_deadline_seconds", 1.0),
        ("action_deadline_seconds", 30.0),
    ]
    for field, value in cases:
        with pytest.raises(ContainerProtocolError):
            build_container_protocol({**_content(), field: value})


def test_reordered_top_level_mapping_is_valid_but_tampering_is_not() -> None:
    protocol = build_container_protocol(_content())
    reordered = {key: protocol[key] for key in reversed(list(protocol))}
    assert validate_container_protocol(reordered) == protocol

    tampered = copy.deepcopy(protocol)
    tampered["source_sha256"] = _sha("changed-source")
    with pytest.raises(ContainerProtocolError, match="mismatch"):
        validate_container_protocol(tampered)
