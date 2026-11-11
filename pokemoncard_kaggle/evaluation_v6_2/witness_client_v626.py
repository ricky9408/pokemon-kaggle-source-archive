"""Live external-witness acquisition contract for v6.2.6.

The transport must be backed by an independently administered service. This
client keeps no authoritative local state: it reads a signed head, asks the
service to perform compare-and-append, and reads a second signed head. Deleting
or restoring a project cache therefore cannot make a redeemed challenge fresh.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import secrets
from typing import Any, Protocol

from .trust_v626 import (
    TrustV626Error,
    WitnessHeadValidation,
    WitnessValidation,
    detect_witness_forks,
    validate_witness_head,
    validate_witness_transition,
)


class ExternalWitnessTransport(Protocol):
    """Transport implemented by an independently controlled witness service."""

    def read_head(
        self,
        *,
        namespace: str,
        release_root_sha256: str,
        response_nonce: str,
    ) -> Mapping[str, Any]: ...

    def compare_and_append(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class WitnessAcquisition:
    opening_head_envelope: Mapping[str, Any]
    opening_head: WitnessHeadValidation
    transition: WitnessValidation
    closing_head: WitnessHeadValidation
    closing_head_envelope: Mapping[str, Any]
    transition_envelope: Mapping[str, Any]


def acquire_witness_transition(
    *,
    transport: ExternalWitnessTransport,
    policy: Mapping[str, Any],
    redemption_request: Mapping[str, Any],
) -> WitnessAcquisition:
    """Acquire and validate one live CAS transition without local authority."""

    opening_nonce = secrets.token_hex(16)
    closing_nonce = secrets.token_hex(16)
    if opening_nonce == closing_nonce:
        raise TrustV626Error("MONOTONIC_WITNESS_UNAVAILABLE", "witness head nonces collided")
    opening_envelope = transport.read_head(
        namespace=policy["namespace"],
        release_root_sha256=policy["release_root_sha256"],
        response_nonce=opening_nonce,
    )
    opening = validate_witness_head(
        opening_envelope,
        policy=policy,
        expected_response_nonce=opening_nonce,
    )
    if redemption_request.get("expected_state_sha256") != opening.state_sha256 or redemption_request.get("expected_sequence") != str(opening.sequence):
        raise TrustV626Error("MONOTONIC_CAS_REJECTED", "redemption request is stale relative to the external witness head")
    transition_envelope = transport.compare_and_append(redemption_request)
    transition = validate_witness_transition(transition_envelope, policy=policy)
    closing_envelope = transport.read_head(
        namespace=policy["namespace"],
        release_root_sha256=policy["release_root_sha256"],
        response_nonce=closing_nonce,
    )
    closing = validate_witness_head(
        closing_envelope,
        policy=policy,
        expected_response_nonce=closing_nonce,
    )
    if (
        opening.checkpoint_tree_size != transition.previous_checkpoint_tree_size
        or opening.checkpoint_root_sha256 != transition.previous_checkpoint_root_sha256
        or closing.checkpoint_tree_size != transition.checkpoint_tree_size
    ):
        raise TrustV626Error("OPENING_CLOSING_CONSISTENCY_FAILURE", "live witness heads and transition checkpoints disagree")
    if transition.previous_state_sha256 != opening.state_sha256 or transition.previous_sequence != opening.sequence:
        raise TrustV626Error("OPENING_HEAD_TRANSITION_MISMATCH", "external transition does not extend the opening head")
    if closing.state_sha256 != transition.new_state_sha256 or closing.sequence != transition.new_sequence:
        raise TrustV626Error("CLOSING_HEAD_TRANSITION_MISMATCH", "closing external head does not match the accepted transition")
    detect_witness_forks([transition])
    return WitnessAcquisition(
        opening_head_envelope=opening_envelope,
        opening_head=opening,
        transition=transition,
        closing_head=closing,
        closing_head_envelope=closing_envelope,
        transition_envelope=transition_envelope,
    )


__all__ = [
    "ExternalWitnessTransport",
    "WitnessAcquisition",
    "acquire_witness_transition",
]
