"""Live trusted-time acquisition contract for v6.2.6."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .trust_v626 import (
    validate_close_time_quorum,
    validate_open_time_quorum,
    validate_time_window,
)


class ExternalTimeTransport(Protocol):
    """Transport implemented by independently controlled time authorities."""

    def request_opening_quorum(self, binding: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]: ...

    def request_closing_quorum(self, binding: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]: ...


@dataclass(frozen=True)
class TrustedTimeAcquisition:
    opening_receipts: tuple[Mapping[str, Any], ...]
    closing_receipts: tuple[Mapping[str, Any], ...]


def acquire_trusted_time_quorums(
    *,
    transport: ExternalTimeTransport,
    policy: Mapping[str, Any],
    opening_binding: Mapping[str, Any],
    closing_binding: Mapping[str, Any],
    checkpoint_observed_at: Any,
) -> TrustedTimeAcquisition:
    """Request, validate, and bind live opening and closing time quorums."""

    opening_receipts = tuple(transport.request_opening_quorum(opening_binding))
    opening = validate_open_time_quorum(
        list(opening_receipts),
        policy=policy,
        expected=opening_binding,
    )
    closing_receipts = tuple(transport.request_closing_quorum(closing_binding))
    closing = validate_close_time_quorum(
        list(closing_receipts),
        policy=policy,
        expected=closing_binding,
    )
    validate_time_window(
        opening=opening,
        closing=closing,
        checkpoint_observed_at=checkpoint_observed_at,
    )
    return TrustedTimeAcquisition(
        opening_receipts=opening_receipts,
        closing_receipts=closing_receipts,
    )


__all__ = [
    "ExternalTimeTransport",
    "TrustedTimeAcquisition",
    "acquire_trusted_time_quorums",
]
