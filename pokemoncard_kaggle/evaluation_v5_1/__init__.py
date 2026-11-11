"""Evidence-producing evaluator v5.1.

This package is deliberately authority-free.  Its verifiers can reject bad
evidence, but no module in this package may authorize holdout access or a
Kaggle submission.
"""

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import (
    DOMAIN_PREFIX,
    EnvelopeError,
    build_envelope,
    signing_payload,
    verify_envelope,
)

PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"

__all__ = [
    "CanonicalJSONError",
    "DOMAIN_PREFIX",
    "EnvelopeError",
    "PROTOCOL_ID",
    "build_envelope",
    "canonical_json_bytes",
    "canonical_sha256",
    "signing_payload",
    "verify_envelope",
]
