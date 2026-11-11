"""Research-only VOI-P5 protocol and evidence-integrity primitives."""

from .protocol import (
    PAIR_ASSIGNMENT_SCHEMA,
    POPULATION_MANIFEST_SCHEMA,
    PROTOCOL_SCHEMA,
    ProtocolError,
    build_pair_assignment,
    build_population_manifest,
    canonical_sha256,
    protocol_core_sha256,
    validate_pair_assignment,
    validate_population_manifest,
    validate_protocol,
    write_pair_assignment_once,
    write_population_manifest_once,
    write_protocol_once,
)

__all__ = [
    "PAIR_ASSIGNMENT_SCHEMA",
    "POPULATION_MANIFEST_SCHEMA",
    "PROTOCOL_SCHEMA",
    "ProtocolError",
    "build_pair_assignment",
    "build_population_manifest",
    "canonical_sha256",
    "protocol_core_sha256",
    "validate_pair_assignment",
    "validate_population_manifest",
    "validate_protocol",
    "write_pair_assignment_once",
    "write_population_manifest_once",
    "write_protocol_once",
]
