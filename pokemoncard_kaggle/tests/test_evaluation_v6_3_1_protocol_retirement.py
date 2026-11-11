from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

import evaluation_v6_3_1.protocol_retirement as retirement
from evaluation_v6_3_1.unified_rng_protocol import canonical_cbor_encode


def _assert_code(code: str, fn, *args, **kwargs) -> None:
    with pytest.raises(retirement.ProtocolRetirementError) as raised:
        fn(*args, **kwargs)
    assert raised.value.code == code


def test_current_records_pass_only_the_zero_authority_version_boundary() -> None:
    records = (
        canonical_cbor_encode([631302, 1]),
        [631302, 2],
    )
    admission = retirement.admit_current_protocol_records(
        records,
        trace_format=retirement.CURRENT_TRACE_FORMAT,
    )
    assert admission.protocol_version == 631302
    assert admission.record_count == 2
    assert admission.state == "CURRENT_VERSION_ONLY_REQUIRES_SCHEMA_VERIFICATION"
    assert admission.authority == "NO_UPLOAD"
    assert admission.calibration_upload_authorized is False
    assert admission.production_upload_authorized is False
    assert admission.permits == ()
    with pytest.raises(FrozenInstanceError):
        admission.state = "AUTHORIZED"  # type: ignore[misc]
    with pytest.raises(TypeError):
        admission.as_dict()["production_upload_authorized"] = True  # type: ignore[index]


def test_retired_and_mixed_record_sets_fail_with_exact_codes() -> None:
    _assert_code(
        "RNG_PROTOCOL_631301_RETIRED",
        retirement.admit_current_protocol_records,
        [[631301, 1]],
        trace_format=retirement.CURRENT_TRACE_FORMAT,
    )
    _assert_code(
        "RNG_MIXED_PROTOCOL_SESSION",
        retirement.admit_current_protocol_records,
        [[631302, 1], [631301, 1]],
        trace_format=retirement.CURRENT_TRACE_FORMAT,
    )
    _assert_code(
        "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
        retirement.admit_current_protocol_records,
        [[631303, 1]],
        trace_format=retirement.CURRENT_TRACE_FORMAT,
    )


@pytest.mark.parametrize("trace_format", sorted(retirement.LEGACY_TRACE_FORMATS))
def test_legacy_trace_formats_have_no_compatibility_path(trace_format: str) -> None:
    _assert_code(
        "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
        retirement.admit_current_protocol_records,
        [[631302, 1]],
        trace_format=trace_format,
    )
    _assert_code(
        "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
        retirement.reject_legacy_migration,
        "compatibility-parse",
        trace_format,
    )


def test_retired_artifacts_cannot_be_parented_or_exposed_as_converters() -> None:
    _assert_code(
        "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
        retirement.require_current_parent_protocol,
        631301,
    )
    assert retirement.require_current_parent_protocol(631302) is None
    for forbidden_name in (
        "translate_legacy_artifact",
        "wrap_legacy_artifact",
        "rehash_legacy_artifact",
        "decode_legacy_trace",
    ):
        assert not hasattr(retirement, forbidden_name)
